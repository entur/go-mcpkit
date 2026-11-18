package enturauth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"time"
)

const (
	refreshAfter = 5 * time.Minute         // after the last success
	retryFloor   = time.Minute             // between two fetches, whatever started them
	fetchTimeout = 2 * time.Second         // one fetch, and the longest a request waits for one
	lastGood     = 24 * time.Hour          // how long a snapshot stays usable without a success
	maxJWKS      = 64 << 10                // bytes of a JWKS document
	maxKeys      = 16                      // keys in a JWKS document
	minBits      = 2048                    // RSA modulus
	maxBits      = 8192                    // RSA modulus
	exponent     = 65537                   // the only accepted e, "AQAB"
	retryAfter   = "60"                    // seconds, on a 503
	jwksPath     = ".well-known/jwks.json" // appended to the issuer
)

// keyring holds one issuer's usable signing keys. A fetch replaces the
// snapshot wholesale; there is no verdict cache.
type keyring struct {
	ctx       context.Context // the authenticator's lifetime
	issuer    string
	client    *http.Client
	onRefresh func(string, error)

	mu     sync.Mutex
	keys   map[string]*rsa.PublicKey
	loaded time.Time     // the last success
	tried  time.Time     // the start of the last fetch
	flight chan struct{} // closed when the running fetch ends; nil when none runs
	usable bool          // a load has held a usable key (the Ready latch)
	err    error         // the last fetch's error
}

// startKeyring runs the first fetch, waiting at most fetchTimeout, and keeps
// the keys fresh until ctx ends. A nil transport is the network.
func startKeyring(ctx context.Context, issuer string, transport http.RoundTripper, onRefresh func(string, error)) *keyring {
	if transport == nil {
		transport = &http.Transport{Proxy: http.ProxyFromEnvironment, DisableCompression: true, ForceAttemptHTTP2: true}
	}
	k := &keyring{ctx: ctx, issuer: issuer, onRefresh: onRefresh, client: &http.Client{
		Transport:     transport,
		Timeout:       fetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	k.mu.Lock()
	done := k.start(time.Now())
	k.mu.Unlock()
	await(ctx, done)
	go k.run()
	return k
}

// run refreshes 5 min after the last success and retries every minute
// before the first and after a failure, until the lifetime ends.
func (k *keyring) run() {
	defer k.client.CloseIdleConnections()
	for {
		k.mu.Lock()
		next := k.tried.Add(retryFloor)
		if r := k.loaded.Add(refreshAfter); !k.loaded.IsZero() && r.After(next) {
			next = r
		}
		var done <-chan struct{}
		var wake <-chan time.Time
		if now := time.Now(); now.Before(next) {
			wake = time.After(next.Sub(now))
		} else {
			done = k.start(now)
		}
		k.mu.Unlock()
		select {
		case <-k.ctx.Done():
			return
		case <-done:
		case <-wake:
		}
	}
}

// start begins a fetch unless one runs, the floor forbids it or the lifetime
// has ended, and returns the running fetch's channel (nil when none runs).
// The caller holds mu.
func (k *keyring) start(now time.Time) <-chan struct{} {
	if k.flight == nil && now.Sub(k.tried) >= retryFloor && k.ctx.Err() == nil {
		k.flight, k.tried = make(chan struct{}), now
		go k.fetch(k.flight)
	}
	return k.flight
}

// fetch publishes one fetch's outcome and completes the flight under the
// lock, then reports it outside the lock.
func (k *keyring) fetch(flight chan struct{}) {
	keys, err := k.get()
	k.mu.Lock()
	if err == nil {
		k.keys, k.loaded = keys, time.Now()
		k.usable = k.usable || len(keys) > 0
	}
	k.err = err
	close(flight)
	k.flight = nil
	k.mu.Unlock()
	if k.onRefresh != nil {
		k.onRefresh(k.issuer, err)
	}
}

// get fetches and parses the JWKS. Its errors name the pinned URL and at most
// an HTTP status.
func (k *keyring) get() (map[string]*rsa.PublicKey, error) {
	jwks := k.issuer + jwksPath
	fail := func(why string) (map[string]*rsa.PublicKey, error) {
		return nil, fmt.Errorf("enturauth: %s: %s", jwks, why)
	}
	req, err := http.NewRequestWithContext(k.ctx, http.MethodGet, jwks, http.NoBody)
	var resp *http.Response
	if err == nil {
		resp, err = k.client.Do(req)
	}
	if err != nil {
		return fail("request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Sprintf("HTTP %d", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKS+1))
	switch {
	case err != nil:
		return fail("request failed")
	case len(body) > maxJWKS:
		return fail("document over 64 KiB")
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return fail(err.Error())
	}
	return keys, nil
}

// parseJWKS returns the usable keys of a JWKS document by kid.
func parseJWKS(b []byte) (map[string]*rsa.PublicKey, error) {
	doc, err := members(b)
	var list []json.RawMessage
	if err != nil || len(doc["keys"]) == 0 || doc["keys"][0] != '[' || json.Unmarshal(doc["keys"], &list) != nil {
		return nil, errors.New("malformed JSON")
	}
	if len(list) > maxKeys {
		return nil, errors.New("too many keys")
	}
	keys := map[string]*rsa.PublicKey{}
	for _, raw := range list {
		m, err := members(raw)
		if err != nil {
			return nil, errors.New("malformed JSON")
		}
		kid, pub := usableKey(m)
		if pub == nil {
			continue
		}
		if keys[kid] != nil {
			return nil, errors.New("ambiguous kid")
		}
		keys[kid] = pub
	}
	return keys, nil
}

// usableKey returns the kid and key of an RS256 verification key, or nil.
// x5c, x5t and jku are ignored.
func usableKey(m object) (string, *rsa.PublicKey) {
	var ops []string
	if raw, ok := m["key_ops"]; ok && (json.Unmarshal(raw, &ops) != nil || !slices.Equal(ops, []string{"verify"})) {
		return "", nil
	}
	_, hasUse := m["use"]
	_, hasAlg := m["alg"]
	kid, _ := m.str("kid")
	n64, _ := m.str("n")
	n, err := unb64(n64)
	modulus := new(big.Int).SetBytes(n)
	if !m.is("kty", "RSA") || (hasUse && !m.is("use", "sig")) || (hasAlg && !m.is("alg", "RS256")) || !m.is("e", "AQAB") ||
		kid == "" || err != nil || modulus.BitLen() < minBits || modulus.BitLen() > maxBits {
		return "", nil
	}
	return kid, &rsa.PublicKey{N: modulus, E: exponent}
}

// key returns kid's key from the current snapshot. An unknown kid starts or
// joins one fetch and waits for it, at most fetchTimeout or until ctx ends; a
// known kid never waits.
func (k *keyring) key(ctx context.Context, kid string) (*rsa.PublicKey, Reason) {
	pub, why, done := k.lookup(kid, true)
	if done != nil {
		await(ctx, done)
		pub, why, _ = k.lookup(kid, false)
	}
	return pub, why
}

func (k *keyring) lookup(kid string, fetch bool) (*rsa.PublicKey, Reason, <-chan struct{}) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := time.Now()
	pub, why := k.eligible(kid, now)
	var done <-chan struct{}
	if why != "" && fetch {
		done = k.start(now)
	}
	return pub, why, done
}

// confirm takes the admission decision under the lock, without a fetch: the
// lifetime and the snapshot are still usable and kid still names pub's key
// material (compared by value, so a refetch of the same key passes). It
// returns the decision's time for the date checks.
func (k *keyring) confirm(kid string, pub *rsa.PublicKey) (time.Time, Reason) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := time.Now()
	current, why := k.eligible(kid, now)
	if why == "" && !current.Equal(pub) {
		why = RejectUnknownKey
	}
	return now, why
}

// eligible returns kid's key while the lifetime lasts and the snapshot is
// usable at now. The caller holds mu.
func (k *keyring) eligible(kid string, now time.Time) (*rsa.PublicKey, Reason) {
	if k.ctx.Err() != nil || now.Sub(k.loaded) >= lastGood || len(k.keys) == 0 {
		return nil, RejectUnavailable
	}
	if pub := k.keys[kid]; pub != nil {
		return pub, ""
	}
	return nil, RejectUnknownKey
}

// await waits for done, at most fetchTimeout, or until ctx ends.
func await(ctx context.Context, done <-chan struct{}) {
	if done == nil {
		return
	}
	t := time.NewTimer(fetchTimeout)
	defer t.Stop()
	select {
	case <-done:
	case <-ctx.Done():
	case <-t.C:
	}
}

func (k *keyring) ready() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case k.usable:
		return nil
	case k.err != nil:
		return k.err
	}
	return errors.New("enturauth: no usable signing key yet")
}
