// Package enturauthtest stands in for Entur's Auth0 tenants in tests of
// servers built with enturauth. It serves signing keys for every pinned
// issuer from memory and mints RFC 9068 access tokens signed with them.
//
// Import it only from _test.go files. An authenticator built from its
// Context trusts its keys, and its posture reason starts with
// "TEST SIGNING KEYS:".
package enturauthtest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entur/go-mcpkit/enturauth"
	"github.com/entur/go-mcpkit/internal/kittest"
)

// Auth0 is the stand-in. Each issuer starts with one signing key, kid "k1",
// generated on first use; Rotate adds k2, k3 and so on. Its methods are safe
// for concurrent use.
type Auth0 struct {
	t       testing.TB
	mu      sync.Mutex
	keys    map[string][]*signingKey // by issuer, oldest first; the newest signs
	outage  func(*http.Request) (*http.Response, error)
	fetches int
}

type signingKey struct {
	kid       string
	priv      *rsa.PrivateKey
	published bool
}

// New returns a stand-in that serves every issuer's published keys.
func New(t testing.TB) *Auth0 { return &Auth0{t: t, keys: map[string][]*signingKey{}} }

// Context returns ctx carrying the stand-in, for enturauth.New.
func (a *Auth0) Context(ctx context.Context) context.Context {
	return kittest.WithJWKSTransport(ctx, roundTripper(a.roundTrip))
}

// Issuer is the pinned issuer of cfg's tenant and environment.
func Issuer(cfg enturauth.Config) string {
	if cfg.Tenant != enturauth.Partner {
		return ""
	}
	switch cfg.Env {
	case enturauth.Dev:
		return "https://partner.dev.entur.org/"
	case enturauth.Tst:
		return "https://partner.staging.entur.org/"
	case enturauth.Prd:
		return "https://partner.entur.org/"
	}
	return ""
}

// Claims returns claims that pass every check of cfg, issued now for one
// hour: its first client, its required scopes and organisation 1. Edit them
// for other cases.
func (a *Auth0) Claims(cfg enturauth.Config) map[string]any {
	const lifetime = 3600
	nowSec := time.Now().Unix()
	return map[string]any{
		"iss": Issuer(cfg), "aud": cfg.Resource, "sub": "auth0|user", "jti": "token-1",
		"client_id": cfg.ClientIDs[0], "scope": strings.Join(cfg.RequiredScopes, " "),
		"iat": nowSec, "exp": nowSec + lifetime, "https://entur.io/organisationID": 1,
	}
}

// Token signs claims with the newest key of the issuer they name.
func (a *Auth0) Token(claims map[string]any) string {
	a.t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		a.t.Fatal(err)
	}
	iss, _ := claims["iss"].(string)
	return a.Sign(iss, nil, b)
}

// Sign returns header.claims.signature, signed RS256 with the newest key of
// issuer. The raw JSON is used as given; a nil header is
// {"alg":"RS256","typ":"at+jwt","kid":<that key's kid>}.
func (a *Auth0) Sign(issuer string, header, claims []byte) string {
	a.t.Helper()
	a.mu.Lock()
	k := a.newest(issuer)
	a.mu.Unlock()
	if header == nil {
		header = fmt.Appendf(nil, `{"alg":"RS256","typ":"at+jwt","kid":%q}`, k.kid)
	}
	signed := b64(header) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(nil, k.priv, crypto.SHA256, sum[:])
	if err != nil {
		a.t.Fatal(err)
	}
	return signed + "." + b64(sig)
}

// Rotate publishes a new signing key for issuer and returns its kid. Older
// keys stay published until removed.
func (a *Auth0) Rotate(issuer string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.newest(issuer)
	return a.generate(issuer).kid
}

// Remove stops publishing issuer's key kid. Tokens it signed stay
// signed with it.
func (a *Auth0) Remove(issuer, kid string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, k := range a.keys[issuer] {
		if k.kid == kid {
			k.published = false
		}
	}
}

// Outage answers every signing-key fetch with f instead of the published
// keys, until Outage(nil). f may block until the request's context ends, to
// model a stall.
func (a *Auth0) Outage(f func(*http.Request) (*http.Response, error)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.outage = f
}

// Fetches counts the signing-key fetches so far, outages included.
func (a *Auth0) Fetches() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fetches
}

func (a *Auth0) roundTrip(r *http.Request) (*http.Response, error) {
	issuer, ok := strings.CutSuffix(r.URL.String(), ".well-known/jwks.json")
	keys := []map[string]string{}
	a.mu.Lock()
	a.fetches++
	outage := a.outage
	if ok {
		a.newest(issuer)
		for _, k := range a.keys[issuer] {
			if k.published {
				keys = append(keys, map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k.kid,
					"n": b64(k.priv.N.Bytes()), "e": b64(big.NewInt(int64(k.priv.E)).Bytes())})
			}
		}
	}
	a.mu.Unlock()
	if outage != nil {
		return outage(r)
	}
	rec := httptest.NewRecorder()
	if !ok {
		rec.WriteHeader(http.StatusNotFound)
		return rec.Result(), nil
	}
	rec.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rec).Encode(map[string]any{"keys": keys})
	return rec.Result(), nil
}

// newest returns issuer's newest key, generating k1 on first use. The caller
// holds mu.
func (a *Auth0) newest(issuer string) *signingKey {
	if ks := a.keys[issuer]; len(ks) > 0 {
		return ks[len(ks)-1]
	}
	return a.generate(issuer)
}

// generate adds a published key to issuer. The caller holds mu.
func (a *Auth0) generate(issuer string) *signingKey {
	const bits = 2048
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err) // crypto/rand does not fail
	}
	k := &signingKey{kid: fmt.Sprint("k", len(a.keys[issuer])+1), priv: priv, published: true}
	a.keys[issuer] = append(a.keys[issuer], k)
	return k
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
