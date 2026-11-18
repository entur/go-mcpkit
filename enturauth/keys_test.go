package enturauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/entur/go-mcpkit/enturauth"
	"github.com/entur/go-mcpkit/internal/kittest"
	"github.com/entur/go-mcpkit/mcpkittest/enturauthtest"
)

func down(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp 10.0.0.1:443: secret detail")
}

// TestKeys drives the keyring state machine on the bubble's clock.
func TestKeys(t *testing.T) {
	t.Parallel()
	a0 := enturauthtest.New(t)
	cfg := config()
	dev := enturauthtest.Issuer(cfg)
	// token is a fresh token naming kid, signed with the newest key.
	token := func(kid string) string {
		return a0.Sign(dev, fmt.Appendf(nil, `{"alg":"RS256","typ":"at+jwt","kid":%q}`, kid), js(a0.Claims(cfg)))
	}
	check := func(t *testing.T, a *enturauth.Authenticator, name, tok string, want enturauth.Reason) {
		t.Helper()
		rec, _ := serve(a, t.Context(), "/partner", "Bearer "+tok)
		checkResponse(t, name, rec, want)
	}
	fetches := func(t *testing.T, name string, want int) {
		t.Helper()
		synctest.Wait()
		if got := a0.Fetches(); got != want {
			t.Errorf("%s: %d fetches, want %d", name, got, want)
		}
	}

	t.Run("lifecycle", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			a := start(t, ctx, a0, cfg)
			n := a0.Fetches()
			if a.Ready() != nil || n != 1 {
				t.Fatalf("start: %v after %d fetches", a.Ready(), n)
			}
			check(t, a, "k1", token("k1"), "")

			k2 := a0.Rotate(dev)
			check(t, a, "new kid within the floor", token(k2), enturauth.RejectUnknownKey)
			fetches(t, "within the floor", 1)
			time.Sleep(time.Minute)
			check(t, a, "new kid after the floor", token(k2), "")
			fetches(t, "rotation", 2)

			time.Sleep(time.Minute)
			var wg sync.WaitGroup
			for i := range 50 {
				wg.Go(func() { check(t, a, "flood", token(fmt.Sprint("x", i)), enturauth.RejectUnknownKey) })
			}
			wg.Wait()
			check(t, a, "flood again", token("y"), enturauth.RejectUnknownKey)
			fetches(t, "flood", 3)

			// Removal mid-wait: a waiter for k3 joins a held fetch while the
			// known k2 is served at once; the fetched document drops k2.
			tok2 := token(k2)
			release := make(chan struct{})
			jwks := kittest.JWKSTransport(a0.Context(t.Context()))
			a0.Outage(func(r *http.Request) (*http.Response, error) {
				<-release
				a0.Outage(nil)
				return jwks.RoundTrip(r)
			})
			k3 := a0.Rotate(dev)
			a0.Remove(dev, k2)
			time.Sleep(time.Minute)
			began := time.Now()
			wg.Go(func() { check(t, a, "waiter", token(k3), "") })
			synctest.Wait()
			check(t, a, "known kid during a fetch", tok2, "")
			close(release)
			wg.Wait()
			if time.Since(began) != 0 {
				t.Errorf("waited %v", time.Since(began))
			}
			check(t, a, "removed key", tok2, enturauth.RejectUnknownKey)
			fetches(t, "removal", 5) // the held fetch counts twice: held, then served

			time.Sleep(5*time.Minute - time.Second)
			fetches(t, "before the refresh", 5)
			time.Sleep(time.Second)
			fetches(t, "refresh 5 min after the last success", 6)

			a0.Outage(down)
			time.Sleep(24*time.Hour - time.Second)
			check(t, a, "last good keys at 24 h - 1 s", token(k3), "")
			check(t, a, "removed key during the outage", token(k2), enturauth.RejectUnknownKey)
			if n := a0.Fetches() - 6; n < 24*60-5 || n > 24*60 {
				t.Errorf("%d retries in 24 h", n)
			}
			time.Sleep(time.Second)
			check(t, a, "no usable key after 24 h", token(k3), enturauth.RejectUnavailable)
			if a.Ready() != nil {
				t.Error("Ready reverted")
			}

			a0.Outage(nil)
			time.Sleep(time.Minute)
			synctest.Wait()
			check(t, a, "recovered", token(k3), "")

			cancel()
			synctest.Wait()
			n = a0.Fetches()
			check(t, a, "after the lifetime", token(k3), enturauth.RejectUnavailable)
			check(t, a, "unknown kid after the lifetime", token("z"), enturauth.RejectUnavailable)
			time.Sleep(time.Hour)
			fetches(t, "after the lifetime", n)
		})
	})

	t.Run("first load fails", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			got := make(chan *http.Request, 1)
			a0.Outage(func(r *http.Request) (*http.Response, error) {
				select {
				case got <- r:
				default:
				}
				return down(r)
			})
			a := start(t, t.Context(), a0, cfg)
			r := <-got
			if err := a.Ready(); err == nil || err.Error() != "enturauth: https://partner.dev.entur.org/.well-known/jwks.json: request failed" {
				t.Errorf("Ready: %v", err)
			}
			if r.Method != http.MethodGet || r.URL.String() != dev+".well-known/jwks.json" || len(r.Header) != 0 {
				t.Errorf("fetch %s %s %v", r.Method, r.URL, r.Header)
			}
			n := a0.Fetches()
			check(t, a, "before the first load", token("k1"), enturauth.RejectUnavailable)
			fetches(t, "within the floor", n)
			a0.Outage(nil)
			time.Sleep(time.Minute)
			synctest.Wait()
			if a.Ready() != nil {
				t.Error(a.Ready())
			}
			check(t, a, "after the retry", a0.Token(a0.Claims(cfg)), "")
		})
	})

	t.Run("waits are bounded", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a := start(t, t.Context(), a0, cfg)
			release := make(chan struct{})
			a0.Outage(func(*http.Request) (*http.Response, error) { <-release; return nil, errors.New("down") }) // ignores the timeout
			time.Sleep(time.Minute)
			short, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			began := time.Now()
			var wg sync.WaitGroup
			for _, w := range []struct {
				ctx  context.Context
				wait time.Duration
			}{{t.Context(), 2 * time.Second}, {short, 500 * time.Millisecond}} {
				wg.Go(func() {
					rec, _ := serve(a, w.ctx, "/partner", "Bearer "+token("k9"))
					checkResponse(t, "waiter", rec, enturauth.RejectUnknownKey)
					if d := time.Since(began); d != w.wait {
						t.Errorf("waited %v, want %v", d, w.wait)
					}
				})
			}
			wg.Wait()
			began = time.Now()
			check(t, a, "known kid", a0.Token(a0.Claims(cfg)), "")
			if time.Since(began) != 0 {
				t.Error("a known kid waited")
			}
			close(release)
			a0.Outage(nil)
		})
	})
}

// TestRefreshCallbackOutsideTheLock calls Ready from OnRefresh. Under the
// keyring lock that call would block until the callback returned. It runs on
// the real clock: a goroutine blocked on a mutex never lets a bubble's clock
// advance, and the bound matters only when the test fails.
func TestRefreshCallbackOutsideTheLock(t *testing.T) {
	t.Parallel()
	a0 := enturauthtest.New(t)
	var a *enturauth.Authenticator
	stored, blocked := make(chan struct{}), make(chan bool, 1)
	cfg := config()
	cfg.OnRefresh = func(string, error) {
		<-stored
		done := make(chan struct{})
		go func() { _ = a.Ready(); close(done) }()
		select {
		case <-done:
			blocked <- false
		case <-time.After(5 * time.Second):
			blocked <- true
		}
	}
	a = start(t, t.Context(), a0, cfg)
	close(stored)
	if <-blocked {
		t.Error("OnRefresh ran under the keyring lock")
	}
}

// publishedKey is the JWK the stand-in publishes for issuer.
func publishedKey(t *testing.T, a0 *enturauthtest.Auth0, issuer string) map[string]any {
	t.Helper()
	resp, err := kittest.JWKSTransport(a0.Context(t.Context())).RoundTrip(httptest.NewRequest(http.MethodGet, issuer+".well-known/jwks.json", nil))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc.Keys[0]
}

func with(key map[string]any, kv ...any) map[string]any {
	k := maps.Clone(key)
	set(k, kv)
	return k
}

func jwks(keys ...map[string]any) []byte {
	return js(map[string]any{"keys": append([]map[string]any{}, keys...)})
}

func answer(status int, body []byte, header ...string) func(*http.Request) (*http.Response, error) {
	return func(*http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		for i := 0; i < len(header); i += 2 {
			rec.Header().Set(header[i], header[i+1])
		}
		rec.WriteHeader(status)
		_, _ = rec.Write(body)
		return rec.Result(), nil
	}
}

// modulus is a base64url modulus of the given size.
func modulus(bits uint) string { return b64(new(big.Int).Lsh(big.NewInt(1), bits-1).Bytes()) }

// TestAdmissionDecision holds a verification between its key lookup and the
// admission decision while the keyring changes: the decision follows the
// keyring and the clock at that instant.
func TestAdmissionDecision(t *testing.T) {
	t.Parallel()
	a0 := enturauthtest.New(t)
	cfg := config()
	dev := enturauthtest.Issuer(cfg)
	key := publishedKey(t, a0, dev)
	wait := func(d time.Duration) func(*testing.T, *enturauth.Authenticator, context.CancelFunc) {
		return func(*testing.T, *enturauth.Authenticator, context.CancelFunc) { time.Sleep(d) }
	}
	refetch := func(doc []byte) func(*testing.T, *enturauth.Authenticator, context.CancelFunc) {
		return func(t *testing.T, a *enturauth.Authenticator, _ context.CancelFunc) {
			a0.Outage(answer(http.StatusOK, doc))
			time.Sleep(time.Minute)
			rec, _ := serve(a, t.Context(), "/partner", "Bearer "+a0.Sign(dev, []byte(`{"alg":"RS256","typ":"at+jwt","kid":"k0"}`), js(a0.Claims(cfg))))
			checkResponse(t, "refetch", rec, enturauth.RejectUnknownKey)
		}
	}
	for _, tc := range []struct {
		name      string
		held      time.Duration // through an outage, before the request
		edit      func(c map[string]any)
		meanwhile func(*testing.T, *enturauth.Authenticator, context.CancelFunc)
		want      enturauth.Reason
	}{
		{"same key fetched again", 0, nil, refetch(jwks(key)), ""},
		{"key removed", 0, nil, refetch(jwks(with(key, "kid", "k2"))), enturauth.RejectUnknownKey},
		{"same kid, other key material", 0, nil, refetch(jwks(with(key, "n", modulus(2048)))), enturauth.RejectUnknownKey},
		{"lifetime ended", 0, nil, func(_ *testing.T, _ *enturauth.Authenticator, cancel context.CancelFunc) { cancel() }, enturauth.RejectUnavailable},
		{"last good window ended", 24*time.Hour - time.Second, nil, wait(time.Second), enturauth.RejectUnavailable},
		{"expired meanwhile", 0, func(c map[string]any) { c["iat"], c["exp"] = c["iat"].(int64)-3600, c["iat"].(int64)-59 }, wait(time.Second), enturauth.RejectDates},
	} {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			defer a0.Outage(nil)
			a := start(t, ctx, a0, cfg)
			if tc.held > 0 {
				a0.Outage(down)
				time.Sleep(tc.held)
			}
			c := a0.Claims(cfg)
			if tc.edit != nil {
				tc.edit(c)
			}
			token := a0.Token(c)
			reached, release, result := make(chan struct{}), make(chan struct{}), make(chan *httptest.ResponseRecorder)
			enturauth.PauseAfterKeyLookup(a, func() { close(reached); <-release })
			go func() {
				rec, _ := serve(a, t.Context(), "/partner", "Bearer "+token)
				result <- rec
			}()
			<-reached
			enturauth.PauseAfterKeyLookup(a, nil)
			tc.meanwhile(t, a, cancel)
			close(release)
			checkResponse(t, tc.name, <-result, tc.want)
		})
	}
}

// TestJWKS runs one refresh per document and checks what it leaves usable.
func TestJWKS(t *testing.T) {
	t.Parallel()
	a0 := enturauthtest.New(t)
	cfg := config()
	key := publishedKey(t, a0, enturauthtest.Issuer(cfg))
	ok := func(body []byte) func(*http.Request) (*http.Response, error) { return answer(http.StatusOK, body) }
	full := slices.Concat(jwks(key), []byte(strings.Repeat(" ", 64<<10-len(jwks(key)))))
	failure := regexp.MustCompile(`^enturauth: https://partner\.dev\.entur\.org/\.well-known/jwks\.json: [a-zA-Z0-9 ]+$`)
	for _, tc := range []struct {
		name   string
		serve  func(*http.Request) (*http.Response, error)
		failed bool
		want   enturauth.Reason
	}{
		{"transport error", down, true, ""},
		{"HTTP 500", answer(http.StatusInternalServerError, jwks(key)), true, ""},
		{"redirect", func(r *http.Request) (*http.Response, error) { // followed, it would load an empty set
			if r.URL.Host == "evil.example" {
				return ok(jwks())(r)
			}
			return answer(http.StatusFound, nil, "Location", "https://evil.example/jwks.json")(r)
		}, true, ""},
		{"stall", func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() }, true, ""},
		{"64 KiB", ok(full), false, ""},
		{"over 64 KiB", ok(append(full, ' ')), true, ""},
		{"not JSON", ok([]byte("<html>")), true, ""},
		{"no keys member", ok([]byte(`{}`)), true, ""},
		{"keys null", ok([]byte(`{"keys":null}`)), true, ""},
		{"duplicate keys member", ok(member(jwks(key), `"keys":[]`)), true, ""},
		{"duplicate key member", ok([]byte(`{"keys":[` + string(member(js(key), `"kty":"RSA"`)) + `]}`)), true, ""},
		{"trailing data", ok(slices.Concat(jwks(key), []byte("{}"))), true, ""},
		{"ambiguous kid", ok(jwks(key, key)), true, ""},
		{"17 keys", ok(jwks(slices.Repeat([]map[string]any{with(key, "use", "enc")}, 17)...)), true, ""},
		{"16 keys", ok(jwks(append(slices.Repeat([]map[string]any{with(key, "use", "enc")}, 15), key)...)), false, ""},
		{"no keys", ok(jwks()), false, enturauth.RejectUnavailable},
		{"use enc", ok(jwks(with(key, "use", "enc"))), false, enturauth.RejectUnavailable},
		{"use and alg absent", ok(jwks(with(key, "use", del{}, "alg", del{}))), false, ""},
		{"key_ops verify", ok(jwks(with(key, "key_ops", []any{"verify"}))), false, ""},
		{"key_ops sign", ok(jwks(with(key, "key_ops", []any{"sign"}))), false, enturauth.RejectUnavailable},
		{"key_ops verify and sign", ok(jwks(with(key, "key_ops", []any{"verify", "sign"}))), false, enturauth.RejectUnavailable},
		{"alg RS384", ok(jwks(with(key, "alg", "RS384"))), false, enturauth.RejectUnavailable},
		{"kty EC", ok(jwks(with(key, "kty", "EC"))), false, enturauth.RejectUnavailable},
		{"kty rsa", ok(jwks(with(key, "kty", "rsa"))), false, enturauth.RejectUnavailable},
		{"e 3", ok(jwks(with(key, "e", "Aw"))), false, enturauth.RejectUnavailable},
		{"kid empty", ok(jwks(with(key, "kid", ""))), false, enturauth.RejectUnavailable},
		{"modulus 2047 bits", ok(jwks(with(key, "n", modulus(2047)))), false, enturauth.RejectUnavailable},
		{"modulus 8193 bits", ok(jwks(with(key, "n", modulus(8193)))), false, enturauth.RejectUnavailable},
		{"modulus not base64url", ok(jwks(with(key, "n", "AQAB="))), false, enturauth.RejectUnavailable},
		{"unusable duplicate kid", ok(jwks(key, with(key, "use", "enc"))), false, ""},
		{"x5c and x5t ignored", ok(jwks(with(key, "x5c", []any{"not a certificate"}, "x5t", "x"))), false, ""},
	} {
		synctest.Test(t, func(t *testing.T) {
			refreshed := make(chan error, 4)
			cfg := cfg
			cfg.OnRefresh = func(_ string, err error) { refreshed <- err }
			a := start(t, t.Context(), a0, cfg)
			if err := <-refreshed; err != nil {
				t.Fatal(err)
			}
			a0.Outage(tc.serve)
			defer a0.Outage(nil)
			time.Sleep(5*time.Minute + 2*time.Second)
			synctest.Wait()
			if err := <-refreshed; (err != nil) != tc.failed || (err != nil && !failure.MatchString(err.Error())) {
				t.Errorf("%s: refresh error %v", tc.name, err)
			}
			rec, _ := serve(a, t.Context(), "/partner", "Bearer "+a0.Token(a0.Claims(cfg)))
			checkResponse(t, tc.name, rec, tc.want)
			if a.Ready() != nil {
				t.Errorf("%s: Ready reverted: %v", tc.name, a.Ready())
			}
		})
	}
}
