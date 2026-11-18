package enturauth_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/entur/go-mcpkit/enturauth"
	"github.com/entur/go-mcpkit/internal/kittest"
	"github.com/entur/go-mcpkit/mcpkittest/enturauthtest"
)

// del deletes a member in an edit.
type del struct{}

func set(m map[string]any, kv []any) {
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == (del{}) {
			delete(m, kv[i].(string))
		} else {
			m[kv[i].(string)] = kv[i+1]
		}
	}
}

func claim(kv ...any) func(h, c map[string]any)  { return func(_, c map[string]any) { set(c, kv) } }
func header(kv ...any) func(h, c map[string]any) { return func(h, _ map[string]any) { set(h, kv) } }

func js(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// member adds raw members to a JSON object.
func member(obj []byte, raw string) []byte {
	return slices.Concat(obj[:len(obj)-1], []byte(","+raw+"}"))
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// TestToken runs the token contract, one row per check, in a bubble so that
// the clock stands still at the boundaries.
func TestToken(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		a0 := enturauthtest.New(t)
		var got enturauth.Reason
		cfg := config()
		cfg.ClientIDs = []string{"client-a", "client-b"}
		cfg.OnReject = func(_ *http.Request, why enturauth.Reason) { got = why }
		a := start(t, t.Context(), a0, cfg)
		prdCfg := cfg
		prdCfg.Env = enturauth.Prd
		dev, prd, now := enturauthtest.Issuer(cfg), enturauthtest.Issuer(prdCfg), time.Now().Unix()
		check := func(name string, want enturauth.Reason, authorization ...string) {
			t.Helper()
			got = ""
			rec, next := serve(a, t.Context(), "/partner", authorization...)
			checkResponse(t, name, rec, want)
			if got != want {
				t.Errorf("%s: reason %q, want %q", name, got, want)
			}
			if want == "" {
				p, ok := enturauth.FromContext(next.Context())
				if !ok || p.Issuer != dev || p.Subject == "" || p.ClientID == "" || p.Organisation < 1 || next.Header.Get("Authorization") != "" {
					t.Errorf("%s: principal %+v, %v", name, p, next.Header)
				}
			}
		}
		const org = "https://entur.io/organisationID"
		for _, tc := range []struct {
			name string
			edit func(h, c map[string]any)
			want enturauth.Reason
		}{
			{"valid", nil, ""},
			{"typ application/at+jwt", header("typ", "application/at+jwt"), ""},
			{"unknown and case-variant members", func(h, c map[string]any) { h["x5t"], h["ALG"], c["gty"], c["ISS"] = "x", "none", "x", "evil" }, ""},
			{"audience array", claim("aud", []any{"https://other.example", resource}), ""},
			{"second client", claim("client_id", "client-b"), ""},
			{"azp equal to client_id", claim("azp", "client-a"), ""},
			{"more scopes", claim("scope", "openid mcp:read profile"), ""},
			{"nbf now+60", claim("nbf", now+60), ""},
			{"iat now+60", claim("iat", now+60), ""},
			{"exp now-59", claim("iat", now-3600, "exp", now-59), ""},
			{"lifetime 3600", claim("iat", now-1, "exp", now+3599), ""},
			{"largest organisation", claim(org, json.Number("9223372036854775807")), ""},

			{"alg none", header("alg", "none"), enturauth.RejectHeader},
			{"alg HS256", header("alg", "HS256"), enturauth.RejectHeader},
			{"alg RS384", header("alg", "RS384"), enturauth.RejectHeader},
			{"alg PS256", header("alg", "PS256"), enturauth.RejectHeader},
			{"alg lowercase", header("alg", "rs256"), enturauth.RejectHeader},
			{"alg array", header("alg", []any{"RS256"}), enturauth.RejectHeader},
			{"alg null", header("alg", nil), enturauth.RejectHeader},
			{"alg missing", header("alg", del{}), enturauth.RejectHeader},
			{"alg spelled Alg", header("alg", del{}, "Alg", "RS256"), enturauth.RejectHeader},
			{"typ JWT (ID token)", header("typ", "JWT"), enturauth.RejectHeader},
			{"typ missing", header("typ", del{}), enturauth.RejectHeader},
			{"typ AT+JWT", header("typ", "AT+JWT"), enturauth.RejectHeader},
			{"typ Application/at+jwt", header("typ", "Application/at+jwt"), enturauth.RejectHeader},
			{"typ at+jwt+x", header("typ", "at+jwt+x"), enturauth.RejectHeader},
			{"kid missing", header("kid", del{}), enturauth.RejectHeader},
			{"kid empty", header("kid", ""), enturauth.RejectHeader},
			{"kid number", header("kid", 1), enturauth.RejectHeader},
			{"crit empty", header("crit", []any{}), enturauth.RejectHeader},
			{"crit exp", header("crit", []any{"exp"}), enturauth.RejectHeader},
			{"b64", header("b64", true), enturauth.RejectHeader},
			{"zip", header("zip", "DEF"), enturauth.RejectHeader},
			{"jku", header("jku", "https://evil.example/jwks.json"), enturauth.RejectHeader},
			{"x5u", header("x5u", "https://evil.example/cert.pem"), enturauth.RejectHeader},
			{"jwk", header("jwk", map[string]any{"kty": "RSA"}), enturauth.RejectHeader},
			{"x5c", header("x5c", []any{"MIIB"}), enturauth.RejectHeader},

			{"iss missing", claim("iss", del{}), enturauth.RejectIssuer},
			{"iss without trailing slash", claim("iss", strings.TrimSuffix(dev, "/")), enturauth.RejectIssuer},
			{"iss of another environment", claim("iss", prd), enturauth.RejectIssuer},
			{"iss of another tenant", claim("iss", "https://other.dev.entur.org/"), enturauth.RejectIssuer},
			{"iss host case", claim("iss", "https://PARTNER.dev.entur.org/"), enturauth.RejectIssuer},
			{"iss array", claim("iss", []any{dev}), enturauth.RejectIssuer},
			{"iss with U+FFFD", claim("iss", dev+"�"), enturauth.RejectIssuer},

			{"aud missing", claim("aud", del{}), enturauth.RejectAudience},
			{"aud null", claim("aud", nil), enturauth.RejectAudience},
			{"aud another resource", claim("aud", "https://other.example/partner"), enturauth.RejectAudience},
			{"aud host case", claim("aud", "https://MCP.example.com/partner"), enturauth.RejectAudience},
			{"aud trailing slash", claim("aud", resource+"/"), enturauth.RejectAudience},
			{"aud client (ID token)", claim("aud", "client-a"), enturauth.RejectAudience},
			{"aud empty array", claim("aud", []any{}), enturauth.RejectAudience},
			{"aud array without", claim("aud", []any{"https://other.example"}), enturauth.RejectAudience},
			{"aud array with a number", claim("aud", []any{resource, 1}), enturauth.RejectAudience},
			{"aud number", claim("aud", 1), enturauth.RejectAudience},
			{"aud object", claim("aud", map[string]any{"x": resource}), enturauth.RejectAudience},

			{"sub missing", claim("sub", del{}), enturauth.RejectClaims},
			{"sub empty", claim("sub", ""), enturauth.RejectClaims},
			{"sub number", claim("sub", 1), enturauth.RejectClaims},
			{"sub with U+FFFD", claim("sub", "auth0|�"), enturauth.RejectClaims},
			{"jti missing", claim("jti", del{}), enturauth.RejectClaims},
			{"jti empty", claim("jti", ""), enturauth.RejectClaims},
			{"jti with U+FFFD", claim("jti", "�"), enturauth.RejectClaims},
			{"client_id missing, azp only", claim("client_id", del{}, "azp", "client-a"), enturauth.RejectClaims},
			{"client_id empty", claim("client_id", ""), enturauth.RejectClaims},
			{"client_id with U+FFFD", claim("client_id", "client-a�"), enturauth.RejectClaims},
			{"cnf", claim("cnf", map[string]any{"jkt": "x"}), enturauth.RejectClaims},
			{"act", claim("act", map[string]any{"sub": "agent"}), enturauth.RejectClaims},
			{"sub_profile", claim("sub_profile", "user"), enturauth.RejectClaims},
			{"client_profile", claim("client_profile", "native"), enturauth.RejectClaims},

			{"exp missing", claim("exp", del{}), enturauth.RejectDates},
			{"iat missing", claim("iat", del{}), enturauth.RejectDates},
			{"exp null", claim("exp", nil), enturauth.RejectDates},
			{"exp string", claim("exp", "4102444800"), enturauth.RejectDates},
			{"exp fraction", claim("exp", json.Number("946688400.5")), enturauth.RejectDates},
			{"exp exponent", claim("exp", json.Number("9.466884e8")), enturauth.RejectDates},
			{"exp negative", claim("exp", -1), enturauth.RejectDates},
			{"exp zero", claim("exp", 0), enturauth.RejectDates},
			{"exp after 9999", claim("exp", json.Number("253402300800")), enturauth.RejectDates},
			{"iat zero", claim("iat", 0), enturauth.RejectDates},
			{"iat bool", claim("iat", true), enturauth.RejectDates},
			{"nbf null", claim("nbf", nil), enturauth.RejectDates},
			{"nbf string", claim("nbf", "1"), enturauth.RejectDates},
			{"nbf zero", claim("nbf", 0), enturauth.RejectDates},
			{"expired", claim("iat", now-3600, "exp", now-60), enturauth.RejectDates},
			{"iat now+61", claim("iat", now+61), enturauth.RejectDates},
			{"nbf now+61", claim("nbf", now+61), enturauth.RejectDates},
			{"nbf at exp", claim("iat", now-3000, "exp", now+30, "nbf", now+30), enturauth.RejectDates},
			{"lifetime 3601", claim("exp", now+3601), enturauth.RejectDates},
			{"exp equals iat", claim("exp", now), enturauth.RejectDates},
			{"exp before iat", claim("exp", now-1), enturauth.RejectDates},
			{"far future", claim("iat", int64(253402300799-3600), "exp", int64(253402300799)), enturauth.RejectDates},

			{"unknown kid", header("kid", "k9"), enturauth.RejectUnknownKey},

			{"client not allowed", claim("client_id", "client-c"), enturauth.RejectClient},
			{"azp substitution", claim("client_id", "client-c", "azp", "client-a"), enturauth.RejectClient},
			{"azp conflict", claim("azp", "client-b"), enturauth.RejectClient},
			{"azp null", claim("azp", nil), enturauth.RejectClient},
			{"machine client", claim("sub", "m2m@clients", "client_id", "m2m", "gty", "client-credentials"), enturauth.RejectClient},
			{"scope missing", claim("scope", del{}), enturauth.RejectScope},
			{"scope empty", claim("scope", ""), enturauth.RejectScope},
			{"scope array", claim("scope", []any{"mcp:read"}), enturauth.RejectScope},
			{"scope superstring", claim("scope", "mcp:readx"), enturauth.RejectScope},
			{"scope case", claim("scope", "MCP:READ"), enturauth.RejectScope},
			{"scope OIDC only", claim("scope", "openid profile email offline_access"), enturauth.RejectScope},
			{"scope comma-separated", claim("scope", "openid,mcp:read"), enturauth.RejectScope},
			{"scope tab-separated", claim("scope", "openid\tmcp:read"), enturauth.RejectScope},
			{"organisation missing", claim(org, del{}), enturauth.RejectAdmission},
			{"organisation null", claim(org, nil), enturauth.RejectAdmission},
			{"organisation string", claim(org, "1"), enturauth.RejectAdmission},
			{"organisation zero", claim(org, 0), enturauth.RejectAdmission},
			{"organisation negative", claim(org, -1), enturauth.RejectAdmission},
			{"organisation fraction", claim(org, json.Number("1.5")), enturauth.RejectAdmission},
			{"organisation exponent", claim(org, json.Number("1e3")), enturauth.RejectAdmission},
			{"organisation overflow", claim(org, json.Number("9223372036854775808")), enturauth.RejectAdmission},
			{"organisation claim case", claim(org, del{}, "https://entur.io/organisationid", 1), enturauth.RejectAdmission},
		} {
			h, c := map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "k1"}, a0.Claims(cfg)
			if tc.edit != nil {
				tc.edit(h, c)
			}
			check(tc.name, tc.want, "Bearer "+a0.Sign(dev, js(h), js(c)))
		}

		h, c := js(map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "k1"}), js(a0.Claims(cfg))
		valid := a0.Sign(dev, h, c)
		parts := strings.Split(valid, ".")
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		sig := []byte(parts[2])
		sig[len(sig)-1] = alphabet[strings.IndexByte(alphabet, sig[len(sig)-1])^1] // a padding bit
		size := func(pad int) int {
			return len(parts[0]) + len(parts[2]) + 2 + base64.RawURLEncoding.EncodedLen(len(c)+len(`,"pad":""`)+pad)
		}
		pad := 0
		for size(pad+1) <= 8192 {
			pad++
		}
		fits := a0.Sign(dev, h, member(c, `"pad":"`+strings.Repeat("a", pad)+`"`))
		oversize := a0.Sign(dev, h, member(c, `"pad":"`+strings.Repeat("a", pad+1)+`"`))
		noSub := a0.Claims(cfg)
		delete(noSub, "sub")
		idClaims := map[string]any{"iss": dev, "aud": "client-a", "sub": "auth0|user", "nonce": "n", "iat": now, "exp": now + 3600}
		tampered := a0.Claims(cfg)
		tampered["sub"] = "auth0|admin"
		resp, err := kittest.JWKSTransport(a0.Context(t.Context())).RoundTrip(httptest.NewRequest(http.MethodGet, dev+".well-known/jwks.json", nil))
		if err != nil {
			t.Fatal(err)
		}
		jwks, _ := io.ReadAll(resp.Body)
		hs := b64([]byte(`{"alg":"HS256","typ":"at+jwt","kid":"k1"}`)) + "." + parts[1]
		mac := hmac.New(sha256.New, jwks)
		mac.Write([]byte(hs))
		for _, tc := range []struct {
			name          string
			want          enturauth.Reason
			authorization []string
		}{
			{"lowercase scheme", "", []string{"bearer " + valid}},
			{"uppercase scheme", "", []string{"BEARER " + valid}},
			{"at most 8 KiB", "", []string{"Bearer " + fits}},
			{"no credentials", enturauth.RejectNoToken, nil},
			{"basic", enturauth.RejectNoToken, []string{"Basic eDp5"}},
			{"two headers", enturauth.RejectRequest, []string{"Bearer " + valid, "Bearer " + valid}},
			{"bearer alone", enturauth.RejectMalformed, []string{"Bearer"}},
			{"empty token", enturauth.RejectMalformed, []string{"Bearer "}},
			{"two spaces", enturauth.RejectMalformed, []string{"Bearer  " + valid}},
			{"trailing space", enturauth.RejectMalformed, []string{"Bearer " + valid + " "}},
			{"line break", enturauth.RejectMalformed, []string{"Bearer " + valid[:20] + "\r\n" + valid[20:]}},
			{"over 8 KiB", enturauth.RejectMalformed, []string{"Bearer " + oversize}},
			{"two segments", enturauth.RejectMalformed, []string{"Bearer " + parts[0] + "." + parts[1]}},
			{"four segments", enturauth.RejectMalformed, []string{"Bearer " + valid + "." + parts[2]}},
			{"padding", enturauth.RejectMalformed, []string{"Bearer " + valid + "=="}},
			{"standard alphabet", enturauth.RejectMalformed, []string{"Bearer " + valid[:len(valid)-1] + "+"}},
			{"non-zero trailing bits", enturauth.RejectMalformed, []string{"Bearer " + parts[0] + "." + parts[1] + "." + string(sig)}},
			{"header not JSON", enturauth.RejectMalformed, []string{"Bearer " + a0.Sign(dev, []byte("alg"), c)}},
			{"claims array", enturauth.RejectMalformed, []string{"Bearer " + a0.Sign(dev, h, []byte("[]"))}},
			{"trailing data", enturauth.RejectMalformed, []string{"Bearer " + a0.Sign(dev, h, slices.Concat(c, []byte("{}")))}},
			{"duplicate alg", enturauth.RejectMalformed, []string{"Bearer " + a0.Sign(dev, member(h, `"alg":"none"`), c)}},
			{"duplicate kid", enturauth.RejectMalformed, []string{"Bearer " + a0.Sign(dev, member(h, `"kid":"k2"`), c)}},
			{"duplicate iss", enturauth.RejectMalformed, []string{"Bearer " + a0.Sign(dev, h, member(c, `"iss":"https://evil.example/"`))}},
			{"escaped duplicate iss", enturauth.RejectMalformed, []string{"Bearer " + a0.Sign(dev, h, member(c, `"iss":"`+dev+`"`))}},
			{"duplicate sub", enturauth.RejectMalformed, []string{"Bearer " + a0.Sign(dev, h, member(c, `"sub":"auth0|admin"`))}},
			{"sub not UTF-8", enturauth.RejectClaims, []string{"Bearer " + a0.Sign(dev, h, member(js(noSub), "\"sub\":\"auth0|\xff\""))}},
			{"alg none, no signature", enturauth.RejectHeader, []string{"Bearer " + b64([]byte(`{"alg":"none","typ":"at+jwt","kid":"k1"}`)) + "." + parts[1] + "."}},
			{"HS256 keyed with the published JWKS", enturauth.RejectHeader, []string{"Bearer " + hs + "." + b64(mac.Sum(nil))}},
			{"ID token", enturauth.RejectHeader, []string{"Bearer " + a0.Sign(dev, js(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"}), js(idClaims))}},
			{"tampered claims", enturauth.RejectSignature, []string{"Bearer " + parts[0] + "." + b64(js(tampered)) + "." + parts[2]}},
			{"same kid, key of another issuer", enturauth.RejectSignature, []string{"Bearer " + a0.Sign(prd, h, c)}},
			{"same sub, another issuer", enturauth.RejectIssuer, []string{"Bearer " + a0.Sign(prd, h, js(a0.Claims(prdCfg)))}},
		} {
			check(tc.name, tc.want, tc.authorization...)
		}
	})
}
