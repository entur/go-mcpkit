package enturauth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzParse checks that every token parse accepts is canonical strict
// base64url and carries the header the contract requires.
func FuzzParse(f *testing.F) {
	enc := base64.RawURLEncoding.EncodeToString
	h := enc([]byte(`{"alg":"RS256","typ":"at+jwt","kid":"k1"}`))
	for _, s := range []string{
		h + "." + enc([]byte(`{"iss":"https://partner.dev.entur.org/","exp":1}`)) + "." + enc([]byte("signature")),
		h + ".e30.",
		h + ".W10.",
		h + ".e30=.",
		h + ".e30.A",
		enc([]byte(`{"alg":"RS256","alg":"none","typ":"at+jwt","kid":"k1"}`)) + ".e30.",
		enc([]byte(`{"alg":"RS256","typ":"application/at+jwt","kid":"k1","crit":[]}`)) + ".e30.",
		enc([]byte(`{"alg":"none"}`)) + ".e30.",
		"..", "a.b.c", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		got, why := parse(token)
		if why != "" {
			return
		}
		parts := strings.Split(token, ".")
		var header map[string]any
		for i, p := range parts {
			b, err := base64.RawURLEncoding.DecodeString(p)
			if err != nil || enc(b) != p {
				t.Fatalf("accepted non-canonical segment %q", p)
			}
			if i == 0 && json.Unmarshal(b, &header) != nil {
				t.Fatalf("accepted header %q", b)
			}
		}
		typ := header["typ"]
		if len(token) > maxToken || header["alg"] != "RS256" || (typ != "at+jwt" && typ != "application/at+jwt") ||
			got.kid == "" || header["kid"] != got.kid || got.signed != parts[0]+"."+parts[1] || got.claims == nil {
			t.Fatalf("accepted %q as %+v", token, got)
		}
		for _, n := range []string{"crit", "b64", "zip", "jku", "x5u", "jwk", "x5c"} {
			if _, ok := header[n]; ok {
				t.Fatalf("accepted header member %s", n)
			}
		}
	})
}
