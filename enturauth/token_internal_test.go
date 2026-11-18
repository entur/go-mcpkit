package enturauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzParse checks that every token parse accepts has three non-empty,
// canonical strict base64url segments, no duplicate member name at any depth
// of its header and claims, and the header the contract requires.
func FuzzParse(f *testing.F) {
	enc := base64.RawURLEncoding.EncodeToString
	h := enc([]byte(`{"alg":"RS256","typ":"at+jwt","kid":"k1"}`))
	for _, s := range []string{
		h + "." + enc([]byte(`{"iss":"https://partner.dev.entur.org/","exp":1}`)) + "." + enc([]byte("signature")),
		h + ".e30.",
		h + ".e30.AA",
		h + ".W10.AA",
		h + ".e30=.AA",
		h + "." + enc([]byte(`{"x":{"a":1,"a":2}}`)) + ".AA",
		h + "." + enc([]byte(`{"x":{"a":1,"a":2}}`)) + ".AA",
		h + "." + enc([]byte(`{"x":[{"a":1,"a":2}],"y":"a:b"}`)) + ".AA",
		h + "." + enc([]byte(`{"extra":1e9999}`)) + ".AA",
		enc([]byte(`{"alg":"RS256","typ":"at+jwt","kid":"k1","extra":1e9999}`)) + ".e30.AA",
		enc([]byte(`{"alg":"RS256","alg":"none","typ":"at+jwt","kid":"k1"}`)) + ".e30.AA",
		enc([]byte(`{"alg":"RS256","typ":"application/at+jwt","kid":"k1","crit":[]}`)) + ".e30.AA",
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
			if p == "" || err != nil || enc(b) != p {
				t.Fatalf("accepted empty or non-canonical segment %q", p)
			}
			var v any
			d := json.NewDecoder(bytes.NewReader(b))
			d.UseNumber() // as parse does: a number beyond float64 is valid JSON
			if i < 2 && (d.Decode(&v) != nil || colons(b) != names(v)) {
				t.Fatalf("accepted segment %q with a duplicate member", b)
			}
			if i == 0 {
				header, _ = v.(map[string]any)
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

// colons counts the name separators of a JSON text: one per member.
func colons(b []byte) int {
	n, in, esc := 0, false, false
	for _, c := range b {
		switch {
		case esc:
			esc = false
		case in && c == '\\':
			esc = true
		case c == '"':
			in = !in
		case !in && c == ':':
			n++
		}
	}
	return n
}

// names counts the member names of every object in a decoded JSON value; a
// duplicate collapses into one.
func names(v any) int {
	n := 0
	switch v := v.(type) {
	case map[string]any:
		n = len(v)
		for _, e := range v {
			n += names(e)
		}
	case []any:
		for _, e := range v {
			n += names(e)
		}
	}
	return n
}
