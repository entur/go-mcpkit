package enturauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxToken    = 8 << 10      // bytes of a compact JWS
	leeway      = 60           // seconds of allowed clock skew
	maxLifetime = 3600         // seconds from iat to exp
	maxDate     = 253402300799 // 9999-12-31T23:59:59Z
	orgClaim    = "https://entur.io/organisationID"
	tokenBytes  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."
)

// object is a JSON object by member name. Names match case-sensitively.
type object map[string]json.RawMessage

// jws is a token that passed framing and the header checks.
type jws struct {
	kid       string
	claims    object
	signed    string // header "." payload
	signature []byte
}

// parse checks the framing and the header of token, in that order.
func parse(token string) (jws, Reason) {
	if len(token) > maxToken || strings.Count(token, ".") != 2 || strings.Trim(token, tokenBytes) != "" {
		return jws{}, RejectMalformed
	}
	h64, rest, _ := strings.Cut(token, ".")
	c64, s64, _ := strings.Cut(rest, ".")
	hb, err1 := unb64(h64)
	cb, err2 := unb64(c64)
	sig, err3 := unb64(s64)
	h, err4 := members(hb)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return jws{}, RejectMalformed
	}
	kid, _ := h.str("kid")
	if typ, _ := h.str("typ"); !h.is("alg", "RS256") || (typ != "at+jwt" && typ != "application/at+jwt") || kid == "" ||
		h.hasAny("crit", "b64", "zip", "jku", "x5u", "jwk", "x5c") {
		return jws{}, RejectHeader
	}
	c, err := members(cb)
	if err != nil {
		return jws{}, RejectMalformed
	}
	return jws{kid: kid, claims: c, signed: h64 + "." + c64, signature: sig}, ""
}

// verify runs the token contract on token, in order: framing and header,
// the unverified claims, the key and signature, the dates, and authorization.
func (a *Authenticator) verify(ctx context.Context, token string) (Principal, Reason) {
	t, why := parse(token)
	if why != "" {
		return Principal{}, why
	}
	c := t.claims
	sub, _ := c.str("sub")
	jti, _ := c.str("jti")
	client, _ := c.str("client_id")
	exp, expOK := date(c["exp"])
	iat, iatOK := date(c["iat"])
	nbf, nbfOK := date(c["nbf"])
	_, hasNBF := c["nbf"]
	switch {
	case !c.is("iss", a.issuer): // exact, so iss holds no U+FFFD either
		return Principal{}, RejectIssuer
	case !audience(c["aud"], a.resource):
		return Principal{}, RejectAudience
	case sub == "" || jti == "" || client == "" || strings.ContainsRune(sub+jti+client, utf8.RuneError):
		return Principal{}, RejectClaims
	case !expOK || !iatOK || (hasNBF && !nbfOK):
		return Principal{}, RejectDates
	case c.hasAny("cnf", "act", "sub_profile", "client_profile"):
		return Principal{}, RejectClaims
	}

	pub, why := a.keys.key(ctx, t.kid)
	if why != "" {
		return Principal{}, why
	}
	sum := sha256.Sum256([]byte(t.signed))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], t.signature) != nil {
		return Principal{}, RejectSignature
	}

	nowSec := time.Now().Unix() // after any key wait
	if nowSec >= exp+leeway || iat > nowSec+leeway || (hasNBF && (nbf > nowSec+leeway || nbf >= exp)) || exp-iat <= 0 || exp-iat > maxLifetime {
		return Principal{}, RejectDates
	}

	_, hasAZP := c["azp"]
	scope, _ := c.str("scope")
	granted := strings.Split(scope, " ")
	org, orgOK := integer(c[orgClaim], math.MaxInt64)
	switch {
	case !slices.Contains(a.clientIDs, client) || (hasAZP && !c.is("azp", client)): // never replaced by azp
		return Principal{}, RejectClient
	case slices.ContainsFunc(a.scopes, func(s string) bool { return !slices.Contains(granted, s) }):
		return Principal{}, RejectScope
	case !orgOK: // AllowAnyOrganisation admits every valid organisation
		return Principal{}, RejectAdmission
	}
	return Principal{Issuer: a.issuer, Subject: sub, ClientID: client, Organisation: org}, ""
}

// audience reports whether raw is a string, or an array of strings, that
// contains want.
func audience(raw json.RawMessage, want string) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	switch v := v.(type) {
	case string:
		return v == want
	case []any:
		found := false
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return false
			}
			found = found || s == want
		}
		return found
	}
	return false
}

// date reads a NumericDate: a JSON integer in [1, maxDate].
func date(raw json.RawMessage) (int64, bool) { return integer(raw, maxDate) }

// integer reads a JSON integer in [1, limit]: digits only, so no sign,
// fraction, exponent or string.
func integer(raw json.RawMessage, limit int64) (int64, bool) {
	if len(raw) == 0 || strings.Trim(string(raw), "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	return n, err == nil && n >= 1 && n <= limit
}

// unb64 decodes strict unpadded base64url.
func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.Strict().DecodeString(s) }

// members decodes one JSON object, refusing duplicate member names (compared
// after unescaping) and trailing data.
func members(b []byte) (object, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	m := object{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, err
		}
		name, _ := t.(string)
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return nil, err
		}
		if _, dup := m[name]; dup {
			return nil, errors.New("duplicate member")
		}
		m[name] = v
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return m, nil
}

// str returns member name when it is a JSON string.
func (m object) str(name string) (string, bool) {
	var s string
	raw := m[name]
	ok := len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, &s) == nil
	return s, ok
}

// is reports whether member name is the JSON string want.
func (m object) is(name, want string) bool {
	s, ok := m.str(name)
	return ok && s == want
}

// hasAny reports whether any of names is a member, whatever its value.
func (m object) hasAny(names ...string) bool {
	return slices.ContainsFunc(names, func(n string) bool { _, ok := m[n]; return ok })
}
