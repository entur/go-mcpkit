// Package enturauth makes an mcpkit endpoint an OAuth 2 resource server for
// Entur's Auth0 tenants. It validates the RFC 9068 access token of every
// request against one pinned issuer and serves the RFC 9728 protected-resource
// metadata; login, consent and token issuance stay at Auth0.
//
// The contract is fixed: one algorithm (RS256), no configurable leeway or
// lifetime, no verifier, key source or HTTP client to inject. The bearer
// never reaches the application: the request passed on carries no
// Authorization, Proxy-Authorization or Cookie header. The package logs
// nothing; OnReject and OnRefresh report fixed reasons and fetch outcomes.
package enturauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/entur/go-mcpkit"
	"github.com/entur/go-mcpkit/internal/kittest"
)

// Tenant is an Entur Auth0 tenant. Its zero value is refused.
type Tenant uint8

// Partner is the partner tenant, the only one in v0.2.0.
const Partner Tenant = 1

// Env selects one issuer of a tenant. Its zero value is refused.
type Env uint8

// The environments of a tenant.
const (
	Dev Env = iota + 1
	Tst
	Prd
)

// issuer is the pinned issuer of t in e, or "" for an unknown pair. The
// signing keys are at issuer + ".well-known/jwks.json".
func issuer(t Tenant, e Env) string {
	if t != Partner {
		return ""
	}
	switch e {
	case Dev:
		return "https://partner.dev.entur.org/"
	case Tst:
		return "https://partner.staging.entur.org/"
	case Prd:
		return "https://partner.entur.org/"
	}
	return ""
}

// Config describes one protected MCP resource. Every field except the two
// callbacks is required.
type Config struct {
	Tenant Tenant
	Env    Env
	// Resource is the canonical https URL of the MCP endpoint: the Auth0 API
	// identifier, the required audience and the metadata "resource".
	Resource string
	// ClientIDs are the pre-registered public clients whose tokens are
	// accepted (exact client_id match).
	ClientIDs []string
	// RequiredScopes must all be granted. They are advertised in the
	// metadata and in every challenge.
	RequiredScopes []string
	Admission      Admission
	// OnReject, if set, receives every refusal with its reason. The request
	// it gets is a copy without credentials. It must not panic.
	OnReject func(*http.Request, Reason)
	// OnRefresh, if set, receives the outcome of every signing-key fetch
	// (nil on success). It must return promptly and must not panic.
	OnRefresh func(issuer string, err error)
}

// Admission decides which authenticated organisations are let in. Its zero
// value is refused.
type Admission struct{ reason string }

// AllowAnyOrganisation admits every token that carries a valid
// https://entur.io/organisationID. reason says why the server is open to
// every organisation.
func AllowAnyOrganisation(reason string) Admission { return Admission{reason: reason} }

// Reason classifies a refusal, for OnReject.
type Reason string

// The refusals, by response: 400, 401 without and with invalid_token, 403
// without a challenge, 403 insufficient_scope, and 503.
const (
	RejectRequest     Reason = "request"     // several Authorization headers or a query token
	RejectNoToken     Reason = "no_token"    // no Bearer credentials
	RejectMalformed   Reason = "malformed"   // framing, base64url or JSON
	RejectHeader      Reason = "header"      // alg, typ, kid or a refused header member
	RejectIssuer      Reason = "issuer"      // iss
	RejectAudience    Reason = "audience"    // aud
	RejectClaims      Reason = "claims"      // sub, jti, client_id or a refused claim
	RejectDates       Reason = "dates"       // exp, iat, nbf
	RejectUnknownKey  Reason = "unknown_key" // kid not in the issuer's usable keys
	RejectSignature   Reason = "signature"   // RS256 verification
	RejectClient      Reason = "client"      // client_id not allowed, or a conflicting azp
	RejectAdmission   Reason = "admission"   // organisation missing, malformed or not admitted
	RejectScope       Reason = "scope"       // a required scope is missing
	RejectUnavailable Reason = "unavailable" // no usable signing keys, or the lifetime ended
)

// Authenticator validates the tokens of one Config. It is safe for
// concurrent use.
type Authenticator struct {
	issuer    string
	resource  string
	clientIDs []string
	scopes    []string
	onReject  func(*http.Request, Reason)
	posture   string
	keys      *keyring

	metaPath  string
	metadata  []byte
	challenge challenges
}

// challenges are the WWW-Authenticate values, fixed in New.
type challenges struct{ none, request, token, scope string }

// New checks cfg, loads the issuer's signing keys (waiting at most 2 s) and
// keeps them fresh until ctx ends; after that every request is answered 503.
// A failed first load is not an error: Ready reports it and the keys are
// retried every minute.
func New(ctx context.Context, cfg Config) (*Authenticator, error) {
	iss := issuer(cfg.Tenant, cfg.Env)
	if iss == "" {
		return nil, errors.New("enturauth: unknown tenant or environment")
	}
	u, err := url.Parse(cfg.Resource)
	switch {
	case err != nil || !cleanResource(cfg.Resource, u):
		return nil, errors.New("enturauth: Resource is not a clean https URL")
	case u.Path == "" && slices.Contains([]string{"api.entur.io", "api.dev.entur.io", "api.staging.entur.io"}, u.Hostname()),
		"https://"+u.Hostname()+"/" == iss:
		return nil, errors.New("enturauth: Resource is a shared Entur audience or the issuer")
	case len(cfg.ClientIDs) == 0 || slices.ContainsFunc(cfg.ClientIDs, badClientID):
		return nil, errors.New("enturauth: ClientIDs are empty or malformed")
	case len(cfg.RequiredScopes) == 0 || slices.ContainsFunc(cfg.RequiredScopes, badScope) || duplicated(cfg.RequiredScopes):
		return nil, errors.New("enturauth: RequiredScopes are empty, duplicated, malformed or OIDC scopes")
	case strings.TrimSpace(cfg.Admission.reason) == "":
		return nil, errors.New("enturauth: no Admission, or a blank reason")
	case ctx.Err() != nil:
		return nil, fmt.Errorf("enturauth: lifetime context: %w", ctx.Err())
	}

	scope := strings.Join(cfg.RequiredScopes, " ")
	metaPath := "/.well-known/oauth-protected-resource" + u.Path
	params := `resource_metadata="https://` + u.Host + metaPath + `", scope="` + scope + `"`
	transport := kittest.JWKSTransport(ctx)
	posture := fmt.Sprintf("Auth0 %s RFC 9068 access tokens for %s, scope %q, %d client(s); admission: %s",
		iss, cfg.Resource, scope, len(cfg.ClientIDs), cfg.Admission.reason)
	if transport != nil {
		posture = "TEST SIGNING KEYS: " + posture
	}
	a := &Authenticator{
		issuer:    iss,
		resource:  cfg.Resource,
		clientIDs: slices.Clone(cfg.ClientIDs),
		scopes:    slices.Clone(cfg.RequiredScopes),
		onReject:  cfg.OnReject,
		posture:   posture,
		metaPath:  metaPath,
		metadata:  metadataDocument(cfg.Resource, iss, cfg.RequiredScopes),
		challenge: challenges{
			none:    "Bearer " + params,
			request: `Bearer error="invalid_request", ` + params,
			token:   `Bearer error="invalid_token", ` + params,
			scope:   `Bearer error="insufficient_scope", ` + params,
		},
	}
	a.keys = startKeyring(ctx, iss, transport, cfg.OnRefresh)
	return a, nil
}

// cleanResource reports whether r, parsed as u, is a canonical https URL with
// a lowercase host, no userinfo, query, fragment, escape or trailing slash, and
// a clean path that a ServeMux pattern takes literally.
func cleanResource(r string, u *url.URL) bool {
	const pathBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~/"
	return u.Scheme == "https" && u.Host != "" && u.Host == strings.ToLower(u.Host) && u.String() == r &&
		!strings.ContainsAny(r, "?#%@") && !strings.HasSuffix(r, "/") &&
		(u.Path == "" || path.Clean(u.Path) == u.Path) && strings.Trim(u.Path, pathBytes) == ""
}

func badClientID(id string) bool {
	const idBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
	return id == "" || len(id) > 128 || strings.Trim(id, idBytes) != ""
}

// badScope refuses what is not an RFC 6749 scope-token without '"' and '\',
// and the OIDC scopes every login carries.
func badScope(s string) bool {
	return s == "" || strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r > '~' || r == '"' || r == '\\' }) ||
		slices.Contains([]string{"openid", "profile", "email", "address", "phone", "offline_access"}, s)
}

func duplicated(s []string) bool {
	return len(slices.Compact(slices.Sorted(slices.Values(s)))) != len(s)
}

// Access is the endpoint's access posture: mcpkit.Protected with this
// authenticator. Its reason describes the configuration, and starts with
// "TEST SIGNING KEYS:" when the keys come from enturauthtest.
func (a *Authenticator) Access() mcpkit.Access { return mcpkit.Protected(a.wrap, a.posture) }

// Ready reports whether a usable signing key has been loaded once, for a
// startup probe. It never reverts, so a later outage cannot cause restarts;
// requests are answered 503 while no key is usable.
func (a *Authenticator) Ready() error { return a.keys.ready() }

// Principal is the authenticated caller; (Issuer, Subject) is its identity.
type Principal struct {
	Issuer, Subject, ClientID string
	Organisation              int64
}

type principalKey struct{}

// FromContext returns the principal of an authenticated request.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// SubjectKey is an httpguard.SubjectKey over (Issuer, Subject). The pinned
// issuer contains no space, so the key is unambiguous.
func SubjectKey(ctx context.Context) (key string, present bool) {
	p, ok := FromContext(ctx)
	if !ok {
		return "", false
	}
	return p.Issuer + " " + p.Subject, true
}

func (a *Authenticator) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, why := a.authenticate(r)
		if why != "" {
			a.refuse(w, r, why)
			return
		}
		admitted := r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
		admitted.Header = r.Header.Clone()
		stripCredentials(admitted.Header)
		next.ServeHTTP(w, admitted)
	})
}

func (a *Authenticator) authenticate(r *http.Request) (Principal, Reason) {
	values := r.Header.Values("Authorization")
	if _, query := dropQueryToken(r.URL.RawQuery); len(values) > 1 || query {
		return Principal{}, RejectRequest
	}
	if len(values) == 0 {
		return Principal{}, RejectNoToken
	}
	scheme, token, _ := strings.Cut(values[0], " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return Principal{}, RejectNoToken
	}
	return a.verify(r.Context(), token)
}

// refuse reports the refusal on a copy of r without credentials, then answers
// it. Nothing from the token or an error reaches the response.
func (a *Authenticator) refuse(w http.ResponseWriter, r *http.Request, why Reason) {
	if a.onReject != nil {
		c := r.Clone(r.Context())
		stripCredentials(c.Header)
		if q, found := dropQueryToken(c.URL.RawQuery); found {
			c.URL.RawQuery = q
			c.RequestURI = c.URL.RequestURI()
			c.Form.Del("access_token")
		}
		a.onReject(c, why)
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	switch why {
	case RejectRequest:
		h.Set("WWW-Authenticate", a.challenge.request)
		http.Error(w, "bad request", http.StatusBadRequest)
	case RejectNoToken:
		h.Set("WWW-Authenticate", a.challenge.none)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case RejectScope:
		h.Set("WWW-Authenticate", a.challenge.scope)
		http.Error(w, "forbidden", http.StatusForbidden)
	case RejectClient, RejectAdmission: // a new login cannot help
		http.Error(w, "forbidden", http.StatusForbidden)
	case RejectUnavailable:
		h.Set("Retry-After", retryAfter)
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
	default:
		h.Set("WWW-Authenticate", a.challenge.token)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

// stripCredentials removes every credential carrier from h, whatever the
// spelling of its key.
func stripCredentials(h http.Header) {
	for k := range h {
		switch http.CanonicalHeaderKey(k) {
		case "Authorization", "Proxy-Authorization", "Cookie":
			delete(h, k)
		}
	}
}

// dropQueryToken returns raw without its access_token parameters and whether
// it had one. It splits on both separators and matches the unescaped name, so
// no spelling a server might read slips through.
func dropQueryToken(raw string) (string, bool) {
	var kept []string
	found := false
	for _, p := range strings.FieldsFunc(raw, func(r rune) bool { return r == '&' || r == ';' }) {
		name, _, _ := strings.Cut(p, "=")
		if n, _ := url.QueryUnescape(name); n == "access_token" {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, "&"), found
}
