package enturauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/time/rate"

	"github.com/entur/go-mcpkit"
	"github.com/entur/go-mcpkit/enturauth"
	"github.com/entur/go-mcpkit/httpguard"
	"github.com/entur/go-mcpkit/mcpkittest/enturauthtest"
	"github.com/entur/go-mcpkit/output"
)

const (
	resource = "https://mcp.example.com/partner"
	params   = `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/partner", scope="mcp:read"`
)

func config() enturauth.Config {
	return enturauth.Config{Tenant: enturauth.Partner, Env: enturauth.Dev, Resource: resource, ClientIDs: []string{"client-a"},
		RequiredScopes: []string{"mcp:read"}, Admission: enturauth.AllowAnyOrganisation("every partner organisation")}
}

func start(t *testing.T, ctx context.Context, a0 *enturauthtest.Auth0, cfg enturauth.Config) *enturauth.Authenticator {
	t.Helper()
	a, err := enturauth.New(a0.Context(ctx), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// serve sends one request with the given Authorization values through a's
// middleware and returns the response and the request the next handler got.
func serve(a *enturauth.Authenticator, ctx context.Context, target string, authorization ...string) (*httptest.ResponseRecorder, *http.Request) {
	var admitted *http.Request
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	for _, v := range authorization {
		req.Header.Add("Authorization", v)
	}
	rec := httptest.NewRecorder()
	enturauth.Wrap(a, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { admitted = r })).ServeHTTP(rec, req)
	return rec, admitted
}

// checkResponse asserts the ADR's response for why ("" is admitted).
func checkResponse(t *testing.T, name string, rec *httptest.ResponseRecorder, why enturauth.Reason) {
	t.Helper()
	status, challenge, body := http.StatusUnauthorized, `Bearer error="invalid_token", `+params, "unauthorized\n"
	switch why {
	case "":
		status, challenge, body = http.StatusOK, "", ""
	case enturauth.RejectRequest:
		status, challenge, body = http.StatusBadRequest, `Bearer error="invalid_request", `+params, "bad request\n"
	case enturauth.RejectNoToken:
		challenge = "Bearer " + params
	case enturauth.RejectScope:
		status, challenge, body = http.StatusForbidden, `Bearer error="insufficient_scope", `+params, "forbidden\n"
	case enturauth.RejectClient, enturauth.RejectAdmission:
		status, challenge, body = http.StatusForbidden, "", "forbidden\n"
	case enturauth.RejectUnavailable:
		status, challenge, body = http.StatusServiceUnavailable, "", "authentication unavailable\n"
	}
	h := rec.Header()
	noStore := why == "" || h.Get("Cache-Control") == "no-store"
	retry := (why == enturauth.RejectUnavailable) == (h.Get("Retry-After") == "60")
	if rec.Code != status || h.Get("WWW-Authenticate") != challenge || rec.Body.String() != body || !noStore || !retry {
		t.Errorf("%s: %d %q %q %v, want %d %q %q (%s)", name, rec.Code, h.Get("WWW-Authenticate"), rec.Body, h, status, challenge, body, why)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	a0 := enturauthtest.New(t)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	deadline, stop := context.WithTimeout(t.Context(), time.Hour)
	defer stop()
	for _, tc := range []struct {
		name string
		edit func(*enturauth.Config)
		ctx  context.Context
		want string // "" accepts
	}{
		{"valid", nil, nil, ""},
		{"shared host with a path", func(c *enturauth.Config) { c.Resource = "https://api.entur.io/partner-mcp" }, nil, ""},
		{"bare host", func(c *enturauth.Config) { c.Resource = "https://mcp.example.com" }, nil, ""},
		{"lifetime with a deadline", nil, deadline, ""},
		{"zero tenant", func(c *enturauth.Config) { c.Tenant = 0 }, nil, "tenant"},
		{"unknown tenant", func(c *enturauth.Config) { c.Tenant = 2 }, nil, "tenant"},
		{"zero env", func(c *enturauth.Config) { c.Env = 0 }, nil, "tenant"},
		{"unknown env", func(c *enturauth.Config) { c.Env = 4 }, nil, "tenant"},
		{"empty resource", func(c *enturauth.Config) { c.Resource = "" }, nil, "clean https"},
		{"http", func(c *enturauth.Config) { c.Resource = "http://mcp.example.com/partner" }, nil, "clean https"},
		{"scheme case", func(c *enturauth.Config) { c.Resource = "HTTPS://mcp.example.com/partner" }, nil, "clean https"},
		{"host case", func(c *enturauth.Config) { c.Resource = "https://MCP.example.com/partner" }, nil, "clean https"},
		{"userinfo", func(c *enturauth.Config) { c.Resource = "https://u@mcp.example.com/partner" }, nil, "clean https"},
		{"query", func(c *enturauth.Config) { c.Resource = resource + "?x=1" }, nil, "clean https"},
		{"empty query", func(c *enturauth.Config) { c.Resource = resource + "?" }, nil, "clean https"},
		{"fragment", func(c *enturauth.Config) { c.Resource = resource + "#x" }, nil, "clean https"},
		{"escape", func(c *enturauth.Config) { c.Resource = "https://mcp.example.com/p%61rtner" }, nil, "clean https"},
		{"trailing slash", func(c *enturauth.Config) { c.Resource = resource + "/" }, nil, "clean https"},
		{"root slash", func(c *enturauth.Config) { c.Resource = "https://mcp.example.com/" }, nil, "clean https"},
		{"unclean path", func(c *enturauth.Config) { c.Resource = "https://mcp.example.com/a//b" }, nil, "clean https"},
		{"dot segment", func(c *enturauth.Config) { c.Resource = "https://mcp.example.com/a/../b" }, nil, "clean https"},
		{"wildcard", func(c *enturauth.Config) { c.Resource = "https://mcp.example.com/{x}" }, nil, "clean https"},
		{"no scheme", func(c *enturauth.Config) { c.Resource = "mcp.example.com/partner" }, nil, "clean https"},
		{"shared prd audience", func(c *enturauth.Config) { c.Resource = "https://api.entur.io" }, nil, "shared"},
		{"shared dev audience", func(c *enturauth.Config) { c.Resource = "https://api.dev.entur.io" }, nil, "shared"},
		{"shared tst audience", func(c *enturauth.Config) { c.Resource = "https://api.staging.entur.io" }, nil, "shared"},
		{"issuer host", func(c *enturauth.Config) { c.Resource = "https://partner.dev.entur.org/userinfo" }, nil, "shared"},
		{"no clients", func(c *enturauth.Config) { c.ClientIDs = nil }, nil, "ClientIDs"},
		{"empty client", func(c *enturauth.Config) { c.ClientIDs = []string{"a", ""} }, nil, "ClientIDs"},
		{"client with space", func(c *enturauth.Config) { c.ClientIDs = []string{"a b"} }, nil, "ClientIDs"},
		{"long client", func(c *enturauth.Config) { c.ClientIDs = []string{strings.Repeat("a", 129)} }, nil, "ClientIDs"},
		{"no scopes", func(c *enturauth.Config) { c.RequiredScopes = nil }, nil, "RequiredScopes"},
		{"empty scope", func(c *enturauth.Config) { c.RequiredScopes = []string{""} }, nil, "RequiredScopes"},
		{"duplicate scope", func(c *enturauth.Config) { c.RequiredScopes = []string{"a", "b", "a"} }, nil, "RequiredScopes"},
		{"scope with space", func(c *enturauth.Config) { c.RequiredScopes = []string{"a b"} }, nil, "RequiredScopes"},
		{"scope with quote", func(c *enturauth.Config) { c.RequiredScopes = []string{`a"`} }, nil, "RequiredScopes"},
		{"scope with backslash", func(c *enturauth.Config) { c.RequiredScopes = []string{`a\`} }, nil, "RequiredScopes"},
		{"non-ASCII scope", func(c *enturauth.Config) { c.RequiredScopes = []string{"lås"} }, nil, "RequiredScopes"},
		{"openid", func(c *enturauth.Config) { c.RequiredScopes = []string{"mcp:read", "openid"} }, nil, "RequiredScopes"},
		{"offline_access", func(c *enturauth.Config) { c.RequiredScopes = []string{"offline_access"} }, nil, "RequiredScopes"},
		{"zero admission", func(c *enturauth.Config) { c.Admission = enturauth.Admission{} }, nil, "Admission"},
		{"blank reason", func(c *enturauth.Config) { c.Admission = enturauth.AllowAnyOrganisation(" \t") }, nil, "Admission"},
		{"cancelled lifetime", nil, cancelled, "lifetime"},
	} {
		cfg := config()
		if tc.edit != nil {
			tc.edit(&cfg)
		}
		ctx := tc.ctx
		if ctx == nil {
			ctx = t.Context()
		}
		a, err := enturauth.New(a0.Context(ctx), cfg)
		switch {
		case tc.want == "" && (err != nil || a.Ready() != nil):
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestContainment proves the credential never moves on: the next handler and
// OnReject get copies without it, and the original request is untouched.
func TestContainment(t *testing.T) {
	t.Parallel()
	a0 := enturauthtest.New(t)
	var seen []*http.Request
	cfg := config()
	cfg.OnReject = func(r *http.Request, _ enturauth.Reason) { seen = append(seen, r) }
	a := start(t, t.Context(), a0, cfg)
	bearer := "Bearer " + a0.Token(a0.Claims(cfg))
	var next *http.Request
	h := enturauth.Wrap(a, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { next = r }))
	credentials := func(r *http.Request) []string {
		var found []string
		for k := range r.Header {
			if c := http.CanonicalHeaderKey(k); c == "Authorization" || c == "Proxy-Authorization" || c == "Cookie" {
				found = append(found, k)
			}
		}
		return found
	}

	req := httptest.NewRequest(http.MethodPost, "/partner?q=1", nil)
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Proxy-Authorization", "Basic eDp5")
	req.Header.Set("Cookie", "session=1")
	req.Header["cookie"] = []string{"spelled=1"}
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if next == nil || credentials(next) != nil || next.Header.Get("Mcp-Protocol-Version") == "" || len(credentials(req)) != 4 {
		t.Fatalf("admitted request: next %v, original %v", next, req.Header)
	}

	for _, query := range []string{"access_token=SECRET&b=2", "b=2;access_token=SECRET", "b=2&access%5Ftoken=SECRET"} {
		seen = nil
		req = httptest.NewRequest(http.MethodGet, "/partner?a=1&"+query, nil)
		req.Header.Set("Authorization", bearer)
		req.Header.Set("Cookie", "session=1")
		_ = req.ParseForm() // an earlier hook read the form
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		checkResponse(t, query, rec, enturauth.RejectRequest)
		if len(seen) != 1 {
			t.Fatalf("%s: %d observations", query, len(seen))
		}
		c := seen[0]
		if leak := c.URL.String() + c.RequestURI + c.Form.Encode(); strings.Contains(leak, "SECRET") || credentials(c) != nil ||
			c.URL.Query().Get("b") != "2" || c.Form.Get("a") != "1" {
			t.Errorf("%s: observed copy %q %q %v %v", query, c.URL, c.RequestURI, c.Form, c.Header)
		}
		if !strings.Contains(req.RequestURI, "SECRET") || len(credentials(req)) != 2 {
			t.Errorf("%s: original request mutated", query)
		}
	}
}

// TestEndToEnd drives a real MCP client session through mcpkit.Handler.
func TestEndToEnd(t *testing.T) {
	t.Parallel()
	a0 := enturauthtest.New(t)
	cfg := config()
	a := start(t, t.Context(), a0, cfg)
	b := mcpkit.New(mcpkit.Options{})
	rule, err := mcpkit.UntrustedDataRule(mcpkit.English, "a result", "", "Use whoami.")
	if err != nil {
		t.Fatal(err)
	}
	ep, err := b.Endpoint("partner", mcpkit.EndpointOptions{Implementation: mcp.Implementation{Name: "partner", Version: "1"}, Access: a.Access(), Instructions: rule})
	if err != nil {
		t.Fatal(err)
	}
	type whoami struct {
		Key          string   `json:"key"`
		Organisation int64    `json:"organisation"`
		Credentials  []string `json:"credentials"`
	}
	err = mcpkit.AddReadTool(ep, mcpkit.ReadTool[struct{}, whoami]{
		Tool:     &mcp.Tool{Name: "whoami", Title: "Who am I", Description: "Reports the caller."},
		Output:   output.Policy{MaxEnvelopeBytes: 4 * output.KiB, MaxStringBytes: 256},
		Failures: mcpkit.Failures{Fallback: "failed"},
		Handle: func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (whoami, error) {
			key, _ := enturauth.SubjectKey(ctx)
			p, _ := enturauth.FromContext(ctx)
			h := req.Extra.Header
			return whoami{key, p.Organisation, slices.DeleteFunc([]string{h.Get("Authorization"), h.Get("Cookie")}, func(s string) bool { return s == "" })}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := a.MountMetadata(mux); err != nil {
		t.Fatal(err)
	}
	h, err := b.Handler(mcpkit.HTTPOptions{Mux: mux, Routes: []mcpkit.Route{{Path: "/partner", Endpoint: ep}},
		Limiter: httpguard.NewSubjectLimiter(rate.Inf, 1, time.Minute), Subject: enturauth.SubjectKey, BodyBytes: 64 << 10, WriteDeadline: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if p := b.Posture()[0]; p.Kind != "protected" || !strings.HasPrefix(p.Reason, "TEST SIGNING KEYS: Auth0 https://partner.dev.entur.org/") {
		t.Errorf("posture %+v", p)
	}

	connect := func(token string) (*mcp.ClientSession, error) {
		client := &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
			r = r.Clone(r.Context())
			r.Header.Set("Cookie", "session=1")
			if token != "" {
				r.Header.Set("Authorization", "Bearer "+token)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			return rec.Result(), nil
		})}
		return mcp.NewClient(&mcp.Implementation{Name: "client", Version: "1"}, nil).Connect(t.Context(),
			&mcp.StreamableClientTransport{Endpoint: resource, HTTPClient: client, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	}
	if _, err := connect(""); err == nil {
		t.Error("connected without a token")
	}
	claims := a0.Claims(cfg)
	claims["scope"] = "openid"
	if _, err := connect(a0.Token(claims)); err == nil {
		t.Error("connected without the required scope")
	}
	cs, err := connect(a0.Token(a0.Claims(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "whoami"})
	if err != nil || res.IsError {
		t.Fatal(err, res)
	}
	var got struct {
		UntrustedData whoami `json:"untrusted_data"`
	}
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &got); err != nil || got.UntrustedData.Key != "https://partner.dev.entur.org/ auth0|user" ||
		got.UntrustedData.Organisation != 1 || len(got.UntrustedData.Credentials) != 0 {
		t.Errorf("tool saw %s", raw)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/partner", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("metadata through the handler: %d %v", rec.Code, rec.Header())
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
