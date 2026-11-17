package mcpkit

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/entur/go-mcpkit/httpguard"
)

// Route serves one endpoint at an exact path. The two hooks place trusted
// application middleware at fixed points of the route's guard chain.
type Route struct {
	// Path is a clean absolute path without method, host, wildcards or
	// escapes; "/" matches every path not otherwise routed.
	Path     string
	Endpoint *Endpoint
	// BeforeGuards, if set, runs first: before the write deadline, the body
	// cap and authentication (an Origin check, say).
	BeforeGuards func(http.Handler) http.Handler
	// AfterLimit, if set, runs after authentication and the subject limiter,
	// directly before the MCP transport (accounting of admitted requests).
	AfterLimit func(http.Handler) http.Handler
}

// HTTPOptions configure Handler. A ResponseWriter wrapper in any hook must
// implement Unwrap() http.ResponseWriter, so the write deadline reaches the
// connection.
type HTTPOptions struct {
	// Mux holds the application's routes; Handler adds the MCP routes and
	// /metrics (nil starts an empty one). A method or host pattern for a route
	// path would take its requests past every guard, so register none.
	Mux *http.ServeMux
	// BeforeMux, if set, wraps the routing of every request, inside panic
	// recovery and the security headers.
	BeforeMux func(http.Handler) http.Handler
	Routes    []Route
	// Metrics, if set, is served at /metrics to loopback peers only, unless
	// MetricsPublic gives the reason any peer may reach it.
	Metrics       http.Handler
	MetricsPublic string
	// Limiter and Subject rate-limit every Protected route by subject, one
	// bucket per subject across routes. Required with a Protected route.
	Limiter *httpguard.SubjectLimiter
	Subject httpguard.SubjectKey
	// BodyBytes caps each MCP request body and WriteDeadline replaces the
	// server's write timeout on MCP routes; both are required. Set the
	// deadline above the platform's request timeout.
	BodyBytes     int64
	WriteDeadline time.Duration
	// Guard observations; each may be nil.
	OnPanic               func(r *http.Request, panicValue any, stack []byte)
	OnRateLimited         func(*http.Request)
	OnDeadlineUnsupported func(*http.Request, error)
}

// Handler seals the builder and returns the application's HTTP handler. In
// execution order: Recover, SecurityHeaders, BeforeMux, Mux; each MCP route
// runs BeforeGuards, StreamWriteDeadline, LimitBody, the endpoint's Access
// wrapper, the shared subject limiter (Protected routes), AfterLimit and the
// stateless JSON-response transport. An error before sealing (a refused
// option or route conflict) leaves the builder open; discard Mux then.
func (b *Builder) Handler(opts HTTPOptions) (http.Handler, error) {
	if opts.BodyBytes <= 0 || opts.WriteDeadline <= 0 {
		return nil, errors.New("mcpkit: HTTP handler needs a positive body cap and write deadline")
	}
	for _, r := range opts.Routes {
		fail := func(why string) (http.Handler, error) { return nil, fmt.Errorf("mcpkit: route %q: %s", r.Path, why) }
		switch {
		case r.Endpoint == nil || r.Endpoint.b != b:
			return fail("endpoint is not from this builder")
		case !strings.HasPrefix(r.Path, "/") || path.Clean(r.Path) != r.Path || strings.ContainsAny(r.Path, "%{} \t\r\n"):
			return fail("not a clean absolute path")
		case r.Endpoint.access.kind == accessLocal:
			return fail("LocalProcess endpoint cannot be served over HTTP")
		case r.Endpoint.access.kind == accessProtected && (opts.Limiter == nil || opts.Subject == nil):
			return fail("Protected route without a subject limiter")
		}
	}

	mux := cmp.Or(opts.Mux, http.NewServeMux())
	if m := opts.Metrics; m != nil {
		if strings.TrimSpace(opts.MetricsPublic) == "" {
			m = httpguard.LoopbackOnly(m)
		}
		if err := handle(mux, "/metrics", m); err != nil {
			return nil, err
		}
	}
	for _, r := range opts.Routes {
		ep := r.Endpoint
		var h http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return ep.server },
			&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
		if r.AfterLimit != nil {
			h = r.AfterLimit(h)
		}
		if ep.access.kind == accessProtected {
			h = ep.access.auth(opts.Limiter.Middleware(opts.Subject, opts.OnRateLimited, h))
		}
		h = httpguard.StreamWriteDeadline(opts.WriteDeadline, opts.OnDeadlineUnsupported, httpguard.LimitBody(opts.BodyBytes, h))
		if r.BeforeGuards != nil {
			h = r.BeforeGuards(h)
		}
		if err := handle(mux, r.Path, h); err != nil {
			return nil, err
		}
	}
	if err := b.seal(); err != nil {
		return nil, err
	}
	var root http.Handler = mux
	if opts.BeforeMux != nil {
		root = opts.BeforeMux(root)
	}
	return httpguard.Recover(opts.OnPanic, httpguard.SecurityHeaders(root)), nil
}

// handle returns ServeMux's conflict panic as an error (it changes nothing first).
func handle(mux *http.ServeMux, pattern string, h http.Handler) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("mcpkit: route %q: %v", pattern, p)
		}
	}()
	mux.Handle(pattern, h)
	return nil
}
