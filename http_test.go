package mcpkit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/time/rate"

	"github.com/entur/go-mcpkit/httpguard"
)

func TestHandlerRefusals(t *testing.T) {
	b, other := New(Options{}), New(Options{})
	pass := func(h http.Handler) http.Handler { return h }
	ep := func(b *Builder, name string, access Access) *Endpoint {
		e, err := b.Endpoint(name, EndpointOptions{Implementation: mcp.Implementation{Name: name}, Access: access, Instructions: instructions(t)})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	protected, open, local := ep(b, "p", Protected(pass, "staff")), ep(b, "o", PublicReadOnly("open data")), ep(b, "l", LocalProcess("stdio"))
	foreign := ep(other, "f", PublicReadOnly("open data"))
	ok := HTTPOptions{Limiter: httpguard.NewSubjectLimiter(1, 1, time.Minute), Subject: func(context.Context) (string, bool) { return "", false },
		BodyBytes: 1, WriteDeadline: time.Second}
	for _, tc := range []struct {
		name   string
		routes []Route
		edit   func(*HTTPOptions)
		want   string
	}{
		{"no body cap", []Route{{Path: "/o", Endpoint: open}}, func(o *HTTPOptions) { o.BodyBytes = 0 }, "positive body cap"},
		{"no deadline", []Route{{Path: "/o", Endpoint: open}}, func(o *HTTPOptions) { o.WriteDeadline = -1 }, "write deadline"},
		{"no endpoint", []Route{{Path: "/o"}}, nil, "not from this builder"},
		{"foreign endpoint", []Route{{Path: "/f", Endpoint: foreign}}, nil, "not from this builder"},
		{"relative path", []Route{{Path: "mcp", Endpoint: open}}, nil, "clean absolute path"},
		{"trailing slash", []Route{{Path: "/mcp/", Endpoint: open}}, nil, "clean absolute path"},
		{"method pattern", []Route{{Path: "/mcp POST", Endpoint: open}}, nil, "clean absolute path"},
		{"wildcard", []Route{{Path: "/mcp/{x}", Endpoint: open}}, nil, "clean absolute path"},
		{"escaped path", []Route{{Path: "/mcp", Endpoint: open}, {Path: "/m%63p", Endpoint: protected}}, nil, "clean absolute path"},
		{"escaped metrics path", []Route{{Path: "/%6detrics", Endpoint: open}}, func(o *HTTPOptions) { o.Metrics = http.NotFoundHandler() }, "clean absolute path"},
		{"duplicate path", []Route{{Path: "/o", Endpoint: open}, {Path: "/o", Endpoint: protected}}, nil, "conflicts with"},
		{"application pattern", []Route{{Path: "/", Endpoint: open}}, func(o *HTTPOptions) { o.Mux = http.NewServeMux(); o.Mux.Handle("/", http.NotFoundHandler()) }, "conflicts with"},
		{"metrics path", []Route{{Path: "/metrics", Endpoint: open}}, func(o *HTTPOptions) { o.Metrics = http.NotFoundHandler() }, "conflicts with"},
		{"LocalProcess", []Route{{Path: "/l", Endpoint: local}}, nil, "LocalProcess"},
		{"no limiter", []Route{{Path: "/p", Endpoint: protected}}, func(o *HTTPOptions) { o.Limiter = nil }, "without a subject limiter"},
		{"no subject key", []Route{{Path: "/p", Endpoint: protected}}, func(o *HTTPOptions) { o.Subject = nil }, "without a subject limiter"},
	} {
		o := ok
		o.Routes = tc.routes
		if tc.edit != nil {
			tc.edit(&o)
		}
		if _, err := b.Handler(o); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	if r := echo(new(int)); b.sealed || other.sealed || AddReadTool(open, r) != nil {
		t.Error("a refused handler sealed its builder")
	}
}

// deadlineProbe records the write deadline the chain sets on it.
type deadlineProbe struct {
	http.ResponseWriter
	trace *[]string
}

func (p deadlineProbe) SetWriteDeadline(time.Time) error {
	*p.trace = append(*p.trace, "deadline")
	return nil
}

func (p deadlineProbe) Unwrap() http.ResponseWriter { return p.ResponseWriter }

// TestHandlerComposition drives every hook and guard with probes: the order
// of one admitted request, a shared limiter across Protected routes, an
// unlimited public route, panic recovery around everything, the application's
// own routes and loopback-only /metrics.
func TestHandlerComposition(t *testing.T) {
	var trace []string
	note := func(s string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				trace = append(trace, s)
				if r.URL.Path == "/boom" {
					panic("boom")
				}
				next.ServeHTTP(w, r)
			})
		}
	}
	var uncapped io.ReadCloser
	before := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			trace, uncapped = append(trace, "before"), r.Body
			next.ServeHTTP(deadlineProbe{w, &trace}, r)
		})
	}
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != uncapped {
				trace = append(trace, "capped")
			}
			note("auth")(next).ServeHTTP(w, r)
		})
	}
	b := New(Options{})
	var routes []Route
	for _, r := range []struct {
		path   string
		access Access
	}{{"/p", Protected(auth, "staff")}, {"/q", Protected(auth, "staff")}, {"/open", PublicReadOnly("open data")}} {
		ep, err := b.Endpoint(r.path, EndpointOptions{Implementation: mcp.Implementation{Name: r.path}, Access: r.access, Instructions: instructions(t)})
		if err != nil {
			t.Fatal(err)
		}
		routes = append(routes, Route{Path: r.path, Endpoint: ep, BeforeGuards: before, AfterLimit: note("after")})
	}
	app := http.NewServeMux()
	app.HandleFunc("/", func(http.ResponseWriter, *http.Request) { trace = append(trace, "app") })
	var panics, limited int
	opts := HTTPOptions{
		Mux:       app,
		BeforeMux: note("mux"),
		Routes:    routes,
		Metrics:   http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "metrics") }),
		Limiter:   httpguard.NewSubjectLimiter(rate.Every(time.Hour), 2, time.Minute),
		Subject: func(context.Context) (string, bool) {
			trace = append(trace, "limit")
			return "s", true
		},
		BodyBytes: 1 << 10, WriteDeadline: time.Minute,
		OnPanic:       func(*http.Request, any, []byte) { panics++ },
		OnRateLimited: func(*http.Request) { limited++ },
	}
	h, err := b.Handler(opts)
	if err != nil {
		t.Fatal(err)
	}
	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`
	do := func(method, path, body, peer string) *httptest.ResponseRecorder {
		trace = nil
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.RemoteAddr = peer
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s: no security headers", method, path)
		}
		return rec
	}
	const peer = "203.0.113.5:1"
	for _, tc := range []struct {
		method, path, body, peer string
		status                   int
		trace                    string
	}{
		{"POST", "/p", initialize, peer, 200, "mux before deadline capped auth limit after"},
		{"POST", "/q", initialize, peer, 200, "mux before deadline capped auth limit after"},
		{"POST", "/p", initialize, peer, 429, "mux before deadline capped auth limit"}, // one bucket across routes
		{"POST", "/open", initialize, peer, 200, "mux before deadline after"},
		{"POST", "/open", strings.Repeat(" ", 1<<10) + initialize, peer, 413, "mux before deadline after"},
		{"GET", "/other", "", peer, 200, "mux app"},
		{"GET", "/boom", "", peer, 500, "mux"},
		{"GET", "/metrics", "", peer, 404, "mux"},
		{"GET", "/metrics", "", "127.0.0.1:1", 200, "mux"},
	} {
		rec := do(tc.method, tc.path, tc.body, tc.peer)
		if got := strings.Join(trace, " "); rec.Code != tc.status || got != tc.trace {
			t.Errorf("%s %s from %s: %d [%s], want %d [%s]", tc.method, tc.path, tc.peer, rec.Code, got, tc.status, tc.trace)
		}
	}
	if panics != 1 || limited != 1 {
		t.Errorf("panics %d, rate-limited %d; want 1 and 1", panics, limited)
	}

	opts.Mux, opts.Routes, opts.MetricsPublic = nil, nil, "debugging"
	if h, err = b.Handler(opts); err != nil {
		t.Fatal(err)
	}
	if rec := do("GET", "/metrics", "", peer); rec.Code != 200 || rec.Body.String() != "metrics" || !slices.Equal(trace, []string{"mux"}) {
		t.Errorf("public /metrics: %d %q", rec.Code, rec.Body)
	}
}
