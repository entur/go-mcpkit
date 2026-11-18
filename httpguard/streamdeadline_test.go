package httpguard

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// serveWithWriteTimeout runs h behind a real http.Server with the given
// server-wide WriteTimeout and returns its base URL. A real server (not
// httptest.NewServer, which owns its own config) is what makes the deadline
// observable: httptest.ResponseRecorder has no connection to set one on.
func serveWithWriteTimeout(t *testing.T, writeTimeout time.Duration, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h, WriteTimeout: writeTimeout}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

// slowHandler writes only after d has elapsed, mimicking a stream that is
// held open past the server-wide WriteTimeout before its closing write.
func slowHandler(d time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(d)
		_, _ = io.WriteString(w, "complete-body")
	})
}

// TestStreamWriteDeadlineExtendsPastServerWriteTimeout covers what the
// middleware is actually for: a handler that legitimately outlives the
// server-wide WriteTimeout must still deliver its body intact once the route
// opts into a longer deadline. (Not a platform severing an open SSE stream,
// which no app-side deadline can make clean.)
func TestStreamWriteDeadlineExtendsPastServerWriteTimeout(t *testing.T) {
	t.Parallel()
	const (
		serverWriteTimeout = 50 * time.Millisecond
		handlerDelay       = 150 * time.Millisecond
		routeDeadline      = 5 * time.Second
	)

	base := serveWithWriteTimeout(t, serverWriteTimeout,
		StreamWriteDeadline(routeDeadline, nil, slowHandler(handlerDelay)))

	resp, err := http.Get(base + "/mcp")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "complete-body" {
		t.Errorf("body = %q, want %q (write deadline was not extended)", body, "complete-body")
	}
}

// TestWithoutStreamWriteDeadlineBodyIsTruncated pins the behaviour the
// middleware exists to prevent: without it, the same handler loses its body to
// the expired write deadline. This is the negative control — if net/http ever
// stops truncating here, the middleware is no longer load-bearing and its
// rationale should be revisited rather than left in place unexamined.
func TestWithoutStreamWriteDeadlineBodyIsTruncated(t *testing.T) {
	t.Parallel()
	const (
		serverWriteTimeout = 50 * time.Millisecond
		handlerDelay       = 150 * time.Millisecond
	)

	base := serveWithWriteTimeout(t, serverWriteTimeout, slowHandler(handlerDelay))

	resp, err := http.Get(base + "/mcp")
	if err != nil {
		// A transport-level failure is the same defect surfacing earlier.
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, rerr := io.ReadAll(resp.Body)
	if rerr == nil && string(body) == "complete-body" {
		t.Error("expected the expired write deadline to truncate the body; " +
			"if net/http changed this, revisit StreamWriteDeadline's rationale")
	}
}

// TestStreamWriteDeadlineCallsThroughWhenUnsupported covers the
// ResponseRecorder path: no deadline can be set, and that must be a logged
// non-event rather than a failed request.
func TestStreamWriteDeadlineCallsThroughWhenUnsupported(t *testing.T) {
	called := false
	h := StreamWriteDeadline(time.Minute, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))

	if !called {
		t.Error("next handler was not invoked")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}
