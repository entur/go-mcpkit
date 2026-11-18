package httpguard

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestSecurityHeaders(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s: got %q, want %q", k, got, v)
		}
	}
}

func TestSecurityHeadersDoNotOverrideHandlerHeader(t *testing.T) {
	// Handlers set Cache-Control deliberately (e.g. a static document). The
	// middleware does not touch it; this guards against accidentally adding it
	// to the fixed set.
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("Cache-Control: got %q, want handler's value", got)
	}
}

func TestLoopbackOnly(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		passed     bool
		wantStatus int
	}{
		{"ipv4 loopback", "127.0.0.1:54321", true, http.StatusTeapot},
		{"ipv4 loopback range", "127.0.0.42:1024", true, http.StatusTeapot},
		{"ipv6 loopback", "[::1]:54321", true, http.StatusTeapot},
		{"link-local relay", "169.254.1.1:8080", false, http.StatusNotFound},
		{"rfc1918", "10.0.0.5:60000", false, http.StatusNotFound},
		{"public ipv4", "203.0.113.5:443", false, http.StatusNotFound},
		{"malformed", "garbage", false, http.StatusNotFound},
		{"empty", "", false, http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var calledNext bool
			h := LoopbackOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calledNext = true
				w.WriteHeader(http.StatusTeapot)
			}))
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			req.RemoteAddr = c.remoteAddr
			h.ServeHTTP(rec, req)

			if calledNext != c.passed {
				t.Errorf("next called = %v, want %v", calledNext, c.passed)
			}
			if rec.Code != c.wantStatus {
				t.Errorf("status: got %d, want %d", rec.Code, c.wantStatus)
			}
		})
	}
}

func TestRecover(t *testing.T) {
	var got []any
	onPanic := func(_ *http.Request, v any, stack []byte) {
		if len(stack) == 0 {
			t.Error("empty stack")
		}
		got = append(got, v)
	}
	for _, c := range []struct {
		name       string
		cb         func(*http.Request, any, []byte)
		handler    http.HandlerFunc
		wantStatus int
		wantBody   string
		wantCalls  int
	}{
		{"panic reported", onPanic, func(http.ResponseWriter, *http.Request) { panic("boom") }, 500, "internal server error\n", 1},
		{"nil callback", nil, func(http.ResponseWriter, *http.Request) { panic("boom") }, 500, "internal server error\n", 0},
		{"no panic", onPanic, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }, 418, "", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			got = nil
			rec := httptest.NewRecorder()
			Recover(c.cb, c.handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
			if rec.Code != c.wantStatus || rec.Body.String() != c.wantBody || len(got) != c.wantCalls {
				t.Errorf("status %d body %q calls %v; want %d %q x%d", rec.Code, rec.Body, got, c.wantStatus, c.wantBody, c.wantCalls)
			}
		})
	}
}

func TestSubjectLimiterAllow(t *testing.T) {
	// Slow refill so the burst is what matters.
	l := NewSubjectLimiter(rate.Every(time.Hour), 2, time.Minute)
	for i, want := range []bool{true, true, false} {
		if got := l.Allow("u1"); got != want {
			t.Errorf("u1 call %d = %v, want %v", i+1, got, want)
		}
	}
	if !l.Allow("u2") {
		t.Error("a different subject has its own bucket")
	}
}

func TestSubjectLimiterEvictsIdleEntries(t *testing.T) {
	current := time.Now()
	l := NewSubjectLimiter(rate.Every(time.Hour), 1, 100*time.Millisecond)
	l.now = func() time.Time { return current }

	l.Allow("u1")
	// Advance past TTL and touch a different subject; u1 should be evicted.
	current = current.Add(200 * time.Millisecond)
	l.Allow("u2")
	if _, stillThere := l.seen["u1"]; stillThere {
		t.Error("u1 should have been evicted after TTL")
	}
}

type ctxKey struct{}

// keyFromCtx reads the subject from the context: absent means not present, an
// empty value is present with an empty key.
func keyFromCtx(ctx context.Context) (string, bool) {
	s, ok := ctx.Value(ctxKey{}).(string)
	return s, ok
}

func TestSubjectLimiterMiddleware(t *testing.T) {
	// One token per subject: the second request with a present key is throttled.
	for _, c := range []struct {
		name     string
		subject  *string
		want     []int
		rejected int
	}{
		{"no subject passes through", nil, []int{200, 200}, 0},
		{"subject limited", ptr("sub-1"), []int{200, 429}, 1},
		{"empty subject is still limited", ptr(""), []int{200, 429}, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			rejected := 0
			h := NewSubjectLimiter(rate.Every(time.Hour), 1, time.Minute).Middleware(keyFromCtx,
				func(*http.Request) { rejected++ },
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if c.subject != nil {
				req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, *c.subject))
			}
			var got []int
			for range c.want {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				got = append(got, rec.Code)
				if rec.Code == 429 && (rec.Header().Get("Retry-After") != "3600" || rec.Body.String() != "rate limited: try again shortly\n") {
					t.Errorf("429 = %q Retry-After %q", rec.Body, rec.Header().Get("Retry-After"))
				}
			}
			if !slices.Equal(got, c.want) || rejected != c.rejected {
				t.Errorf("statuses %v, rejected %d; want %v", got, rejected, c.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestSubjectLimiterMinRetryAfterFloor(t *testing.T) {
	l := NewSubjectLimiter(rate.Limit(100), 1, time.Minute) // 100 rps → 10 ms refill
	if got := l.minRetryAfter(); got < time.Second {
		t.Errorf("minRetryAfter: got %s, want >= 1s floor", got)
	}
}

func TestLimitBodyEnforcesCap(t *testing.T) {
	guarded := LimitBody(16, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		}
	}))
	for body, want := range map[string]int{"hi": 200, strings.Repeat("a", 1024): 413} {
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body)))
		if rec.Code != want {
			t.Errorf("%d-byte body: status %d, want %d", len(body), rec.Code, want)
		}
	}
}
