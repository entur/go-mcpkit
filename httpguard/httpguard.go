// Package httpguard provides small, policy-free HTTP middlewares: security
// response headers, loopback-only scoping, panic recovery, a body cap, a
// per-subject rate limiter and a stream write deadline.
//
// The package knows nothing about identity, metrics or logging. Where a
// middleware needs one, it takes a nil-safe, synchronous callback from the
// application.
//
// A ResponseWriter wrapper placed around StreamWriteDeadline must implement
// Unwrap() http.ResponseWriter, or the deadline cannot reach the connection.
package httpguard

import (
	"context"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// SubjectKey names the caller a request is limited as. present is false for a
// request with no authenticated caller, which the limiter passes through; a
// present key may be empty and still consumes a bucket.
type SubjectKey func(context.Context) (key string, present bool)

// SecurityHeaders sets a fixed set of defence-in-depth response headers on
// every request before delegating to next. A handler that sets one of them
// later overrides it, which is intentional (a static document may set its own
// Cache-Control, which is not in the set).
//
// The headers suit an HTTPS-only API service with no user-controlled HTML in
// any response: the CSP is the maximally restrictive default-src 'none';
// frame-ancestors 'none'. Neither XHR endpoints nor OAuth redirect flows,
// which never render a body in the browser, are affected by it.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// LoopbackOnly wraps next so it only responds to requests whose immediate TCP
// peer is a loopback IP (127.0.0.0/8 or ::1); everything else gets a 404. It
// never reads a forwarding header: a request relayed by a proxy or load
// balancer arrives from the relay's non-loopback address and falls through to
// the 404. It suits a metrics endpoint scraped by a sidecar in the same
// network namespace.
//
// 404 rather than 403: an external probe gets the same response as for any
// other unrouted path, so the endpoint's existence does not leak.
func LoopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Recover wraps next so a panic in any handler is caught, reported to
// onPanic with the stack (server-side only, may be nil), and surfaced to the
// caller as a 500. Go's net/http already recovers per-connection so the
// server survives without this; the value here is the callback's audit line
// and counter, not crash protection.
func Recover(onPanic func(r *http.Request, panicValue any, stack []byte), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if onPanic != nil {
				onPanic(r, rec, debug.Stack())
			}
			// If the handler already started writing (status / body set),
			// http.Error's WriteHeader is a no-op and the client sees a
			// truncated response — the best we can do without buffering.
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}

// SubjectLimiter is a token-bucket rate limiter keyed by an authenticated
// subject. Concurrent-safe; idle subject entries are swept on each Allow call
// after ttl so the map stays bounded over a long uptime.
//
// The intended use is on an MCP endpoint, after authentication has run, as a
// guard against a single compromised credential hammering downstream APIs.
// Per-tool limiters still apply on top.
type SubjectLimiter struct {
	mu    sync.Mutex
	seen  map[string]*subjectEntry
	rate  rate.Limit
	burst int
	ttl   time.Duration
	now   func() time.Time
}

type subjectEntry struct {
	lim  *rate.Limiter
	last time.Time
}

// NewSubjectLimiter returns a limiter admitting r tokens per second with
// the given burst, evicting per-subject state after ttl of inactivity.
func NewSubjectLimiter(r rate.Limit, burst int, ttl time.Duration) *SubjectLimiter {
	return &SubjectLimiter{
		seen:  make(map[string]*subjectEntry),
		rate:  r,
		burst: burst,
		ttl:   ttl,
		now:   time.Now,
	}
}

// Allow consults the bucket for subject and returns true if the request
// fits. New-subject insertions trigger an inline sweep of stale entries
// so the map stays bounded under a long uptime; repeat hits from an
// existing subject skip the sweep, which is the dominant request shape.
func (l *SubjectLimiter) Allow(subject string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	e, ok := l.seen[subject]
	if !ok {
		// Sweeping only when the map is about to grow keeps the hot
		// hit path off the O(n) iteration. Eviction tests rely on this
		// happening on the next new-subject arrival, which it still
		// does.
		for k, v := range l.seen {
			if now.Sub(v.last) > l.ttl {
				delete(l.seen, k)
			}
		}
		e = &subjectEntry{lim: rate.NewLimiter(l.rate, l.burst)}
		l.seen[subject] = e
	}
	e.last = now

	return e.lim.AllowN(now, 1)
}

// Middleware enforces the per-subject limit. Requests with no subject
// (key reports not present) are passed through unchanged: authentication is
// the previous layer's responsibility, not the limiter's. Throttled requests
// get a 429 with Retry-After after onReject (may be nil) has run.
func (l *SubjectLimiter) Middleware(key SubjectKey, onReject func(*http.Request), next http.Handler) http.Handler {
	retryAfter := strconv.Itoa(int(l.minRetryAfter().Seconds()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, ok := key(r.Context())
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		if !l.Allow(subject) {
			w.Header().Set("Retry-After", retryAfter)
			if onReject != nil {
				onReject(r)
			}
			http.Error(w, "rate limited: try again shortly", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// minRetryAfter derives a reasonable Retry-After hint from the bucket
// refill rate. A client that hits the limit can be asked to wait long
// enough for at least one fresh token.
func (l *SubjectLimiter) minRetryAfter() time.Duration {
	if l.rate <= 0 {
		return time.Minute
	}
	d := time.Duration(float64(time.Second) / float64(l.rate))
	if d < time.Second {
		return time.Second
	}
	return d
}

// streamDeadlineUnsupported keeps the ErrNotSupported report to one call
// per process. The condition is a static property of the middleware chain,
// not of any individual request, so logging it per request would be pure
// noise.
var streamDeadlineUnsupported sync.Once

// StreamWriteDeadline extends the per-request write deadline to d for the
// route it wraps, overriding the server-wide http.Server.WriteTimeout.
//
// WriteTimeout is an absolute deadline measured from the start of the
// request, which suits ordinary request/response handlers but silently
// truncates one that is still running when it expires: the handler's write
// fails against a dead deadline and the client gets a partial response. MCP
// routes can legitimately run longer than the server-wide bound, so they need
// a looser one.
//
// Set d above the platform's own request timeout. The point is that exactly
// one bound governs request duration — the platform's — rather than two that
// can disagree, with the app's firing first and cutting off work the platform
// would have allowed. Routes that are not wrapped keep the tighter
// server-wide WriteTimeout.
//
// What this does NOT do is make a platform-terminated stream clean. An SSE
// body has no complete state until the stream ends, so a stream severed
// mid-flight is truncated no matter what deadline the app holds. Keeping such
// streams from being opened is a separate concern, handled by the locked
// capabilities of each mcpkit endpoint.
//
// A ResponseWriter that cannot expose its deadline (no Unwrap chain to the
// real connection, e.g. httptest.ResponseRecorder) is not an error: the
// request proceeds under the server-wide WriteTimeout, and onUnsupported (may
// be nil) hears the reason once per process.
func StreamWriteDeadline(d time.Duration, onUnsupported func(*http.Request, error), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d)); err != nil {
			streamDeadlineUnsupported.Do(func() {
				if onUnsupported != nil {
					onUnsupported(r, err)
				}
			})
		}
		next.ServeHTTP(w, r)
	})
}

// LimitBody wraps next so the request body is capped at n bytes. Any read
// past the limit produces an *http.MaxBytesError to the handler, which the
// handler is expected to surface as a 4xx. Defence in depth for an MCP
// endpoint: the SDK validates its protocol payloads but does not bound total
// bytes.
func LimitBody(n int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, n)
		next.ServeHTTP(w, r)
	})
}
