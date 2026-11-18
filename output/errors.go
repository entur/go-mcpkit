package output

import "errors"

// ErrResultTooLarge identifies a logical result that exceeded a server-side
// expansion or output budget, including the centrally enforced complete
// schema-v2 envelope budget. Public callers receive a fixed safe summary; the
// detailed size remains server-side only.
var ErrResultTooLarge = errors.New("tool result exceeds output budget")

// Failure classes a handler may wrap an error with so the public message can
// name which kind of failure it was. Only the sentinel crosses the boundary,
// never the wrapped error's text, so an upstream body, a query fragment, a
// credential or prompt-like string still cannot ride out in a tool result.
// The classes are deliberately coarse: enough to tell a caller which of their
// own possible mistakes to look at, not enough to describe the target.
//
// They exist because one generic "check the arguments and your access" cannot
// separate a malformed argument from a target absent from an index from an
// access refusal, and the three cases need three different next steps.
//
// A handler that wraps nothing keeps the generic summary, so adoption is
// per-tool and incremental.
var (
	// ErrInvalidArgument: rejected before reaching any upstream service.
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrNotFound: the target is absent from the index or mapping consulted.
	ErrNotFound = errors.New("not found")
	// ErrPermissionDenied: an upstream refused under the caller's own identity.
	ErrPermissionDenied = errors.New("permission denied")
	// ErrUnauthenticated: no usable credential on the session for this tool,
	// or the upstream refused the credential itself. Its summary advises
	// renewing the credential and never claims a missing scope.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrInsufficientScope: the upstream refused the caller's access token
	// because it lacks the scope this tool needs. Distinct from an access
	// denial and from an expired credential: only an authorization that
	// actually requests the scope repairs it.
	ErrInsufficientScope = errors.New("insufficient scope")
	// ErrRateLimited: a server or upstream limiter rejected the call.
	ErrRateLimited = errors.New("rate limited")
	// ErrUpstreamFailure: the upstream failed for reasons that are neither the
	// caller's arguments nor their access.
	ErrUpstreamFailure = errors.New("upstream failure")
)

// Federation classes, for a call the server relays to a third-party MCP
// server under its own (or no) credential. The classes above make claims
// that are false there: ErrInvalidArgument promises no upstream was reached,
// ErrPermissionDenied names the caller's own identity, and
// ErrUpstreamFailure invites a retry.
var (
	// ErrPolicyDenied: the server's federation policy refused the call before
	// any upstream byte was sent (audience, disabled upstream/tool, operation).
	ErrPolicyDenied = errors.New("federation policy denied")
	// ErrToolUnavailable: the federated tool is quarantined, unverifiable,
	// unknown upstream, or needs interaction the server does not bridge.
	ErrToolUnavailable = errors.New("federated tool unavailable")
	// ErrUpstreamRejected: the upstream received the arguments and rejected
	// them (JSON-RPC -32602 or equivalent).
	ErrUpstreamRejected = errors.New("upstream rejected arguments")
	// ErrUpstreamCredential: the upstream refused the server's own service
	// credential, not the caller's identity.
	ErrUpstreamCredential = errors.New("upstream refused service credential")
	// ErrUpstreamIncompatible: negotiated protocol version, capability or
	// content type falls outside the reviewed policy for this upstream.
	ErrUpstreamIncompatible = errors.New("upstream incompatible")
	// ErrAmbiguousOutcome: the request may have reached the upstream and no
	// complete response arrived. The server does not retry and makes no claim
	// either way about whether the operation completed.
	ErrAmbiguousOutcome = errors.New("ambiguous upstream outcome")
)
