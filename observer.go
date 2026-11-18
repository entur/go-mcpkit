package mcpkit

import (
	"context"
	"time"
)

// Observer receives tool events. Every field is optional. Callbacks are
// trusted application code and must not panic: they run synchronously on the
// call's goroutine, and a panicking Started skips the call's Completed. They
// cannot change a call's outcome and see sizes and status, never arguments or
// results, except PackFailure.Err and Recovery, which can quote a result's
// own encoding error or a panic value and are sensitive server-side data.
type Observer struct {
	// Registered fires once per registration, on each endpoint a tool is
	// registered on.
	Registered func(tool string)
	// Started fires when a call reaches the tool boundary, before its input
	// is validated.
	Started func(context.Context, Start)
	// Completed fires exactly once per call that Started, after the final
	// result is packed, a recovered panic included.
	Completed func(context.Context, Completion)
	// PackFailed fires when a result could not be packed into the envelope.
	PackFailed func(context.Context, PackFailure)
	// Recovered fires when a handler or result packing panicked; the call
	// then answers the tool's fallback failure text.
	Recovered func(context.Context, Recovery)
}

// Start describes a call as it reaches the boundary.
type Start struct {
	Tool string
	// InputBytes is the length of the raw arguments JSON; HasInput is false
	// when the request carried no parameters.
	InputBytes int
	HasInput   bool
}

// Completion describes a finished call.
type Completion struct {
	Tool     string
	Duration time.Duration
	// OutputBytes is the length of the result's single text content: the
	// envelope or the failure text. HasOutput reports whether a result was
	// produced; since panics are recovered it is false only when the handler's
	// goroutine exited through runtime.Goexit.
	OutputBytes int
	HasOutput   bool
	IsError     bool
}

// PackFailure describes a result that could not be packed. Err is the
// envelope error; Marshal is true when the envelope itself failed to encode,
// and Err is then that encoding error.
type PackFailure struct {
	Tool    string
	Err     error
	Marshal bool
}

// Recovery describes a panic recovered at the tool boundary. Value is what
// was passed to panic and Stack the panicking goroutine's stack; both can
// hold argument or result data, so keep them server-side.
type Recovery struct {
	Tool  string
	Value any
	Stack []byte
}
