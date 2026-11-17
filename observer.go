package mcpkit

import (
	"context"
	"time"
)

// Observer receives tool events. Every field is optional. Callbacks run
// synchronously on the call's goroutine and cannot change its outcome; they
// see sizes and status, never arguments or results.
type Observer struct {
	// Registered fires once per registration, on each endpoint a tool is
	// registered on.
	Registered func(tool string)
	// Started fires when a call reaches the tool boundary, before its input
	// is validated.
	Started func(context.Context, Start)
	// Completed fires exactly once per call that Started, after the final
	// result is packed, or while a panic unwinds.
	Completed func(context.Context, Completion)
	// PackFailed fires when a result could not be packed into the envelope.
	PackFailed func(context.Context, PackFailure)
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
	// envelope or the failure text. HasOutput is false when no result was
	// produced (a panic); IsError then is false too.
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
