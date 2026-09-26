// Package exitcode defines the process exit codes Preflight documents.
package exitcode

import "errors"

const (
	// Ready means no blocker failed and nothing warned.
	Ready = 0
	// ReadyWithWarnings means no blocker failed but at least one check warned.
	ReadyWithWarnings = 1
	// NotReady means at least one blocker check failed.
	NotReady = 2
	// ToolError means Preflight itself could not run.
	ToolError = 3
)

// Error carries an exit code out of a command.
type Error struct {
	Code int
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// ToolFailure wraps err as a Preflight failure (exit 3).
func ToolFailure(err error) error { return &Error{Code: ToolError, Err: err} }

// FromError returns the exit code for err: 0 for nil, the carried code for
// an *Error, and ToolError for anything else.
func FromError(err error) int {
	if err == nil {
		return Ready
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ToolError
}
