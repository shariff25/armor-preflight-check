package cli

import (
	"context"
	"os/exec"
)

// execTools runs workstation tools for WS-01.
type execTools struct{}

func (execTools) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (execTools) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
