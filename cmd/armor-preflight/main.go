// Command armor-preflight checks whether an environment is ready for a
// Fortanix Armor on-prem install.
package main

import (
	"fmt"
	"os"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/cli"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/output"
)

func main() {
	err := cli.NewRootCmd(os.Stdout, os.Stderr).Execute()
	if err != nil && !exitcode.IsQuiet(err) {
		// Error text can quote API or endpoint responses; keep escape
		// sequences out of the operator's terminal.
		fmt.Fprintln(os.Stderr, "error:", output.StripControl(err.Error()))
	}
	os.Exit(exitcode.FromError(err))
}
