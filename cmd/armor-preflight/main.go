// Command armor-preflight checks whether an environment is ready for a
// Fortanix Armor on-prem install.
package main

import (
	"fmt"
	"os"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/cli"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
)

func main() {
	err := cli.NewRootCmd(os.Stdout, os.Stderr).Execute()
	if err != nil && !exitcode.IsQuiet(err) {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(exitcode.FromError(err))
}
