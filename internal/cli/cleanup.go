package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
)

type cleanupOptions struct {
	*globalOptions
	runID string
}

func newCleanupCmd(g *globalOptions) *cobra.Command {
	o := &cleanupOptions{globalOptions: g}
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Delete leftover Preflight objects, found by label",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return exitcode.ToolFailure(errors.New("cleanup is not implemented yet"))
		},
	}
	cmd.Flags().StringVar(&o.runID, "run-id", "", "only delete objects from this run (default: all runs)")
	return cmd
}
