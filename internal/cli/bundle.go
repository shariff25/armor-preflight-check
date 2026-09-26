package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
)

type bundleOptions struct {
	outputDir string
	listOnly  bool
	yes       bool
}

func newBundleCmd() *cobra.Command {
	o := &bundleOptions{}
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Package the latest run into a redacted archive for a support ticket",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return exitcode.ToolFailure(errors.New("bundle is not implemented yet"))
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.outputDir, "output", "o", DefaultOutputDir, "output directory of the run to bundle")
	f.BoolVar(&o.listOnly, "list", false, "list the bundle contents without writing it")
	f.BoolVarP(&o.yes, "yes", "y", false, "write the bundle without asking for confirmation")
	return cmd
}
