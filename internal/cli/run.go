package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
)

// Mode is how much of the catalog a run covers.
type Mode string

const (
	// ModeWorkstation runs every check that needs no probe pods and makes no
	// changes to the cluster.
	ModeWorkstation Mode = "workstation"
	// ModeCluster also runs probe pods on each node pool.
	ModeCluster Mode = "cluster"
)

type runOptions struct {
	*globalOptions
	mode         Mode
	settingsFile string
	outputDir    string
	checkTimeout time.Duration
}

func newRunCmd(g *globalOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the readiness checks",
	}
	cmd.AddCommand(
		newRunModeCmd(g, ModeWorkstation, "Run every check that needs no probe pods; makes zero changes to the cluster"),
		newRunModeCmd(g, ModeCluster, "Run workstation checks, then probe pods on each node pool"),
	)
	return cmd
}

func newRunModeCmd(g *globalOptions, mode Mode, short string) *cobra.Command {
	o := &runOptions{globalOptions: g, mode: mode}
	cmd := &cobra.Command{
		Use:   string(mode),
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.settingsFile, "settings", "f", "", "settings file (optional; settings-dependent checks are skipped without it)")
	f.StringVarP(&o.outputDir, "output", "o", DefaultOutputDir, "output directory")
	f.DurationVarP(&o.checkTimeout, "timeout", "t", DefaultCheckTimeout, "per-check timeout")
	return cmd
}

func (o *runOptions) run(_ *cobra.Command) error {
	if o.checkTimeout <= 0 {
		return exitcode.ToolFailure(fmt.Errorf("--timeout must be positive, got %s", o.checkTimeout))
	}
	return exitcode.ToolFailure(fmt.Errorf("run %s is not implemented yet", o.mode))
}
