package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/buildinfo"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/checks"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
)

// Hooks tests replace.
var (
	registry                     = checks.Registry
	lookupEnv settings.EnvLookup = os.LookupEnv
	now                          = time.Now
)

type runOptions struct {
	*globalOptions
	mode         engine.Mode
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
		newRunModeCmd(g, engine.ModeWorkstation, "Run every check that needs no probe pods; makes zero changes to the cluster"),
		newRunModeCmd(g, engine.ModeCluster, "Run workstation checks, then probe pods on each node pool"),
	)
	return cmd
}

func newRunModeCmd(g *globalOptions, mode engine.Mode, short string) *cobra.Command {
	o := &runOptions{globalOptions: g, mode: mode}
	cmd := &cobra.Command{
		Use:   string(mode),
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return o.run(ctx, cmd.OutOrStdout())
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.settingsFile, "settings", "f", "", "settings file (optional; settings-dependent checks are skipped without it)")
	f.StringVarP(&o.outputDir, "output", "o", DefaultOutputDir, "output directory")
	f.DurationVarP(&o.checkTimeout, "timeout", "t", DefaultCheckTimeout, "per-check timeout")
	return cmd
}

func (o *runOptions) run(ctx context.Context, out io.Writer) error {
	if o.checkTimeout <= 0 {
		return exitcode.ToolFailure(fmt.Errorf("--timeout must be positive, got %s", o.checkTimeout))
	}
	cat, err := catalog.Load()
	if err != nil {
		return exitcode.ToolFailure(err)
	}
	st := settings.Default()
	if o.settingsFile != "" {
		if st, err = settings.Load(o.settingsFile); err != nil {
			return exitcode.ToolFailure(err)
		}
		if !cat.Covers(st.ArmorVersion) {
			return exitcode.ToolFailure(cat.CoverageError(st.ArmorVersion, buildinfo.Version))
		}
	}

	runID := model.NewRunID(now())
	env := &engine.Env{
		Mode:         o.mode,
		Catalog:      cat,
		Settings:     st,
		SettingsFile: o.settingsFile,
		LookupEnv:    lookupEnv,
	}
	rep, err := engine.Run(ctx, env, registry(), engine.Options{Timeout: o.checkTimeout})
	if err != nil {
		return exitcode.ToolFailure(err)
	}

	printSummary(out, runID, o.mode, st, rep)

	if len(rep.InternalErrors) > 0 {
		return exitcode.ToolFailure(fmt.Errorf("Preflight hit %d internal error(s); the result cannot be trusted:\n  %s",
			len(rep.InternalErrors), strings.Join(rep.InternalErrors, "\n  ")))
	}
	if len(rep.Unimplemented) > 0 {
		return exitcode.ToolFailure(fmt.Errorf("this build does not implement %d of %d checks (%s), so the verdict is incomplete",
			len(rep.Unimplemented), len(cat.Checks), strings.Join(rep.Unimplemented, ", ")))
	}
	v := rep.Verdict()
	return exitcode.WithCode(v.ExitCode(), v.Display())
}

// printSummary is a plain summary; milestone M2 replaces it with the full
// terminal report and file outputs.
func printSummary(out io.Writer, runID string, mode engine.Mode, st *settings.Settings, rep *engine.Report) {
	target := "no settings file"
	if st.ArmorVersion != "" {
		target = "Armor " + st.ArmorVersion
	}
	fmt.Fprintf(out, "armor-preflight %s  run %s  %s mode  %s\n\n", buildinfo.Version, runID, mode, target)
	for _, r := range rep.Results {
		if r.Status == model.StatusPass {
			continue
		}
		detail := ""
		if r.SkippedReason != nil {
			detail = *r.SkippedReason
		} else if len(r.Evidence) > 0 {
			detail = r.Evidence[0].Detail
		}
		fmt.Fprintf(out, "  %-7s %-7s %-22s %s\n", strings.ToUpper(string(r.Status)), r.ID, r.Scope, detail)
	}
	c := model.Count(rep.Results)
	verdict := rep.Verdict().Display()
	if len(rep.Unimplemented) > 0 || len(rep.InternalErrors) > 0 {
		verdict = "INCOMPLETE"
	}
	fmt.Fprintf(out, "\nResult: %s  (pass %d, fail %d, warn %d, skipped %d, info %d)\n",
		verdict, c.Pass, c.Fail, c.Warn, c.Skipped, c.Info)
}
