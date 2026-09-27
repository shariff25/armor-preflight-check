package cli

import (
	"context"
	"fmt"
	"io"
	"net"
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
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/kube"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/output"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/redact"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/tlsutil"
)

// Hooks tests replace.
var (
	registry                     = checks.Registry
	lookupEnv settings.EnvLookup = os.LookupEnv
	now                          = time.Now
	loadKube                     = kube.Load
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

func (o *runOptions) run(ctx context.Context, stdout io.Writer) (err error) {
	started := now()
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

	// From here on, everything printed, written or returned is redacted.
	red := newRedactor(st)
	out := redact.NewWriter(red, stdout)
	defer func() {
		out.Flush()
		err = red.Error(err)
	}()

	runID := model.NewRunID(started)
	env := &engine.Env{
		Mode:         o.mode,
		Catalog:      cat,
		Settings:     st,
		SettingsFile: o.settingsFile,
		LookupEnv:    lookupEnv,
		Local:        execTools{},
		DNS:          net.DefaultResolver,
		HTTP:         tlsutil.NewHTTPClient(tlsutil.Options{}),
		Now:          now,
	}
	// Both modes use the read-only guard for now; cluster mode's probe
	// orchestration (M4) widens it to the run namespace only.
	env.Kube, env.KubeErr = loadKube(kube.Options{Kubeconfig: o.kubeconfig, Context: o.kubeContext, Mode: kube.ReadOnly})
	target := output.Target{ArmorVersion: st.ArmorVersion, KubeContext: o.kubeContext}
	if env.Kube != nil {
		target.KubeContext = env.Kube.Context
		if v, err := env.Kube.Core.Discovery().ServerVersion(); err == nil {
			target.KubernetesVersion = strings.TrimPrefix(v.GitVersion, "v")
		}
		env.Topology = checks.Topology(ctx, env)
	}

	rep, err := engine.Run(ctx, env, registry(), engine.Options{Timeout: o.checkTimeout})
	if err != nil {
		return exitcode.ToolFailure(err)
	}

	rec := output.NewRecord(
		output.Tool{Version: buildinfo.Version, Commit: buildinfo.Commit, CatalogVersion: cat.CatalogVersion},
		target,
		output.RunInfo{ID: runID, Mode: string(o.mode), StartedAt: started.UTC()},
		rep.Results, rep.Unimplemented, rep.InternalErrors)
	rec.Duration(now().Sub(started))
	rec.RBAC = append(rec.RBAC, kube.WorkstationPermissions...)

	files, werr := output.WriteFiles(o.outputDir, rec, output.FirewallInputs{Catalog: cat, Settings: st, Topology: env.Topology}, red)
	if werr == nil {
		var extra []string
		extra, werr = output.WriteArtifacts(o.outputDir, env.Artifacts(), red)
		files = append(files, extra...)
	}
	output.WriteTerminal(out, rec, files)
	if werr != nil {
		return exitcode.ToolFailure(werr)
	}

	if len(rep.InternalErrors) > 0 {
		return exitcode.ToolFailure(fmt.Errorf("Preflight hit %d internal error(s), so the result cannot be trusted", len(rep.InternalErrors)))
	}
	if len(rep.Unimplemented) > 0 {
		return exitcode.ToolFailure(fmt.Errorf("this build does not implement %d of %d checks, so the verdict is incomplete",
			len(rep.Unimplemented), len(cat.Checks)))
	}
	v := rep.Verdict()
	return exitcode.WithCode(v.ExitCode(), v.Display())
}

// newRedactor registers every secret the settings name, including the
// user:password form that ends up base64-encoded in docker auth strings.
func newRedactor(st *settings.Settings) *redact.Redactor {
	sec := st.ResolveSecrets(lookupEnv)
	red := redact.New(sec.Values()...)
	if sec.RegistryPassword != "" && st.Registry.Username != "" {
		red.Add(st.Registry.Username + ":" + sec.RegistryPassword)
	}
	return red
}
