package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/buildinfo"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/checks"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/kube"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/output"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/orchestrator"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/protocol"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/redact"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/tlsutil"
)

// Hooks tests replace.
var (
	registry                           = checks.Registry
	lookupEnv       settings.EnvLookup = os.LookupEnv
	now                                = time.Now
	loadKube                           = kube.Load
	newOrchestrator                    = orchestrator.New
	// The workstation's only outbound paths besides the Kubernetes API.
	newHTTPClient                 = func() *http.Client { return tlsutil.NewHTTPClient(tlsutil.Options{}) }
	resolver      engine.Resolver = net.DefaultResolver
	// The local tools WS-01 looks for.
	localTools engine.LocalTools = execTools{}
)

// DefaultProbeTimeout bounds how long cluster mode waits for probe pods.
const DefaultProbeTimeout = 3 * time.Minute

type runOptions struct {
	*globalOptions
	mode          engine.Mode
	settingsFile  string
	outputDir     string
	checkTimeout  time.Duration
	probeImage    string
	sgxProbeImage string
	probeTimeout  time.Duration
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
	if mode == engine.ModeCluster {
		f.StringVar(&o.probeImage, "probe-image", "", "probe image, preferably pinned by digest (default: the image this release was built with)")
		f.StringVar(&o.sgxProbeImage, "sgx-probe-image", "", "SGX probe image for CC-05 (quote generation on each SGX node; see docs/sgx-probe.md)")
		f.DurationVar(&o.probeTimeout, "probe-timeout", DefaultProbeTimeout, "how long to wait for probe pods")
	}
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
		Local:        localTools,
		DNS:          resolver,
		HTTP:         newHTTPClient(),
		Now:          now,
	}
	// Workstation mode can only read. Cluster mode can also write, but only
	// to its own temporary namespace.
	kopts := kube.Options{Kubeconfig: o.kubeconfig, Context: o.kubeContext, Mode: kube.ReadOnly}
	if o.mode == engine.ModeCluster {
		kopts.Mode, kopts.Namespace = kube.RunNamespace, orchestrator.NamespaceName(runID)
	}
	env.Kube, env.KubeErr = loadKube(kopts)
	target := output.Target{ArmorVersion: st.ArmorVersion, KubeContext: o.kubeContext}
	if env.Kube != nil {
		target.KubeContext = env.Kube.Context
		if v, err := env.Kube.Core.Discovery().ServerVersion(); err == nil {
			target.KubernetesVersion = strings.TrimPrefix(v.GitVersion, "v")
		}
		env.Topology = checks.Topology(ctx, env)
	}

	var probes []output.Probe
	if o.mode == engine.ModeCluster && env.Kube != nil {
		orch := newOrchestrator(env.Kube.Core, runID, o.image(cat))
		defer func() {
			if cerr := o.cleanup(orch, out); cerr != nil && err == nil {
				err = exitcode.ToolFailure(cerr)
			}
		}()
		probes, err = o.startCluster(ctx, env, orch)
		if err != nil {
			return exitcode.ToolFailure(err)
		}
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
	if o.mode == engine.ModeCluster {
		rec.RBAC = append(rec.RBAC, kube.ClusterPermissions...)
		rec.Probes = append(rec.Probes, probes...)
	}

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
		return exitcode.ToolFailure(fmt.Errorf("preflight hit %d internal error(s), so the result cannot be trusted", len(rep.InternalErrors)))
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

// image is the probe image to use: the flag, else the release default,
// else the catalog value (unless TBD).
func (o *runOptions) image(cat *catalog.Catalog) string {
	switch {
	case o.probeImage != "":
		return o.probeImage
	case buildinfo.ProbeImage != "":
		return buildinfo.ProbeImage
	case cat.Parameters.ProbeImage != catalog.TBD:
		return cat.Parameters.ProbeImage
	}
	return ""
}

// startCluster creates the run namespace and runs the probe pods. Problems
// that stop probes (no image, image not pullable, namespace refused) are
// recorded on the environment so the affected checks report them; only an
// interrupt is returned as an error.
func (o *runOptions) startCluster(ctx context.Context, env *engine.Env, orch *orchestrator.Orchestrator) ([]output.Probe, error) {
	if err := orch.CreateNamespace(ctx); err != nil {
		env.RunNamespaceErr = err
		env.ProbeUnavailable = "Preflight could not create its temporary namespace: " + err.Error()
		return nil, nil
	}
	env.RunNamespace, env.ProbeImage = orch.Namespace, orch.Image
	if orch.Image == "" {
		env.ProbeUnavailable = "no probe image is configured; pass --probe-image"
		return nil, nil
	}
	if o.probeTimeout <= 0 {
		return nil, fmt.Errorf("--probe-timeout must be positive, got %s", o.probeTimeout)
	}
	nodes, err := env.Kube.Core.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		env.ProbeUnavailable = "could not list nodes to place probes: " + err.Error()
		return nil, nil
	}
	p := env.Params()
	pools := orchestrator.PoolsFromNodes(nodes.Items, p.NodePoolLabel, p.InstanceTypeLabel)
	plan, err := checks.Plan(env, orch.RunID)
	if err != nil {
		env.ProbeUnavailable = "could not plan the probes: " + err.Error()
		return nil, nil
	}
	env.ProbeNotes = &engine.ProbeNotes{Images: plan.ImagesNote, Storage: plan.StorageNote}
	request := func(pool string) protocol.Request {
		r := plan.Request(pool)
		r.Timeout = o.checkTimeout
		return r
	}
	outcome, err := orch.RunProbes(ctx, pools, request, plan.Secret, o.probeTimeout)
	if err != nil {
		return nil, fmt.Errorf("run interrupted while probes were running: %w", err)
	}
	env.Probes = &engine.ProbeData{Results: outcome.Results, PoolErrors: outcome.PoolErrors}
	env.ProbeUnavailable = outcome.Unavailable
	var probes []output.Probe
	for _, pr := range outcome.Probes {
		probes = append(probes, output.Probe{NodePool: pr.NodePool, Node: pr.Node, Pod: pr.Pod, Image: pr.Image, ImageDigest: pr.ImageID, Error: outcome.PoolErrors[pr.NodePool]})
	}
	for pool, reason := range outcome.PoolErrors {
		if !hasProbe(probes, pool) {
			probes = append(probes, output.Probe{NodePool: pool, Image: orch.Image, Error: reason})
		}
	}
	sort.Slice(probes, func(i, j int) bool { return probes[i].NodePool < probes[j].NodePool })

	sgxProbes, err := o.runSGXProbes(ctx, env, orch)
	if err != nil {
		return nil, err
	}
	return append(probes, sgxProbes...), nil
}

// runSGXProbes runs one SGX probe per SGX node for CC-05, each asked to
// bind its quote to a fresh random nonce.
func (o *runOptions) runSGXProbes(ctx context.Context, env *engine.Env, orch *orchestrator.Orchestrator) ([]output.Probe, error) {
	if o.sgxProbeImage == "" {
		env.Probes.SGXUnavailable = "no SGX probe image is configured; CC-05 needs one that can generate quotes (pass --sgx-probe-image; see docs/sgx-probe.md)"
		return nil, nil
	}
	nodes, err := checks.SGXNodes(ctx, env)
	if err != nil {
		env.Probes.SGXUnavailable = "could not list SGX nodes: " + err.Error()
		return nil, nil
	}
	if len(nodes) == 0 {
		env.Probes.SGXUnavailable = "no SGX nodes found"
		return nil, nil
	}
	request := func(node string) protocol.Request {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			panic(err) // crypto/rand does not fail on supported platforms
		}
		return protocol.Request{Version: protocol.Version, RunID: orch.RunID, SGX: &protocol.SGX{Nonce: hex.EncodeToString(nonce)}, Timeout: o.checkTimeout}
	}
	outcome, err := orch.RunNodeProbes(ctx, o.sgxProbeImage, nodes, request, o.probeTimeout)
	if err != nil {
		return nil, fmt.Errorf("run interrupted while SGX probes were running: %w", err)
	}
	env.Probes.NodeResults, env.Probes.NodeErrors = outcome.Results, outcome.PoolErrors
	var probes []output.Probe
	for _, pr := range outcome.Probes {
		probes = append(probes, output.Probe{NodePool: env.Topology.PoolOf(pr.Node), Node: pr.Node, Pod: pr.Pod, Image: pr.Image, ImageDigest: pr.ImageID, Error: outcome.PoolErrors[pr.Node]})
	}
	return probes, nil
}

func hasProbe(probes []output.Probe, pool string) bool {
	for _, p := range probes {
		if p.NodePool == pool {
			return true
		}
	}
	return false
}

// cleanup removes the run's namespace and objects. It runs on every exit,
// including an interrupt, with its own deadline.
func (o *runOptions) cleanup(orch *orchestrator.Orchestrator, out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := orch.Cleanup(ctx); err != nil {
		fmt.Fprintf(out, "\nCleanup did not finish: %v\nRun `armor-preflight cleanup --run-id %s` to remove what is left.\n", err, orch.RunID)
		return fmt.Errorf("cleanup did not finish: %w", err)
	}
	fmt.Fprintf(out, "\nRemoved Preflight's temporary namespace %s and everything in it.\n", orch.Namespace)
	return nil
}
