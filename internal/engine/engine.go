// Package engine runs catalog checks in dependency order and turns what each
// check observed into complete results.
package engine

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
)

// Mode is how much of the catalog a run covers.
type Mode string

const (
	// ModeWorkstation runs every check that needs no probe pods and makes no
	// changes to the cluster.
	ModeWorkstation Mode = "workstation"
	// ModeCluster also runs checks that create test objects and probe pods.
	ModeCluster Mode = "cluster"
)

// ReasonWorkstationMode is the skip reason for checks that need cluster mode.
const ReasonWorkstationMode = "workstation mode"

// ReasonNotImplemented is the skip reason for checks this build lacks.
const ReasonNotImplemented = "not implemented in this build"

// Topology is what the run knows about node pools.
type Topology struct {
	// Pools maps each node pool to its node names.
	Pools map[string][]string
	// NodeIPs maps each node to its InternalIP, for firewall requests when
	// the pool subnet is not in the settings.
	NodeIPs map[string]string
}

// PoolOf returns the pool a node belongs to, or "".
func (t Topology) PoolOf(node string) string {
	for pool, nodes := range t.Pools {
		for _, n := range nodes {
			if n == node {
				return pool
			}
		}
	}
	return ""
}

// Env is everything a check can read. Checks must treat it as read-only.
type Env struct {
	Mode         Mode
	Catalog      *catalog.Catalog
	Settings     *settings.Settings
	SettingsFile string // path of the settings file, "" when none was given
	LookupEnv    settings.EnvLookup
	Topology     Topology
	// ProbeUnavailable, when set, is why probe-based checks cannot run (for
	// example, the probe image could not be pulled).
	ProbeUnavailable string
}

// Params returns the catalog parameters.
func (e *Env) Params() catalog.Parameters { return e.Catalog.Parameters }

// CheckFunc runs one check and returns one result per scope. It fills in
// Status, Scope, Evidence and, when it has something more specific than the
// catalog's text, Remediation. The engine fills in everything else.
type CheckFunc func(ctx context.Context, env *Env, def *catalog.Check) []model.Result

// Registry maps catalog IDs to their implementations.
type Registry map[string]CheckFunc

// Options tune a run.
type Options struct {
	// Timeout bounds each check.
	Timeout time.Duration
}

// Report is the outcome of a run.
type Report struct {
	Results []model.Result
	// Unimplemented lists catalog checks with no implementation, in catalog
	// order, whether or not the run reached them.
	Unimplemented []string
	// InternalErrors lists Preflight bugs hit during the run (a check
	// panicked or returned malformed results). Any entry means the run
	// cannot be trusted and Preflight exits 3.
	InternalErrors []string
}

// Verdict is the overall result of the run.
func (r *Report) Verdict() model.Verdict { return model.Decide(r.Results) }

// Run executes every catalog check.
func Run(ctx context.Context, env *Env, reg Registry, opts Options) (*Report, error) {
	levels, err := env.Catalog.Levels()
	if err != nil {
		return nil, err
	}
	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be positive, got %s", opts.Timeout)
	}
	r := &runner{env: env, reg: reg, opts: opts, results: map[string][]model.Result{}}
	for _, level := range levels {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("run interrupted: %w", err)
		}
		var wg sync.WaitGroup
		for _, def := range level {
			wg.Add(1)
			go func(def *catalog.Check) {
				defer wg.Done()
				res := r.runOne(ctx, def)
				r.mu.Lock()
				r.results[def.ID] = res
				r.mu.Unlock()
			}(def)
		}
		wg.Wait()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("run interrupted: %w", err)
	}
	rep := &Report{InternalErrors: r.internalErrors}
	for _, def := range env.Catalog.Checks {
		rep.Results = append(rep.Results, r.results[def.ID]...)
		if reg[def.ID] == nil {
			rep.Unimplemented = append(rep.Unimplemented, def.ID)
		}
	}
	return rep, nil
}

type runner struct {
	env  *Env
	reg  Registry
	opts Options

	mu             sync.Mutex
	results        map[string][]model.Result
	internalErrors []string
}

func (r *runner) parentResults(id string) []model.Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.results[id]
}

func (r *runner) noteInternal(format string, args ...any) string {
	msg := fmt.Sprintf(format, args...)
	r.mu.Lock()
	r.internalErrors = append(r.internalErrors, msg)
	r.mu.Unlock()
	return msg
}

// template is a result with every catalog-derived field filled in.
func (r *runner) template(def *catalog.Check) model.Result {
	deps := append([]string{}, def.DependsOn...)
	return model.Result{
		ID:          def.ID,
		Title:       def.Title,
		Area:        def.Area,
		Severity:    def.SeverityFor(r.env.Settings.Storage.Environment),
		Scope:       model.ClusterScope(),
		Remediation: def.Remediation,
		Owner:       def.Owner,
		DocLink:     def.DocLink,
		DependsOn:   deps,
	}
}

func (r *runner) skipAll(def *catalog.Check, reason string) []model.Result {
	return []model.Result{r.template(def).Skipped(reason)}
}

func (r *runner) runOne(ctx context.Context, def *catalog.Check) []model.Result {
	if reason := r.preconditions(def); reason != "" {
		return r.skipAll(def, reason)
	}
	blocks := r.collectBlocks(def)
	if reason := blocks.cluster(); reason != "" {
		return r.skipAll(def, reason)
	}
	if def.Scope == catalog.ScopeCluster {
		if reason := blocks.any(); reason != "" {
			return r.skipAll(def, reason)
		}
	}
	if reason := r.inputs(def); reason != "" {
		return r.skipAll(def, reason)
	}

	fn := r.reg[def.ID]
	if fn == nil {
		return r.skipAll(def, ReasonNotImplemented)
	}

	raw, err := r.call(ctx, fn, def)
	if err != nil {
		if err == errTimeout {
			res := r.template(def)
			res.Status = model.StatusFail
			res.Evidence = []model.Evidence{{Stage: "timeout", OK: false, Detail: fmt.Sprintf("check did not finish within %s", r.opts.Timeout)}}
			return []model.Result{r.normalize(def, res)}
		}
		return r.skipAll(def, "Preflight internal error: "+r.noteInternal("%s: %v", def.ID, err))
	}
	if len(raw) == 0 {
		return r.skipAll(def, "Preflight internal error: "+r.noteInternal("%s returned no results", def.ID))
	}

	out := make([]model.Result, 0, len(raw))
	for _, got := range raw {
		res := r.template(def)
		res.Status, res.Scope, res.Evidence, res.SkippedReason = got.Status, got.Scope, got.Evidence, got.SkippedReason
		if got.Remediation != "" {
			res.Remediation = got.Remediation
		}
		if msg := checkScope(def, res); msg != "" {
			return r.skipAll(def, "Preflight internal error: "+r.noteInternal("%s: %s", def.ID, msg))
		}
		if reason := blocks.forScope(res.Scope, r.env.Topology); reason != "" {
			res = res.Skipped(reason)
		}
		res = r.normalize(def, res)
		if err := res.Validate(); err != nil {
			return r.skipAll(def, "Preflight internal error: "+r.noteInternal("%v", err))
		}
		out = append(out, res)
	}
	return out
}

// preconditions returns why the check cannot run in this run at all.
func (r *runner) preconditions(def *catalog.Check) string {
	if def.Target != catalog.TargetCluster {
		return fmt.Sprintf("target %q is not supported in this build", def.Target)
	}
	if def.RunsIn != catalog.RunsInWorkstation && r.env.Mode == ModeWorkstation {
		return ReasonWorkstationMode
	}
	if def.RunsIn == catalog.RunsInProbe && r.env.ProbeUnavailable != "" {
		return r.env.ProbeUnavailable
	}
	return ""
}

// inputs returns why a missing setting or environment variable stops the check.
func (r *runner) inputs(def *catalog.Check) string {
	for _, p := range def.Needs {
		if !r.env.Settings.Has(p) {
			if r.env.SettingsFile == "" {
				return fmt.Sprintf("no settings file given (-f); needs `%s`", p)
			}
			return fmt.Sprintf("missing setting `%s`", p)
		}
	}
	for _, p := range def.NeedsEnv {
		if !r.env.Settings.Has(p) && r.env.SettingsFile == "" {
			return fmt.Sprintf("no settings file given (-f); needs `%s`", p)
		}
		if reason := r.env.Settings.MissingEnv(p, r.env.LookupEnv); reason != "" {
			return reason
		}
	}
	return ""
}

var errTimeout = fmt.Errorf("timeout")

// call runs fn with the per-check timeout, turning a panic into an error.
func (r *runner) call(ctx context.Context, fn CheckFunc, def *catalog.Check) ([]model.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()
	type outcome struct {
		res []model.Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- outcome{err: fmt.Errorf("panic: %v\n%s", p, firstFrames(debug.Stack()))}
			}
		}()
		done <- outcome{res: fn(ctx, r.env, def)}
	}()
	select {
	case o := <-done:
		return o.res, o.err
	case <-ctx.Done():
		// Give the check a moment to return what it has after cancellation.
		select {
		case o := <-done:
			if o.err == nil && len(o.res) > 0 {
				return o.res, nil
			}
			if o.err != nil {
				return nil, o.err
			}
		case <-time.After(100 * time.Millisecond):
		}
		return nil, errTimeout
	}
}

func firstFrames(stack []byte) string {
	lines := strings.Split(string(stack), "\n")
	if len(lines) > 12 {
		lines = lines[:12]
	}
	return strings.Join(lines, "\n")
}

// normalize maps a status onto what the check's severity allows: a violated
// warning-severity check reports warn, and an info check reports info.
func (r *runner) normalize(_ *catalog.Check, res model.Result) model.Result {
	if res.Status == model.StatusSkipped {
		return res
	}
	switch res.Severity {
	case model.SeverityWarning:
		if res.Status == model.StatusFail {
			res.Status = model.StatusWarn
		}
	case model.SeverityInfo:
		res.Status = model.StatusInfo
	}
	return res
}

func checkScope(def *catalog.Check, res model.Result) string {
	set := 0
	for _, b := range []bool{res.Scope.Cluster, res.Scope.NodePool != "", res.Scope.Node != ""} {
		if b {
			set++
		}
	}
	if set != 1 {
		return fmt.Sprintf("result scope %+v must set exactly one field", res.Scope)
	}
	switch {
	case res.Status == model.StatusSkipped && res.Scope.Cluster:
		return "" // a check may skip itself wholesale
	case def.Scope == catalog.ScopeCluster && !res.Scope.Cluster,
		def.Scope == catalog.ScopeNodePool && res.Scope.NodePool == "",
		def.Scope == catalog.ScopeNode && res.Scope.Node == "":
		return fmt.Sprintf("result scope %s does not match catalog scope %s", res.Scope, def.Scope)
	}
	return ""
}
