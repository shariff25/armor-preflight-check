package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
)

const fullSettings = `armorVersion: "1.0.404"
domains: {armor: armor.example.com, staticAssets: static.armor.example.com}
certificates: {caReady: true}
registry: {username: u, passwordEnv: REG_PW}
storage: {accountFqdn: s.blob.core.windows.net, container: medusa, credentialsEnv: BAK_KEY, environment: production,
  accountKind: StorageV2, performance: Standard, replication: LRS}
syslog: {host: syslog.example.com}
`

var topo = Topology{Pools: map[string][]string{"systempool": {"sys-0", "sys-1", "sys-2"}, "sgxpool1": {"sgx-0", "sgx-1", "sgx-2"}}}

func env(t *testing.T, mode Mode) *Env {
	t.Helper()
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	s, err := settings.Parse([]byte(fullSettings))
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"REG_PW": "pw", "BAK_KEY": "key"}
	return &Env{Mode: mode, Catalog: cat, Settings: s, SettingsFile: "settings.yaml", Topology: topo,
		LookupEnv: func(k string) (string, bool) { v, ok := vars[k]; return v, ok }}
}

func ev(detail string) []model.Evidence {
	return []model.Evidence{{Stage: "observed", OK: true, Detail: detail}}
}

// passFor returns a check that passes for every scope of its kind.
func passFor(def *catalog.Check) CheckFunc {
	return func(context.Context, *Env, *catalog.Check) []model.Result {
		return resultsFor(def, model.StatusPass, nil)
	}
}

// resultsFor builds one result per scope, with status overridden where
// override names the scope (pool or node name).
func resultsFor(def *catalog.Check, status model.Status, override map[string]model.Status) []model.Result {
	mk := func(scope model.Scope, key string) model.Result {
		st := status
		if o, ok := override[key]; ok {
			st = o
		}
		return model.Result{Status: st, Scope: scope, Evidence: ev(def.ID + " " + key)}
	}
	var out []model.Result
	switch def.Scope {
	case catalog.ScopeCluster:
		out = append(out, mk(model.ClusterScope(), "cluster"))
	case catalog.ScopeNodePool:
		for _, p := range []string{"sgxpool1", "systempool"} {
			out = append(out, mk(model.PoolScope(p), p))
		}
	case catalog.ScopeNode:
		for _, n := range []string{"sgx-0", "sgx-1", "sgx-2"} {
			out = append(out, mk(model.NodeScope(n), n))
		}
	}
	return out
}

func allPass(e *Env) Registry {
	reg := Registry{}
	for i := range e.Catalog.Checks {
		def := &e.Catalog.Checks[i]
		reg[def.ID] = passFor(def)
	}
	return reg
}

func run(t *testing.T, e *Env, reg Registry) *Report {
	t.Helper()
	rep, err := Run(context.Background(), e, reg, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func find(rep *Report, id string, scope model.Scope) *model.Result {
	for i := range rep.Results {
		if rep.Results[i].ID == id && rep.Results[i].Scope == scope {
			return &rep.Results[i]
		}
	}
	return nil
}

func reason(r *model.Result) string {
	if r == nil || r.SkippedReason == nil {
		return ""
	}
	return *r.SkippedReason
}

func TestCompliantClusterIsReady(t *testing.T) {
	e := env(t, ModeCluster)
	rep := run(t, e, allPass(e))
	if v := rep.Verdict(); v != model.VerdictReady {
		t.Fatalf("verdict %s", v)
	}
	c := model.Count(rep.Results)
	if c.Fail != 0 || c.Skipped != 0 || c.Warn != 0 {
		t.Fatalf("counts %+v", c)
	}
	if len(rep.Unimplemented)+len(rep.InternalErrors) != 0 {
		t.Fatalf("unexpected %v %v", rep.Unimplemented, rep.InternalErrors)
	}
	if find(rep, "K8S-12", model.ClusterScope()).Status != model.StatusInfo {
		t.Fatal("info-severity check should report info")
	}
}

// Every result carries evidence, remediation, owner and doc link (R1.1).
func TestNoEmptyFields(t *testing.T) {
	for _, mode := range []Mode{ModeWorkstation, ModeCluster} {
		e := env(t, mode)
		reg := allPass(e)
		reg["WS-01"] = func(_ context.Context, _ *Env, d *catalog.Check) []model.Result {
			return resultsFor(d, model.StatusFail, nil)
		}
		for _, r := range run(t, e, reg).Results {
			if err := r.Validate(); err != nil {
				t.Errorf("%s: %v", mode, err)
			}
			if r.Title == "" || r.Area == "" || r.Severity == "" {
				t.Errorf("%s: %s missing catalog fields", mode, r.ID)
			}
		}
	}
}

func TestParentFailureSkipsChildrenAndNamesParent(t *testing.T) {
	e := env(t, ModeCluster)
	reg := allPass(e)
	reg["REG-01"] = func(_ context.Context, _ *Env, d *catalog.Check) []model.Result {
		return resultsFor(d, model.StatusFail, nil)
	}
	rep := run(t, e, reg)
	for _, id := range []string{"REG-02", "REG-04", "REG-05"} {
		if r := find(rep, id, model.ClusterScope()); r == nil || r.Status != model.StatusSkipped || reason(r) != "parent REG-01 failed" {
			t.Errorf("%s: %+v", id, r)
		}
	}
	// REG-03 depends on REG-01 cluster-wide, so it skips once at cluster scope.
	if r := find(rep, "REG-03", model.ClusterScope()); reason(r) != "parent REG-01 failed" {
		t.Errorf("REG-03: %q", reason(r))
	}
	// CC-05 depends on REG-03, which was skipped.
	r := find(rep, "CC-05", model.ClusterScope())
	if !strings.Contains(reason(r), "parent REG-03 was skipped (parent REG-01 failed)") {
		t.Errorf("CC-05: %q", reason(r))
	}
	if rep.Verdict() != model.VerdictNotReady {
		t.Errorf("verdict %s", rep.Verdict())
	}
}

// The brief's example: CC-05 names REG-03 when REG-03 fails.
func TestCC05NamesREG03(t *testing.T) {
	e := env(t, ModeCluster)
	reg := allPass(e)
	reg["REG-03"] = func(_ context.Context, _ *Env, d *catalog.Check) []model.Result {
		return resultsFor(d, model.StatusPass, map[string]model.Status{"sgxpool1": model.StatusFail})
	}
	rep := run(t, e, reg)
	for _, n := range []string{"sgx-0", "sgx-1", "sgx-2"} {
		r := find(rep, "CC-05", model.NodeScope(n))
		if r == nil || r.Status != model.StatusSkipped || reason(r) != "parent REG-03 failed for node pool sgxpool1" {
			t.Errorf("%s: %+v", n, r)
		}
	}
}

// A failure on one node pool only skips that pool's dependent results.
func TestScopeAwareSkip(t *testing.T) {
	e := env(t, ModeCluster)
	reg := allPass(e)
	reg["NET-01"] = func(_ context.Context, _ *Env, d *catalog.Check) []model.Result {
		return resultsFor(d, model.StatusPass, map[string]model.Status{"sgxpool1": model.StatusFail})
	}
	rep := run(t, e, reg)
	if r := find(rep, "NET-02", model.PoolScope("sgxpool1")); reason(r) != "parent NET-01 failed for node pool sgxpool1" {
		t.Errorf("sgxpool1: %+v", r)
	}
	if r := find(rep, "NET-02", model.PoolScope("systempool")); r == nil || r.Status != model.StatusPass {
		t.Errorf("systempool should still pass: %+v", r)
	}
	// NET-03 on systempool still runs; on sgxpool1 it names NET-02.
	if r := find(rep, "NET-03", model.PoolScope("systempool")); r == nil || r.Status != model.StatusPass {
		t.Errorf("NET-03 systempool: %+v", r)
	}
	if r := find(rep, "NET-03", model.PoolScope("sgxpool1")); !strings.HasPrefix(reason(r), "parent NET-02 was skipped") {
		t.Errorf("NET-03 sgxpool1: %q", reason(r))
	}
}

// A node-level parent failure blocks only that node.
func TestNodeLevelParentFailure(t *testing.T) {
	e := env(t, ModeCluster)
	reg := allPass(e)
	reg["CC-01"] = func(_ context.Context, _ *Env, d *catalog.Check) []model.Result {
		return resultsFor(d, model.StatusPass, map[string]model.Status{"sgx-1": model.StatusFail})
	}
	rep := run(t, e, reg)
	if r := find(rep, "CC-05", model.NodeScope("sgx-1")); reason(r) != "parent CC-01 failed for node sgx-1" {
		t.Errorf("sgx-1: %+v", r)
	}
	for _, n := range []string{"sgx-0", "sgx-2"} {
		if r := find(rep, "CC-05", model.NodeScope(n)); r.Status != model.StatusPass {
			t.Errorf("%s: %+v", n, r)
		}
	}
}

func TestMultipleFailedParentsAreAllNamed(t *testing.T) {
	e := env(t, ModeCluster)
	reg := allPass(e)
	fail := func(_ context.Context, _ *Env, d *catalog.Check) []model.Result {
		return resultsFor(d, model.StatusFail, nil)
	}
	reg["CC-01"], reg["CC-02"] = fail, fail
	rep := run(t, e, reg)
	if r := find(rep, "CC-05", model.NodeScope("sgx-0")); reason(r) != "parents CC-01, CC-02 failed for node sgx-0" {
		t.Errorf("got %q", reason(r))
	}
}

func TestWorkstationModeSkipsProbeAndWriteChecks(t *testing.T) {
	e := env(t, ModeWorkstation)
	var mu sync.Mutex
	called := map[string]bool{}
	reg := Registry{}
	for i := range e.Catalog.Checks {
		def := &e.Catalog.Checks[i]
		reg[def.ID] = func(ctx context.Context, en *Env, d *catalog.Check) []model.Result {
			mu.Lock()
			called[d.ID] = true
			mu.Unlock()
			return passFor(def)(ctx, en, d)
		}
	}
	rep := run(t, e, reg)
	for _, def := range e.Catalog.Checks {
		if def.RunsIn == catalog.RunsInWorkstation {
			continue
		}
		if called[def.ID] {
			t.Errorf("%s ran in workstation mode", def.ID)
		}
		r := find(rep, def.ID, model.ClusterScope())
		if reason(r) != ReasonWorkstationMode {
			t.Errorf("%s: %q", def.ID, reason(r))
		}
	}
	if !called["K8S-01"] {
		t.Error("workstation checks did not run")
	}
}

func TestProbeUnavailable(t *testing.T) {
	e := env(t, ModeCluster)
	e.ProbeUnavailable = "probe image example@sha256:abc could not be pulled"
	rep := run(t, e, allPass(e))
	if r := find(rep, "NET-01", model.ClusterScope()); reason(r) != e.ProbeUnavailable {
		t.Errorf("got %q", reason(r))
	}
	if r := find(rep, "K8S-01", model.ClusterScope()); r.Status != model.StatusPass {
		t.Error("workstation checks must still complete")
	}
}

func TestMissingInputs(t *testing.T) {
	e := env(t, ModeCluster)
	e.Settings, e.SettingsFile = settings.Default(), ""
	rep := run(t, e, allPass(e))
	if r := find(rep, "PKI-01", model.ClusterScope()); reason(r) != "no settings file given (-f); needs `domains.armor`" {
		t.Errorf("PKI-01: %q", reason(r))
	}
	if r := find(rep, "REG-01", model.ClusterScope()); !strings.Contains(reason(r), "no settings file given") {
		t.Errorf("REG-01: %q", reason(r))
	}

	e = env(t, ModeCluster)
	e.Settings.Syslog.Host = ""
	e.LookupEnv = func(string) (string, bool) { return "", false }
	rep = run(t, e, allPass(e))
	if r := find(rep, "NET-06", model.ClusterScope()); reason(r) != "missing setting `syslog.host`" {
		t.Errorf("NET-06: %q", reason(r))
	}
	if r := find(rep, "REG-01", model.ClusterScope()); reason(r) != "environment variable REG_PW (named by `registry.passwordEnv`) is not set" {
		t.Errorf("REG-01: %q", reason(r))
	}
}

func TestUnimplemented(t *testing.T) {
	e := env(t, ModeCluster)
	reg := allPass(e)
	delete(reg, "PKI-03")
	delete(reg, "NET-01") // probe check: listed even though a workstation run never reaches it
	e.Mode = ModeWorkstation
	rep := run(t, e, reg)
	if strings.Join(rep.Unimplemented, ",") != "NET-01,PKI-03" {
		t.Fatalf("got %v", rep.Unimplemented)
	}
	if reason(find(rep, "PKI-03", model.ClusterScope())) != ReasonNotImplemented {
		t.Fatal("wrong reason")
	}
}

func TestSeverityNormalisation(t *testing.T) {
	e := env(t, ModeCluster)
	reg := allPass(e)
	fail := func(_ context.Context, _ *Env, d *catalog.Check) []model.Result {
		return resultsFor(d, model.StatusFail, nil)
	}
	reg["NET-04"], reg["K8S-12"] = fail, fail
	rep := run(t, e, reg)
	if r := find(rep, "NET-04", model.ClusterScope()); r.Status != model.StatusWarn {
		t.Errorf("warning-severity violation should warn, got %s", r.Status)
	}
	if r := find(rep, "K8S-12", model.ClusterScope()); r.Status != model.StatusInfo {
		t.Errorf("info check should report info, got %s", r.Status)
	}
	if rep.Verdict() != model.VerdictReadyWithWarnings {
		t.Errorf("verdict %s", rep.Verdict())
	}
}

func TestNonProductionSeverity(t *testing.T) {
	e := env(t, ModeCluster)
	e.Settings.Storage.Environment = settings.EnvironmentPOC
	reg := allPass(e)
	reg["BAK-01"] = func(_ context.Context, _ *Env, d *catalog.Check) []model.Result {
		return resultsFor(d, model.StatusFail, nil)
	}
	rep := run(t, e, reg)
	r := find(rep, "BAK-01", model.ClusterScope())
	if r.Severity != model.SeverityWarning || r.Status != model.StatusWarn || rep.Verdict() != model.VerdictReadyWithWarnings {
		t.Errorf("got %s/%s verdict %s", r.Severity, r.Status, rep.Verdict())
	}
}

func TestTimeout(t *testing.T) {
	e := env(t, ModeCluster)
	reg := allPass(e)
	hang := func(ctx context.Context, _ *Env, _ *catalog.Check) []model.Result {
		<-ctx.Done()
		time.Sleep(time.Second)
		return nil
	}
	reg["K8S-01"], reg["NET-04"] = hang, hang
	rep, err := Run(context.Background(), e, reg, Options{Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	r := find(rep, "K8S-01", model.ClusterScope())
	if r.Status != model.StatusFail || !strings.Contains(r.Evidence[0].Detail, "did not finish within 50ms") {
		t.Errorf("K8S-01: %+v", r)
	}
	if r := find(rep, "NET-04", model.ClusterScope()); r.Status != model.StatusWarn {
		t.Errorf("warning-severity timeout should warn: %s", r.Status)
	}
}

func TestInternalErrors(t *testing.T) {
	cases := map[string]CheckFunc{
		"panic":      func(context.Context, *Env, *catalog.Check) []model.Result { panic("boom") },
		"no results": func(context.Context, *Env, *catalog.Check) []model.Result { return nil },
		"no evidence": func(context.Context, *Env, *catalog.Check) []model.Result {
			return []model.Result{{Status: model.StatusPass, Scope: model.ClusterScope()}}
		},
		"wrong scope": func(context.Context, *Env, *catalog.Check) []model.Result {
			return []model.Result{{Status: model.StatusPass, Scope: model.PoolScope("p"), Evidence: ev("x")}}
		},
		"two scopes": func(context.Context, *Env, *catalog.Check) []model.Result {
			return []model.Result{{Status: model.StatusPass, Scope: model.Scope{Cluster: true, Node: "n"}, Evidence: ev("x")}}
		},
		"skip no why": func(context.Context, *Env, *catalog.Check) []model.Result {
			return []model.Result{{Status: model.StatusSkipped, Scope: model.ClusterScope(), Evidence: ev("x")}}
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			e := env(t, ModeCluster)
			reg := allPass(e)
			reg["K8S-05"] = fn
			rep := run(t, e, reg)
			if len(rep.InternalErrors) != 1 {
				t.Fatalf("internal errors: %v", rep.InternalErrors)
			}
			r := find(rep, "K8S-05", model.ClusterScope())
			if r.Status != model.StatusSkipped || !strings.HasPrefix(reason(r), "Preflight internal error") {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

func TestCheckCanSkipItselfWithReason(t *testing.T) {
	e := env(t, ModeCluster)
	reg := allPass(e)
	why := "not in mirror mode"
	reg["REG-04"] = func(context.Context, *Env, *catalog.Check) []model.Result {
		return []model.Result{{Status: model.StatusSkipped, Scope: model.ClusterScope(), SkippedReason: &why, Evidence: ev(why)}}
	}
	rep := run(t, e, reg)
	if reason(find(rep, "REG-04", model.ClusterScope())) != why || len(rep.InternalErrors) != 0 {
		t.Fatal("self-skip not honoured")
	}
}

func TestRemediationOverride(t *testing.T) {
	e := env(t, ModeCluster)
	reg := allPass(e)
	reg["NET-02"] = func(_ context.Context, _ *Env, d *catalog.Check) []model.Result {
		rs := resultsFor(d, model.StatusFail, nil)
		rs[0].Remediation = "Allow outbound TCP 443 from sgxpool1 to cr.download.fortanix.com."
		return rs
	}
	rep := run(t, e, reg)
	if r := find(rep, "NET-02", model.PoolScope("sgxpool1")); r.Remediation != "Allow outbound TCP 443 from sgxpool1 to cr.download.fortanix.com." {
		t.Errorf("got %q", r.Remediation)
	}
	if r := find(rep, "NET-02", model.PoolScope("systempool")); r.Remediation != e.Catalog.Check("NET-02").Remediation {
		t.Errorf("default remediation not used: %q", r.Remediation)
	}
}

func TestResultsInCatalogOrder(t *testing.T) {
	e := env(t, ModeCluster)
	rep := run(t, e, allPass(e))
	idx := map[string]int{}
	for i, id := range e.Catalog.IDs() {
		idx[id] = i
	}
	for i := 1; i < len(rep.Results); i++ {
		if idx[rep.Results[i-1].ID] > idx[rep.Results[i].ID] {
			t.Fatalf("%s before %s", rep.Results[i-1].ID, rep.Results[i].ID)
		}
	}
}

func TestBadTimeout(t *testing.T) {
	e := env(t, ModeCluster)
	if _, err := Run(context.Background(), e, nil, Options{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestInterruptAbortsRun(t *testing.T) {
	e := env(t, ModeCluster)
	ctx, cancel := context.WithCancel(context.Background())
	reg := allPass(e)
	reg["WS-01"] = func(_ context.Context, _ *Env, d *catalog.Check) []model.Result {
		cancel()
		return resultsFor(d, model.StatusPass, nil)
	}
	if _, err := Run(ctx, e, reg, Options{Timeout: time.Second}); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("got %v", err)
	}
}

func TestCatalogTimeoutOverride(t *testing.T) {
	e := env(t, ModeCluster)
	e.Catalog.Check("K8S-11").TimeoutSeconds = 1
	reg := allPass(e)
	reg["K8S-11"] = func(ctx context.Context, _ *Env, d *catalog.Check) []model.Result {
		select {
		case <-time.After(300 * time.Millisecond):
			return resultsFor(d, model.StatusPass, nil)
		case <-ctx.Done():
			return nil
		}
	}
	rep, err := Run(context.Background(), e, reg, Options{Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if r := find(rep, "K8S-11", model.ClusterScope()); r.Status != model.StatusPass {
		t.Fatalf("K8S-11 should use its own 1s timeout: %+v", r)
	}
}

func TestMemo(t *testing.T) {
	e := &Env{}
	calls := 0
	fail := true
	fn := func() (any, error) {
		calls++
		if fail {
			return nil, errors.New("transient")
		}
		return calls, nil
	}
	if _, err := e.Memo("k", fn); err == nil {
		t.Fatal("error not returned")
	}
	fail = false
	v1, _ := e.Memo("k", fn)
	v2, _ := e.Memo("k", fn)
	if v1 != 2 || v2 != 2 || calls != 2 {
		t.Fatalf("errors must not be cached, results must be: %v %v %d", v1, v2, calls)
	}
	var wg sync.WaitGroup
	var n int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Memo("concurrent", func() (any, error) { atomic.AddInt32(&n, 1); time.Sleep(10 * time.Millisecond); return 1, nil })
		}()
	}
	wg.Wait()
	if n != 1 {
		t.Fatalf("concurrent callers fetched %d times", n)
	}
}
