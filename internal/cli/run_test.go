package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/kube"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/output"
)

const settingsYAML = `armorVersion: "1.0.404"
domains: {armor: armor.example.com}
certificates: {caReady: true}
registry: {username: u, passwordEnv: REG_PW}
storage: {accountFqdn: s.blob.core.windows.net, container: medusa, credentialsEnv: BAK_KEY,
  accountKind: StorageV2, performance: Standard, replication: LRS}
syslog: {host: syslog.example.com}
`

func writeSettings(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "settings.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func scopeFor(def *catalog.Check) model.Scope {
	switch def.Scope {
	case catalog.ScopeNodePool:
		return model.PoolScope("sgxpool1")
	case catalog.ScopeNode:
		return model.NodeScope("sgx-0")
	}
	return model.ClusterScope()
}

// fakeRegistry passes every check except those in statuses.
func fakeRegistry(statuses map[string]model.Status) func() engine.Registry {
	return func() engine.Registry {
		cat, _ := catalog.Load()
		reg := engine.Registry{}
		for i := range cat.Checks {
			def := cat.Checks[i]
			st := model.StatusPass
			if s, ok := statuses[def.ID]; ok {
				st = s
			}
			reg[def.ID] = func(context.Context, *engine.Env, *catalog.Check) []model.Result {
				return []model.Result{{Status: st, Scope: scopeFor(&def), Evidence: []model.Evidence{{Stage: "observed", OK: st == model.StatusPass, Detail: "fake"}}}}
			}
		}
		return reg
	}
}

var testEnv = map[string]string{"REG_PW": "test-registry-password", "BAK_KEY": "test-storage-key"}

func withFakes(t *testing.T, reg func() engine.Registry) {
	t.Helper()
	oldReg, oldEnv, oldKube := registry, lookupEnv, loadKube
	registry = reg
	lookupEnv = func(k string) (string, bool) { v, ok := testEnv[k]; return v, ok }
	loadKube = noCluster
	t.Cleanup(func() { registry, lookupEnv, loadKube = oldReg, oldEnv, oldKube })
}

// noCluster keeps CLI tests hermetic: they never use a real kubeconfig.
func noCluster(kube.Options) (*kube.Clients, error) {
	return nil, errors.New("no cluster in tests")
}

func TestRunExitCodes(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		statuses map[string]model.Status
		want     int
		verdict  string
	}{
		{"ready", "cluster", nil, exitcode.Ready, "READY"},
		{"warnings", "cluster", map[string]model.Status{"NET-07": model.StatusFail}, exitcode.ReadyWithWarnings, "READY_WITH_WARNINGS"},
		{"not ready", "cluster", map[string]model.Status{"K8S-05": model.StatusFail}, exitcode.NotReady, "NOT_READY"},
		{"workstation ready", "workstation", nil, exitcode.Ready, "READY"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withFakes(t, fakeRegistry(c.statuses))
			dir := t.TempDir()
			out, err := execute("run", c.mode, "-f", writeSettings(t, settingsYAML), "-o", dir)
			if got := exitcode.FromError(err); got != c.want {
				t.Fatalf("exit %d, want %d (%v)\n%s", got, c.want, err, out)
			}
			rec, err := output.ReadRecord(dir)
			if err != nil {
				t.Fatal(err)
			}
			if rec.Verdict != c.verdict || rec.Run.Mode != c.mode || rec.Target.ArmorVersion != "1.0.404" {
				t.Fatalf("record: %s %s %s", rec.Verdict, rec.Run.Mode, rec.Target.ArmorVersion)
			}
			display := model.Verdict(c.verdict).Display()
			if !regexp.MustCompile(`(?m)^  ` + display + `   `).MatchString(out) {
				t.Fatalf("terminal missing verdict %q:\n%s", display, out)
			}
		})
	}
}

// R1.3: every run writes a terminal summary, the HTML report, the JSON
// result and the firewall-request CSV.
func TestRunWritesAllOutputs(t *testing.T) {
	withFakes(t, fakeRegistry(map[string]model.Status{"NET-02": model.StatusFail}))
	dir := filepath.Join(t.TempDir(), "nested", "out")
	out, _ := execute("run", "cluster", "-f", writeSettings(t, settingsYAML), "-o", dir, "-c", "aks-armor-prod")
	for _, f := range []string{output.ResultFile, output.ReportFile, output.FirewallFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s not written: %v", f, err)
		}
	}
	for _, want := range []string{"To fix, by team", "Network", "NET-02", "Wrote " + filepath.Join(dir, output.ResultFile)} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal missing %q", want)
		}
	}
	rec, _ := output.ReadRecord(dir)
	if rec.Target.KubeContext != "aks-armor-prod" {
		t.Errorf("context %q", rec.Target.KubeContext)
	}
}

func TestWorkstationRunListsSkippedProbeChecks(t *testing.T) {
	withFakes(t, fakeRegistry(nil))
	out, _ := execute("run", "workstation", "-f", writeSettings(t, settingsYAML), "-o", t.TempDir())
	if !regexp.MustCompile(`workstation mode: CC-03, CC-04, CC-05, NET-01, NET-02, NET-03, NET-06, NET-07, REG-03, BAK-02, K8S-10, K8S-11|workstation mode: K8S-10`).MatchString(out) {
		t.Fatalf("got:\n%s", out)
	}
}

func TestUncoveredArmorVersionIsRefused(t *testing.T) {
	withFakes(t, fakeRegistry(nil))
	dir := t.TempDir()
	p := writeSettings(t, strings.Replace(settingsYAML, "1.0.404", "1.0.999", 1))
	_, err := execute("run", "workstation", "-f", p, "-o", dir)
	if exitcode.FromError(err) != exitcode.ToolError || !strings.Contains(err.Error(), "Armor 1.0.999 is not covered") {
		t.Fatalf("got %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("a refused run must not write outputs")
	}
}

func TestInvalidSettingsIsToolError(t *testing.T) {
	withFakes(t, fakeRegistry(nil))
	for name, body := range map[string]string{
		"inline secret": settingsYAML + "  password: hunter2\n",
		"missing file":  "",
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "absent.yaml")
			if body != "" {
				p = writeSettings(t, body)
			}
			if _, err := execute("run", "cluster", "-f", p, "-o", t.TempDir()); exitcode.FromError(err) != exitcode.ToolError {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// With every check implemented, a run with the real registry reaches a
// verdict. Without a cluster, WS-01 fails and the run is NOT READY (exit 2),
// not INCOMPLETE.
func TestRealRegistryReachesAVerdict(t *testing.T) {
	oldKube := loadKube
	loadKube = noCluster
	t.Cleanup(func() { loadKube = oldKube })
	dir := t.TempDir()
	out, err := execute("run", "workstation", "-o", dir)
	if exitcode.FromError(err) != exitcode.NotReady {
		t.Fatalf("exit %d: %v\n%s", exitcode.FromError(err), err, out)
	}
	rec, err := output.ReadRecord(dir)
	if err != nil || rec.Verdict != "NOT_READY" || len(rec.Unimplemented) != 0 {
		t.Fatalf("%+v %v", rec, err)
	}
	if !strings.Contains(out, "FAIL WS-01") || !strings.Contains(out, "no cluster in tests") {
		t.Fatalf("WS-01 should explain the missing cluster:\n%s", out)
	}
}
