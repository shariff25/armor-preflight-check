package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
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
				scope := model.ClusterScope()
				switch def.Scope {
				case catalog.ScopeNodePool:
					scope = model.PoolScope("sgxpool1")
				case catalog.ScopeNode:
					scope = model.NodeScope("sgx-0")
				}
				return []model.Result{{Status: st, Scope: scope, Evidence: []model.Evidence{{Stage: "observed", OK: st == model.StatusPass, Detail: "fake"}}}}
			}
		}
		return reg
	}
}

func withFakes(t *testing.T, statuses map[string]model.Status) {
	t.Helper()
	oldReg, oldEnv := registry, lookupEnv
	registry = fakeRegistry(statuses)
	lookupEnv = func(k string) (string, bool) { return map[string]string{"REG_PW": "pw", "BAK_KEY": "k"}[k], true }
	t.Cleanup(func() { registry, lookupEnv = oldReg, oldEnv })
}

func TestRunExitCodes(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		statuses map[string]model.Status
		want     int
		verdict  string
	}{
		{"ready", "cluster", nil, exitcode.Ready, "Result: READY "},
		{"warnings", "cluster", map[string]model.Status{"NET-07": model.StatusFail}, exitcode.ReadyWithWarnings, "Result: READY WITH WARNINGS"},
		{"not ready", "cluster", map[string]model.Status{"K8S-05": model.StatusFail}, exitcode.NotReady, "Result: NOT READY"},
		{"workstation ready", "workstation", nil, exitcode.Ready, "Result: READY "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withFakes(t, c.statuses)
			out, err := execute("run", c.mode, "-f", writeSettings(t, settingsYAML))
			if got := exitcode.FromError(err); got != c.want {
				t.Fatalf("exit %d, want %d (%v)\n%s", got, c.want, err, out)
			}
			if !strings.Contains(out, c.verdict) {
				t.Fatalf("missing %q in:\n%s", c.verdict, out)
			}
		})
	}
}

func TestWorkstationRunListsSkippedProbeChecks(t *testing.T) {
	withFakes(t, nil)
	out, _ := execute("run", "workstation", "-f", writeSettings(t, settingsYAML))
	if !strings.Contains(out, "SKIPPED NET-02") || !strings.Contains(out, "workstation mode") {
		t.Fatalf("got:\n%s", out)
	}
}

func TestUncoveredArmorVersionIsRefused(t *testing.T) {
	withFakes(t, nil)
	p := writeSettings(t, strings.Replace(settingsYAML, "1.0.404", "1.0.999", 1))
	_, err := execute("run", "workstation", "-f", p)
	if exitcode.FromError(err) != exitcode.ToolError || !strings.Contains(err.Error(), "Armor 1.0.999 is not covered") {
		t.Fatalf("got %v", err)
	}
}

func TestInvalidSettingsIsToolError(t *testing.T) {
	withFakes(t, nil)
	for name, body := range map[string]string{
		"inline secret": settingsYAML + "  password: hunter2\n",
		"missing file":  "",
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "absent.yaml")
			if body != "" {
				p = writeSettings(t, body)
			}
			if _, err := execute("run", "cluster", "-f", p); exitcode.FromError(err) != exitcode.ToolError {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestUnimplementedChecksMakeRunExit3(t *testing.T) {
	// The real registry: checks land in M3 to M6.
	out, err := execute("run", "workstation")
	if exitcode.FromError(err) != exitcode.ToolError || !strings.Contains(err.Error(), "does not implement") {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "does not implement 35 of 35 checks") {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(out, "Result: INCOMPLETE") {
		t.Fatalf("an incomplete run must not print a verdict:\n%s", out)
	}
}
