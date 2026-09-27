package catalog

import (
	"strings"
	"testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
)

func mustLoad(t *testing.T) *Catalog {
	t.Helper()
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The Phase 1 catalog from the build brief, with each check's dependencies.
var brief = map[string][]string{
	"WS-01":  nil,
	"K8S-01": {"WS-01"}, "K8S-02": {"WS-01"}, "K8S-03": {"WS-01"}, "K8S-04": {"WS-01"},
	"K8S-05": {"WS-01"}, "K8S-06": {"WS-01"}, "K8S-07": {"WS-01"}, "K8S-08": {"WS-01"},
	"K8S-09": {"WS-01"}, "K8S-10": {"WS-01"}, "K8S-11": {"WS-01"}, "K8S-12": {"WS-01"},
	"CC-01": {"K8S-03"}, "CC-02": {"K8S-03"}, "CC-03": {"NET-01"}, "CC-04": {"NET-01"},
	"CC-05":  {"CC-01", "CC-02", "CC-03", "CC-04", "REG-03"},
	"NET-01": nil, "NET-02": {"NET-01"}, "NET-03": {"NET-02"}, "NET-04": {"WS-01"},
	"NET-05": {"WS-01"}, "NET-06": {"NET-01"}, "NET-07": nil,
	"REG-01": {"WS-01"}, "REG-02": {"REG-01"}, "REG-03": {"REG-01", "NET-02"},
	"REG-04": {"REG-01"}, "REG-05": {"REG-01"},
	"BAK-01": nil, "BAK-02": {"NET-02"},
	"PKI-01": nil, "PKI-02": nil, "PKI-03": nil,
}

func TestCatalogMatchesBrief(t *testing.T) {
	c := mustLoad(t)
	if len(c.Checks) != 35 || len(brief) != 35 {
		t.Fatalf("catalog has %d checks, brief %d; want 35", len(c.Checks), len(brief))
	}
	for id, deps := range brief {
		ch := c.Check(id)
		if ch == nil {
			t.Errorf("%s missing from catalog", id)
			continue
		}
		if strings.Join(ch.DependsOn, ",") != strings.Join(deps, ",") {
			t.Errorf("%s dependsOn %v, brief says %v", id, ch.DependsOn, deps)
		}
	}
}

func TestSeveritiesFromBrief(t *testing.T) {
	c := mustLoad(t)
	warnings := map[string]bool{"K8S-04": true, "K8S-11": true, "NET-04": true, "NET-05": true, "NET-06": true, "NET-07": true, "REG-05": true}
	for _, ch := range c.Checks {
		want := model.SeverityBlocker
		if warnings[ch.ID] {
			want = model.SeverityWarning
		}
		if ch.ID == "K8S-12" {
			want = model.SeverityInfo
		}
		if ch.Severity != want {
			t.Errorf("%s severity %s, want %s", ch.ID, ch.Severity, want)
		}
	}
	for _, id := range []string{"BAK-01", "BAK-02"} {
		ch := c.Check(id)
		if ch.SeverityFor("production") != model.SeverityBlocker || ch.SeverityFor("poc") != model.SeverityWarning {
			t.Errorf("%s environment severities wrong", id)
		}
	}
}

func TestProbeChecks(t *testing.T) {
	c := mustLoad(t)
	probe := map[string]bool{"CC-03": true, "CC-04": true, "CC-05": true, "NET-01": true, "NET-02": true, "NET-03": true,
		"NET-06": true, "NET-07": true, "REG-03": true, "BAK-02": true}
	for _, ch := range c.Checks {
		if (ch.RunsIn == RunsInProbe) != probe[ch.ID] {
			t.Errorf("%s runsIn %s", ch.ID, ch.RunsIn)
		}
	}
	for _, id := range []string{"K8S-10", "K8S-11"} {
		if c.Check(id).RunsIn != RunsInClusterWrite {
			t.Errorf("%s should be cluster-write (D-4)", id)
		}
	}
}

func TestLevelsRespectDependencies(t *testing.T) {
	c := mustLoad(t)
	levels, err := c.Levels()
	if err != nil {
		t.Fatal(err)
	}
	pos := map[string]int{}
	n := 0
	for i, l := range levels {
		for _, ch := range l {
			pos[ch.ID] = i
			n++
		}
	}
	if n != 35 {
		t.Fatalf("levels hold %d checks", n)
	}
	for _, ch := range c.Checks {
		for _, dep := range ch.DependsOn {
			if pos[dep] >= pos[ch.ID] {
				t.Errorf("%s (level %d) not after %s (level %d)", ch.ID, pos[ch.ID], dep, pos[dep])
			}
		}
	}
}

func TestCoverage(t *testing.T) {
	c := mustLoad(t)
	if !c.Covers("1.0.404") || c.Covers("1.0.500") {
		t.Fatal("Covers wrong")
	}
	err := c.CoverageError("1.0.500", "0.1.0")
	if !strings.Contains(err.Error(), "Armor 1.0.500 is not covered") || !strings.Contains(err.Error(), "support portal") {
		t.Fatal(err)
	}
	c.PreflightForArmor = []VersionMapping{{ArmorVersions: []string{"1.0.500"}, Preflight: "0.2.0"}}
	if err := c.CoverageError("1.0.500", "0.1.0"); !strings.Contains(err.Error(), "use Preflight 0.2.0") {
		t.Fatal(err)
	}
}

const minimal = `catalogVersion: "x"
armorVersions: ["1.0.0"]
checks:
  - {id: A-01, title: t, area: network, severity: blocker, owner: o, runsIn: workstation, scope: cluster, docLink: "https://d", remediation: r}
`

func TestParseRejects(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"no version":     {"armorVersions: [\"1\"]\n", "catalogVersion is empty"},
		"no armor":       {"catalogVersion: \"x\"\n", "armorVersions is empty"},
		"unknown field":  {minimal + "bogus: 1\n", "bogus"},
		"malformed yaml": {"catalogVersion: [\n", "parse catalog"},
		"duplicate":      {minimal + "  - {id: A-01, title: t, area: network, severity: blocker, owner: o, runsIn: workstation, scope: cluster, docLink: \"https://d\", remediation: r}\n", "duplicate check id A-01"},
		"unknown dep":    {minimal + "  - {id: A-02, title: t, area: network, severity: blocker, owner: o, runsIn: workstation, scope: cluster, docLink: \"https://d\", remediation: r, dependsOn: [Z-99]}\n", "unknown check Z-99"},
		"cycle": {minimal + "  - {id: A-02, title: t, area: network, severity: blocker, owner: o, runsIn: workstation, scope: cluster, docLink: \"https://d\", remediation: r, dependsOn: [A-03]}\n" +
			"  - {id: A-03, title: t, area: network, severity: blocker, owner: o, runsIn: workstation, scope: cluster, docLink: \"https://d\", remediation: r, dependsOn: [A-02]}\n", "dependency cycle"},
		"empty owner":   {strings.Replace(minimal, "owner: o", "owner: \"\"", 1), "owner is empty"},
		"bad area":      {strings.Replace(minimal, "area: network", "area: nope", 1), "unknown area"},
		"bad severity":  {strings.Replace(minimal, "severity: blocker", "severity: meh", 1), "unknown severity"},
		"bad runsIn":    {strings.Replace(minimal, "runsIn: workstation", "runsIn: moon", 1), "unknown runsIn"},
		"bad scope":     {strings.Replace(minimal, "scope: cluster", "scope: rack", 1), "unknown scope"},
		"http docLink":  {strings.Replace(minimal, "https://d", "http://d", 1), "not https"},
		"bad id":        {strings.Replace(minimal, "A-01", "a1", 1), "not AREA-NN"},
		"unknown needs": {strings.Replace(minimal, "remediation: r}", "remediation: r, needs: [nope.path]}", 1), "unknown settings path"},
	}
	for name, cs := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(cs.in))
			if err == nil || !strings.Contains(err.Error(), cs.want) {
				t.Fatalf("got %v, want %q", err, cs.want)
			}
		})
	}
	if _, err := Parse([]byte(minimal)); err != nil {
		t.Fatalf("minimal catalog rejected: %v", err)
	}
}

func TestEndpointsFromBrief(t *testing.T) {
	c := mustLoad(t)
	want := map[string]bool{"cr.download.fortanix.com": true, "pccs.fortanix.com": true, "global.acccache.azure.net": true, "api.trustedservices.intel.com": true}
	settingBacked := map[string]bool{"attestation.azureAttestationHost": true, "storage.accountFqdn": true, "syslog.host": true}
	for _, ep := range c.Endpoints {
		if ep.FQDN != "" {
			delete(want, ep.FQDN)
		} else {
			delete(settingBacked, ep.FromSetting)
		}
	}
	if len(want)+len(settingBacked) != 0 {
		t.Fatalf("missing endpoints: %v %v", want, settingBacked)
	}
}
