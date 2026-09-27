package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/redact"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
)

var started = time.Date(2026, 9, 26, 15, 12, 4, 0, time.UTC)

// result builds a result the way the engine would, from the real catalog.
func result(t *testing.T, id string, status model.Status, scope model.Scope, ev ...model.Evidence) model.Result {
	t.Helper()
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	d := cat.Check(id)
	if len(ev) == 0 {
		ev = []model.Evidence{{Stage: "observed", OK: status == model.StatusPass, Detail: id + " observed"}}
	}
	r := model.Result{ID: id, Title: d.Title, Area: d.Area, Severity: d.Severity, Status: status, Scope: scope, Evidence: ev,
		Remediation: d.Remediation, Owner: d.Owner, DocLink: d.DocLink, DependsOn: append([]string{}, d.DependsOn...)}
	if status == model.StatusSkipped {
		r = r.Skipped("workstation mode")
	}
	return r
}

func tcpFail(target string) model.Evidence {
	return model.Evidence{Stage: "tcp", Target: target, OK: false, Detail: "connection timed out after 10s"}
}

func sample(t *testing.T) *Record {
	pool := model.PoolScope("sgxpool1")
	results := []model.Result{
		result(t, "WS-01", model.StatusPass, model.ClusterScope()),
		result(t, "K8S-12", model.StatusInfo, model.ClusterScope()),
		result(t, "NET-01", model.StatusPass, pool),
		result(t, "NET-02", model.StatusFail, pool,
			model.Evidence{Stage: "dns", Target: "cr.download.fortanix.com", OK: true, Detail: "resolved to 20.1.2.3"},
			tcpFail("cr.download.fortanix.com:443"),
			tcpFail("pccs.fortanix.com:443")),
		result(t, "NET-02", model.StatusPass, model.PoolScope("systempool")),
		result(t, "CC-03", model.StatusFail, pool,
			model.Evidence{Stage: "tls", Target: "pccs.fortanix.com:443", OK: false, Detail: "connection reset during handshake"}),
		result(t, "NET-07", model.StatusWarn, pool, model.Evidence{Stage: "clock", Target: "cr.download.fortanix.com", OK: false, Detail: "node clock 8s ahead"}),
		result(t, "NET-03", model.StatusSkipped, model.ClusterScope()),
	}
	rec := NewRecord(Tool{Version: "0.1.0", Commit: "abc", CatalogVersion: "2026.09"},
		Target{ArmorVersion: "1.0.404", KubeContext: "aks-armor-prod", KubernetesVersion: "1.34.8"},
		RunInfo{ID: "20260926-1512-7f3a", Mode: "cluster", StartedAt: started}, results, nil, nil)
	rec.Duration(212 * time.Second)
	rec.Probes = []Probe{{NodePool: "sgxpool1", Pod: "probe-sgxpool1", Image: "example/probe", ImageDigest: "sha256:abc"}}
	return rec
}

func fwInputs(t *testing.T, st *settings.Settings) FirewallInputs {
	cat, _ := catalog.Load()
	if st == nil {
		st = settings.Default()
	}
	return FirewallInputs{Catalog: cat, Settings: st}
}

func TestRecordShapeAndVerdict(t *testing.T) {
	rec := sample(t)
	if rec.Verdict != "NOT_READY" || rec.Counts != (model.Counts{Pass: 3, Fail: 2, Warn: 1, Skipped: 1, Info: 1}) || rec.Run.DurationSeconds != 212 {
		t.Fatalf("got %s %+v %d", rec.Verdict, rec.Counts, rec.Run.DurationSeconds)
	}
	inc := NewRecord(Tool{}, Target{}, RunInfo{}, nil, []string{"PKI-03"}, nil)
	if inc.Verdict != VerdictIncomplete || inc.Results == nil || inc.Probes == nil {
		t.Fatalf("got %+v", inc)
	}
}

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	sch, err := c.Compile("../../schema/result.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

func TestJSONMatchesSchema(t *testing.T) {
	sch := compileSchema(t)
	for name, rec := range map[string]*Record{
		"sample":     sample(t),
		"incomplete": NewRecord(Tool{Version: "0.1.0", CatalogVersion: "x"}, Target{}, RunInfo{ID: "20260926-1512-0000", Mode: "workstation", StartedAt: started}, nil, []string{"PKI-03"}, []string{"boom"}),
	} {
		t.Run(name, func(t *testing.T) {
			b, err := MarshalRecord(rec)
			if err != nil {
				t.Fatal(err)
			}
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			if err := sch.Validate(inst); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSchemaRejectsBrokenResults(t *testing.T) {
	sch := compileSchema(t)
	b, _ := MarshalRecord(sample(t))
	for name, mutate := range map[string]func(map[string]any){
		"empty evidence":         func(m map[string]any) { first(m)["evidence"] = []any{} },
		"skipped without reason": func(m map[string]any) { first(m)["status"] = "skipped" },
		"unknown verdict":        func(m map[string]any) { m["verdict"] = "MAYBE" },
		"two scopes":             func(m map[string]any) { first(m)["scope"] = map[string]any{"cluster": true, "node": "n"} },
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			json.Unmarshal(b, &m)
			mutate(m)
			raw, _ := json.Marshal(m)
			inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if sch.Validate(inst) == nil {
				t.Fatal("schema accepted a broken record")
			}
		})
	}
}

func first(m map[string]any) map[string]any { return m["results"].([]any)[0].(map[string]any) }

func TestReadRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	rec := sample(t)
	if _, err := WriteFiles(dir, rec, fwInputs(t, nil), redact.New()); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRecord(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Run.ID != rec.Run.ID || len(got.Results) != len(rec.Results) || !got.Run.StartedAt.Equal(started) {
		t.Fatalf("got %+v", got.Run)
	}
	os.WriteFile(filepath.Join(dir, ResultFile), []byte(`{"schemaVersion":"2"}`), 0o644)
	if _, err := ReadRecord(dir); err == nil || !strings.Contains(err.Error(), "schema version") {
		t.Fatalf("got %v", err)
	}
	if _, err := ReadRecord(t.TempDir()); err == nil || !strings.Contains(err.Error(), "run `armor-preflight run` first") {
		t.Fatalf("got %v", err)
	}
}

// R1.3: the report opens with no network access and loads nothing.
func TestHTMLIsSelfContained(t *testing.T) {
	b, err := RenderHTML(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	for _, banned := range []string{"<script", "<link", "<img", "<iframe", "<object", "<embed", "<video", "<audio", "<source", "@import", "url(", " src=", "srcset="} {
		if strings.Contains(strings.ToLower(html), banned) {
			t.Errorf("report contains %q", banned)
		}
	}
	// Links are allowed (they load nothing) but only to Fortanix docs.
	for _, m := range regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(html, -1) {
		if !strings.HasPrefix(m[1], "https://support.fortanix.com/") && !strings.HasPrefix(m[1], "#") {
			t.Errorf("unexpected link %s", m[1])
		}
	}
	if !strings.HasPrefix(html, "<!doctype html>") || !strings.Contains(html, `<meta charset="utf-8">`) {
		t.Error("missing doctype or charset")
	}
}

// R1.3: findings are grouped by team, and each team's section prints on
// its own page.
func TestHTMLGroupsByTeam(t *testing.T) {
	rec := sample(t)
	b, _ := RenderHTML(rec)
	html := string(b)
	if !regexp.MustCompile(`@media print \{[^}]*\}?[\s\S]*\.team \{ break-before: page; \}`).MatchString(html) {
		t.Error("team sections do not start a new printed page")
	}
	teams := ByTeam(rec.Results)
	if got := strings.Count(html, `<section class="team"`); got != len(teams) {
		t.Fatalf("%d team sections, want %d", got, len(teams))
	}
	// Network owns NET-02 and CC-03; both appear inside its section.
	start := strings.Index(html, `id="team-network"`)
	end := strings.Index(html[start+1:], `<section class="team"`)
	if end < 0 {
		end = strings.Index(html[start:], `<section class="appendix"`)
	}
	section := html[start : start+1+end]
	for _, want := range []string{"NET-02", "CC-03", "cr.download.fortanix.com:443", "Allow outbound TCP 443"} {
		if !strings.Contains(section, want) {
			t.Errorf("Network section missing %q", want)
		}
	}
	if strings.Contains(section, "NET-07") {
		t.Error("NET-07 belongs to Platform, not Network")
	}
	// The verdict and severity counts come first.
	if v := strings.Index(html, "NOT READY"); v < 0 || v > strings.Index(html, "Results by severity") || strings.Index(html, "Results by severity") > start {
		t.Error("report must open with the verdict and counts by severity")
	}
	if !strings.Contains(html, "sha256:abc") {
		t.Error("probe digest missing")
	}
}

func TestHTMLEscapesEvidence(t *testing.T) {
	rec := sample(t)
	rec.Results[3].Evidence[0].Detail = `<script>alert(1)</script>`
	b, _ := RenderHTML(rec)
	if strings.Contains(string(b), "<script>alert") || !strings.Contains(string(b), "&lt;script&gt;") {
		t.Fatal("evidence not escaped")
	}
}

func TestFirewallRows(t *testing.T) {
	rec := sample(t)
	st, _ := settings.Parse([]byte("armorVersion: 1.0.404\nnodePools: {sgxpool1: {subnet: 10.20.0.0/22}}\n"))
	rows := FirewallRows(rec.Results, fwInputs(t, st))
	b, err := RenderFirewallCSV(rows)
	if err != nil {
		t.Fatal(err)
	}
	want := "source_subnet,destination,port,protocol,direction,purpose,check_id\n" +
		"10.20.0.0/22,cr.download.fortanix.com,443,TCP,outbound,Armor images and Helm charts,NET-02\n" +
		"10.20.0.0/22,pccs.fortanix.com,443,TCP,outbound,SGX DCAP collateral (Fortanix PCCS),CC-03\n"
	if string(b) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", b, want)
	}
}

func TestFirewallSourceFallbacks(t *testing.T) {
	rec := sample(t)
	in := fwInputs(t, nil)
	in.Topology = engine.Topology{Pools: map[string][]string{"sgxpool1": {"b", "a"}}, NodeIPs: map[string]string{"a": "10.0.0.5", "b": "10.0.0.4"}}
	if rows := FirewallRows(rec.Results, in); rows[0].SourceSubnet != "10.0.0.4/32 10.0.0.5/32" {
		t.Fatalf("got %q", rows[0].SourceSubnet)
	}
	if rows := FirewallRows(rec.Results, fwInputs(t, nil)); !strings.HasPrefix(rows[0].SourceSubnet, "UNKNOWN (node pool sgxpool1") {
		t.Fatalf("got %q", rows[0].SourceSubnet)
	}
}

func TestFirewallIgnoresNonEgressFailures(t *testing.T) {
	pool := model.PoolScope("p")
	results := []model.Result{
		result(t, "NET-01", model.StatusFail, pool, model.Evidence{Stage: "dns", Target: "x.example.com", OK: false, Detail: "NXDOMAIN"}),
		result(t, "NET-07", model.StatusWarn, pool, model.Evidence{Stage: "clock", Target: "x.example.com:443", OK: false, Detail: "skew"}),
		result(t, "NET-02", model.StatusPass, pool, model.Evidence{Stage: "tcp", Target: "x.example.com:443", OK: true, Detail: "ok"}),
		result(t, "K8S-02", model.StatusFail, model.ClusterScope(), tcpFail("x.example.com:443")),
	}
	if rows := FirewallRows(results, fwInputs(t, nil)); len(rows) != 0 {
		t.Fatalf("got %+v", rows)
	}
	b, _ := RenderFirewallCSV(nil)
	if string(b) != strings.Join(FirewallHeader, ",")+"\n" {
		t.Fatalf("empty CSV should still have the header, got %q", b)
	}
}

func TestTerminal(t *testing.T) {
	var buf bytes.Buffer
	WriteTerminal(&buf, sample(t), []string{"preflight-out/report.html"})
	out := buf.String()
	for _, want := range []string{
		"NOT READY   2 blockers failed, 1 warning",
		"To fix, by team",
		"  Network\n",
		"FAIL NET-02  node pool sgxpool1",
		"tcp cr.download.fortanix.com:443: connection timed out after 10s",
		"fix: Allow outbound TCP 443",
		"Not checked\n  workstation mode: NET-03",
		"Wrote preflight-out/report.html",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if !regexp.MustCompile(`(?m)^  network\s+2\s+1\s+1\s+1\s+0$`).MatchString(out) {
		t.Errorf("network counts row wrong:\n%s", out)
	}
	// Teams with blockers come before teams with only warnings.
	if strings.Index(out, "  Network\n") > strings.Index(out, "  Platform\n") {
		t.Error("team order")
	}
}

func TestBundle(t *testing.T) {
	rec := sample(t)
	entries, err := BuildBundle(rec, redact.New(), started)
	if err != nil {
		t.Fatal(err)
	}
	var list bytes.Buffer
	ListBundle(&list, rec, entries)
	for _, want := range []string{"run 20260926-1512-7f3a", "Armor 1.0.404", "result.json", "versions.json", "MANIFEST.txt", "No logs, secrets or workload data"} {
		if !strings.Contains(list.String(), want) {
			t.Errorf("listing missing %q", want)
		}
	}
	path := filepath.Join(t.TempDir(), BundleFile)
	if err := WriteBundle(path, rec, entries, started); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(path)
	defer f.Close()
	files, err := ReadBundle(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("bundle has %d files", len(files))
	}
	// R1.6: Support can see the Preflight version, Armor version, context and run time.
	var v Versions
	if err := json.Unmarshal(files["versions.json"], &v); err != nil {
		t.Fatal(err)
	}
	if v.Tool.Version != "0.1.0" || v.Target.ArmorVersion != "1.0.404" || v.Target.KubeContext != "aks-armor-prod" || !v.Run.StartedAt.Equal(started) || v.Run.DurationSeconds != 212 {
		t.Fatalf("versions.json: %+v", v)
	}
	for _, e := range entries[:2] {
		if !strings.Contains(string(files["MANIFEST.txt"]), e.SHA256+"  ") {
			t.Errorf("manifest missing hash for %s", e.Name)
		}
	}
}

func TestBundleRefusesUnregisteredCredentials(t *testing.T) {
	rec := sample(t)
	rec.Results[0].Evidence[0].Detail = "-----BEGIN RSA PRIVATE KEY-----"
	if _, err := BuildBundle(rec, redact.New(), started); !errors.Is(err, redact.ErrUnredacted) {
		t.Fatalf("got %v", err)
	}
}

func TestWriteFilesRedacts(t *testing.T) {
	const secret = "canary-Pa55w0rd-9f2c"
	rec := sample(t)
	rec.Results[3].Evidence[1].Detail = "login as user:" + secret + " refused"
	rec.Results[3].Remediation = "rotate " + secret
	dir := t.TempDir()
	files, err := WriteFiles(dir, rec, fwInputs(t, nil), redact.New(secret))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("wrote %v", files)
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("%s leaks the secret", f)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, ResultFile))
	if !bytes.Contains(b, []byte(redact.Mask)) {
		t.Error("expected the mask in result.json")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 3 {
		t.Errorf("stray files: %v", entries)
	}
}

// Pen test: a destination or purpose that looks like a formula is
// neutralised in the CSV (CWE-1236).
func TestCSVFormulaInjection(t *testing.T) {
	b, err := RenderFirewallCSV([]FirewallRow{{SourceSubnet: "=HYPERLINK(\"http://evil\")", Destination: "@SUM(1+1)", Port: 443, Purpose: "+cmd|' /C calc'!A0", CheckID: "-NET-02"}})
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Split(string(b), "\n")[1]
	for _, bad := range []string{",=", ",@", ",+", ",-"} {
		if strings.Contains(","+line, bad) {
			t.Fatalf("formula not neutralised: %s", line)
		}
	}
	if !strings.HasPrefix(line, "\"'=HYPERLINK") {
		t.Fatalf("got %s", line)
	}
}

// Pen test: ANSI escape sequences in evidence cannot reach the terminal.
func TestTerminalStripsControlCharacters(t *testing.T) {
	rec := sample(t)
	rec.Results[3].Evidence[1].Detail = "timed out\x1b[2J\x1b[1;1HREADY — all checks passed\x07"
	var buf bytes.Buffer
	WriteTerminal(&buf, rec, nil)
	if strings.ContainsAny(buf.String(), "\x1b\x07") {
		t.Fatalf("control characters reached the terminal: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "timed out?[2J") {
		t.Fatalf("got %q", buf.String())
	}
}

func TestHTMLHasRestrictiveCSP(t *testing.T) {
	b, _ := RenderHTML(sample(t))
	if !strings.Contains(string(b), `content="default-src 'none'; style-src 'unsafe-inline'`) {
		t.Fatal("missing Content-Security-Policy")
	}
}

func TestOutputPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	files, err := WriteFiles(dir, sample(t), fwInputs(t, nil), redact.New())
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o750 {
		t.Errorf("dir mode %v", fi.Mode().Perm())
	}
	for _, f := range files {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o640 {
			t.Errorf("%s mode %v", f, fi.Mode().Perm())
		}
	}
}

func TestStripControl(t *testing.T) {
	// U+009B is the C1 control sequence introducer; a lone 0x9b byte is not
	// valid UTF-8 and comes out as the harmless U+FFFD.
	if got := StripControl("a\x1b[31mb\tc\nd\u009be\x9bf"); got != "a?[31mb\tc\nd?e\ufffdf" {
		t.Fatalf("%q", got)
	}
}
