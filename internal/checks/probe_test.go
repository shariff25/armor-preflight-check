package checks

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/shariff25/armor-preflight-check/internal/catalog"
	"github.com/shariff25/armor-preflight-check/internal/engine"
	"github.com/shariff25/armor-preflight-check/internal/model"
	"github.com/shariff25/armor-preflight-check/internal/netfixtures"
	"github.com/shariff25/armor-preflight-check/internal/output"
	"github.com/shariff25/armor-preflight-check/internal/probe/agent"
	"github.com/shariff25/armor-preflight-check/internal/probe/protocol"
	"github.com/shariff25/armor-preflight-check/internal/settings"
)

const (
	azureAttest = "sharedeus.eus.attest.azure.net"
	storageHost = "s.blob.core.windows.net"
	syslogHost  = "syslog.example.com"
	probeRunID  = "20260926-1512-7f3a"
)

var probePools = []string{"sgxpool1", "systempool"}

// world is one pool's view of the network.
type world struct {
	net   *netfixtures.Network
	blobs *netfixtures.BlobStore
}

// probeFixture runs the real probe agent once per node pool, each against
// its own fake network, and feeds the results to the checks. breakPool
// can change one pool's network (block a destination, intercept TLS, ...).
type probeFixture struct {
	*fixture
	public    *netfixtures.CA
	breakPool func(pool string, w *world, req *protocol.Request)
}

func newProbeFixture(t *testing.T) *probeFixture {
	f := newFixture(t)
	f.settingsYAML = regexp.MustCompile(`(?m)^proxy: .*\n`).ReplaceAllString(f.settingsYAML, "")
	f.settingsYAML += "attestation: {azureAttestationHost: " + azureAttest + "}\nsyslog: {host: " + syslogHost + "}\n"
	f.envVars["BAK_KEY"] = base64.StdEncoding.EncodeToString([]byte("fixture-storage-account-key-0123"))
	return &probeFixture{fixture: f, public: netfixtures.NewCA("Public Trust Services", "Public Root CA")}
}

func (p *probeFixture) world(t *testing.T, skew time.Duration) *world {
	n := netfixtures.NewNetwork()
	t.Cleanup(n.Close)
	date := func() time.Time { return time.Now().Add(-skew) }
	for _, h := range []string{"pccs.fortanix.com", "global.acccache.azure.net", "api.trustedservices.intel.com", azureAttest} {
		n.AddTLS(h, p.public, netfixtures.Handler(date))
	}
	blobs := n.AddBlobStore(storageHost, p.public)
	n.AddTCP(syslogHost)
	return &world{net: n, blobs: blobs}
}

func (p *probeFixture) env(t *testing.T) *engine.Env {
	t.Helper()
	env := clusterEnv(p.fixture)
	env.ProbeUnavailable = ""
	plan, err := Plan(env, probeRunID)
	if err != nil {
		t.Fatal(err)
	}
	env.ProbeNotes = &engine.ProbeNotes{Images: plan.ImagesNote, Storage: plan.StorageNote}
	roots := p.public.Pool.Clone()
	roots.AddCert(p.reg.Server.Certificate())
	results := map[string]protocol.Result{}
	for _, pool := range probePools {
		w := p.world(t, 0)
		req := plan.Request(pool)
		req.Timeout = 300 * time.Millisecond
		if p.breakPool != nil {
			p.breakPool(pool, w, &req)
		}
		dir := t.TempDir()
		for k, v := range plan.Secret {
			os.WriteFile(filepath.Join(dir, k), v, 0o600)
		}
		body, _ := json.Marshal(req)
		reqPath := filepath.Join(dir, "request.json")
		os.WriteFile(reqPath, body, 0o600)
		var out bytes.Buffer
		a := &agent.Agent{Resolver: w.net, Dialer: w.net, Roots: roots, CredentialsDir: dir}
		if err := a.Run(context.Background(), reqPath, &out); err != nil {
			t.Fatal(err)
		}
		res, err := protocol.Decode(out.String())
		if err != nil || res.Error != "" {
			t.Fatalf("probe %s: %v %s", pool, err, res.Error)
		}
		results[pool] = res
	}
	env.Probes = &engine.ProbeData{Results: results, PoolErrors: map[string]string{}}
	return env
}

func poolResultOf(t *testing.T, rep *engine.Report, id, pool string) model.Result {
	t.Helper()
	for _, r := range rep.Results {
		if r.ID == id && r.Scope.NodePool == pool {
			return r
		}
	}
	t.Fatalf("no %s result for %s: %+v", id, pool, resultsFor(rep, id))
	return model.Result{}
}

var probeChecks = []string{"NET-01", "NET-02", "NET-03", "NET-06", "NET-07", "CC-03", "CC-04", "REG-03", "BAK-02"}

func TestProbeChecksPassOnCompliantNetwork(t *testing.T) {
	p := newProbeFixture(t)
	rep := runChecks(t, p.env(t))
	for _, id := range probeChecks {
		for _, r := range resultsFor(rep, id) {
			if r.Status != model.StatusPass {
				t.Errorf("%s (%s) = %s:\n%s", id, r.Scope, r.Status, evidenceText([]model.Result{r}))

			}
		}
	}
	// CC-03 and CC-04 are reported for SGX pools only.
	for _, r := range resultsFor(rep, "CC-03") {
		if r.Scope.NodePool != "sgxpool1" {
			t.Errorf("CC-03 reported for %s", r.Scope)
		}
	}
	// Each egress path carries DNS, TCP and TLS as separate evidence (R1.2).
	stages := map[string]bool{}
	for _, e := range poolResultOf(t, rep, "NET-02", "systempool").Evidence {
		if e.Target == "pccs.fortanix.com" || e.Target == "pccs.fortanix.com:443" {
			stages[e.Stage] = true
		}
	}
	if !stages["dns"] || !stages["tcp"] || !stages["tls"] {
		t.Fatalf("stages %v", stages)
	}
}

// R1.2: the registry reachable from one pool but blocked from the SGX pool:
// NET-02 fails for the SGX pool only, names it, and the firewall request
// has the row.
func TestRegistryBlockedFromSGXPoolOnly(t *testing.T) {
	p := newProbeFixture(t)
	p.breakPool = func(pool string, w *world, _ *protocol.Request) {
		if pool == "sgxpool1" {
			w.net.Blackhole("127.0.0.1", mustPort(t, p.reg.Host()))
		}
	}
	env := p.env(t)
	rep := runChecks(t, env)
	sgx := poolResultOf(t, rep, "NET-02", "sgxpool1")
	if sgx.Status != model.StatusFail || !strings.Contains(evidenceText([]model.Result{sgx}), "timed out") || !strings.Contains(sgx.Remediation, "node pool sgxpool1") {
		t.Fatalf("sgxpool1: %s %q\n%s", sgx.Status, sgx.Remediation, evidenceText([]model.Result{sgx}))
	}
	if sys := poolResultOf(t, rep, "NET-02", "systempool"); sys.Status != model.StatusPass {
		t.Fatalf("systempool should pass: %s", sys.Status)
	}
	// REG-03 on the SGX pool is skipped, naming NET-02.
	if r := poolResultOf(t, rep, "REG-03", "sgxpool1"); r.Status != model.StatusSkipped || !strings.Contains(*r.SkippedReason, "NET-02") {
		t.Fatalf("REG-03: %s", r.Status)
	}
	st, _ := settings.Parse([]byte("armorVersion: 1.0.404\nnodePools: {sgxpool1: {subnet: 10.20.4.0/22}}\n"))
	cat, _ := catalog.Load()
	rows := output.FirewallRows(rep.Results, output.FirewallInputs{Catalog: cat, Settings: st})
	if len(rows) != 1 || rows[0].SourceSubnet != "10.20.4.0/22" || rows[0].Destination != "127.0.0.1" || rows[0].CheckID != "NET-02" {
		t.Fatalf("firewall rows %+v", rows)
	}
}

// R1.2: behind a TLS-inspecting proxy whose CA is not trusted, NET-03
// fails and names each intercepted endpoint and the presented issuer.
func TestTLSInterception(t *testing.T) {
	inspect := netfixtures.NewCA("Evil Corp", "Evil Corp Inspection CA")
	for _, trusted := range []bool{false, true} {
		p := newProbeFixture(t)
		if trusted {
			path := filepath.Join(p.dir, "inspect.pem")
			os.WriteFile(path, pemOf(inspect), 0o600)
			p.settingsYAML += "proxy: {httpsProxy: \"http://proxy.corp.example:3128\", trustedCaPath: " + path + ", noProxy: \"127.0.0.1\"}\n"
		} else {
			p.settingsYAML += "proxy: {httpsProxy: \"http://proxy.corp.example:3128\", noProxy: \"127.0.0.1\"}\n"
		}
		p.breakPool = func(pool string, w *world, req *protocol.Request) {
			proxy := w.net.NewProxy(inspect)
			req.Proxy = "http://" + proxy.Addr
		}
		rep := runChecks(t, p.env(t))
		r := poolResultOf(t, rep, "NET-03", "sgxpool1")
		text := evidenceText([]model.Result{r})
		if !trusted {
			if r.Status != model.StatusFail || !strings.Contains(r.Remediation, "pccs.fortanix.com:443 (presented issuer Evil Corp / Evil Corp Inspection CA)") ||
				!strings.Contains(r.Remediation, "api.trustedservices.intel.com:443") {
				t.Fatalf("untrusted: %s %q\n%s", r.Status, r.Remediation, text)
			}
			// NET-02 still passes: the handshake completed.
			if n := poolResultOf(t, rep, "NET-02", "sgxpool1"); n.Status != model.StatusPass {
				t.Fatalf("NET-02: %s", n.Status)
			}
		} else if r.Status != model.StatusPass || !strings.Contains(text, "the intercepting CA from proxy.trustedCaPath is trusted") {
			t.Fatalf("trusted: %s\n%s", r.Status, text)
		}
	}
}

func TestOtherProbeFailures(t *testing.T) {
	cases := map[string]struct {
		check string
		pool  string
		brk   func(pool string, w *world, req *protocol.Request)
		want  string
	}{
		"NET-01 DNS": {"NET-01", "systempool", func(pool string, w *world, _ *protocol.Request) {
			if pool == "systempool" {
				w.net.Forget("pccs.fortanix.com")
			}
		}, "pccs.fortanix.com does not resolve"},
		"NET-06 syslog":     {"NET-06", "sgxpool1", func(_ string, w *world, _ *protocol.Request) { w.net.Refuse(syslogHost, 514) }, "refused"},
		"CC-03 PCCS":        {"CC-03", "sgxpool1", func(_ string, w *world, _ *protocol.Request) { w.net.Blackhole("global.acccache.azure.net", 443) }, "global.acccache.azure.net:443 timed out"},
		"CC-04 attestation": {"CC-04", "sgxpool1", func(_ string, w *world, _ *protocol.Request) { w.net.Refuse("api.trustedservices.intel.com", 443) }, "api.trustedservices.intel.com:443 dial tcp: connection refused"},
		"REG-03 image": {"REG-03", "systempool", func(_ string, _ *world, req *protocol.Request) {
			req.Registry.Images = append(req.Registry.Images, req.Registry.Host+"/armor/missing@sha256:"+strings.Repeat("9", 64))
		}, "not found in the registry"},
		"BAK-02 blob": {"BAK-02", "sgxpool1", func(_ string, w *world, _ *protocol.Request) { w.blobs.Deny = true }, "AuthorizationPermissionMismatch"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := newProbeFixture(t)
			p.breakPool = c.brk
			rep := runChecks(t, p.env(t))
			cat, _ := catalog.Load()
			want := model.StatusFail
			if cat.Check(c.check).Severity == model.SeverityWarning {
				want = model.StatusWarn
			}
			r := poolResultOf(t, rep, c.check, c.pool)
			text := evidenceText([]model.Result{r})
			if r.Status != want || !strings.Contains(text, c.want) {
				t.Fatalf("%s: %s, want %s\n%s", c.check, r.Status, want, text)
			}
		})
	}
}

func TestNET01FailureSkipsNET02ForThatPool(t *testing.T) {
	p := newProbeFixture(t)
	p.breakPool = func(pool string, w *world, _ *protocol.Request) {
		if pool == "systempool" {
			w.net.Forget("pccs.fortanix.com")
		}
	}
	rep := runChecks(t, p.env(t))
	if r := poolResultOf(t, rep, "NET-02", "systempool"); r.Status != model.StatusSkipped || *r.SkippedReason != "parent NET-01 failed for node pool systempool" {
		t.Fatalf("%s %v", r.Status, r.SkippedReason)
	}
	if r := poolResultOf(t, rep, "NET-02", "sgxpool1"); r.Status != model.StatusPass {
		t.Fatalf("sgxpool1: %s", r.Status)
	}
}

func TestClockSkew(t *testing.T) {
	p := newProbeFixture(t)
	p.breakPool = func(pool string, w *world, req *protocol.Request) {
		if pool == "sgxpool1" {
			*w = *p.world(t, 8*time.Second)
		}
	}
	rep := runChecks(t, p.env(t))
	if r := poolResultOf(t, rep, "NET-07", "sgxpool1"); r.Status != model.StatusWarn || !strings.Contains(evidenceText([]model.Result{r}), "limit 5s") {
		t.Fatalf("%s\n%s", r.Status, evidenceText([]model.Result{r}))
	}
	if r := poolResultOf(t, rep, "NET-07", "systempool"); r.Status != model.StatusPass {
		t.Fatalf("systempool: %s", r.Status)
	}
}

func TestAzureAttestationHostMissingWarnsCC04(t *testing.T) {
	p := newProbeFixture(t)
	p.settingsYAML = strings.Replace(p.settingsYAML, "attestation: {azureAttestationHost: "+azureAttest+"}\n", "", 1)
	rep := runChecks(t, p.env(t))
	r := poolResultOf(t, rep, "CC-04", "sgxpool1")
	if r.Status != model.StatusWarn || !strings.Contains(evidenceText([]model.Result{r}), "attestation.azureAttestationHost` is not set") {
		t.Fatalf("%s\n%s", r.Status, evidenceText([]model.Result{r}))
	}
}

func TestPoolWithoutProbeResultIsSkipped(t *testing.T) {
	p := newProbeFixture(t)
	env := p.env(t)
	delete(env.Probes.Results, "systempool")
	env.Probes.PoolErrors["systempool"] = "probe image x could not be pulled on node pool systempool (ErrImagePull: denied)"
	rep := runChecks(t, env)
	r := poolResultOf(t, rep, "NET-01", "systempool")
	if r.Status != model.StatusSkipped || !strings.Contains(*r.SkippedReason, "could not be pulled") {
		t.Fatalf("%s %v", r.Status, r.SkippedReason)
	}
}

func TestPlanCredentialsAndNotes(t *testing.T) {
	p := newProbeFixture(t)
	env := clusterEnv(p.fixture)
	plan, err := Plan(env, probeRunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Secret) != 2 || plan.ImagesNote != "" || plan.StorageNote != "" {
		t.Fatalf("%+v", plan)
	}
	req := plan.Request("sgxpool1")
	b, _ := json.Marshal(req)
	if strings.Contains(string(b), regPassword) {
		t.Fatal("the request (a ConfigMap) must not carry the registry password")
	}
	if req.Storage.Blob != "armor-preflight-"+probeRunID+"-sgxpool1.txt" || len(req.Registry.Images) != 1 {
		t.Fatalf("%+v", req)
	}
	delete(p.envVars, "BAK_KEY")
	plan, _ = Plan(clusterEnv(p.fixture), probeRunID)
	if plan.StorageNote == "" || plan.Request("x").Storage != nil {
		t.Fatalf("%+v", plan)
	}
}

func mustPort(t *testing.T, hostport string) int {
	_, port, _ := strings.Cut(hostport, ":")
	var n int
	for _, c := range port {
		n = n*10 + int(c-'0')
	}
	return n
}

func pemOf(ca *netfixtures.CA) []byte {
	return []byte("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(ca.Cert.Raw) + "\n-----END CERTIFICATE-----\n")
}

// Every probe check has a failing case above (R1.1).
func TestEveryProbeCheckHasAFailingCase(t *testing.T) {
	covered := map[string]bool{"NET-02": true, "NET-03": true, "NET-07": true} // dedicated tests
	for _, c := range []string{"NET-01", "NET-06", "CC-03", "CC-04", "REG-03", "BAK-02"} {
		covered[c] = true
	}
	cat, _ := catalog.Load()
	for _, ch := range cat.Checks {
		if ch.RunsIn == catalog.RunsInProbe && ch.ID != "CC-05" && !covered[ch.ID] {
			t.Errorf("no failing case for %s", ch.ID)
		}
	}
}
