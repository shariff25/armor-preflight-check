package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stesting "k8s.io/client-go/testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
)

func runChecks(t *testing.T, env *engine.Env) *engine.Report {
	t.Helper()
	rep, err := engine.Run(context.Background(), env, Registry(), engine.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.InternalErrors) > 0 {
		t.Fatalf("internal errors: %v", rep.InternalErrors)
	}
	return rep
}

func resultsFor(rep *engine.Report, id string) []model.Result {
	var out []model.Result
	for _, r := range rep.Results {
		if r.ID == id {
			out = append(out, r)
		}
	}
	return out
}

func evidenceText(rs []model.Result) string {
	var b strings.Builder
	for _, r := range rs {
		for _, e := range r.Evidence {
			b.WriteString(e.Target + " " + e.Detail + "\n")
		}
		if r.SkippedReason != nil {
			b.WriteString("skipped: " + *r.SkippedReason + "\n")
		}
	}
	return b.String()
}

// A cluster that meets every prerequisite passes every implemented
// workstation check.
func TestCompliantClusterPasses(t *testing.T) {
	f := newFixture(t)
	rep := runChecks(t, clusterEnv(f))
	impl := Registry()
	cat, _ := catalog.Load()
	for _, r := range rep.Results {
		if impl[r.ID] == nil || r.SkippedReason != nil && *r.SkippedReason == "not implemented in this build" {
			continue
		}
		if def := cat.Check(r.ID); def.RunsIn == catalog.RunsInProbe {
			continue // covered with real probe results in probe_test.go
		}
		switch {
		case r.ID == "K8S-12" && r.Status == model.StatusInfo:
		case r.ID == "REG-04" && r.Status == model.StatusSkipped: // direct mode
		case r.Status == model.StatusPass:
		default:
			t.Errorf("%s (%s) = %s:\n%s", r.ID, r.Scope, r.Status, evidenceText([]model.Result{r}))
		}
	}
}

// R1.1: for each implemented check, a fixture that violates the
// prerequisite makes it fail (warn for warning-severity checks).
func TestEachCheckFailsOnItsFixture(t *testing.T) {
	cases := map[string]struct {
		mutate func(f *fixture)
		want   string // evidence substring
	}{
		"WS-01":  {func(f *fixture) { delete(f.tools, "jq") }, "jq not found on PATH"},
		"K8S-01": {func(f *fixture) { f.serverVersion = "v1.33.5" }, "v1.33.5 is older than 1.34.8"},
		"K8S-02": {func(f *fixture) {
			f.nodes[0].Status.Capacity[corev1.ResourceCPU] = *resourceQty(2)
		}, "2 suitable node(s) in the system pool systempool; 3 required"},
		"K8S-03": {func(f *fixture) { f.settingsYAML = "replicas: 4\n" + f.settingsYAML }, "3 suitable node(s) in the SGX pool sgxpool1; 4 required"},
		"K8S-04": {func(f *fixture) { f.nodes[1].Status.NodeInfo.OSImage = "Azure Linux 3.0" }, "runs Azure Linux 3.0; the validated OS is Ubuntu 24.x"},
		"K8S-05": {func(f *fixture) { f.crds = append(f.crds, crd("k8ssandraclusters.k8ssandra.io", "k8ssandra.io")) }, "K8ssandra CRDs present: k8ssandraclusters.k8ssandra.io"},
		"K8S-06": {func(f *fixture) { f.crds = append(f.crds, crd("armorplatforms."+testCRDGroup, testCRDGroup)) }, "an Armor operator is already installed"},
		"K8S-07": {func(f *fixture) { f.pods = f.pods[1:] }, "IngressClass nginx (k8s.io/ingress-nginx): no ready controller pods found"},
		"K8S-08": {func(f *fixture) { f.issuers = []*unstructuredT{issuer("corp-ca", false)} }, "no ClusterIssuer is Ready (corp-ca)"},
		"K8S-09": {func(f *fixture) { f.deny["certificatesigningrequests/approval"] = true }, "approve CertificateSigningRequests not allowed"},
		"CC-01": {func(f *fixture) {
			delete(f.nodes[3].Status.Allocatable, "sgx.intel.com/enclave")
		}, "aks-sgxpool1-1 does not advertise sgx.intel.com/enclave"},
		"CC-02": {func(f *fixture) {
			f.pods[2].Spec.Containers[0].Image = "registry.k8s.io/nfd/node-feature-discovery:v0.14.2"
		}, "Node Feature Discovery v0.14.2 is older than 0.15.0"},
		"NET-04": {func(f *fixture) { f.settingsYAML = strings.Replace(f.settingsYAML, ",10.0.0.0/16", "", 1) }, "does not cover 10.0.0.0/16"},
		"NET-05": {func(f *fixture) { delete(f.dns, "static.armor.example.com") }, "static.armor.example.com is recorded in the settings file but does not resolve yet"},
		"REG-01": {func(f *fixture) { f.envVars["REG_PW"] = "wrong-password" }, "rejected the credentials for example-user"},
		"REG-02": {func(f *fixture) {
			f.settingsYAML = strings.Replace(f.settingsYAML, `armorVersion: "1.0.404"`, `armorVersion: "1.0.405"`, 1)
		}, "chart version 1.0.405 not found"},
		"REG-04": {func(f *fixture) { mirrorMode(f, false) }, "armor/operator@" + imageDigest + " not found in the mirror"},
		"REG-05": {func(f *fixture) { f.secrets = nil }, "no image pull secret for"},
		"K8S-10": {func(f *fixture) { f.storageClasses = nil }, "no default storage class"},
		"K8S-11": {func(f *fixture) { f.lbAddress = "" }, "received no address within 1s"},
		"BAK-01": {func(f *fixture) {
			f.settingsYAML = strings.Replace(f.settingsYAML, "accountKind: StorageV2", "accountKind: BlobStorage", 1)
		}, "account kind BlobStorage (StorageV2 required)"},
		"PKI-01": {func(f *fixture) {
			f.settingsYAML = strings.Replace(f.settingsYAML, "armor: armor.example.com,", "armor: armor_example,", 1)
		}, `"armor_example" is not a valid fully qualified domain name`},
		"PKI-02": {func(f *fixture) {
			f.settingsYAML = strings.Replace(f.settingsYAML, "caReady: true", "caReady: false", 1)
		}, "caReady is false"},
		"PKI-03": {func(f *fixture) {
			f.settingsYAML = strings.Replace(f.settingsYAML, "certificates: {caReady: true, sampleApiCertPath: ", "certificates: {caReady: true, plannedApiSans: [www.armor.example.com], sampleApiCertPath: ", 1)
		}, "does not include api.armor.example.com"},
	}
	cat, _ := catalog.Load()
	for id := range Registry() {
		if cat.Check(id).RunsIn == catalog.RunsInProbe {
			continue // probe_test.go
		}
		if _, ok := cases[id]; !ok && id != "K8S-12" {
			t.Errorf("no failing fixture for %s", id)
		}
	}
	for id, c := range cases {
		t.Run(id, func(t *testing.T) {
			f := newFixture(t)
			c.mutate(f)
			rep := runChecks(t, clusterEnv(f))
			rs := resultsFor(rep, id)
			want := model.StatusFail
			if cat.Check(id).Severity == model.SeverityWarning {
				want = model.StatusWarn
			}
			got := false
			for _, r := range rs {
				if r.Status == want {
					got = true
				}
			}
			if !got {
				t.Fatalf("no %s result for %s:\n%s", want, id, evidenceText(rs))
			}
			if text := evidenceText(rs); !strings.Contains(text, c.want) {
				t.Fatalf("evidence missing %q:\n%s", c.want, text)
			}
		})
	}
}

type unstructuredT = unstructuredAlias

// R1.2: with the device plugin missing from one node, CC-01 fails for that
// node only, naming it.
func TestCC01FailsOnlyForTheBrokenNode(t *testing.T) {
	f := newFixture(t)
	delete(f.nodes[3].Status.Allocatable, "sgx.intel.com/enclave")
	rep := runChecks(t, f.env(engine.ModeWorkstation))
	rs := resultsFor(rep, "CC-01")
	if len(rs) != 3 {
		t.Fatalf("%d results", len(rs))
	}
	for _, r := range rs {
		want := model.StatusPass
		if r.Scope.Node == "aks-sgxpool1-1" {
			want = model.StatusFail
		}
		if r.Status != want {
			t.Errorf("%s: %s, want %s", r.Scope, r.Status, want)
		}
	}
}

func TestK8S04WarnsOnlyForTheOddNode(t *testing.T) {
	f := newFixture(t)
	f.nodes[1].Status.NodeInfo.OSImage = "Azure Linux 3.0"
	rep := runChecks(t, f.env(engine.ModeWorkstation))
	for _, r := range resultsFor(rep, "K8S-04") {
		if (r.Status == model.StatusWarn) != (r.Scope.Node == f.nodes[1].Name) {
			t.Errorf("%s: %s", r.Scope, r.Status)
		}
	}
}

func TestK8S12ReportsCIDRs(t *testing.T) {
	f := newFixture(t)
	rep := runChecks(t, f.env(engine.ModeWorkstation))
	text := evidenceText(resultsFor(rep, "K8S-12"))
	if !strings.Contains(text, "10.244.0.0/24") || !strings.Contains(text, "service CIDRs: 10.0.0.0/16") {
		t.Fatalf("got:\n%s", text)
	}
	f = newFixture(t)
	for _, n := range f.nodes {
		n.Spec.PodCIDR, n.Spec.PodCIDRs = "", nil
	}
	rep = runChecks(t, f.env(engine.ModeWorkstation))
	rs := resultsFor(rep, "K8S-12")
	if rs[0].Status != model.StatusInfo || !strings.Contains(evidenceText(rs), "Azure CNI without overlay") {
		t.Fatalf("got %s:\n%s", rs[0].Status, evidenceText(rs))
	}
}

// D-8: a cluster that is not AKS never passes silently.
func TestUnsupportedProfileWarns(t *testing.T) {
	f := newFixture(t)
	for _, n := range f.nodes {
		n.Spec.ProviderID = "kind://docker/kind/" + n.Name
		delete(n.Labels, "kubernetes.azure.com/agentpool")
	}
	rep := runChecks(t, f.env(engine.ModeWorkstation))
	for _, id := range []string{"K8S-02", "K8S-03"} {
		rs := resultsFor(rep, id)
		if rs[0].Status != model.StatusWarn || !strings.Contains(evidenceText(rs), "unsupported profile") {
			t.Errorf("%s: %s\n%s", id, rs[0].Status, evidenceText(rs))
		}
	}
}

func TestKubeconfigProblemFailsWS01AndSkipsKubernetesChecks(t *testing.T) {
	f := newFixture(t)
	env := f.env(engine.ModeWorkstation)
	env.Kube, env.KubeErr = nil, errors.New(`kube context "nope" not found in kubeconfig`)
	rep := runChecks(t, env)
	ws := resultsFor(rep, "WS-01")
	if ws[0].Status != model.StatusFail || !strings.Contains(evidenceText(ws), `kube context "nope" not found`) {
		t.Fatalf("WS-01: %s\n%s", ws[0].Status, evidenceText(ws))
	}
	for _, id := range []string{"K8S-01", "K8S-09", "REG-01", "NET-04"} {
		r := resultsFor(rep, id)[0]
		if r.Status != model.StatusSkipped || !strings.Contains(*r.SkippedReason, "parent WS-01 failed") {
			t.Errorf("%s: %s", id, r.Status)
		}
	}
	// Checks that need no cluster still run.
	if r := resultsFor(rep, "PKI-01")[0]; r.Status != model.StatusPass {
		t.Errorf("PKI-01: %s", r.Status)
	}
}

func TestWrongContextFailsWS01(t *testing.T) {
	f := newFixture(t)
	f.settingsYAML = "kubeContext: aks-armor-staging\n" + f.settingsYAML
	rep := runChecks(t, f.env(engine.ModeWorkstation))
	ws := resultsFor(rep, "WS-01")
	if ws[0].Status != model.StatusFail || !strings.Contains(evidenceText(ws), `expects "aks-armor-staging"`) {
		t.Fatalf("got %s\n%s", ws[0].Status, evidenceText(ws))
	}
}

// R1.4: workstation mode makes no create, update, patch or delete calls
// (SelfSubjectAccessReviews are not persisted; D-1).
func TestWorkstationModeMakesNoWrites(t *testing.T) {
	f := newFixture(t)
	runChecks(t, f.env(engine.ModeWorkstation))
	check := func(actions []k8stesting.Action) {
		for _, a := range actions {
			switch a.GetVerb() {
			case "get", "list", "watch":
			case "create":
				if a.GetResource().Resource != "selfsubjectaccessreviews" {
					t.Errorf("create %s", a.GetResource().Resource)
				}
			default:
				t.Errorf("%s %s", a.GetVerb(), a.GetResource().Resource)
			}
		}
	}
	check(f.core.Actions())
	check(f.dyn.Actions())
	if len(f.core.Actions()) == 0 {
		t.Fatal("no API calls recorded")
	}
}

// mirrorMode switches the fixture to mirror mode with a one-image release
// manifest; present controls whether the image is in the mirror.
func mirrorMode(f *fixture, present bool) {
	manifest := filepath.Join(f.dir, "images.txt")
	os.WriteFile(manifest, []byte("# release images\ncr.download.fortanix.com/armor/operator@"+imageDigest+"\n"), 0o600)
	f.settingsYAML = strings.Replace(f.settingsYAML, "mode: direct", "mode: mirror, releaseManifestPath: "+manifest, 1)
	if present {
		f.reg.Add("armor/operator", imageDigest, imageDigest)
	}
}

func TestREG04MirrorWritesImageOverrides(t *testing.T) {
	f := newFixture(t)
	mirrorMode(f, true)
	env := f.env(engine.ModeWorkstation)
	rep := runChecks(t, env)
	r := resultsFor(rep, "REG-04")[0]
	if r.Status != model.StatusPass {
		t.Fatalf("%s\n%s", r.Status, evidenceText([]model.Result{r}))
	}
	art := string(env.Artifacts()[ImageOverridesFile])
	if !strings.Contains(art, "original: cr.download.fortanix.com/armor/operator@"+imageDigest) ||
		!strings.Contains(art, "image: "+f.reg.Host()+"/armor/operator@"+imageDigest) {
		t.Fatalf("artifact:\n%s", art)
	}
}

func TestREG04WithoutManifestChecksChartOnly(t *testing.T) {
	f := newFixture(t)
	f.settingsYAML = strings.Replace(f.settingsYAML, "mode: direct", "mode: mirror", 1)
	rep := runChecks(t, f.env(engine.ModeWorkstation))
	r := resultsFor(rep, "REG-04")[0]
	if r.Status != model.StatusPass || !strings.Contains(evidenceText([]model.Result{r}), "only the operator chart was checked") {
		t.Fatalf("%s\n%s", r.Status, evidenceText([]model.Result{r}))
	}
}

func TestREG05ExpiryAndMissingInfo(t *testing.T) {
	f := newFixture(t)
	f.secrets[0].Annotations = map[string]string{"expires": "2026-10-01"}
	rep := runChecks(t, f.env(engine.ModeWorkstation))
	if r := resultsFor(rep, "REG-05")[0]; r.Status != model.StatusWarn || !strings.Contains(evidenceText([]model.Result{r}), "expires 2026-10-01, within 14 days") {
		t.Fatalf("near expiry: %s", r.Status)
	}
	f = newFixture(t)
	f.secrets[0].Annotations = nil
	rep = runChecks(t, f.env(engine.ModeWorkstation))
	if r := resultsFor(rep, "REG-05")[0]; r.Status != model.StatusInfo {
		t.Fatalf("no readable expiry should be info, got %s", r.Status)
	}
}

func TestREG01Unreachable(t *testing.T) {
	f := newFixture(t)
	env := f.env(engine.ModeWorkstation)
	f.reg.Close()
	rep := runChecks(t, env)
	r := resultsFor(rep, "REG-01")[0]
	if r.Status != model.StatusFail || !strings.Contains(evidenceText([]model.Result{r}), "could not reach") || !strings.Contains(r.Remediation, "Allow this workstation") {
		t.Fatalf("%s %q\n%s", r.Status, r.Remediation, evidenceText([]model.Result{r}))
	}
	for _, id := range []string{"REG-02", "REG-05"} {
		if s := resultsFor(rep, id)[0]; s.Status != model.StatusSkipped || !strings.Contains(*s.SkippedReason, "parent REG-01 failed") {
			t.Errorf("%s: %s", id, s.Status)
		}
	}
}

func TestPKI02IncompleteChain(t *testing.T) {
	f := newFixture(t)
	partial := writeChain(t, f.dir, "api.armor.example.com", false)
	f.settingsYAML = regexp.MustCompile(`(?m)^certificates: .*$`).ReplaceAllString(f.settingsYAML,
		fmt.Sprintf("certificates: {caReady: true, sampleApiCertPath: %q}", partial))
	rep := runChecks(t, f.env(engine.ModeWorkstation))
	r := resultsFor(rep, "PKI-02")[0]
	if r.Status != model.StatusFail || !strings.Contains(evidenceText([]model.Result{r}), "include the leaf, every intermediate and the root") {
		t.Fatalf("%s\n%s", r.Status, evidenceText([]model.Result{r}))
	}
}

// TBD catalog values skip the check and name the value (D-9).
func TestTBDValuesSkip(t *testing.T) {
	f := newFixture(t)
	f.params = func(*catalog.Parameters) {} // shipped catalog: TBD values
	rep := runChecks(t, f.env(engine.ModeWorkstation))
	for id, param := range map[string]string{"K8S-06": "armorOperatorCrdGroup", "REG-02": "operatorChartRef"} {
		r := resultsFor(rep, id)[0]
		if r.Status != model.StatusSkipped || !strings.Contains(*r.SkippedReason, param) {
			t.Errorf("%s: %s", id, r.Status)
		}
	}
	r := resultsFor(rep, "K8S-08")[0]
	if r.Status != model.StatusWarn || !strings.Contains(evidenceText([]model.Result{r}), "unverified") {
		t.Errorf("K8S-08 should warn while certManagerVersions is TBD: %s", r.Status)
	}
}

// clusterEnv is the fixture in cluster mode with short waits. Probe checks
// have no probe data yet, so they report skipped.
func clusterEnv(f *fixture) *engine.Env {
	pollInterval = 10 * time.Millisecond
	env := f.env(engine.ModeCluster)
	env.Catalog.Parameters.VolumeBindTimeoutSeconds = 1
	env.Catalog.Parameters.LoadBalancerTimeoutSeconds = 1
	env.ProbeUnavailable = "no probes in this test"
	return env
}

func TestK8S10(t *testing.T) {
	delete := corev1.PersistentVolumeReclaimDelete
	wffc := storagev1.VolumeBindingWaitForFirstConsumer
	cases := map[string]struct {
		mutate func(f *fixture, env *engine.Env)
		status model.Status
		want   string
	}{
		"retain binds":        {func(*fixture, *engine.Env) {}, model.StatusPass, "a 1Gi volume was provisioned and bound (pvc-0001)"},
		"delete warns":        {func(f *fixture, _ *engine.Env) { f.storageClasses[0].ReclaimPolicy = &delete }, model.StatusWarn, "reclaim policy is Delete"},
		"never binds":         {func(f *fixture, _ *engine.Env) { f.bindVolumes = false }, model.StatusFail, "was not bound within 1s"},
		"wffc without image":  {func(f *fixture, env *engine.Env) { f.storageClasses[0].VolumeBindingMode = &wffc }, model.StatusFail, "binds on first use"},
		"named class missing": {func(f *fixture, _ *engine.Env) { f.settingsYAML = "storageClass: premium\n" + f.settingsYAML }, model.StatusFail, "storage class premium (from the settings file)"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			c.mutate(f, nil)
			env := clusterEnv(f)
			if name == "wffc without image" {
				env.ProbeImage = ""
			}
			r := resultsFor(runChecks(t, env), "K8S-10")[0]
			if r.Status != c.status || !strings.Contains(evidenceText([]model.Result{r}), c.want) {
				t.Fatalf("%s\n%s", r.Status, evidenceText([]model.Result{r}))
			}
		})
	}
}

func TestK8S10WaitForFirstConsumerCreatesRestrictedConsumer(t *testing.T) {
	wffc := storagev1.VolumeBindingWaitForFirstConsumer
	f := newFixture(t)
	f.storageClasses[0].VolumeBindingMode = &wffc
	env := clusterEnv(f)
	runChecks(t, env)
	pod, err := f.core.CoreV1().Pods(f.runNamespace).Get(context.Background(), testConsumerPod, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if *pod.Spec.SecurityContext.RunAsNonRoot != true || pod.Spec.Volumes[0].PersistentVolumeClaim.ClaimName != testPVCName {
		t.Fatalf("%+v", pod.Spec)
	}
}

func TestClusterWriteChecksStayInRunNamespace(t *testing.T) {
	f := newFixture(t)
	runChecks(t, clusterEnv(f))
	for _, a := range f.core.Actions() {
		switch a.GetVerb() {
		case "get", "list", "watch":
		case "create":
			res := a.GetResource().Resource
			if res != "selfsubjectaccessreviews" && a.GetNamespace() != f.runNamespace {
				t.Errorf("create %s in %q", res, a.GetNamespace())
			}
		default:
			t.Errorf("%s %s", a.GetVerb(), a.GetResource().Resource)
		}
	}
}

func TestClusterWriteChecksSkipWithoutNamespace(t *testing.T) {
	f := newFixture(t)
	f.runNamespace = ""
	env := clusterEnv(f)
	env.RunNamespaceErr = errors.New("namespaces is forbidden")
	rep := runChecks(t, env)
	for _, id := range []string{"K8S-10", "K8S-11"} {
		r := resultsFor(rep, id)[0]
		if r.Status != model.StatusSkipped || !strings.Contains(*r.SkippedReason, "namespaces is forbidden") {
			t.Errorf("%s: %s", id, r.Status)
		}
	}
}
