package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/kube"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/output"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/orchestrator"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/protocol"
)

const testProbeImage = "example.invalid/armor-preflight-probe@sha256:abc"

// fakeCluster is a two-pool cluster whose "kubelet" runs probe pods to
// completion (or leaves them pending when pending is true).
func fakeCluster(t *testing.T, pending bool, extra ...runtime.Object) *fake.Clientset {
	t.Helper()
	objs := append([]runtime.Object{
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "aks-systempool-0", Labels: map[string]string{"kubernetes.azure.com/agentpool": "systempool"}}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "aks-sgxpool1-0", Labels: map[string]string{"kubernetes.azure.com/agentpool": "sgxpool1"}}},
	}, extra...)
	core := fake.NewSimpleClientset(objs...)
	core.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{GitVersion: "v1.34.8"}
	core.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		pod := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		if !pending {
			pod.Spec.NodeName = "aks-" + pod.Labels[orchestrator.LabelNodePool] + "-0"
			pod.Status.Phase = corev1.PodSucceeded
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: orchestrator.ContainerName, ImageID: testProbeImage}}
		}
		return false, nil, nil
	})
	return core
}

func withCluster(t *testing.T, core *fake.Clientset) {
	t.Helper()
	withFakes(t, fakeRegistry(nil))
	loadKube = func(o kube.Options) (*kube.Clients, error) {
		dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
			{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}: "CustomResourceDefinitionList",
			{Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers"}:                 "ClusterIssuerList",
		})
		return &kube.Clients{Core: core, Dynamic: dyn, Context: "aks-armor-test", Server: "https://example.invalid"}, nil
	}
	oldOrch := newOrchestrator
	newOrchestrator = func(c kubernetes.Interface, runID, image string) *orchestrator.Orchestrator {
		o := orchestrator.New(c, runID, image)
		o.Poll = 5 * time.Millisecond
		o.Logs = func(_ context.Context, _, pod string) (string, error) {
			line, _ := protocol.Encode(protocol.Result{Version: protocol.Version, RunID: runID, NodePool: strings.TrimPrefix(pod, "probe-")})
			return line + "\n", nil
		}
		return o
	}
	t.Cleanup(func() { newOrchestrator = oldOrch })
}

func namespaces(t *testing.T, core *fake.Clientset) []string {
	nss, err := core.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, n := range nss.Items {
		out = append(out, n.Name)
	}
	return out
}

func TestClusterRunRunsProbesAndCleansUp(t *testing.T) {
	core := fakeCluster(t, false)
	withCluster(t, core)
	dir := t.TempDir()
	out, err := execute("run", "cluster", "-f", writeSettings(t, settingsYAML), "-o", dir, "--probe-image", testProbeImage)
	if exitcode.FromError(err) != exitcode.Ready {
		t.Fatalf("exit %d: %v\n%s", exitcode.FromError(err), err, out)
	}
	if !strings.Contains(out, "Removed Preflight's temporary namespace armor-preflight-") {
		t.Fatalf("no cleanup message:\n%s", out)
	}
	if left := namespaces(t, core); len(left) != 0 {
		t.Fatalf("namespaces left behind: %v", left)
	}
	rec, _ := output.ReadRecord(dir)
	if len(rec.Probes) != 2 || rec.Probes[0].NodePool != "sgxpool1" || rec.Probes[0].ImageDigest != testProbeImage || rec.Probes[0].Error != "" {
		t.Fatalf("probes: %+v", rec.Probes)
	}
	if !strings.Contains(strings.Join(rec.RBAC, "\n"), "armor-preflight-<run id> only") {
		t.Fatalf("cluster permissions missing from the report: %v", rec.RBAC)
	}
	// Every write stayed in the run namespace (or created/deleted it).
	for _, a := range core.Actions() {
		switch a.GetVerb() {
		case "get", "list", "watch":
			continue
		}
		res, ns := a.GetResource().Resource, a.GetNamespace()
		if res == "namespaces" || res == "selfsubjectaccessreviews" || res == "persistentvolumes" {
			continue
		}
		if !strings.HasPrefix(ns, orchestrator.NamespacePrefix) {
			t.Errorf("%s %s in %q", a.GetVerb(), res, ns)
		}
	}
}

func TestClusterRunWithoutProbeImage(t *testing.T) {
	core := fakeCluster(t, false)
	withCluster(t, core)
	dir := t.TempDir()
	out, _ := execute("run", "cluster", "-f", writeSettings(t, settingsYAML), "-o", dir)
	if !strings.Contains(out, "no probe image is configured; pass --probe-image: ") || len(namespaces(t, core)) != 0 {
		t.Fatalf("got:\n%s", out)
	}
	// Workstation checks still ran (R1.5).
	rec, _ := output.ReadRecord(dir)
	for _, r := range rec.Results {
		if r.ID == "K8S-01" && r.Status != "pass" {
			t.Fatalf("K8S-01: %s", r.Status)
		}
	}
}

// R1.5: when nodes can't pull the probe image, the run names the exact image
// to mirror and still completes every check a workstation run completes, with
// the same result.
func TestClusterRunImagePullFailure(t *testing.T) {
	core := fakeCluster(t, true)
	core.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		pod := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		pod.Status.Phase = corev1.PodPending
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name:  orchestrator.ContainerName,
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}},
		}}
		return false, nil, nil
	})
	withCluster(t, core)
	settings := writeSettings(t, settingsYAML)

	wsDir := t.TempDir()
	if _, err := execute("run", "workstation", "-f", settings, "-o", wsDir); exitcode.FromError(err) == exitcode.ToolError {
		t.Fatalf("workstation run: %v", err)
	}
	clDir := t.TempDir()
	out, err := execute("run", "cluster", "-f", settings, "-o", clDir, "--probe-image", testProbeImage)
	if exitcode.FromError(err) == exitcode.ToolError {
		t.Fatalf("cluster run: %v\n%s", err, out)
	}
	if !strings.Contains(out, testProbeImage+" could not be pulled") {
		t.Fatalf("the image to mirror isn't named:\n%s", out)
	}

	ws, _ := output.ReadRecord(wsDir)
	cl, _ := output.ReadRecord(clDir)
	got := map[string]model.Status{}
	for _, r := range cl.Results {
		got[r.ID+" "+r.Scope.String()] = r.Status
	}
	completed := 0
	for _, r := range ws.Results {
		if r.Status == model.StatusSkipped {
			continue // not a workstation-mode check (probe or cluster write)
		}
		completed++
		if g := got[r.ID+" "+r.Scope.String()]; g != r.Status {
			t.Errorf("%s: %s in the workstation run, %q after the pull failure", r.ID, r.Status, g)
		}
	}
	if completed < 20 {
		t.Fatalf("only %d workstation checks completed", completed)
	}
}

func TestClusterRunInterruptStillCleansUp(t *testing.T) {
	core := fakeCluster(t, true) // probes never finish
	withCluster(t, core)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	var stdout, stderr bytes.Buffer
	root := NewRootCmd(&stdout, &stderr)
	root.SetArgs([]string{"run", "cluster", "-f", writeSettings(t, settingsYAML), "-o", t.TempDir(), "--probe-image", testProbeImage})
	err := root.ExecuteContext(ctx)
	if exitcode.FromError(err) != exitcode.ToolError || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("got %v", err)
	}
	if left := namespaces(t, core); len(left) != 0 {
		t.Fatalf("interrupt left %v behind", left)
	}
	if !strings.Contains(stdout.String(), "Removed Preflight's temporary namespace") {
		t.Fatalf("got:\n%s", stdout.String())
	}
}

func TestCleanupCommand(t *testing.T) {
	leftover := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "armor-preflight-20260926-1512-7f3a", Labels: orchestrator.Labels("20260926-1512-7f3a")}}
	other := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "armor"}}
	core := fakeCluster(t, false, leftover, other)
	withCluster(t, core)
	out, err := execute("cleanup")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "deleting namespace armor-preflight-20260926-1512-7f3a") || !strings.Contains(out, "No Preflight objects remain.") {
		t.Fatalf("got:\n%s", out)
	}
	if left := namespaces(t, core); len(left) != 1 || left[0] != "armor" {
		t.Fatalf("left %v", left)
	}
	out, _ = execute("cleanup")
	if !strings.Contains(out, "No Preflight objects found.") {
		t.Fatalf("second run:\n%s", out)
	}
}

func TestClusterRunWithSGXProbeImage(t *testing.T) {
	sgxNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "aks-sgxpool1-1", Labels: map[string]string{
		"kubernetes.azure.com/agentpool": "sgxpool1", "feature.node.kubernetes.io/cpu-security.sgx.enabled": "true"}}}
	core := fakeCluster(t, false, sgxNode)
	withCluster(t, core)
	dir := t.TempDir()
	out, err := execute("run", "cluster", "-f", writeSettings(t, settingsYAML), "-o", dir,
		"--probe-image", testProbeImage, "--sgx-probe-image", "example.invalid/armor-preflight-probe-sgx@sha256:def")
	if exitcode.FromError(err) != exitcode.Ready {
		t.Fatalf("exit %d: %v\n%s", exitcode.FromError(err), err, out)
	}
	created := 0
	for _, a := range core.Actions() {
		if a.GetVerb() == "create" && a.GetResource().Resource == "pods" {
			pod := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
			if pod.Spec.NodeSelector["kubernetes.io/hostname"] == "aks-sgxpool1-1" {
				created++
				if _, ok := pod.Spec.Containers[0].Resources.Limits["sgx.intel.com/enclave"]; !ok {
					t.Error("SGX probe does not request sgx.intel.com/enclave")
				}
			}
		}
	}
	if created != 1 {
		t.Fatalf("%d SGX probe pods created", created)
	}
	rec, _ := output.ReadRecord(dir)
	var found bool
	for _, p := range rec.Probes {
		if p.Node == "aks-sgxpool1-1" && p.Image == "example.invalid/armor-preflight-probe-sgx@sha256:def" && p.NodePool == "sgxpool1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("SGX probe missing from the report: %+v", rec.Probes)
	}
}
