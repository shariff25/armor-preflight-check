package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	psaapi "k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/protocol"
)

const runID = "20260926-1512-7f3a"

func node(name, pool string, taints ...corev1.Taint) corev1.Node {
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"kubernetes.azure.com/agentpool": pool, "node.kubernetes.io/instance-type": "Standard_D4ds_v5"}},
		Spec: corev1.NodeSpec{Taints: taints}}
}

// R1.4: probe pods pass the Pod Security Standards restricted profile.
func TestProbePodIsRestricted(t *testing.T) {
	pod := PodSpec("probe-sgxpool1", NamespaceName(runID), runID, "sgxpool1", "example.invalid/probe@sha256:abc",
		map[string]string{"kubernetes.azure.com/agentpool": "sgxpool1"}, nil, "request-sgxpool1", true)
	eval, err := policy.NewEvaluator(policy.DefaultChecks())
	if err != nil {
		t.Fatal(err)
	}
	res := policy.AggregateCheckResults(eval.EvaluatePod(psaapi.LevelVersion{Level: psaapi.LevelRestricted, Version: psaapi.LatestVersion()}, &pod.ObjectMeta, &pod.Spec))
	if !res.Allowed {
		t.Fatalf("probe pod violates restricted: %s", res.ForbiddenDetail())
	}
	s := pod.Spec
	if s.HostNetwork || s.HostPID || s.HostIPC || *s.AutomountServiceAccountToken || !*s.Containers[0].SecurityContext.ReadOnlyRootFilesystem {
		t.Fatal("probe pod must not use host namespaces or a service account token, and must have a read-only root filesystem")
	}
	if pod.Labels[LabelManagedBy] != ManagedByValue || pod.Labels[LabelRunID] != runID {
		t.Fatalf("labels %v", pod.Labels)
	}
}

func TestPoolsFromNodes(t *testing.T) {
	pools := PoolsFromNodes([]corev1.Node{
		node("sys-0", "systempool", corev1.Taint{Key: "CriticalAddonsOnly", Value: "true", Effect: corev1.TaintEffectNoSchedule}),
		node("sys-1", "systempool"),
		node("sgx-0", "sgxpool1", corev1.Taint{Key: "sgx", Effect: corev1.TaintEffectNoSchedule}),
		{ObjectMeta: metav1.ObjectMeta{Name: "bare", Labels: map[string]string{}}},
	}, "kubernetes.azure.com/agentpool", "node.kubernetes.io/instance-type")
	if len(pools) != 3 {
		t.Fatalf("%+v", pools)
	}
	if pools[0].Name != "systempool" || pools[0].Selector["kubernetes.azure.com/agentpool"] != "systempool" || len(pools[0].Tolerations) != 1 || pools[0].Tolerations[0].Key != "CriticalAddonsOnly" {
		t.Errorf("systempool: %+v", pools[0])
	}
	if pools[2].Selector["kubernetes.io/hostname"] != "bare" {
		t.Errorf("unlabelled node should be pinned by hostname: %+v", pools[2])
	}
}

func TestObjectNames(t *testing.T) {
	if got := objectName("probe-", "sgxpool1"); got != "probe-sgxpool1" {
		t.Errorf("got %s", got)
	}
	a, b := objectName("probe-", "Standard_DC8s_v3"), objectName("probe-", "standard-dc8s-v3")
	if a == b || !strings.HasPrefix(a, "probe-standard-dc8s-v3-") {
		t.Errorf("names must stay distinct and valid: %s %s", a, b)
	}
	if long := objectName("probe-", strings.Repeat("x", 80)); len(long) > 63 {
		t.Errorf("too long: %s", long)
	}
}

// kubelet makes the fake clientset behave like pods ran: each new probe
// pod gets the status the test chose for its pool.
func kubelet(core *fake.Clientset, status func(pool string) corev1.PodStatus) {
	core.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		pod := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		pod.Spec.NodeName = "aks-" + pod.Labels[LabelNodePool] + "-0"
		pod.Status = status(pod.Labels[LabelNodePool])
		return false, nil, nil
	})
}

func succeeded(string) corev1.PodStatus {
	return corev1.PodStatus{Phase: corev1.PodSucceeded, ContainerStatuses: []corev1.ContainerStatus{{Name: ContainerName, ImageID: "example.invalid/probe@sha256:abc"}}}
}

func probeLog(pool string) string {
	line, _ := protocol.Encode(protocol.Result{Version: protocol.Version, RunID: runID, NodePool: pool, Node: "aks-" + pool + "-0"})
	return "starting\n" + line + "\n"
}

func newTest(core *fake.Clientset) *Orchestrator {
	o := New(core, runID, "example.invalid/probe@sha256:abc")
	o.Poll = 5 * time.Millisecond
	o.Logs = func(_ context.Context, _, pod string) (string, error) {
		return probeLog(strings.TrimPrefix(pod, "probe-")), nil
	}
	return o
}

var twoPools = []Pool{{Name: "systempool", Selector: map[string]string{"p": "systempool"}}, {Name: "sgxpool1", Selector: map[string]string{"p": "sgxpool1"}}}

func req(pool string) protocol.Request {
	return protocol.Request{Version: protocol.Version, RunID: runID, NodePool: pool}
}

func TestRunProbesCollectsResults(t *testing.T) {
	core := fake.NewSimpleClientset()
	kubelet(core, succeeded)
	o := newTest(core)
	ctx := context.Background()
	if err := o.CreateNamespace(ctx); err != nil {
		t.Fatal(err)
	}
	ns, _ := core.CoreV1().Namespaces().Get(ctx, o.Namespace, metav1.GetOptions{})
	if ns.Labels["pod-security.kubernetes.io/enforce"] != "restricted" || ns.Labels[LabelRunID] != runID {
		t.Fatalf("namespace labels %v", ns.Labels)
	}
	out, err := o.RunProbes(ctx, twoPools, req, map[string][]byte{"registry-password": []byte("x")}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 2 || out.Results["sgxpool1"].Node != "aks-sgxpool1-0" || len(out.PoolErrors) != 0 || out.Unavailable != "" {
		t.Fatalf("%+v", out)
	}
	if len(out.Probes) != 2 || out.Probes[0].ImageID == "" {
		t.Fatalf("probes %+v", out.Probes)
	}
	// Every object carries the run labels and lives in the run namespace.
	for _, a := range core.Actions() {
		if a.GetVerb() != "create" {
			continue
		}
		obj := a.(k8stesting.CreateAction).GetObject().(metav1.Object)
		if obj.GetLabels()[LabelManagedBy] != ManagedByValue || obj.GetLabels()[LabelRunID] != runID {
			t.Errorf("%s %s missing labels", a.GetResource().Resource, obj.GetName())
		}
		if a.GetResource().Resource != "namespaces" && a.GetNamespace() != o.Namespace {
			t.Errorf("%s created outside the run namespace: %s", a.GetResource().Resource, a.GetNamespace())
		}
	}
	pod, _ := core.CoreV1().Pods(o.Namespace).Get(ctx, "probe-sgxpool1", metav1.GetOptions{})
	if pod.Spec.NodeSelector["p"] != "sgxpool1" {
		t.Errorf("probe not pinned to its pool: %v", pod.Spec.NodeSelector)
	}
}

// R1.5: when the probe image cannot be pulled, name the image to mirror.
func TestImagePullFailure(t *testing.T) {
	core := fake.NewSimpleClientset()
	kubelet(core, func(string) corev1.PodStatus {
		return corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{Name: ContainerName,
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "Back-off pulling image"}}}}}
	})
	o := newTest(core)
	o.CreateNamespace(context.Background())
	out, err := o.RunProbes(context.Background(), twoPools, req, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Unavailable, "probe image example.invalid/probe@sha256:abc could not be pulled") || !strings.Contains(out.Unavailable, "--probe-image") {
		t.Fatalf("got %q", out.Unavailable)
	}
}

func TestOnePoolUnschedulable(t *testing.T) {
	core := fake.NewSimpleClientset()
	kubelet(core, func(pool string) corev1.PodStatus {
		if pool == "sgxpool1" {
			return corev1.PodStatus{Phase: corev1.PodPending, Conditions: []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse,
				Reason: corev1.PodReasonUnschedulable, Message: "0/6 nodes are available: 3 node(s) had untolerated taint"}}}
		}
		return succeeded(pool)
	})
	o := newTest(core)
	o.CreateNamespace(context.Background())
	out, err := o.RunProbes(context.Background(), twoPools, req, nil, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.Results["systempool"]; !ok || out.Unavailable != "" {
		t.Fatalf("systempool should still report: %+v", out)
	}
	if !strings.Contains(out.PoolErrors["sgxpool1"], "could not be scheduled on node pool sgxpool1: 0/6 nodes are available") {
		t.Fatalf("got %q", out.PoolErrors["sgxpool1"])
	}
}

func TestBadProbeOutput(t *testing.T) {
	for name, log := range map[string]string{
		"no result":     "panic: boom\n",
		"wrong version": protocol.Sentinel + `{"version":"0"}` + "\n",
		"other run":     probeLogFor("other-run"),
	} {
		t.Run(name, func(t *testing.T) {
			core := fake.NewSimpleClientset()
			kubelet(core, succeeded)
			o := newTest(core)
			o.Logs = func(context.Context, string, string) (string, error) { return log, nil }
			o.CreateNamespace(context.Background())
			out, _ := o.RunProbes(context.Background(), twoPools[:1], req, nil, time.Second)
			if len(out.Results) != 0 || out.PoolErrors["systempool"] == "" {
				t.Fatalf("%+v", out)
			}
		})
	}
}

func probeLogFor(run string) string {
	line, _ := protocol.Encode(protocol.Result{Version: protocol.Version, RunID: run})
	return line + "\n"
}

func TestInterruptStopsWaiting(t *testing.T) {
	core := fake.NewSimpleClientset()
	kubelet(core, func(string) corev1.PodStatus { return corev1.PodStatus{Phase: corev1.PodPending} })
	o := newTest(core)
	o.CreateNamespace(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	start := time.Now()
	out, err := o.RunProbes(ctx, twoPools, req, nil, time.Minute)
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("interrupt not honoured: %v after %s", err, time.Since(start))
	}
	if !strings.Contains(out.PoolErrors["sgxpool1"], "interrupted") {
		t.Fatalf("%+v", out.PoolErrors)
	}
}

func TestCleanupDeletesNamespaceAndClaimedVolumes(t *testing.T) {
	ns := NamespaceName(runID)
	retained := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pvc-ours"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: ns, Name: "storage-test"}}}
	foreign := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pvc-theirs"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: "cassandra", Name: "data"}}}
	core := fake.NewSimpleClientset(retained, foreign)
	o := newTest(core)
	ctx := context.Background()
	if err := o.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if len(core.Actions()) != 0 {
		t.Fatal("cleanup before the namespace exists must do nothing")
	}
	o.CreateNamespace(ctx)
	if err := o.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := core.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err == nil {
		t.Fatal("namespace still exists")
	}
	pvs, _ := core.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if len(pvs.Items) != 1 || pvs.Items[0].Name != "pvc-theirs" {
		t.Fatalf("volumes left: %v", pvs.Items)
	}
}

// R1.4: after a killed run, `cleanup` removes every labelled namespace and
// volume, and nothing else.
func TestRemoveLeftovers(t *testing.T) {
	mk := func(name string, labels map[string]string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
	}
	objs := []runtime.Object{
		mk(NamespaceName("run-a"), Labels("run-a")),
		mk(NamespaceName("run-b"), Labels("run-b")),
		mk("armor", nil),
		mk("impostor", Labels("run-c")), // labelled but not our prefix
		mk(NamespacePrefix+"unlabelled", nil),
		&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv-a"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: NamespaceName("run-a")}}},
		&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv-x"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: "armor"}}},
	}
	core := fake.NewSimpleClientset(objs...)
	ctx := context.Background()

	left, err := RemoveLeftovers(ctx, core, "run-a")
	if err != nil || fmt.Sprint(left.Namespaces) != "[armor-preflight-run-a]" || fmt.Sprint(left.Volumes) != "[pv-a]" {
		t.Fatalf("run-a: %+v %v", left, err)
	}
	left, err = RemoveLeftovers(ctx, core, "")
	if err != nil || fmt.Sprint(left.Namespaces) != "[armor-preflight-run-b]" {
		t.Fatalf("all: %+v %v", left, err)
	}
	nss, _ := core.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	var names []string
	for _, n := range nss.Items {
		names = append(names, n.Name)
	}
	if fmt.Sprint(names) != "[armor armor-preflight-unlabelled impostor]" {
		t.Fatalf("remaining: %v", names)
	}
}
