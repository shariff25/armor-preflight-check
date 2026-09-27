package orchestrator

import (
	"context"
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

	"github.com/shariff25/armor-preflight-check/internal/probe/protocol"
)

const sgxImage = "example.invalid/armor-preflight-probe-sgx@sha256:def"

func TestRunNodeProbes(t *testing.T) {
	core := fake.NewSimpleClientset()
	core.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		pod := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		pod.Spec.NodeName = pod.Spec.NodeSelector["kubernetes.io/hostname"]
		pod.Status.Phase = corev1.PodSucceeded
		return false, nil, nil
	})
	o := New(core, runID, "example.invalid/probe@sha256:abc")
	o.Poll = 5 * time.Millisecond
	o.Logs = func(_ context.Context, _, pod string) (string, error) {
		line, _ := protocol.Encode(protocol.Result{Version: protocol.Version, RunID: runID, Node: strings.TrimPrefix(pod, "sgx-probe-")})
		return line + "\n", nil
	}
	ctx := context.Background()
	o.CreateNamespace(ctx)
	nodes := []NodeTarget{{Name: "aks-sgxpool1-0"}, {Name: "aks-sgxpool1-1", Tolerations: []corev1.Toleration{{Key: "sgx", Operator: corev1.TolerationOpExists}}}}
	out, err := o.RunNodeProbes(ctx, sgxImage, nodes, func(node string) protocol.Request {
		return protocol.Request{Version: protocol.Version, RunID: runID, SGX: &protocol.SGX{Nonce: "ab"}}
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 2 || out.Results["aks-sgxpool1-1"].Node != "aks-sgxpool1-1" || len(out.Probes) != 2 || out.Probes[0].Node != "aks-sgxpool1-0" || out.Probes[0].Image != sgxImage {
		t.Fatalf("%+v", out)
	}

	pod, err := core.CoreV1().Pods(o.Namespace).Get(ctx, "sgx-probe-aks-sgxpool1-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pod.Spec.NodeSelector["kubernetes.io/hostname"] != "aks-sgxpool1-1" || pod.Labels[LabelNode] != "aks-sgxpool1-1" || pod.Spec.Containers[0].Image != sgxImage {
		t.Fatalf("pinning: %+v %v", pod.Spec.NodeSelector, pod.Labels)
	}
	for _, r := range SGXResources {
		if q := pod.Spec.Containers[0].Resources.Limits[r]; q.Value() != 1 {
			t.Errorf("limit %s = %s", r, q.String())
		}
	}
	if len(pod.Spec.Tolerations) != 1 {
		t.Errorf("tolerations %v", pod.Spec.Tolerations)
	}
	// Requesting SGX devices through the device plugin keeps the pod within
	// the restricted profile: no privileges or host paths are needed.
	eval, _ := policy.NewEvaluator(policy.DefaultChecks())
	res := policy.AggregateCheckResults(eval.EvaluatePod(psaapi.LevelVersion{Level: psaapi.LevelRestricted, Version: psaapi.LatestVersion()}, &pod.ObjectMeta, &pod.Spec))
	if !res.Allowed {
		t.Fatalf("SGX probe violates restricted: %s", res.ForbiddenDetail())
	}
}

func TestNodeProbePullFailureNamesTheNode(t *testing.T) {
	core := fake.NewSimpleClientset()
	core.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		pod := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		pod.Status = corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ErrImagePull"}}}}}
		return false, nil, nil
	})
	o := New(core, runID, "unused")
	o.Poll = 5 * time.Millisecond
	o.CreateNamespace(context.Background())
	out, _ := o.RunNodeProbes(context.Background(), sgxImage, []NodeTarget{{Name: "aks-sgxpool1-0"}}, func(string) protocol.Request { return protocol.Request{} }, time.Second)
	if !strings.Contains(out.PoolErrors["aks-sgxpool1-0"], "could not be pulled on node aks-sgxpool1-0") {
		t.Fatalf("%+v", out.PoolErrors)
	}
}
