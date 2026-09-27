package checks

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/shariff25/armor-preflight-check/internal/catalog"
	"github.com/shariff25/armor-preflight-check/internal/engine"
	"github.com/shariff25/armor-preflight-check/internal/model"
	"github.com/shariff25/armor-preflight-check/internal/probe/orchestrator"
)

// Names of the test objects K8S-10 and K8S-11 create in the run namespace.
const (
	testPVCName     = "storage-test"
	testConsumerPod = "storage-test-consumer"
	testServiceName = "loadbalancer-test"
	defaultClassAnn = "storageclass.kubernetes.io/is-default-class"
	// internalLBAnn keeps the test load balancer off the internet (AKS).
	internalLBAnn = "service.beta.kubernetes.io/azure-load-balancer-internal"
)

// pollInterval is how often K8S-10 and K8S-11 re-check; tests shorten it.
var pollInterval = 2 * time.Second

// runNamespace returns the run namespace, or a skip result if cluster mode
// could not create it.
func runNamespace(env *engine.Env) (string, []model.Result) {
	if env.Kube == nil {
		return "", noKube(env)
	}
	if env.RunNamespace == "" {
		reason := "Preflight's temporary namespace is not available"
		if env.RunNamespaceErr != nil {
			reason += ": " + env.RunNamespaceErr.Error()
		}
		return "", skip(reason)
	}
	return env.RunNamespace, nil
}

func storageClass(ctx context.Context, env *engine.Env) (*storagev1.StorageClass, error) {
	sc := env.Kube.Core.StorageV1().StorageClasses()
	if name := env.Settings.StorageClass; name != "" {
		c, err := sc.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("storage class %s (from the settings file): %w", name, err)
		}
		return c, nil
	}
	list, err := sc.List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list storage classes: %w", err)
	}
	for i := range list.Items {
		if list.Items[i].Annotations[defaultClassAnn] == "true" {
			return &list.Items[i], nil
		}
	}
	return nil, errors.New("no default storage class, and storageClass is not set in the settings file")
}

// k8s10: a storage class provisions a volume. Creates a 1Gi claim in the
// run namespace and waits for it to bind; cleanup deletes the claim, the
// namespace and any retained volume.
func k8s10(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	ns, skipped := runNamespace(env)
	if skipped != nil {
		return skipped
	}
	class, err := storageClass(ctx, env)
	if err != nil {
		return one(verdict(model.ClusterScope(), ev("storageclass", "", false, "%v", err)))
	}
	reclaim := corev1.PersistentVolumeReclaimDelete
	if class.ReclaimPolicy != nil {
		reclaim = *class.ReclaimPolicy
	}
	binding := storagev1.VolumeBindingImmediate
	if class.VolumeBindingMode != nil {
		binding = *class.VolumeBindingMode
	}
	evidence := []model.Evidence{ev("storageclass", class.Name, true, "storage class %s (provisioner %s, binding %s, reclaim policy %s)", class.Name, class.Provisioner, binding, reclaim)}

	name := class.Name
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: testPVCName, Namespace: ns, Labels: orchestrator.Labels(runIDOf(ns))},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: &name,
			Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")}},
		},
	}
	if _, err := env.Kube.Core.CoreV1().PersistentVolumeClaims(ns).Create(ctx, pvc, metav1.CreateOptions{}); err != nil {
		return one(verdict(model.ClusterScope(), append(evidence, ev("claim", testPVCName, false, "could not create the test claim: %v", err))...))
	}
	if binding == storagev1.VolumeBindingWaitForFirstConsumer {
		if env.ProbeImage == "" {
			return one(verdict(model.ClusterScope(), append(evidence, ev("claim", testPVCName, false, "the storage class binds on first use, and no probe image is configured to use the volume (pass --probe-image)"))...))
		}
		if err := createConsumer(ctx, env, ns); err != nil {
			return one(verdict(model.ClusterScope(), append(evidence, ev("claim", testPVCName, false, "could not create a pod to use the volume: %v", err))...))
		}
	}
	timeout := time.Duration(env.Params().VolumeBindTimeoutSeconds) * time.Second
	bound, volume, lastEvent := waitBound(ctx, env, ns, timeout)
	if !bound {
		detail := fmt.Sprintf("the test claim was not bound within %s", timeout)
		if lastEvent != "" {
			detail += " (" + lastEvent + ")"
		}
		return one(verdict(model.ClusterScope(), append(evidence, ev("claim", testPVCName, false, "%s", detail))...))
	}
	evidence = append(evidence, ev("claim", testPVCName, true, "a 1Gi volume was provisioned and bound (%s); it is deleted when the run ends", volume))
	r := verdict(model.ClusterScope(), evidence...)
	if reclaim == corev1.PersistentVolumeReclaimDelete {
		r.Status = model.StatusWarn
		r.Evidence = append(r.Evidence, ev("reclaim", class.Name, false, "reclaim policy is Delete: deleting a claim destroys its data, including Cassandra's"))
		r.Remediation = "Use a storage class with reclaim policy Retain for Armor's volumes, so data survives a deleted claim."
	}
	return one(r)
}

// runIDOf recovers the run ID from the run namespace name.
func runIDOf(ns string) string { return ns[len(orchestrator.NamespacePrefix):] }

func createConsumer(ctx context.Context, env *engine.Env, ns string) error {
	pod := orchestrator.PodSpec(testConsumerPod, ns, runIDOf(ns), "storage-test", env.ProbeImage, nil, nil, "", false)
	// The consumer only has to be scheduled with the volume; it runs the
	// probe binary with no request and exits.
	pod.Spec.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: testPVCName}}}}
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
	pod.Spec.Containers[0].Args = []string{"--request", "/nonexistent"}
	_, err := env.Kube.Core.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
	return err
}

func waitBound(ctx context.Context, env *engine.Env, ns string, timeout time.Duration) (bool, string, string) {
	deadline := time.Now().Add(timeout)
	for {
		pvc, err := env.Kube.Core.CoreV1().PersistentVolumeClaims(ns).Get(ctx, testPVCName, metav1.GetOptions{})
		if err == nil && pvc.Status.Phase == corev1.ClaimBound {
			return true, pvc.Spec.VolumeName, ""
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false, "", lastWarning(context.WithoutCancel(ctx), env, ns, "PersistentVolumeClaim", testPVCName)
		}
		select {
		case <-ctx.Done():
		case <-time.After(pollInterval):
		}
	}
}

// lastWarning returns the newest Warning event for an object, to explain
// why it never became ready.
func lastWarning(ctx context.Context, env *engine.Env, ns, kind, name string) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	events, err := env.Kube.Core.CoreV1().Events(ns).List(ctx, metav1.ListOptions{FieldSelector: "involvedObject.kind=" + kind + ",involvedObject.name=" + name})
	if err != nil {
		return ""
	}
	var latest *corev1.Event
	for i := range events.Items {
		e := &events.Items[i]
		if e.Type == corev1.EventTypeWarning && (latest == nil || e.LastTimestamp.After(latest.LastTimestamp.Time)) {
			latest = e
		}
	}
	if latest == nil {
		return ""
	}
	return latest.Reason + ": " + latest.Message
}

// k8s11: a LoadBalancer Service receives an address. The Service has no
// selector, so it never routes traffic, and asks for an internal load
// balancer so nothing is exposed to the internet.
func k8s11(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	ns, skipped := runNamespace(env)
	if skipped != nil {
		return skipped
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: testServiceName, Namespace: ns, Labels: orchestrator.Labels(runIDOf(ns)),
			Annotations: map[string]string{internalLBAnn: "true"}},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Name: "test", Port: 443, TargetPort: intstr.FromInt32(8443), Protocol: corev1.ProtocolTCP}},
		},
	}
	if _, err := env.Kube.Core.CoreV1().Services(ns).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
		return one(verdict(model.ClusterScope(), ev("service", testServiceName, false, "could not create the test Service: %v", err)))
	}
	timeout := time.Duration(env.Params().LoadBalancerTimeoutSeconds) * time.Second
	deadline := time.Now().Add(timeout)
	for {
		got, err := env.Kube.Core.CoreV1().Services(ns).Get(ctx, testServiceName, metav1.GetOptions{})
		if err == nil && len(got.Status.LoadBalancer.Ingress) > 0 {
			in := got.Status.LoadBalancer.Ingress[0]
			addr := in.IP
			if addr == "" {
				addr = in.Hostname
			}
			return one(verdict(model.ClusterScope(), ev("service", testServiceName, true, "an internal LoadBalancer Service received address %s; it is deleted when the run ends", addr)))
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			detail := fmt.Sprintf("the test LoadBalancer Service received no address within %s", timeout)
			if w := lastWarning(context.WithoutCancel(ctx), env, ns, "Service", testServiceName); w != "" {
				detail += " (" + w + ")"
			}
			return one(verdict(model.ClusterScope(), ev("service", testServiceName, false, "%s", detail)))
		}
		select {
		case <-ctx.Done():
		case <-time.After(pollInterval):
		}
	}
}
