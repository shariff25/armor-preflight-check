package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/shariff25/armor-preflight-check/internal/probe/protocol"
)

// MaxLogBytes caps how much of a probe's log is read, so a misbehaving or
// hostile probe cannot exhaust the CLI's memory. A real result is a few KB.
const MaxLogBytes = 4 << 20

// LogSource reads a pod's log. Tests replace it; the fake clientset cannot
// produce real logs.
type LogSource func(ctx context.Context, namespace, pod string) (string, error)

// Orchestrator runs one Preflight run's objects in the cluster.
type Orchestrator struct {
	Core      kubernetes.Interface
	RunID     string
	Image     string
	Logs      LogSource
	Poll      time.Duration
	Now       func() time.Time
	Namespace string

	created bool
}

// New returns an orchestrator for a run.
func New(core kubernetes.Interface, runID, image string) *Orchestrator {
	o := &Orchestrator{Core: core, RunID: runID, Image: image, Poll: 2 * time.Second, Now: time.Now, Namespace: NamespaceName(runID)}
	o.Logs = func(ctx context.Context, ns, pod string) (string, error) {
		limit := int64(MaxLogBytes)
		b, err := core.CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{Container: ContainerName, LimitBytes: &limit}).DoRaw(ctx)
		return string(b), err
	}
	return o
}

// CreateNamespace creates the run's namespace. The namespace enforces the
// Pod Security Standards restricted profile, so the API server itself
// rejects any probe pod that would weaken it.
func (o *Orchestrator) CreateNamespace(ctx context.Context) error {
	labels := Labels(o.RunID)
	labels["pod-security.kubernetes.io/enforce"] = "restricted"
	labels["pod-security.kubernetes.io/enforce-version"] = "latest"
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: o.Namespace, Labels: labels}}
	if _, err := o.Core.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create namespace %s: %w", o.Namespace, err)
	}
	o.created = true
	return nil
}

// ProbeRecord describes a probe pod that ran, for the report.
type ProbeRecord struct {
	NodePool string
	Node     string
	Pod      string
	Image    string
	ImageID  string
}

// Outcome is what the probes produced.
type Outcome struct {
	Results    map[string]protocol.Result // by node pool
	PoolErrors map[string]string          // by node pool: why no result
	Probes     []ProbeRecord
	// Unavailable is set when no probe could run at all, for example
	// because the image could not be pulled anywhere.
	Unavailable string
}

// RunProbes starts one probe pod per pool and waits up to timeout for them.
// secretData, when non-empty, is mounted read-only into every probe (D-3).
func (o *Orchestrator) RunProbes(ctx context.Context, pools []Pool, request func(pool string) protocol.Request, secretData map[string][]byte, timeout time.Duration) (*Outcome, error) {
	out := &Outcome{Results: map[string]protocol.Result{}, PoolErrors: map[string]string{}}
	if len(pools) == 0 {
		out.Unavailable = "no node pools found to run probes on"
		return out, nil
	}
	if len(secretData) > 0 {
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: CredentialsSecret, Namespace: o.Namespace, Labels: Labels(o.RunID)}, Data: secretData}
		if _, err := o.Core.CoreV1().Secrets(o.Namespace).Create(ctx, s, metav1.CreateOptions{}); err != nil {
			return nil, fmt.Errorf("create probe credentials: %w", err)
		}
	}
	podPool := map[string]string{}
	for _, p := range pools {
		req := request(p.Name)
		body, err := json.Marshal(req)
		if err != nil {
			return nil, err
		}
		cmName := objectName(RequestConfigMapPrefix, p.Name)
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: o.Namespace, Labels: Labels(o.RunID)},
			Data: map[string]string{"request.json": string(body)}}
		if _, err := o.Core.CoreV1().ConfigMaps(o.Namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			return nil, fmt.Errorf("create probe request for %s: %w", p.Name, err)
		}
		podName := objectName("probe-", p.Name)
		pod := PodSpec(podName, o.Namespace, o.RunID, p.Name, o.Image, p.Selector, p.Tolerations, cmName, len(secretData) > 0)
		if _, err := o.Core.CoreV1().Pods(o.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
			out.PoolErrors[p.Name] = fmt.Sprintf("probe pod could not be created: %v", err)
			continue
		}
		podPool[podName] = p.Name
	}
	o.wait(ctx, waitSpec{keys: podPool, image: o.Image}, timeout, out)
	sort.Slice(out.Probes, func(i, j int) bool { return out.Probes[i].NodePool < out.Probes[j].NodePool })

	pullFailures := 0
	for _, reason := range out.PoolErrors {
		if strings.Contains(reason, "could not be pulled") {
			pullFailures++
		}
	}
	if len(out.Results) == 0 && pullFailures > 0 && pullFailures == len(out.PoolErrors) {
		out.Unavailable = fmt.Sprintf("probe image %s could not be pulled on any node pool; mirror that image into a registry the nodes can reach and pass it with --probe-image", o.Image)
	}
	return out, ctx.Err()
}

// SGXResources are requested by per-node SGX probes, so the SGX device
// plugin mounts the enclave and provisioning devices (no privileges needed).
var SGXResources = []corev1.ResourceName{"sgx.intel.com/enclave", "sgx.intel.com/provision"}

// NodeTarget is one node to run a per-node probe on.
type NodeTarget struct {
	Name        string
	Tolerations []corev1.Toleration
}

// RunNodeProbes runs one SGX probe pod on each node (CC-05), pinned by
// hostname and requesting the SGX device plugin resources. Results are
// keyed by node name.
func (o *Orchestrator) RunNodeProbes(ctx context.Context, image string, nodes []NodeTarget, request func(node string) protocol.Request, timeout time.Duration) (*Outcome, error) {
	out := &Outcome{Results: map[string]protocol.Result{}, PoolErrors: map[string]string{}}
	podNode := map[string]string{}
	for _, n := range nodes {
		body, err := json.Marshal(request(n.Name))
		if err != nil {
			return nil, err
		}
		cmName := objectName("sgx-request-", n.Name)
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: o.Namespace, Labels: Labels(o.RunID)},
			Data: map[string]string{"request.json": string(body)}}
		if _, err := o.Core.CoreV1().ConfigMaps(o.Namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			return nil, fmt.Errorf("create SGX probe request for %s: %w", n.Name, err)
		}
		podName := objectName("sgx-probe-", n.Name)
		pod := PodSpec(podName, o.Namespace, o.RunID, n.Name, image, map[string]string{"kubernetes.io/hostname": n.Name}, n.Tolerations, cmName, false)
		delete(pod.Labels, LabelNodePool)
		pod.Labels[LabelNode] = labelValue(n.Name)
		c := &pod.Spec.Containers[0]
		for _, r := range SGXResources {
			one := resource.MustParse("1")
			c.Resources.Requests[r] = one
			c.Resources.Limits[r] = one
		}
		if _, err := o.Core.CoreV1().Pods(o.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
			out.PoolErrors[n.Name] = fmt.Sprintf("SGX probe pod could not be created: %v", err)
			continue
		}
		podNode[podName] = n.Name
	}
	o.wait(ctx, waitSpec{keys: podNode, image: image, perNode: true}, timeout, out)
	sort.Slice(out.Probes, func(i, j int) bool { return out.Probes[i].Node < out.Probes[j].Node })
	return out, ctx.Err()
}

// pullWaitReasons mean the image cannot be pulled.
var pullWaitReasons = map[string]bool{"ErrImagePull": true, "ImagePullBackOff": true, "InvalidImageName": true, "ErrImageNeverPull": true}

// waitSpec says which pods to wait for: pod name -> node pool (or node,
// for per-node probes).
type waitSpec struct {
	keys    map[string]string
	image   string
	perNode bool
}

func (s waitSpec) where(key string) string {
	if s.perNode {
		return "node " + key
	}
	return "node pool " + key
}

func (s waitSpec) record(key, pod, node string) ProbeRecord {
	if s.perNode {
		return ProbeRecord{Node: key, Pod: pod, Image: s.image}
	}
	return ProbeRecord{NodePool: key, Node: node, Pod: pod, Image: s.image}
}

func (o *Orchestrator) wait(ctx context.Context, spec waitSpec, timeout time.Duration, out *Outcome) {
	podPool := spec.keys
	deadline := o.Now().Add(timeout)
	pending := map[string]bool{}
	for name := range podPool {
		pending[name] = true
	}
	for len(pending) > 0 {
		pods, err := o.Core.CoreV1().Pods(o.Namespace).List(ctx, metav1.ListOptions{LabelSelector: LabelRunID + "=" + o.RunID})
		if err == nil {
			for i := range pods.Items {
				p := &pods.Items[i]
				pool, ok := podPool[p.Name]
				if !ok || !pending[p.Name] {
					continue
				}
				if done := o.observe(ctx, p, pool, spec, out); done {
					delete(pending, p.Name)
				}
			}
		}
		if len(pending) == 0 || ctx.Err() != nil {
			break
		}
		if !o.Now().Before(deadline) {
			for name := range pending {
				pool := podPool[name]
				if _, has := out.PoolErrors[pool]; !has {
					out.PoolErrors[pool] = fmt.Sprintf("probe pod %s did not finish within %s", name, timeout)
				}
				out.Probes = append(out.Probes, spec.record(pool, name, ""))
			}
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(o.Poll):
		}
	}
	for name := range pending {
		out.PoolErrors[podPool[name]] = "interrupted before the probe finished"
		out.Probes = append(out.Probes, spec.record(podPool[name], name, ""))
	}
}

// observe records a pod's state; it returns true once nothing more will
// change for that pod.
func (o *Orchestrator) observe(ctx context.Context, p *corev1.Pod, pool string, spec waitSpec, out *Outcome) bool {
	rec := spec.record(pool, p.Name, p.Spec.NodeName)
	for _, cs := range p.Status.ContainerStatuses {
		if cs.ImageID != "" {
			rec.ImageID = cs.ImageID
		}
		if w := cs.State.Waiting; w != nil && pullWaitReasons[w.Reason] {
			out.PoolErrors[pool] = fmt.Sprintf("probe image %s could not be pulled on %s (%s: %s)", spec.image, spec.where(pool), w.Reason, firstLine(w.Message))
			out.Probes = append(out.Probes, rec)
			return true
		}
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason == corev1.PodReasonUnschedulable {
			out.PoolErrors[pool] = fmt.Sprintf("probe pod could not be scheduled on %s: %s", spec.where(pool), firstLine(c.Message))
			// Keep waiting: the scheduler may still place it before the deadline.
			return false
		}
	}
	switch p.Status.Phase {
	case corev1.PodSucceeded, corev1.PodFailed:
	default:
		return false
	}
	delete(out.PoolErrors, pool)
	out.Probes = append(out.Probes, rec)
	log, err := o.Logs(ctx, o.Namespace, p.Name)
	if err != nil {
		out.PoolErrors[pool] = fmt.Sprintf("could not read the probe log: %v", err)
		return true
	}
	res, err := protocol.Decode(log)
	switch {
	case err != nil:
		out.PoolErrors[pool] = fmt.Sprintf("probe on %s returned no usable result: %v", spec.where(pool), err)
	case res.Error != "":
		out.PoolErrors[pool] = fmt.Sprintf("probe on %s failed: %s", spec.where(pool), res.Error)
	case res.RunID != o.RunID:
		out.PoolErrors[pool] = fmt.Sprintf("probe on %s answered for run %q", spec.where(pool), res.RunID)
	default:
		out.Results[pool] = res
	}
	return true
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Cleanup deletes the run namespace (and with it every object inside) and
// any persistent volume left behind by a claim in it, then waits for the
// namespace to disappear.
func (o *Orchestrator) Cleanup(ctx context.Context) error {
	if !o.created {
		return nil
	}
	var errs []error
	if err := deleteNamespace(ctx, o.Core, o.Namespace); err != nil {
		errs = append(errs, err)
	}
	if _, err := deleteClaimedVolumes(ctx, o.Core, func(ns string) bool { return ns == o.Namespace }); err != nil {
		errs = append(errs, err)
	}
	if err := waitGone(ctx, o.Core, o.Namespace, o.Poll); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func deleteNamespace(ctx context.Context, core kubernetes.Interface, name string) error {
	bg := metav1.DeletePropagationBackground
	err := core.CoreV1().Namespaces().Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: &bg})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete namespace %s: %w", name, err)
	}
	return nil
}

// deleteClaimedVolumes deletes persistent volumes whose claim was in a
// namespace accepted by owned. Volumes with reclaim policy Retain outlive
// their claim, so deleting the namespace alone would leave them behind.
func deleteClaimedVolumes(ctx context.Context, core kubernetes.Interface, owned func(namespace string) bool) ([]string, error) {
	pvs, err := core.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list persistent volumes: %w", err)
	}
	var deleted []string
	var errs []error
	for _, pv := range pvs.Items {
		ref := pv.Spec.ClaimRef
		if ref == nil || !owned(ref.Namespace) {
			continue
		}
		if err := core.CoreV1().PersistentVolumes().Delete(ctx, pv.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete persistent volume %s: %w", pv.Name, err))
			continue
		}
		deleted = append(deleted, pv.Name)
	}
	return deleted, errors.Join(errs...)
}

func waitGone(ctx context.Context, core kubernetes.Interface, name string, poll time.Duration) error {
	for {
		_, err := core.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("namespace %s is still terminating; run `armor-preflight cleanup` later to confirm it is gone", name)
		case <-time.After(poll):
		}
	}
}

// Leftovers are objects from earlier runs that were not cleaned up (for
// example after the process was killed).
type Leftovers struct {
	Namespaces []string
	Volumes    []string
}

// RemoveLeftovers deletes every Preflight namespace (optionally only one
// run's) and every persistent volume claimed from one. A namespace must
// carry the managed-by label and the name prefix to be touched.
func RemoveLeftovers(ctx context.Context, core kubernetes.Interface, runID string) (*Leftovers, error) {
	sel := LabelManagedBy + "=" + ManagedByValue
	if runID != "" {
		sel += "," + LabelRunID + "=" + runID
	}
	nss, err := core.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, fmt.Errorf("list Preflight namespaces: %w", err)
	}
	out := &Leftovers{}
	var errs []error
	for _, ns := range nss.Items {
		if !strings.HasPrefix(ns.Name, NamespacePrefix) {
			continue
		}
		if err := deleteNamespace(ctx, core, ns.Name); err != nil {
			errs = append(errs, err)
			continue
		}
		out.Namespaces = append(out.Namespaces, ns.Name)
	}
	vols, err := deleteClaimedVolumes(ctx, core, func(ns string) bool {
		return strings.HasPrefix(ns, NamespacePrefix) && (runID == "" || ns == NamespaceName(runID))
	})
	out.Volumes = vols
	if err != nil {
		errs = append(errs, err)
	}
	return out, errors.Join(errs...)
}
