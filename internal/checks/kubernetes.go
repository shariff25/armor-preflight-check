package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/shariff25/armor-preflight-check/internal/catalog"
	"github.com/shariff25/armor-preflight-check/internal/engine"
	"github.com/shariff25/armor-preflight-check/internal/model"
)

var (
	crdGVR           = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	clusterIssuerGVR = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers"}
)

// k8s01: Kubernetes version.
func k8s01(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Kube == nil {
		return noKube(env)
	}
	v, err := env.Kube.Core.Discovery().ServerVersion()
	if err != nil {
		return one(verdict(model.ClusterScope(), ev("version", "", false, "could not read the server version: %v", err)))
	}
	min := env.Params().MinKubernetes
	ok, err := versionAtLeast(v.GitVersion, min)
	if err != nil {
		return one(verdict(model.ClusterScope(), ev("version", "", false, "unrecognised server version %q", v.GitVersion)))
	}
	if !ok {
		return one(verdict(model.ClusterScope(), ev("version", "", false, "Kubernetes %s is older than %s", v.GitVersion, min)))
	}
	return one(verdict(model.ClusterScope(), ev("version", "", true, "Kubernetes %s (minimum %s); follow the AKS supported upgrade path for later upgrades", v.GitVersion, min)))
}

// profileWarn turns a pass into a warning on clusters that are not AKS, so
// an unsupported profile is never a silent pass (D-8).
func profileWarn(c *cluster, r model.Result) model.Result {
	if c.aks {
		return r
	}
	r.Evidence = append(r.Evidence, ev("profile", "", false, "unsupported profile: no AKS node labels or Azure provider IDs found; Armor on-prem is validated on AKS"))
	if r.Status == model.StatusPass {
		r.Status = model.StatusWarn
	}
	return r
}

// poolSize checks that enough Linux nodes of the right size exist.
func poolSize(c *cluster, pool catalog.Pool, need int, tolerance float64, label string, members []*node) model.Result {
	var evidence []model.Evidence
	good := 0
	skuRE := compileOrNil(pool.SKUPattern)
	for _, n := range members {
		if n.n.Status.NodeInfo.OperatingSystem != "linux" {
			evidence = append(evidence, ev("node", n.name, false, "%s runs %s, not Linux", n.name, n.n.Status.NodeInfo.OperatingSystem))
			continue
		}
		if skuRE != nil && n.sku != "" && !skuRE.MatchString(n.sku) {
			evidence = append(evidence, ev("node", n.name, false, "%s is %s, not an SGX-capable DCsv3 size", n.name, n.sku))
			continue
		}
		ok, desc := sizeOK(n, pool, tolerance)
		evidence = append(evidence, ev("node", n.name, ok, "%s", desc))
		if ok {
			good++
		}
	}
	summary := ev("count", label, good >= need, "%d suitable node(s) in the %s; %d required", good, label, need)
	evidence = append([]model.Evidence{summary}, evidence...)
	if good >= need {
		return result(model.StatusPass, model.ClusterScope(), evidence...)
	}
	return result(model.StatusFail, model.ClusterScope(), evidence...)
}

// k8s02: system pool.
func k8s02(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Kube == nil {
		return noKube(env)
	}
	p := env.Params()
	c, err := discover(ctx, env)
	if err != nil {
		return one(verdict(model.ClusterScope(), ev("nodes", "", false, "%v", err)))
	}
	var members []*node
	for i := range c.nodes {
		if c.nodes[i].system {
			members = append(members, &c.nodes[i])
		}
	}
	label := "system pool " + strings.Join(c.poolNames(func(n *node) bool { return n.system }), ", ")
	if len(members) == 0 {
		label = "system pool"
	}
	return one(profileWarn(c, poolSize(c, p.SystemPool, p.SystemPool.MinNodes, p.MemoryTolerance, label, members)))
}

// k8s03: SGX user pool.
func k8s03(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Kube == nil {
		return noKube(env)
	}
	p := env.Params()
	c, err := discover(ctx, env)
	if err != nil {
		return one(verdict(model.ClusterScope(), ev("nodes", "", false, "%v", err)))
	}
	need := p.SGXPool.MinNodes
	if r := env.Settings.Replicas; r > need {
		need = r
	}
	members := c.sgxNodes()
	label := "SGX pool " + strings.Join(c.poolNames(func(n *node) bool { return n.sgx }), ", ")
	if len(members) == 0 {
		label = "SGX pool"
	}
	return one(profileWarn(c, poolSize(c, p.SGXPool, need, p.MemoryTolerance, label, members)))
}

// k8s04: node OS, per node.
func k8s04(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Kube == nil {
		return noKube(env)
	}
	nodes, err := listNodes(ctx, env)
	if err != nil {
		return skip("could not list nodes: " + err.Error())
	}
	want := env.Params().ValidatedOS
	var out []model.Result
	for _, n := range nodes {
		info := n.Status.NodeInfo
		scope := model.NodeScope(n.Name)
		switch {
		case info.OperatingSystem != "linux":
			out = append(out, verdict(scope, ev("os", n.Name, false, "%s runs %s (%s); Armor needs Linux", n.Name, info.OperatingSystem, info.OSImage)))
		case !strings.HasPrefix(info.OSImage, want):
			out = append(out, verdict(scope, ev("os", n.Name, false, "%s runs %s; the validated OS is %s.x", n.Name, info.OSImage, want)))
		default:
			out = append(out, verdict(scope, ev("os", n.Name, true, "%s runs %s", n.Name, info.OSImage)))
		}
	}
	if len(out) == 0 {
		return one(verdict(model.ClusterScope(), ev("nodes", "", false, "the cluster has no nodes")))
	}
	return out
}

// crdsInGroups lists CRD names whose group is one of groups.
func crdsInGroups(ctx context.Context, env *engine.Env, groups []string) ([]string, error) {
	list, err := env.Kube.Dynamic.Resource(crdGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list CRDs: %w", err)
	}
	want := map[string]bool{}
	for _, g := range groups {
		want[g] = true
	}
	var out []string
	for _, item := range list.Items {
		group, _, _ := unstructured.NestedString(item.Object, "spec", "group")
		if want[group] {
			out = append(out, item.GetName())
		}
	}
	sort.Strings(out)
	return out, nil
}

// podsWithImage finds pods whose containers use an image containing any of
// the given substrings, as "namespace/pod (image)".
func podsWithImage(ctx context.Context, env *engine.Env, substrings ...string) ([]corev1.Pod, error) {
	pods, err := listPods(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	var out []corev1.Pod
	for _, p := range pods {
		if imageMatching(p, substrings...) != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

func imageMatching(p corev1.Pod, substrings ...string) string {
	for _, c := range p.Spec.Containers {
		for _, s := range substrings {
			if strings.Contains(c.Image, s) {
				return c.Image
			}
		}
	}
	return ""
}

func podReady(p corev1.Pod) bool {
	if p.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// k8s05: no K8ssandra.
func k8s05(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Kube == nil {
		return noKube(env)
	}
	crds, err := crdsInGroups(ctx, env, env.Params().K8ssandraCRDGroups)
	if err != nil {
		return one(verdict(model.ClusterScope(), ev("crds", "", false, "%v", err)))
	}
	pods, err := podsWithImage(ctx, env, "k8ssandra-operator", "cass-operator")
	if err != nil {
		return one(verdict(model.ClusterScope(), ev("pods", "", false, "%v", err)))
	}
	var evidence []model.Evidence
	if len(crds) > 0 {
		evidence = append(evidence, ev("crds", "", false, "K8ssandra CRDs present: %s", strings.Join(crds, ", ")))
	} else {
		evidence = append(evidence, ev("crds", "", true, "no CRDs in %s", strings.Join(env.Params().K8ssandraCRDGroups, ", ")))
	}
	if len(pods) > 0 {
		var names []string
		for _, p := range pods {
			names = append(names, p.Namespace+"/"+p.Name)
		}
		evidence = append(evidence, ev("operator", "", false, "K8ssandra operator pods running: %s", strings.Join(names, ", ")))
	} else {
		evidence = append(evidence, ev("operator", "", true, "no k8ssandra-operator or cass-operator pods"))
	}
	return one(verdict(model.ClusterScope(), evidence...))
}

// k8s06: no existing Armor operator.
func k8s06(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	group := env.Params().ArmorOperatorCRDGroup
	if isTBD(group) {
		return tbd("parameters.armorOperatorCrdGroup")
	}
	if env.Kube == nil {
		return noKube(env)
	}
	crds, err := crdsInGroups(ctx, env, []string{group})
	if err != nil {
		return one(verdict(model.ClusterScope(), ev("crds", "", false, "%v", err)))
	}
	if len(crds) > 0 {
		return one(verdict(model.ClusterScope(), ev("crds", group, false, "an Armor operator is already installed (CRDs %s); only one is supported per cluster", strings.Join(crds, ", "))))
	}
	return one(verdict(model.ClusterScope(), ev("crds", group, true, "no CRDs in %s", group)))
}

// ingressControllers maps well-known IngressClass controllers to a pod
// label that identifies their pods.
var ingressControllers = map[string][2]string{
	"k8s.io/ingress-nginx":                     {"app.kubernetes.io/name", "ingress-nginx"},
	"azure/application-gateway":                {"app", "ingress-appgw"},
	"webapprouting.kubernetes.azure.com/nginx": {"app", "nginx"},
	"traefik.io/ingress-controller":            {"app.kubernetes.io/name", "traefik"},
}

// k8s07: ingress controller and IngressClass.
func k8s07(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Kube == nil {
		return noKube(env)
	}
	classes, err := env.Kube.Core.NetworkingV1().IngressClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return one(verdict(model.ClusterScope(), ev("ingressclass", "", false, "list IngressClasses: %v", err)))
	}
	if len(classes.Items) == 0 {
		return one(verdict(model.ClusterScope(), ev("ingressclass", "", false, "no IngressClass exists")))
	}
	pods, err := listPods(ctx, env)
	if err != nil {
		return one(verdict(model.ClusterScope(), ev("controller", "", false, "list pods: %v", err)))
	}
	var evidence []model.Evidence
	anyRunning := false
	for _, ic := range classes.Items {
		ctrl := ic.Spec.Controller
		var ready []string
		for _, p := range pods {
			if podReady(p) && isIngressPod(p, ctrl) {
				ready = append(ready, p.Namespace+"/"+p.Name)
			}
		}
		if len(ready) > 0 {
			anyRunning = true
			evidence = append(evidence, ev("controller", ic.Name, true, "IngressClass %s (%s): controller pods ready: %s", ic.Name, ctrl, strings.Join(ready, ", ")))
		} else {
			evidence = append(evidence, ev("controller", ic.Name, false, "IngressClass %s (%s): no ready controller pods found", ic.Name, ctrl))
		}
	}
	if anyRunning {
		return one(result(model.StatusPass, model.ClusterScope(), evidence...))
	}
	return one(result(model.StatusFail, model.ClusterScope(), evidence...))
}

func isIngressPod(p corev1.Pod, controller string) bool {
	if sel, ok := ingressControllers[controller]; ok {
		return p.Labels[sel[0]] == sel[1]
	}
	for _, key := range []string{"app.kubernetes.io/name", "app.kubernetes.io/component", "app"} {
		if v := p.Labels[key]; strings.Contains(v, "ingress") {
			return true
		}
	}
	return false
}

// k8s08: cert-manager and a Ready ClusterIssuer.
func k8s08(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Kube == nil {
		return noKube(env)
	}
	crds, err := crdsInGroups(ctx, env, []string{"cert-manager.io"})
	if err != nil {
		return one(verdict(model.ClusterScope(), ev("crds", "", false, "%v", err)))
	}
	if len(crds) == 0 {
		return one(verdict(model.ClusterScope(), ev("crds", "cert-manager.io", false, "cert-manager is not installed (no cert-manager.io CRDs)")))
	}
	evidence := []model.Evidence{ev("crds", "cert-manager.io", true, "cert-manager CRDs present (%d)", len(crds))}

	pods, err := podsWithImage(ctx, env, "cert-manager-controller")
	if err != nil {
		return one(verdict(model.ClusterScope(), ev("controller", "", false, "%v", err)))
	}
	version := ""
	for _, p := range pods {
		if podReady(p) {
			version = imageTag(imageMatching(p, "cert-manager-controller"))
			break
		}
	}
	if version == "" && len(pods) == 0 {
		evidence = append(evidence, ev("controller", "", false, "no cert-manager controller pod found"))
	} else if version == "" {
		evidence = append(evidence, ev("controller", "", false, "cert-manager controller pod is not ready"))
	}

	issuers, err := env.Kube.Dynamic.Resource(clusterIssuerGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		evidence = append(evidence, ev("clusterissuer", "", false, "list ClusterIssuers: %v", err))
	} else {
		var ready, notReady []string
		for _, ci := range issuers.Items {
			if conditionTrue(ci, "Ready") {
				ready = append(ready, ci.GetName())
			} else {
				notReady = append(notReady, ci.GetName())
			}
		}
		switch {
		case len(ready) > 0:
			evidence = append(evidence, ev("clusterissuer", "", true, "Ready ClusterIssuers: %s", strings.Join(ready, ", ")))
		case len(notReady) > 0:
			evidence = append(evidence, ev("clusterissuer", "", false, "no ClusterIssuer is Ready (%s)", strings.Join(notReady, ", ")))
		default:
			evidence = append(evidence, ev("clusterissuer", "", false, "no ClusterIssuer exists"))
		}
	}

	r := verdict(model.ClusterScope(), evidence...)
	if version == "" {
		return one(r)
	}
	supported := env.Params().CertManagerVersions
	if isTBD(supported) {
		r.Evidence = append(r.Evidence, ev("version", "", false, "cert-manager %s found; the supported version range is not published yet (catalog value certManagerVersions is TBD), so the version is unverified", version))
		if r.Status == model.StatusPass {
			r.Status = model.StatusWarn
		}
		return one(r)
	}
	ok, err := versionAtLeast(version, supported)
	if err != nil {
		ok = false
	}
	r.Evidence = append(r.Evidence, ev("version", "", ok, "cert-manager %s (supported: %s and later)", version, supported))
	if !ok {
		r.Status = model.StatusFail
	}
	return one(r)
}

func conditionTrue(u unstructured.Unstructured, condType string) bool {
	conds, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if ok && m["type"] == condType && m["status"] == "True" {
			return true
		}
	}
	return false
}

// installerPermissions are what the Armor install needs (K8S-09).
var installerPermissions = []struct {
	desc string
	attr authv1.ResourceAttributes
}{
	{"create CustomResourceDefinitions", authv1.ResourceAttributes{Verb: "create", Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions"}},
	{"create ClusterRoles", authv1.ResourceAttributes{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "clusterroles"}},
	{"create namespaces", authv1.ResourceAttributes{Verb: "create", Resource: "namespaces"}},
	{"approve CertificateSigningRequests", authv1.ResourceAttributes{Verb: "update", Group: "certificates.k8s.io", Resource: "certificatesigningrequests", Subresource: "approval"}},
	{"approve for any signer", authv1.ResourceAttributes{Verb: "approve", Group: "certificates.k8s.io", Resource: "signers"}},
}

// k8s09: installer permissions, via SelfSubjectAccessReview (D-1).
func k8s09(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Kube == nil {
		return noKube(env)
	}
	var evidence []model.Evidence
	for _, p := range installerPermissions {
		attr := p.attr
		review, err := env.Kube.Core.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx,
			&authv1.SelfSubjectAccessReview{Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &attr}}, metav1.CreateOptions{})
		if err != nil {
			evidence = append(evidence, ev("access", p.desc, false, "could not check: %v", err))
			continue
		}
		if review.Status.Allowed {
			evidence = append(evidence, ev("access", p.desc, true, "allowed"))
		} else {
			reason := review.Status.Reason
			if reason == "" {
				reason = "denied"
			}
			evidence = append(evidence, ev("access", p.desc, false, "not allowed for the identity running Preflight (%s); run Preflight with the installer's credentials to check the installer", reason))
		}
	}
	return one(verdict(model.ClusterScope(), evidence...))
}

// k8s12: pod and service CIDRs (info).
func k8s12(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Kube == nil {
		return noKube(env)
	}
	pods, services, notes := discoverCIDRs(ctx, env)
	var evidence []model.Evidence
	if len(pods) > 0 {
		evidence = append(evidence, ev("pods", "", true, "pod CIDRs: %s", strings.Join(pods, ", ")))
	}
	if len(services) > 0 {
		evidence = append(evidence, ev("services", "", true, "service CIDRs: %s", strings.Join(services, ", ")))
	}
	for _, n := range notes {
		evidence = append(evidence, ev("note", "", false, "%s", n))
	}
	return one(result(model.StatusInfo, model.ClusterScope(), evidence...))
}

// discoverCIDRs reads node pod CIDRs and ServiceCIDR objects.
func discoverCIDRs(ctx context.Context, env *engine.Env) (pods, services, notes []string) {
	seen := map[string]bool{}
	nodes, err := listNodes(ctx, env)
	if err != nil {
		notes = append(notes, "could not list nodes: "+err.Error())
	} else {
		for _, n := range nodes {
			cidrs := n.Spec.PodCIDRs
			if len(cidrs) == 0 && n.Spec.PodCIDR != "" {
				cidrs = []string{n.Spec.PodCIDR}
			}
			for _, c := range cidrs {
				if !seen[c] {
					seen[c] = true
					pods = append(pods, c)
				}
			}
		}
	}
	if len(pods) == 0 && err == nil {
		notes = append(notes, "nodes report no pod CIDR (Azure CNI without overlay gives pods addresses from the node subnet); record the node subnets as internalSubnets")
	}
	scs, err := env.Kube.Core.NetworkingV1().ServiceCIDRs().List(ctx, metav1.ListOptions{})
	if err != nil {
		notes = append(notes, "could not list ServiceCIDRs: "+err.Error()+"; read the service CIDR from the AKS network profile")
	} else {
		for _, sc := range scs.Items {
			services = append(services, sc.Spec.CIDRs...)
		}
		if len(services) == 0 {
			notes = append(notes, "no ServiceCIDR objects found; read the service CIDR from the AKS network profile")
		}
	}
	sort.Strings(pods)
	sort.Strings(services)
	return pods, services, notes
}
