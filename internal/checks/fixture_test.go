package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/kube"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/registry/registrytest"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
)

const (
	regUser     = "example-user"
	regPassword = "fixture-registry-password"
	chartDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	imageDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	// testCRDGroup stands in for the Armor operator CRD group, which is
	// TBD in the shipped catalog.
	testCRDGroup = "armor.test.invalid"
)

// fixture is a fake AKS cluster and workstation that meets every
// prerequisite. Tests mutate it to break one check at a time.
type fixture struct {
	t              *testing.T
	nodes          []*corev1.Node
	pods           []*corev1.Pod
	ingressClasses []*networkingv1.IngressClass
	serviceCIDRs   []*networkingv1.ServiceCIDR
	namespaces     []*corev1.Namespace
	secrets        []*corev1.Secret
	crds           []*unstructured.Unstructured
	issuers        []*unstructured.Unstructured
	serverVersion  string
	deny           map[string]bool // SSAR resources to deny
	tools          map[string]string
	dns            map[string][]string
	settingsYAML   string
	envVars        map[string]string
	params         func(*catalog.Parameters)
	reg            *registrytest.Registry
	dir            string
	storageClasses []*storagev1.StorageClass
	bindVolumes    bool   // the fake provisioner binds claims
	lbAddress      string // the fake cloud assigns this address
	runNamespace   string

	core *fake.Clientset
	dyn  *dynamicfake.FakeDynamicClient
}

func mem(gi float64) resource.Quantity {
	return *resource.NewQuantity(int64(gi*float64(gib)), resource.BinarySI)
}

func mkNode(name, pool, mode, sku string, cpu int64, memGiB float64, sgx bool, cidr, ip string) *corev1.Node {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
			"kubernetes.azure.com/agentpool": pool, "kubernetes.azure.com/mode": mode, "node.kubernetes.io/instance-type": sku,
		}},
		Spec: corev1.NodeSpec{ProviderID: "azure:///subscriptions/x/" + name, PodCIDR: cidr, PodCIDRs: []string{cidr}},
		Status: corev1.NodeStatus{
			NodeInfo:    corev1.NodeSystemInfo{OperatingSystem: "linux", OSImage: "Ubuntu 24.04.2 LTS"},
			Capacity:    corev1.ResourceList{corev1.ResourceCPU: *resource.NewQuantity(cpu, resource.DecimalSI), corev1.ResourceMemory: mem(memGiB)},
			Allocatable: corev1.ResourceList{},
			Addresses:   []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}},
		},
	}
	if sgx {
		n.Labels["feature.node.kubernetes.io/cpu-security.sgx.enabled"] = "true"
		n.Status.Allocatable["sgx.intel.com/enclave"] = *resource.NewQuantity(1, resource.DecimalSI)
		n.Status.Allocatable["sgx.intel.com/provision"] = *resource.NewQuantity(1, resource.DecimalSI)
	}
	return n
}

func readyPod(ns, name, image string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: image}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
}

func crd(name, group string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("apiextensions.k8s.io/v1")
	u.SetKind("CustomResourceDefinition")
	u.SetName(name)
	unstructured.SetNestedField(u.Object, group, "spec", "group")
	return u
}

func issuer(name string, ready bool) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("cert-manager.io/v1")
	u.SetKind("ClusterIssuer")
	u.SetName(name)
	status := "False"
	if ready {
		status = "True"
	}
	unstructured.SetNestedSlice(u.Object, []any{map[string]any{"type": "Ready", "status": status}}, "status", "conditions")
	return u
}

func pullSecret(ns, name, host string, annotations map[string]string) *corev1.Secret {
	auth := base64.StdEncoding.EncodeToString([]byte(regUser + ":" + regPassword))
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: annotations},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, host, auth))},
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	reg := registrytest.New(regUser, regPassword)
	t.Cleanup(reg.Close)
	reg.Add("armor/charts/armor-operator", "1.0.404", chartDigest)
	dir := t.TempDir()
	f := &fixture{t: t, reg: reg, dir: dir, serverVersion: "v1.34.8", deny: map[string]bool{}}
	for i := 0; i < 3; i++ {
		f.nodes = append(f.nodes,
			mkNode(fmt.Sprintf("aks-systempool-%d", i), "systempool", "system", "Standard_D4ds_v5", 4, 15.6, false, fmt.Sprintf("10.244.%d.0/24", i), fmt.Sprintf("10.20.0.%d", 4+i)),
			mkNode(fmt.Sprintf("aks-sgxpool1-%d", i), "sgxpool1", "user", "Standard_DC8s_v3", 8, 62.8, true, fmt.Sprintf("10.244.%d.0/24", 10+i), fmt.Sprintf("10.20.4.%d", 4+i)))
	}
	f.pods = []*corev1.Pod{
		readyPod("ingress-nginx", "ingress-nginx-controller-0", "registry.k8s.io/ingress-nginx/controller:v1.11.2", map[string]string{"app.kubernetes.io/name": "ingress-nginx"}),
		readyPod("cert-manager", "cert-manager-0", "quay.io/jetstack/cert-manager-controller:v1.15.3", nil),
		readyPod("node-feature-discovery", "nfd-master-0", "registry.k8s.io/nfd/node-feature-discovery:v0.16.4", nil),
	}
	f.ingressClasses = []*networkingv1.IngressClass{{ObjectMeta: metav1.ObjectMeta{Name: "nginx"}, Spec: networkingv1.IngressClassSpec{Controller: "k8s.io/ingress-nginx"}}}
	f.serviceCIDRs = []*networkingv1.ServiceCIDR{{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes"}, Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.0.0.0/16"}}}}
	f.namespaces = []*corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "armor"}}}
	f.secrets = []*corev1.Secret{pullSecret("armor", "fortanix-pull", reg.Host(), map[string]string{"armor.example/expires": "2027-06-01"})}
	f.crds = []*unstructured.Unstructured{crd("certificates.cert-manager.io", "cert-manager.io"), crd("clusterissuers.cert-manager.io", "cert-manager.io")}
	f.issuers = []*unstructured.Unstructured{issuer("corp-ca", true)}
	f.tools = map[string]string{"kubectl": "Client Version: v1.34.1", "helm": "v3.16.2+g13654a5", "jq": "jq-1.7.1", "openssl": "OpenSSL 3.0.13 30 Jan 2024"}
	retain := corev1.PersistentVolumeReclaimRetain
	f.storageClasses = []*storagev1.StorageClass{{ObjectMeta: metav1.ObjectMeta{Name: "managed-csi-retain", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}},
		Provisioner: "disk.csi.azure.com", ReclaimPolicy: &retain}}
	f.bindVolumes, f.lbAddress, f.runNamespace = true, "10.20.8.40", "armor-preflight-20260926-1512-7f3a"
	f.dns = map[string][]string{"armor.example.com": {"10.20.8.10"}, "static.armor.example.com": {"10.20.8.11"}}
	certPath := writeChain(t, dir, "api.armor.example.com", true)
	f.settingsYAML = fmt.Sprintf(`armorVersion: "1.0.404"
armorNamespaces: [armor]
domains: {armor: armor.example.com, staticAssets: static.armor.example.com}
certificates: {caReady: true, sampleApiCertPath: %q}
registry: {mode: direct, url: %q, username: %s, passwordEnv: REG_PW}
storage: {accountFqdn: s.blob.core.windows.net, container: medusa, credentialsEnv: BAK_KEY, accountKind: StorageV2, performance: Standard, replication: ZRS}
proxy: {httpsProxy: "http://proxy.example.com:8080", noProxy: "10.244.0.0/16,10.0.0.0/16,.armor.example.com"}
`, certPath, reg.Host(), regUser)
	f.envVars = map[string]string{"REG_PW": regPassword, "BAK_KEY": "fixture-storage-key"}
	f.params = func(p *catalog.Parameters) {
		p.OperatorChartRef = reg.Host() + "/armor/charts/armor-operator"
		p.ArmorOperatorCRDGroup = testCRDGroup
		p.CertManagerVersions = "1.14.0"
	}
	return f
}

type fakeTools map[string]string

func (f fakeTools) LookPath(name string) (string, error) {
	if _, ok := f[name]; !ok {
		return "", errors.New("executable file not found in $PATH")
	}
	return "/usr/bin/" + name, nil
}

func (f fakeTools) Output(_ context.Context, name string, _ ...string) ([]byte, error) {
	v := f[filepath.Base(name)]
	if v == "" {
		return nil, errors.New("exit status 1")
	}
	return []byte(v + "\n"), nil
}

type fakeDNS map[string][]string

func (f fakeDNS) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, &netError{host}
}

type netError struct{ host string }

func (e *netError) Error() string { return "lookup " + e.host + ": no such host" }

// env builds the engine environment from the fixture.
func (f *fixture) env(mode engine.Mode) *engine.Env {
	t := f.t
	var objs []runtime.Object
	for _, n := range f.nodes {
		objs = append(objs, n)
	}
	for _, p := range f.pods {
		objs = append(objs, p)
	}
	for _, ic := range f.ingressClasses {
		objs = append(objs, ic)
	}
	for _, sc := range f.serviceCIDRs {
		objs = append(objs, sc)
	}
	for _, ns := range f.namespaces {
		objs = append(objs, ns)
	}
	for _, s := range f.secrets {
		objs = append(objs, s)
	}
	for _, sc := range f.storageClasses {
		objs = append(objs, sc)
	}
	f.core = fake.NewSimpleClientset(objs...)
	f.core.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{GitVersion: f.serverVersion}
	f.core.PrependReactor("create", "selfsubjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		r := a.(k8stesting.CreateAction).GetObject().(*authv1.SelfSubjectAccessReview)
		attr := r.Spec.ResourceAttributes
		r.Status.Allowed = !f.deny[attr.Resource+"/"+attr.Subresource]
		return true, r, nil
	})

	f.core.PrependReactor("create", "persistentvolumeclaims", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if f.bindVolumes {
			pvc := a.(k8stesting.CreateAction).GetObject().(*corev1.PersistentVolumeClaim)
			pvc.Status.Phase, pvc.Spec.VolumeName = corev1.ClaimBound, "pvc-0001"
		}
		return false, nil, nil
	})
	f.core.PrependReactor("create", "services", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if f.lbAddress != "" {
			svc := a.(k8stesting.CreateAction).GetObject().(*corev1.Service)
			svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: f.lbAddress}}
		}
		return false, nil, nil
	})

	scheme := runtime.NewScheme()
	var dynObjs []runtime.Object
	for _, c := range f.crds {
		dynObjs = append(dynObjs, c)
	}
	for _, i := range f.issuers {
		dynObjs = append(dynObjs, i)
	}
	f.dyn = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		crdGVR:           "CustomResourceDefinitionList",
		clusterIssuerGVR: "ClusterIssuerList",
	}, dynObjs...)

	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	f.params(&cat.Parameters)
	st, err := settings.Parse([]byte(f.settingsYAML))
	if err != nil {
		t.Fatal(err)
	}
	vars := f.envVars
	env := &engine.Env{
		Mode: mode, Catalog: cat, Settings: st, SettingsFile: "settings.yaml",
		LookupEnv:    func(k string) (string, bool) { v, ok := vars[k]; return v, ok },
		Kube:         &kube.Clients{Core: f.core, Dynamic: f.dyn, Context: "aks-armor-prod", Server: "https://aks-armor-prod.hcp.eastus.azmk8s.io:443"},
		Local:        fakeTools(f.tools),
		DNS:          fakeDNS(f.dns),
		HTTP:         f.reg.Client(),
		RunNamespace: f.runNamespace,
		ProbeImage:   "example.invalid/armor-preflight-probe@sha256:abc",
		Now:          func() time.Time { return time.Date(2026, 9, 26, 15, 12, 4, 0, time.UTC) },
	}
	env.Topology = Topology(context.Background(), env)
	f.core.ClearActions() // the topology lookup is the CLI's, not a check's
	return env
}

// writeChain writes leaf, intermediate and root certificates to a PEM file.
func writeChain(t *testing.T, dir, san string, complete bool) string {
	t.Helper()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	mk := func(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool, dns []string) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: now, NotAfter: now.AddDate(1, 0, 0), IsCA: ca, BasicConstraintsValid: true, DNSNames: dns}
		if ca {
			tmpl.KeyUsage = x509.KeyUsageCertSign
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key
	}
	root, rootKey := mk("Example Root CA", nil, nil, true, nil)
	inter, interKey := mk("Example Issuing CA", root, rootKey, true, nil)
	leaf, _ := mk(san, inter, interKey, false, []string{san})
	chain := []*x509.Certificate{leaf, inter, root}
	if !complete {
		chain = chain[:2]
	}
	var pemBytes []byte
	for _, c := range chain {
		pemBytes = append(pemBytes, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	p := filepath.Join(dir, fmt.Sprintf("chain-%d.pem", time.Now().UnixNano()))
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type unstructuredAlias = unstructured.Unstructured

func resourceQty(n int64) *resource.Quantity { return resource.NewQuantity(n, resource.DecimalSI) }
