package kube

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// apiServer records every request that reaches it.
type apiServer struct {
	mu   sync.Mutex
	seen []string
}

func (s *apiServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.seen = append(s.seen, r.Method+" "+r.URL.Path)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(r.URL.Path, "selfsubjectaccessreviews"):
		w.Write([]byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","status":{"allowed":true}}`))
	case r.URL.Path == "/api/v1/namespaces":
		w.Write([]byte(`{"apiVersion":"v1","kind":"NamespaceList","items":[]}`))
	default:
		w.Write([]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x"}}`))
	}
}

func clients(t *testing.T, o Options) (*Clients, *apiServer) {
	t.Helper()
	api := &apiServer{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	c, err := FromConfig(&rest.Config{Host: srv.URL}, "test", o)
	if err != nil {
		t.Fatal(err)
	}
	return c, api
}

func TestReadOnlyBlocksWritesBeforeTheyLeave(t *testing.T) {
	c, api := clients(t, Options{Mode: ReadOnly})
	ctx := context.Background()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "x"}}

	if _, err := c.Core.CoreV1().Namespaces().List(ctx, metav1.ListOptions{}); err != nil {
		t.Fatalf("read blocked: %v", err)
	}
	if _, err := c.Core.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("SSAR blocked: %v", err)
	}
	writes := map[string]func() error{
		"create": func() error {
			_, err := c.Core.CoreV1().ConfigMaps("default").Create(ctx, cm, metav1.CreateOptions{})
			return err
		},
		"update": func() error {
			_, err := c.Core.CoreV1().ConfigMaps("default").Update(ctx, cm, metav1.UpdateOptions{})
			return err
		},
		"patch": func() error {
			_, err := c.Core.CoreV1().ConfigMaps("default").Patch(ctx, "x", "application/merge-patch+json", []byte(`{}`), metav1.PatchOptions{})
			return err
		},
		"delete": func() error { return c.Core.CoreV1().ConfigMaps("default").Delete(ctx, "x", metav1.DeleteOptions{}) },
		"create namespace": func() error {
			_, err := c.Core.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "armor-preflight-x"}}, metav1.CreateOptions{})
			return err
		},
	}
	for name, do := range writes {
		var blocked *ErrBlocked
		if err := do(); !errors.As(err, &blocked) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	for _, s := range api.seen {
		if !strings.HasPrefix(s, "GET ") && s != "POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			t.Errorf("write reached the API server: %s", s)
		}
	}
	if len(c.Guard.Blocked()) != len(writes) {
		t.Errorf("blocked %v", c.Guard.Blocked())
	}
}

func TestRunNamespaceMode(t *testing.T) {
	g := &Guard{Mode: RunNamespace, Namespace: "armor-preflight-20260926-1512-7f3a"}
	allowed := []string{
		"POST /api/v1/namespaces",
		"DELETE /api/v1/namespaces/armor-preflight-20260926-1512-7f3a",
		"POST /api/v1/namespaces/armor-preflight-20260926-1512-7f3a/pods",
		"POST /api/v1/namespaces/armor-preflight-20260926-1512-7f3a/persistentvolumeclaims",
		"DELETE /api/v1/namespaces/armor-preflight-20260926-1512-7f3a/services/lb",
		"GET /api/v1/nodes",
		"DELETE /api/v1/persistentvolumes/pvc-123",
	}
	refused := []string{
		"POST /api/v1/namespaces/default/pods",
		"DELETE /api/v1/namespaces/armor-preflight-20260926-1512-7f3a-evil/pods/x",
		"DELETE /api/v1/namespaces/kube-system",
		"POST /apis/rbac.authorization.k8s.io/v1/clusterroles",
		"PATCH /api/v1/nodes/n1",
		"POST /api/v1/persistentvolumes",
		"POST /apis/apps/v1/namespaces/default/deployments",
		// Pen test: traversal out of the run namespace.
		"POST /api/v1/namespaces/armor-preflight-20260926-1512-7f3a/../default/pods",
		"DELETE /api/v1/namespaces/armor-preflight-20260926-1512-7f3a/./../kube-system",
		"POST /apis/apps/v1/namespaces/armor-preflight-20260926-1512-7f3a//../../namespaces/default/deployments",
		"DELETE /api/v1/persistentvolumes/../namespaces/default",
		"POST /api/v1/namespaces/armor-preflight-20260926-1512-7f3a%2F..%2Fdefault/pods",
		// A cluster-scoped path that merely contains the run namespace.
		"DELETE /apis/example.com/v1/clusterthings/namespaces/armor-preflight-20260926-1512-7f3a/x",
		"POST /apis/apps/v1/namespaces/armor-preflight-20260926-1512-7f3a",
	}
	for _, s := range allowed {
		m, p, _ := strings.Cut(s, " ")
		if !g.allowed(m, p) {
			t.Errorf("should allow %s", s)
		}
	}
	for _, s := range refused {
		m, p, _ := strings.Cut(s, " ")
		if g.allowed(m, p) {
			t.Errorf("should refuse %s", s)
		}
	}
}

func TestCleanupMode(t *testing.T) {
	g := &Guard{Mode: Cleanup}
	for s, want := range map[string]bool{
		"DELETE /api/v1/namespaces/armor-preflight-20260926-1512-7f3a":    true,
		"DELETE /api/v1/persistentvolumes/pvc-1":                          true,
		"GET /api/v1/namespaces":                                          true,
		"DELETE /api/v1/namespaces/kube-system":                           false,
		"DELETE /api/v1/namespaces/armor-preflight-x/pods/p":              false,
		"POST /api/v1/namespaces":                                         false,
		"PATCH /api/v1/namespaces/armor-preflight-20260926-1512-7f3a":     false,
		"POST /api/v1/namespaces/armor-preflight-20260926-1512-7f3a/pods": false,
	} {
		m, p, _ := strings.Cut(s, " ")
		if got := g.allowed(m, p); got != want {
			t.Errorf("%s: allowed=%v, want %v", s, got, want)
		}
	}
}

// Pen test: in cluster mode the guard refuses to create any namespace but
// the run's own, even without the admission policy installed.
func TestRunNamespaceGuardChecksNamespaceName(t *testing.T) {
	c, api := clients(t, Options{Mode: RunNamespace, Namespace: "armor-preflight-20260926-1512-7f3a"})
	ctx := context.Background()
	for _, name := range []string{"kube-system-2", "armor-preflight-other-run"} {
		_, err := c.Core.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{})
		var blocked *ErrBlocked
		if !errors.As(err, &blocked) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	for _, s := range api.seen {
		if strings.HasPrefix(s, "POST /api/v1/namespaces") {
			t.Fatalf("a foreign namespace create reached the API server: %s", s)
		}
	}
	if _, err := c.Core.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "armor-preflight-20260926-1512-7f3a"}}, metav1.CreateOptions{}); err != nil {
		var blocked *ErrBlocked
		if errors.As(err, &blocked) {
			t.Fatalf("own namespace blocked: %v", err)
		}
	}
}

type recorder struct{ seen []string }

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.seen = append(r.seen, req.Method+" "+req.URL.EscapedPath())
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
}

// The server receives the escaped path. A %2F that decodes into an allowed
// path must still be refused, since the guard cannot know how the server
// will interpret it.
func TestGuardChecksTheEscapedPath(t *testing.T) {
	ns := "armor-preflight-20260926-1512-7f3a"
	next := &recorder{}
	g := &Guard{Mode: RunNamespace, Namespace: ns, Next: next}
	req, _ := http.NewRequest(http.MethodDelete, "https://api.example/api/v1/namespaces/"+ns+"/pods%2Fx", nil)
	if req.URL.Path != "/api/v1/namespaces/"+ns+"/pods/x" {
		t.Fatalf("test setup: decoded path %q", req.URL.Path)
	}
	if _, err := g.RoundTrip(req); err == nil || len(next.seen) != 0 {
		t.Fatalf("an encoded path was let through: err=%v seen=%v", err, next.seen)
	}
	ok, _ := http.NewRequest(http.MethodDelete, "https://api.example/api/v1/namespaces/"+ns+"/pods/x", nil)
	if _, err := g.RoundTrip(ok); err != nil || len(next.seen) != 1 {
		t.Fatalf("a clean path was refused: %v", err)
	}
}

// Each client gets its own binding to its own transport; building a second
// client must not rewire the first one's requests.
func TestGuardBindsEachTransport(t *testing.T) {
	g := &Guard{Mode: ReadOnly}
	a, b := &recorder{}, &recorder{}
	ra, rb := g.bind(a), g.bind(b)
	req, _ := http.NewRequest(http.MethodGet, "https://api.example/api/v1/nodes", nil)
	ra.RoundTrip(req)
	rb.RoundTrip(req)
	if len(a.seen) != 1 || len(b.seen) != 1 {
		t.Fatalf("a=%v b=%v", a.seen, b.seen)
	}
	w, _ := http.NewRequest(http.MethodPost, "https://api.example/api/v1/namespaces/x/pods", nil)
	if _, err := rb.RoundTrip(w); err == nil || len(g.Blocked()) != 1 {
		t.Fatalf("a bound guard must still block writes and record them: %v %v", err, g.Blocked())
	}
}
