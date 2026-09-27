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
	}
	refused := []string{
		"POST /api/v1/namespaces/default/pods",
		"DELETE /api/v1/namespaces/armor-preflight-20260926-1512-7f3a-evil/pods/x",
		"DELETE /api/v1/namespaces/kube-system",
		"POST /apis/rbac.authorization.k8s.io/v1/clusterroles",
		"PATCH /api/v1/nodes/n1",
		"DELETE /api/v1/persistentvolumes/pv1",
		"POST /apis/apps/v1/namespaces/default/deployments",
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
