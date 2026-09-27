package kube

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// GuardMode says which writes the guard lets through.
type GuardMode int

const (
	// ReadOnly allows no writes except SelfSubjectAccessReview and
	// SelfSubjectRulesReview, which the API server does not persist (D-1).
	ReadOnly GuardMode = iota
	// RunNamespace additionally allows writes to the run's own namespace
	// object and to objects inside it.
	RunNamespace
)

// nonPersisted are the only resources ReadOnly lets a POST reach.
var nonPersisted = map[string]bool{
	"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews": true,
	"/apis/authorization.k8s.io/v1/selfsubjectrulesreviews":  true,
}

// Guard is an http.RoundTripper that refuses any write the mode does not
// allow, before it leaves the process. It is the enforcement behind
// "workstation mode makes zero create, update, patch or delete calls".
type Guard struct {
	Mode      GuardMode
	Namespace string // the run namespace, for RunNamespace mode
	Next      http.RoundTripper

	mu      sync.Mutex
	blocked []string
}

// ErrBlocked is returned for a refused write.
type ErrBlocked struct{ Method, Path string }

func (e *ErrBlocked) Error() string {
	return fmt.Sprintf("armor-preflight refused a %s to %s: this mode makes no changes to the cluster", e.Method, e.Path)
}

// RoundTrip implements http.RoundTripper.
func (g *Guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if !g.allowed(req.Method, req.URL.Path) {
		g.mu.Lock()
		g.blocked = append(g.blocked, req.Method+" "+req.URL.Path)
		g.mu.Unlock()
		return nil, &ErrBlocked{Method: req.Method, Path: req.URL.Path}
	}
	return g.Next.RoundTrip(req)
}

// Blocked lists writes the guard refused, as "METHOD path".
func (g *Guard) Blocked() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.blocked...)
}

func (g *Guard) allowed(method, path string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	path = strings.TrimSuffix(path, "/")
	if method == http.MethodPost && nonPersisted[path] {
		return true
	}
	if g.Mode != RunNamespace || g.Namespace == "" {
		return false
	}
	ns := "/api/v1/namespaces/" + g.Namespace
	switch {
	case method == http.MethodPost && path == "/api/v1/namespaces":
		// Creating the run namespace itself. The body is not inspected
		// here; the orchestrator only ever creates its own namespace, and
		// the shipped admission policy enforces the name (D-2).
		return true
	case path == ns, strings.HasPrefix(path, ns+"/"):
		return true
	case strings.HasPrefix(path, "/apis/") && strings.Contains(path, "/namespaces/"+g.Namespace+"/"):
		return true
	}
	return false
}
