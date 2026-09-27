package kube

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	// object and to objects inside it, and deleting persistent volumes
	// (the orchestrator only deletes volumes claimed from its namespace;
	// the shipped admission policy enforces that, D-2).
	RunNamespace
	// Cleanup allows only deleting Preflight namespaces (armor-preflight-*)
	// and persistent volumes, for `armor-preflight cleanup`.
	Cleanup
)

// namespacePrefix mirrors orchestrator.NamespacePrefix (kept here to avoid
// an import cycle).
const namespacePrefix = "armor-preflight-"

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
	ok := g.allowed(req.Method, req.URL.Path)
	if ok && g.Mode == RunNamespace && req.Method == http.MethodPost && strings.TrimSuffix(req.URL.Path, "/") == "/api/v1/namespaces" {
		// Creating a namespace: check it is this run's, so the guard does
		// not depend on the admission policy being installed.
		ok = g.createsRunNamespace(req)
	}
	if !ok {
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
	isPVDelete := method == http.MethodDelete && strings.HasPrefix(path, "/api/v1/persistentvolumes/")
	if g.Mode == Cleanup {
		name := strings.TrimPrefix(path, "/api/v1/namespaces/")
		return isPVDelete || (method == http.MethodDelete && name != path && strings.HasPrefix(name, namespacePrefix) && !strings.Contains(name, "/"))
	}
	if g.Mode != RunNamespace || g.Namespace == "" {
		return false
	}
	if isPVDelete {
		return true
	}
	ns := "/api/v1/namespaces/" + g.Namespace
	switch {
	case method == http.MethodPost && path == "/api/v1/namespaces":
		// Creating the run namespace itself; RoundTrip checks the name in
		// the request body.
		return true
	case path == ns, strings.HasPrefix(path, ns+"/"):
		return true
	case strings.HasPrefix(path, "/apis/") && strings.Contains(path, "/namespaces/"+g.Namespace+"/"):
		return true
	}
	return false
}

// createsRunNamespace reads a namespace-create body (restoring it for the
// real request) and reports whether it names the run namespace.
func (g *Guard) createsRunNamespace(req *http.Request) bool {
	if req.Body == nil {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	req.Body.Close()
	if err != nil {
		return false
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	var ns struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	if json.Unmarshal(body, &ns) != nil {
		return false // not JSON (for example protobuf): refuse rather than guess
	}
	return ns.Metadata.Name == g.Namespace
}
