package kube

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	gopath "path"
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

// RoundTrip implements http.RoundTripper, forwarding allowed requests to
// g.Next.
func (g *Guard) RoundTrip(req *http.Request) (*http.Response, error) {
	return g.roundTrip(req, g.Next)
}

// bind returns a RoundTripper that applies this guard's policy (and records
// into its blocked list) in front of next. Each client gets its own binding,
// so building a second client never rewires the first one's transport.
func (g *Guard) bind(next http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) { return g.roundTrip(req, next) })
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func (g *Guard) roundTrip(req *http.Request, next http.RoundTripper) (*http.Response, error) {
	// Judge the path as the server will receive it: escaped. A %2F that
	// decodes into an allowed path is refused, because how the server then
	// interprets it is not the guard's to guess.
	path := req.URL.EscapedPath()
	ok := g.allowed(req.Method, path)
	if ok && g.Mode == RunNamespace && req.Method == http.MethodPost && strings.TrimSuffix(path, "/") == "/api/v1/namespaces" {
		// Creating a namespace: check it is this run's, so the guard does
		// not depend on the admission policy being installed.
		ok = g.createsRunNamespace(req)
	}
	if !ok {
		g.mu.Lock()
		g.blocked = append(g.blocked, req.Method+" "+path)
		g.mu.Unlock()
		return nil, &ErrBlocked{Method: req.Method, Path: path}
	}
	return next.RoundTrip(req)
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
	// Refuse any write whose path is not already clean, so a path such as
	// /api/v1/namespaces/armor-preflight-x/../default/pods cannot pass the
	// prefix checks below and be normalised by the server into another
	// namespace.
	if path == "" || path[0] != '/' || gopath.Clean(path) != strings.TrimSuffix(path, "/") || strings.Contains(path, "%") {
		return false
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
	}
	// A namespaced API group resource: /apis/{group}/{version}/namespaces/{ns}/{resource}[/...].
	seg := strings.Split(path, "/")
	return len(seg) >= 7 && seg[1] == "apis" && seg[4] == "namespaces" && seg[5] == g.Namespace
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
