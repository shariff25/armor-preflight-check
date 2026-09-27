// Package registrytest is a fake OCI registry with bearer-token auth, for tests.
package registrytest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Registry is a fake registry. Manifests maps "repo@ref" (tag or digest)
// to the digest it resolves to.
type Registry struct {
	Username, Password string
	// BasicAuth makes the registry challenge with Basic instead of Bearer.
	BasicAuth bool

	mu        sync.Mutex
	manifests map[string]string
	Server    *httptest.Server
	requests  []string
}

// New starts a fake registry over TLS.
func New(user, pass string) *Registry {
	r := &Registry{Username: user, Password: pass, manifests: map[string]string{}}
	r.Server = httptest.NewTLSServer(r)
	return r
}

// Host is the registry's host:port.
func (r *Registry) Host() string { return strings.TrimPrefix(r.Server.URL, "https://") }

// Client is an HTTP client that trusts the registry's certificate.
func (r *Registry) Client() *http.Client { return r.Server.Client() }

// Close stops the server.
func (r *Registry) Close() { r.Server.Close() }

// Add makes repo:ref exist, resolving to digest.
func (r *Registry) Add(repo, ref, digest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[repo+"@"+ref] = digest
	r.manifests[repo+"@"+digest] = digest
}

// Requests lists "METHOD path" for every request received.
func (r *Registry) Requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.requests...)
}

const token = "test-token"

func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.requests = append(r.requests, req.Method+" "+req.URL.Path)
	r.mu.Unlock()

	if req.URL.Path == "/token" {
		u, p, ok := req.BasicAuth()
		if !ok || u != r.Username || p != r.Password {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"token": token})
		return
	}
	if !r.authorized(req) {
		if r.BasicAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+r.Server.URL+`/token",service="test"`)
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if req.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	// /v2/<repo>/manifests/<ref>
	rest := strings.TrimPrefix(req.URL.Path, "/v2/")
	i := strings.LastIndex(rest, "/manifests/")
	if i < 0 {
		http.NotFound(w, req)
		return
	}
	repo, ref := rest[:i], rest[i+len("/manifests/"):]
	r.mu.Lock()
	digest, ok := r.manifests[repo+"@"+ref]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusOK)
}

func (r *Registry) authorized(req *http.Request) bool {
	if r.BasicAuth {
		u, p, ok := req.BasicAuth()
		return ok && u == r.Username && p == r.Password
	}
	return req.Header.Get("Authorization") == "Bearer "+token
}
