package cli

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/shariff25/armor-preflight-check/internal/catalog"
	"github.com/shariff25/armor-preflight-check/internal/checks"
	"github.com/shariff25/armor-preflight-check/internal/settings"
	"github.com/shariff25/armor-preflight-check/internal/tlsutil"
)

// egressRecorder stands in for the network: it records every name looked up
// and every address dialled, and lets nothing through.
type egressRecorder struct {
	mu    sync.Mutex
	hosts map[string]bool
}

func (e *egressRecorder) add(host string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hosts[strings.ToLower(strings.TrimSuffix(host, "."))] = true
}

func (e *egressRecorder) LookupHost(_ context.Context, host string) ([]string, error) {
	e.add(host)
	return nil, &net.DNSError{Err: "blocked in test", Name: host, IsNotFound: true}
}

func (e *egressRecorder) dial(_ context.Context, _, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	e.add(host)
	return nil, errors.New("blocked in test")
}

// presentTools reports every workstation tool as installed, so WS-01 passes
// and the checks behind it run.
type presentTools struct{}

func (presentTools) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }
func (presentTools) Output(context.Context, string, ...string) ([]byte, error) {
	return []byte("v1.0.0\n"), nil
}

// R1.4 (packet capture, the automated part): with every real check, a
// workstation run reaches out only to the endpoints under test: the catalog's
// endpoints and the hosts the settings file names. The Kubernetes API is the
// other connection, and it goes where the kubeconfig says.
func TestWorkstationEgressIsOnlyTheEndpointsUnderTest(t *testing.T) {
	withCluster(t, fakeCluster(t, false))
	registry = checks.Registry // the real checks; withCluster's cleanup restores it
	rec := &egressRecorder{hosts: map[string]bool{}}
	oldHTTP, oldDNS := newHTTPClient, resolver
	newHTTPClient = func() *http.Client {
		return tlsutil.NewHTTPClient(tlsutil.Options{
			DialContext: rec.dial,
			Proxy:       func(*http.Request) (*url.URL, error) { return nil, nil },
		})
	}
	resolver = rec
	oldTools := localTools
	localTools = presentTools{}
	t.Cleanup(func() { newHTTPClient, resolver, localTools = oldHTTP, oldDNS, oldTools })

	path := writeSettings(t, settingsYAML)
	if _, err := execute("run", "workstation", "-f", path, "-o", t.TempDir()); err == nil {
		t.Fatal("the run passed with the network blocked, so the network checks didn't run")
	}

	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	st, err := settings.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, ep := range cat.ResolveEndpoints(st) {
		if ep.Missing == "" {
			allowed[strings.ToLower(ep.Host)] = true
		}
	}
	for p := range settings.KnownPaths() {
		if h := hostOf(st.Get(p)); h != "" {
			allowed[h] = true
		}
	}

	var got []string
	for h := range rec.hosts {
		got = append(got, h)
		if !allowed[h] {
			t.Errorf("contacted %s, which is neither a catalog endpoint nor named in the settings file", h)
		}
	}
	sort.Strings(got)
	t.Logf("contacted: %v", got)
	// Not vacuous: the registry and the Armor domain were tried.
	for _, want := range []string{"cr.download.fortanix.com", "armor.example.com"} {
		if !rec.hosts[want] {
			t.Errorf("%s was never contacted, so the network checks didn't run", want)
		}
	}
}

// hostOf returns the host in a settings value that names one (a hostname,
// host:port or URL), lower-cased; "" otherwise.
func hostOf(v string) string {
	if v == "" || strings.ContainsAny(v, " /") && !strings.Contains(v, "://") {
		return ""
	}
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil {
			return ""
		}
		return strings.ToLower(u.Hostname())
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(v)
}
