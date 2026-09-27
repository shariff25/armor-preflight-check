package registry

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shariff25/armor-preflight-check/internal/registry/registrytest"
)

const d1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func TestPingAndManifest(t *testing.T) {
	for _, basic := range []bool{false, true} {
		fake := registrytest.New("user", "pass")
		fake.BasicAuth = basic
		defer fake.Close()
		fake.Add("armor/operator", "1.0.404", d1)

		c := &Client{HTTP: fake.Client(), Host: fake.Host(), Username: "user", Password: "pass"}
		ctx := context.Background()
		if err := c.Ping(ctx); err != nil {
			t.Fatalf("basic=%v: %v", basic, err)
		}
		ok, dig, err := c.Manifest(ctx, "armor/operator", "1.0.404")
		if err != nil || !ok || dig != d1 {
			t.Fatalf("basic=%v: %v %v %s", basic, err, ok, dig)
		}
		ok, _, err = c.Manifest(ctx, "armor/operator", "9.9.9")
		if err != nil || ok {
			t.Fatalf("missing tag: %v %v", err, ok)
		}

		bad := &Client{HTTP: fake.Client(), Host: fake.Host(), Username: "user", Password: "wrong"}
		if err := bad.Ping(ctx); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("basic=%v wrong password: %v", basic, err)
		}
	}
}

func TestUnreachable(t *testing.T) {
	fake := registrytest.New("u", "p")
	host := fake.Host()
	client := fake.Client()
	fake.Close()
	c := &Client{HTTP: client, Host: host, Username: "u", Password: "p"}
	if err := c.Ping(context.Background()); err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("got %v", err)
	}
}

func TestParseReference(t *testing.T) {
	good := map[string]Reference{
		"cr.download.fortanix.com/armor/operator:1.0.404":      {Host: "cr.download.fortanix.com", Repo: "armor/operator", Tag: "1.0.404"},
		"cr.download.fortanix.com/armor/operator@" + d1:        {Host: "cr.download.fortanix.com", Repo: "armor/operator", Digest: d1},
		"oci://registry.local:5000/charts/armor:1.0.404@" + d1: {Host: "registry.local:5000", Repo: "charts/armor", Tag: "1.0.404", Digest: d1},
		"localhost/x:1": {Host: "localhost", Repo: "x", Tag: "1"},
	}
	for in, want := range good {
		got, err := ParseReference(in)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	for _, in := range []string{"armor/operator:1", "operator:1", "cr.example.com/x", "cr.example.com/x@sha256:bad"} {
		if _, err := ParseReference(in); err == nil {
			t.Errorf("%s: expected error", in)
		}
	}
	refs, err := ParseManifestList(strings.NewReader("# images\n\ncr.example.com/a@" + d1 + "\ncr.example.com/b:1\n"))
	if err != nil || len(refs) != 2 {
		t.Fatalf("%v %v", refs, err)
	}
	if _, err := ParseManifestList(strings.NewReader("ok.example.com/a:1\nbad\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("got %v", err)
	}
}

// Pen test: a registry that advertises a token realm on another domain must
// not receive the credentials.
func TestCredentialsNotSentToForeignRealm(t *testing.T) {
	var leaked []string
	thief := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); ok {
			leaked = append(leaked, u+":"+p)
		}
		w.Write([]byte(`{"token":"x"}`))
	}))
	defer thief.Close()
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://attacker.example.net/token",service="x"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer evil.Close()
	client := evil.Client()
	// Route attacker.example.net to the thief so a leak would be observable.
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "attacker.example.net") {
			addr = strings.TrimPrefix(thief.URL, "https://")
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	c := &Client{HTTP: client, Host: strings.TrimPrefix(evil.URL, "https://"), Username: "user", Password: "secret"}
	err := c.Ping(context.Background())
	if len(leaked) != 0 {
		t.Fatalf("credentials leaked: %v", leaked)
	}
	if err == nil || !strings.Contains(err.Error(), "outside the registry's domain") {
		t.Fatalf("got %v", err)
	}
}

func TestSameSite(t *testing.T) {
	for _, c := range []struct {
		reg, realm string
		want       bool
	}{
		{"cr.download.fortanix.com", "cr.download.fortanix.com", true},
		{"cr.download.fortanix.com", "auth.download.fortanix.com", true},
		{"cr.download.fortanix.com", "auth.fortanix.com", false},
		{"cr.download.fortanix.com", "evil.com", false},
		{"cr.download.fortanix.com", "download.fortanix.com.evil.com", false},
		{"mirror.corp.example:5000", "mirror.corp.example:5001", true},
		{"registry.io", "evil.io", false},
		{"127.0.0.1:5000", "127.0.0.1:443", true},
		{"10.0.0.1:5000", "0.0.1", false},
	} {
		if got := sameSite(c.reg, c.realm); got != c.want {
			t.Errorf("%s -> %s: %v", c.reg, c.realm, got)
		}
	}
}

// Pen test: repository names cannot walk out of /v2/<repo>/manifests/.
func TestManifestRejectsPathTraversal(t *testing.T) {
	c := &Client{HTTP: http.DefaultClient, Host: "cr.example.com"}
	for _, repo := range []string{"../../v2/_catalog", "armor/../../x", "Armor/Upper", "a//b", ""} {
		if _, _, err := c.Manifest(context.Background(), repo, "1.0"); err == nil || !strings.Contains(err.Error(), "invalid repository") {
			t.Errorf("%q: %v", repo, err)
		}
	}
	if _, _, err := c.Manifest(context.Background(), "armor/op", "../x"); err == nil {
		t.Error("bad tag accepted")
	}
	if _, err := ParseReference("cr.example.com/armor/../secret:1"); err == nil {
		t.Error("ParseReference accepted a traversal")
	}
}
