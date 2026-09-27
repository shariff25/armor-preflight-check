package registry

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/registry/registrytest"
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
