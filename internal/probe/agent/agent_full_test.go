package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shariff25/armor-preflight-check/internal/netfixtures"
	"github.com/shariff25/armor-preflight-check/internal/probe/protocol"
	"github.com/shariff25/armor-preflight-check/internal/registry/registrytest"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestAgentEndToEnd(t *testing.T) {
	n := netfixtures.NewNetwork()
	defer n.Close()
	public := netfixtures.NewCA("Public Trust Services", "Public Root CA")
	n.AddTLS("cr.download.fortanix.com", public, netfixtures.Handler(time.Now))
	n.AddTLS("pccs.fortanix.com", public, netfixtures.Handler(time.Now))
	n.AddTCP("syslog.example.com")

	reg := registrytest.New("user", "s3cret")
	defer reg.Close()
	reg.Add("armor/operator", digestA, digestA)
	roots := public.Pool.Clone()
	roots.AddCert(reg.Server.Certificate())

	creds := t.TempDir()
	os.WriteFile(filepath.Join(creds, protocol.RegistryPasswordKey), []byte("s3cret\n"), 0o600)

	req := protocol.Request{Version: protocol.Version, RunID: "r1", NodePool: "sgxpool1", Timeout: 2 * time.Second,
		Targets: []protocol.Target{
			{Host: "cr.download.fortanix.com", Port: 443, Path: "/v2/"},
			{Host: "pccs.fortanix.com", Port: 443, Path: "/"},
			{Host: "syslog.example.com", Port: 514, TCPOnly: true},
			{Host: "missing.example.com", Port: 443, Path: "/"},
		},
		Registry: &protocol.Registry{Host: reg.Host(), Username: "user", Images: []string{
			reg.Host() + "/armor/operator@" + digestA,
			reg.Host() + "/armor/console@" + digestB,
		}},
		Storage: &protocol.Storage{AccountFQDN: "acct.blob.core.windows.net", Container: "medusa", Blob: "armor-preflight-r1.txt"},
	}
	body, _ := json.Marshal(req)
	reqPath := filepath.Join(t.TempDir(), "request.json")
	os.WriteFile(reqPath, body, 0o600)

	var out bytes.Buffer
	a := &Agent{Resolver: n, Dialer: n, Roots: roots, CredentialsDir: creds}
	if err := a.Run(context.Background(), reqPath, &out); err != nil {
		t.Fatal(err)
	}
	res, err := protocol.Decode(out.String())
	if err != nil {
		t.Fatal(err)
	}
	if res.Error != "" {
		t.Fatalf("result error: %s", res.Error)
	}
	got := map[string]protocol.Stage{}
	for _, s := range res.Stages {
		got[s.Stage+" "+s.Target] = s
	}
	for _, want := range []string{
		"http cr.download.fortanix.com:443", "http pccs.fortanix.com:443", "tcp syslog.example.com:514",
		"manifest " + reg.Host() + "/armor/operator@" + digestA,
	} {
		if s, ok := got[want]; !ok || !s.OK {
			t.Errorf("%s: %+v", want, s)
		}
	}
	for _, want := range []string{"dns missing.example.com", "manifest " + reg.Host() + "/armor/console@" + digestB} {
		if s, ok := got[want]; !ok || s.OK {
			t.Errorf("%s should fail: %+v", want, s)
		}
	}
	if c := got["clock "]; !c.OK || c.Data[protocol.DataSkewSeconds] == "" {
		t.Errorf("clock: %+v", c)
	}
	// No storage credential is mounted, so BAK-02 reports that, not a crash.
	if s := got["blob-write acct.blob.core.windows.net/medusa/armor-preflight-r1.txt"]; s.OK || !strings.Contains(s.Detail, "not mounted") {
		t.Errorf("blob: %+v", s)
	}
	if strings.Contains(out.String(), "s3cret") {
		t.Fatal("the probe printed the registry password")
	}
}
