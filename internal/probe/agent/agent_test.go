package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/protocol"
)

func TestRun(t *testing.T) {
	p := filepath.Join(t.TempDir(), "request.json")
	os.WriteFile(p, []byte(`{"version":"1","runId":"20260926-1512-7f3a","nodePool":"sgxpool1"}`), 0o600)
	t.Setenv("NODE_NAME", "aks-sgxpool1-0")
	t.Setenv("POD_NAME", "armor-preflight-probe-sgxpool1")
	var out bytes.Buffer
	if err := Run(context.Background(), p, &out, func() time.Time { return time.Unix(10, 0) }); err != nil {
		t.Fatal(err)
	}
	res, err := protocol.Decode(out.String())
	if err != nil {
		t.Fatal(err)
	}
	if res.Node != "aks-sgxpool1-0" || res.NodePool != "sgxpool1" || res.RunID != "20260926-1512-7f3a" || res.Error != "" {
		t.Fatalf("%+v", res)
	}
}

func TestRunReportsBadRequest(t *testing.T) {
	var out bytes.Buffer
	Run(context.Background(), filepath.Join(t.TempDir(), "missing.json"), &out, time.Now)
	res, err := protocol.Decode(out.String())
	if err != nil || res.Error == "" {
		t.Fatalf("%+v %v", res, err)
	}
}
