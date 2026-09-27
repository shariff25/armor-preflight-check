package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/protocol"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/sgx"
)

func runSGX(t *testing.T, provider sgx.Provider, nonce string) []protocol.Stage {
	t.Helper()
	body, _ := json.Marshal(protocol.Request{Version: protocol.Version, RunID: "r", NodePool: "sgxpool1", SGX: &protocol.SGX{Nonce: nonce}})
	p := filepath.Join(t.TempDir(), "request.json")
	os.WriteFile(p, body, 0o600)
	var out bytes.Buffer
	if err := (&Agent{SGX: provider}).Run(context.Background(), p, &out); err != nil {
		t.Fatal(err)
	}
	res, err := protocol.Decode(out.String())
	if err != nil {
		t.Fatal(err)
	}
	return res.Stages
}

func TestQuoteUpToDate(t *testing.T) {
	st := runSGX(t, &sgx.Fake{Status: sgx.UpToDate}, "a1b2c3")
	if len(st) != 2 || !st[0].OK || !st[1].OK || st[1].Data[protocol.DataTCBStatus] != "UpToDate" || st[1].Data[protocol.DataNonceMatches] != "true" {
		t.Fatalf("%+v", st)
	}
}

func TestQuoteReplayDetected(t *testing.T) {
	st := runSGX(t, &sgx.Fake{WrongReportData: true}, "a1b2c3")
	if st[1].OK || !strings.Contains(st[1].Detail, "does not carry this run's nonce") {
		t.Fatalf("%+v", st)
	}
}

func TestQuoteFailures(t *testing.T) {
	if st := runSGX(t, nil, "a1"); st[0].OK || !strings.Contains(st[0].Detail, "cannot generate SGX quotes") {
		t.Fatalf("standard image: %+v", st)
	}
	if st := runSGX(t, &sgx.Fake{VerifyErr: errors.New("collateral expired")}, "a1"); len(st) != 2 || st[1].OK || !strings.Contains(st[1].Detail, "collateral expired") {
		t.Fatalf("verify error: %+v", st)
	}
	if st := runSGX(t, &sgx.Fake{}, "not-hex"); st[0].OK {
		t.Fatalf("bad nonce: %+v", st)
	}
}
