package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/agent"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/protocol"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/sgx"
)

// sgxEnv runs the real agent with a fake SGX provider on each SGX node.
func sgxEnv(t *testing.T, providers map[string]*sgx.Fake) *engine.Env {
	t.Helper()
	p := newProbeFixture(t)
	env := p.env(t)
	nodes, err := SGXNodes(context.Background(), env)
	if err != nil || len(nodes) != 3 {
		t.Fatalf("SGX nodes: %v %v", nodes, err)
	}
	env.Probes.NodeResults = map[string]protocol.Result{}
	env.Probes.NodeErrors = map[string]string{}
	for _, n := range nodes {
		prov := providers[n.Name]
		if prov == nil {
			prov = &sgx.Fake{Status: sgx.UpToDate}
		}
		body, _ := json.Marshal(protocol.Request{Version: protocol.Version, RunID: probeRunID, SGX: &protocol.SGX{Nonce: "0a1b2c3d"}})
		path := filepath.Join(t.TempDir(), "request.json")
		os.WriteFile(path, body, 0o600)
		var out bytes.Buffer
		if err := (&agent.Agent{SGX: prov}).Run(context.Background(), path, &out); err != nil {
			t.Fatal(err)
		}
		res, err := protocol.Decode(out.String())
		if err != nil {
			t.Fatal(err)
		}
		env.Probes.NodeResults[n.Name] = res
	}
	return env
}

func nodeResult(t *testing.T, rep *engine.Report, id, node string) model.Result {
	t.Helper()
	for _, r := range rep.Results {
		if r.ID == id && r.Scope.Node == node {
			return r
		}
	}
	t.Fatalf("no %s result for %s: %+v", id, node, resultsFor(rep, id))
	return model.Result{}
}

// R1.2: on a compliant cluster, CC-05 generates and verifies a quote on
// every SGX node and reports per node.
func TestCC05PassesPerNode(t *testing.T) {
	rep := runChecks(t, sgxEnv(t, nil))
	rs := resultsFor(rep, "CC-05")
	if len(rs) != 3 {
		t.Fatalf("%d results", len(rs))
	}
	for _, r := range rs {
		if r.Status != model.StatusPass || r.Scope.Node == "" || !strings.Contains(evidenceText([]model.Result{r}), "TCB status UpToDate") {
			t.Errorf("%s: %s\n%s", r.Scope, r.Status, evidenceText([]model.Result{r}))
		}
	}
}

func TestCC05Outcomes(t *testing.T) {
	rep := runChecks(t, sgxEnv(t, map[string]*sgx.Fake{
		"aks-sgxpool1-0": {Status: sgx.OutOfDate, Advisories: []string{"INTEL-SA-00615"}},
		"aks-sgxpool1-1": {Status: sgx.SWHardeningNeeded, Advisories: []string{"INTEL-SA-00334"}},
		"aks-sgxpool1-2": {WrongReportData: true},
	}))
	if r := nodeResult(t, rep, "CC-05", "aks-sgxpool1-0"); r.Status != model.StatusFail || !strings.Contains(evidenceText([]model.Result{r}), "OutOfDate; advisories INTEL-SA-00615") {
		t.Errorf("out of date: %s\n%s", r.Status, evidenceText([]model.Result{r}))
	}
	if r := nodeResult(t, rep, "CC-05", "aks-sgxpool1-1"); r.Status != model.StatusWarn {
		t.Errorf("hardening needed should warn: %s", r.Status)
	}
	if r := nodeResult(t, rep, "CC-05", "aks-sgxpool1-2"); r.Status != model.StatusFail || !strings.Contains(evidenceText([]model.Result{r}), "does not carry this run's nonce") {
		t.Errorf("replay: %s", r.Status)
	}
}

func TestCC05WithoutSGXImage(t *testing.T) {
	env := sgxEnv(t, nil)
	env.Probes.NodeResults = nil
	env.Probes.SGXUnavailable = "no SGX probe image is configured"
	r := resultsFor(runChecks(t, env), "CC-05")[0]
	if r.Status != model.StatusSkipped || *r.SkippedReason != "no SGX probe image is configured" {
		t.Fatalf("%s %v", r.Status, r.SkippedReason)
	}
}

func TestCC05StandardImageCannotQuote(t *testing.T) {
	env := sgxEnv(t, nil)
	// A per-node probe running the standard image reports it cannot quote.
	for node := range env.Probes.NodeResults {
		body, _ := json.Marshal(protocol.Request{Version: protocol.Version, RunID: probeRunID, SGX: &protocol.SGX{Nonce: "0a"}})
		path := filepath.Join(t.TempDir(), "request.json")
		os.WriteFile(path, body, 0o600)
		var out bytes.Buffer
		(&agent.Agent{}).Run(context.Background(), path, &out)
		env.Probes.NodeResults[node], _ = protocol.Decode(out.String())
	}
	r := nodeResult(t, runChecks(t, env), "CC-05", "aks-sgxpool1-0")
	if r.Status != model.StatusFail || !strings.Contains(evidenceText([]model.Result{r}), "cannot generate SGX quotes") {
		t.Fatalf("%s\n%s", r.Status, evidenceText([]model.Result{r}))
	}
}

func TestCC05SkippedWhereParentsFail(t *testing.T) {
	env := sgxEnv(t, nil)
	delete(env.Probes.NodeResults, "aks-sgxpool1-2")
	env.Probes.NodeErrors["aks-sgxpool1-2"] = "SGX probe pod could not be scheduled on node aks-sgxpool1-2"
	rep := runChecks(t, env)
	if r := nodeResult(t, rep, "CC-05", "aks-sgxpool1-2"); r.Status != model.StatusSkipped || !strings.Contains(*r.SkippedReason, "could not be scheduled") {
		t.Fatalf("%s %v", r.Status, r.SkippedReason)
	}
}

// A pool-level parent failure skips CC-05 on every node of that pool.
func TestCC05SkippedWhenREG03FailsForThePool(t *testing.T) {
	env := sgxEnv(t, nil)
	res := env.Probes.Results["sgxpool1"]
	for i := range res.Stages {
		if res.Stages[i].Stage == protocol.StageManifest {
			res.Stages[i].OK, res.Stages[i].Detail = false, "not found in the registry"
		}
	}
	env.Probes.Results["sgxpool1"] = res
	rep := runChecks(t, env)
	for _, n := range []string{"aks-sgxpool1-0", "aks-sgxpool1-1", "aks-sgxpool1-2"} {
		r := nodeResult(t, rep, "CC-05", n)
		if r.Status != model.StatusSkipped || *r.SkippedReason != "parent REG-03 failed for node pool sgxpool1" {
			t.Errorf("%s: %s %v", n, r.Status, r.SkippedReason)
		}
	}
}
