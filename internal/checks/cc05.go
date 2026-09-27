package checks

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/orchestrator"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/protocol"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/sgx"
)

// SGXNodes lists the SGX nodes to run per-node probes on, tolerating each
// node's taints.
func SGXNodes(ctx context.Context, env *engine.Env) ([]orchestrator.NodeTarget, error) {
	if env.Kube == nil {
		return nil, env.KubeErr
	}
	c, err := discover(ctx, env)
	if err != nil {
		return nil, err
	}
	var out []orchestrator.NodeTarget
	for _, n := range c.sgxNodes() {
		t := orchestrator.NodeTarget{Name: n.name}
		for _, taint := range n.n.Spec.Taints {
			t.Tolerations = append(t.Tolerations, corev1.Toleration{Key: taint.Key, Operator: corev1.TolerationOpExists, Effect: taint.Effect})
		}
		out = append(out, t)
	}
	return out, nil
}

// cc05: each SGX node generates a quote bound to this run's nonce, and the
// quote verifies against collateral from the PCCS with an acceptable TCB
// status.
func cc05(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Probes == nil {
		return skip("no probe results")
	}
	if env.Probes.SGXUnavailable != "" {
		return skip(env.Probes.SGXUnavailable)
	}
	nodes, err := SGXNodes(ctx, env)
	if err != nil {
		return skip(fmt.Sprintf("could not list SGX nodes: %v", err))
	}
	if len(nodes) == 0 {
		return skip("no SGX nodes found")
	}
	var out []model.Result
	for _, n := range nodes {
		scope := model.NodeScope(n.Name)
		res, ok := env.Probes.NodeResults[n.Name]
		if !ok {
			reason := env.Probes.NodeErrors[n.Name]
			if reason == "" {
				reason = "no SGX probe ran on this node"
			}
			out = append(out, model.Result{Scope: scope}.Skipped("SGX probe did not report: "+reason))
			continue
		}
		out = append(out, quoteResult(scope, res.Stages))
	}
	return out
}

func quoteResult(scope model.Scope, stages []protocol.Stage) model.Result {
	var evidence []model.Evidence
	var verify *protocol.Stage
	for i, s := range stages {
		if s.Stage != protocol.StageQuote && s.Stage != protocol.StageVerify {
			continue
		}
		evidence = append(evidence, toEvidence(s))
		if s.Stage == protocol.StageVerify {
			verify = &stages[i]
		}
	}
	if len(evidence) == 0 {
		return model.Result{Scope: scope}.Skipped("the SGX probe reported no quote")
	}
	r := verdict(scope, evidence...)
	if r.Status != model.StatusPass {
		return r
	}
	// A quote that was never verified proves nothing: never pass without a
	// successful verify stage that confirms the nonce.
	if verify == nil || verify.Data[protocol.DataNonceMatches] != "true" {
		r.Status = model.StatusFail
		r.Evidence = append(r.Evidence, model.Evidence{Stage: protocol.StageVerify, OK: false, Detail: "the SGX probe did not report a verified quote bound to this run's nonce"})
		return r
	}
	status := verify.Data[protocol.DataTCBStatus]
	detail := "TCB status " + status
	if adv := verify.Data[protocol.DataAdvisories]; adv != "" {
		detail += "; advisories " + strings.ReplaceAll(adv, ",", ", ")
	}
	if src := verify.Data[protocol.DataCollateral]; src != "" {
		detail += "; collateral from " + src
	}
	switch sgx.Classify(status) {
	case sgx.Acceptable:
		r.Evidence = append(r.Evidence, model.Evidence{Stage: "tcb", OK: true, Detail: detail})
	case sgx.Attention:
		r.Status = model.StatusWarn
		r.Evidence = append(r.Evidence, model.Evidence{Stage: "tcb", OK: false, Detail: detail + " (the platform needs configuration or software hardening)"})
		r.Remediation = "Apply the BIOS configuration and software mitigations Intel lists for the advisories above, or confirm with Fortanix that Armor's attestation policy accepts this TCB status."
	default:
		r.Status = model.StatusFail
		r.Evidence = append(r.Evidence, model.Evidence{Stage: "tcb", OK: false, Detail: detail + " (not acceptable for attestation)"})
		r.Remediation = "Update the platform's microcode and BIOS (on Azure, redeploy the node to move to current hardware), then re-run; contact Fortanix Support with this report if it persists."
	}
	return r
}
