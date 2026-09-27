package checks

import (
	"context"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/shariff25/armor-preflight-check/internal/catalog"
	"github.com/shariff25/armor-preflight-check/internal/engine"
	"github.com/shariff25/armor-preflight-check/internal/model"
	"github.com/shariff25/armor-preflight-check/internal/probe/protocol"
)

// poolResult is one pool's probe outcome.
type poolResult struct {
	pool   string
	stages []protocol.Stage
	err    string
}

// probeResults lists every pool that ran a probe, in order. Pools whose
// probe produced nothing carry err.
func probeResults(env *engine.Env) ([]poolResult, []model.Result) {
	if env.Probes == nil {
		return nil, skip("no probe results")
	}
	var pools []string
	for p := range env.Probes.Results {
		pools = append(pools, p)
	}
	for p := range env.Probes.PoolErrors {
		if _, ok := env.Probes.Results[p]; !ok {
			pools = append(pools, p)
		}
	}
	if len(pools) == 0 {
		return nil, skip("no probe results")
	}
	sort.Strings(pools)
	out := make([]poolResult, 0, len(pools))
	for _, p := range pools {
		if r, ok := env.Probes.Results[p]; ok {
			out = append(out, poolResult{pool: p, stages: r.Stages})
		} else {
			out = append(out, poolResult{pool: p, err: env.Probes.PoolErrors[p]})
		}
	}
	return out, nil
}

func poolSkip(pool, reason string) model.Result {
	return model.Result{Scope: model.PoolScope(pool)}.Skipped(reason)
}

func toEvidence(s protocol.Stage) model.Evidence {
	return model.Evidence{Stage: s.Stage, Target: s.Target, OK: s.OK, Detail: s.Detail}
}

// endpointsFor returns the resolved endpoints a check covers, keyed by
// host, plus notes for endpoints skipped for want of a setting.
func endpointsFor(env *engine.Env, check string) (map[string]catalog.ResolvedEndpoint, []string) {
	eps := map[string]catalog.ResolvedEndpoint{}
	var missing []string
	for _, ep := range env.Catalog.ResolveEndpoints(env.Settings) {
		if check != "" && !ep.HasCheck(check) {
			continue
		}
		if ep.Missing != "" {
			missing = append(missing, fmt.Sprintf("%s not tested: `%s` is not set", ep.Purpose, ep.Missing))
			continue
		}
		eps[ep.Host] = ep
	}
	return eps, missing
}

func stageHost(s protocol.Stage) string {
	if h, _, err := net.SplitHostPort(s.Target); err == nil {
		return h
	}
	return s.Target
}

// perPool runs fn for every pool with probe results; pools whose probe
// failed are reported skipped with the reason.
func perPool(env *engine.Env, pools func(string) bool, fn func(pr poolResult) model.Result) []model.Result {
	results, skipped := probeResults(env)
	if skipped != nil {
		return skipped
	}
	var out []model.Result
	for _, pr := range results {
		if pools != nil && !pools(pr.pool) {
			continue
		}
		if pr.err != "" {
			out = append(out, poolSkip(pr.pool, "probe did not report: "+pr.err))
			continue
		}
		out = append(out, fn(pr))
	}
	if len(out) == 0 {
		return skip("no node pool this check applies to reported probe results")
	}
	return out
}

func stagesFor(pr poolResult, eps map[string]catalog.ResolvedEndpoint, names ...string) []model.Evidence {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []model.Evidence
	for _, s := range pr.stages {
		if want[s.Stage] {
			if _, ok := eps[stageHost(s)]; ok {
				out = append(out, toEvidence(s))
			}
		}
	}
	return out
}

func noEvidence(pool string) model.Result {
	return poolSkip(pool, "the probe reported no stages for this check")
}

// net01: every required FQDN resolves from each pool.
func net01(_ context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	eps, _ := endpointsFor(env, "")
	return perPool(env, nil, func(pr poolResult) model.Result {
		ev := stagesFor(pr, eps, protocol.StageDNS)
		if len(ev) == 0 {
			return noEvidence(pr.pool)
		}
		r := verdict(model.PoolScope(pr.pool), ev...)
		if bad := failedTargets(ev); len(bad) > 0 {
			r.Remediation = fmt.Sprintf("Make %s resolvable from pods on node pool %s (check the cluster DNS forwarders and any private DNS zones).", strings.Join(bad, ", "), pr.pool)
		}
		return r
	})
}

func failedTargets(ev []model.Evidence) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range ev {
		if !e.OK && !seen[e.Target] {
			seen[e.Target] = true
			out = append(out, e.Target)
		}
	}
	return out
}

// net02: TCP and TLS succeed from each pool to each egress FQDN (the DNS
// stage is included so each path reads end to end).
func net02(_ context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	eps, _ := endpointsFor(env, "NET-02")
	return perPool(env, nil, func(pr poolResult) model.Result {
		ev := stagesFor(pr, eps, protocol.StageDNS, protocol.StageTCP, protocol.StageTLS)
		if len(ev) == 0 {
			return noEvidence(pr.pool)
		}
		r := verdict(model.PoolScope(pr.pool), ev...)
		if bad := failedTargets(ev); len(bad) > 0 {
			r.Remediation = fmt.Sprintf("Allow outbound TCP from node pool %s's subnet to %s (see firewall-request.csv).", pr.pool, strings.Join(bad, ", "))
		}
		return r
	})
}

// net03: no TLS interception on the registry and attestation paths, unless
// the intercepting CA is supplied as trusted.
func net03(_ context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	all, _ := endpointsFor(env, "")
	eps := map[string]catalog.ResolvedEndpoint{}
	for h, ep := range all {
		if ep.InterceptSensitive {
			eps[h] = ep
		}
	}
	return perPool(env, nil, func(pr poolResult) model.Result {
		var ev []model.Evidence
		var intercepted []string
		for _, s := range pr.stages {
			if s.Stage != protocol.StageTLS || !s.OK {
				continue
			}
			if _, ok := eps[stageHost(s)]; !ok {
				continue
			}
			issuer := s.Data[protocol.DataIssuer]
			switch {
			case s.Data[protocol.DataVerified] == "true":
				ev = append(ev, ev1(s, true, "certificate chain verifies against the public roots (issuer %s)", issuer))
			case s.Data[protocol.DataVerifiedCustom] == "true":
				ev = append(ev, ev1(s, true, "TLS is intercepted (certificate issued by %s); the intercepting CA from proxy.trustedCaPath is trusted", issuer))
			default:
				ev = append(ev, ev1(s, false, "certificate is not trusted: issued by %s, chain %s (%s)", issuer, s.Data[protocol.DataChain], s.Data[protocol.DataVerifyError]))
				intercepted = append(intercepted, fmt.Sprintf("%s (presented issuer %s)", s.Target, issuer))
			}
		}
		if len(ev) == 0 {
			return noEvidence(pr.pool)
		}
		r := verdict(model.PoolScope(pr.pool), ev...)
		if len(intercepted) > 0 {
			r.Remediation = "TLS to " + strings.Join(intercepted, "; ") + " is intercepted or untrusted. Exempt these endpoints from TLS inspection, or set proxy.trustedCaPath to the inspecting CA."
		}
		return r
	})
}

func ev1(s protocol.Stage, ok bool, format string, args ...any) model.Evidence {
	return model.Evidence{Stage: "chain", Target: s.Target, OK: ok, Detail: fmt.Sprintf(format, args...)}
}

// net06: syslog reachable over TCP.
func net06(_ context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	eps, _ := endpointsFor(env, "NET-06")
	return perPool(env, nil, func(pr poolResult) model.Result {
		ev := stagesFor(pr, eps, protocol.StageDNS, protocol.StageTCP)
		if len(ev) == 0 {
			return noEvidence(pr.pool)
		}
		return verdict(model.PoolScope(pr.pool), ev...)
	})
}

// net07: node clock skew, against the Date headers of endpoints already
// under test (D-14).
func net07(_ context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	limit := float64(env.Params().ClockSkewSeconds)
	return perPool(env, nil, func(pr poolResult) model.Result {
		for _, s := range pr.stages {
			if s.Stage != protocol.StageClock {
				continue
			}
			if !s.OK {
				return poolSkip(pr.pool, s.Detail)
			}
			skew, err := strconv.ParseFloat(s.Data[protocol.DataSkewSeconds], 64)
			if err != nil {
				return poolSkip(pr.pool, "unreadable clock measurement")
			}
			ok := math.Abs(skew) < limit
			return verdict(model.PoolScope(pr.pool), model.Evidence{Stage: "clock", OK: ok, Detail: fmt.Sprintf("%s (limit %.0fs)", s.Detail, limit)})
		}
		return noEvidence(pr.pool)
	})
}

// sgxPools returns a filter for pools with SGX nodes.
func sgxPools(ctx context.Context, env *engine.Env) (func(string) bool, []model.Result) {
	if env.Kube == nil {
		return nil, noKube(env)
	}
	c, err := discover(ctx, env)
	if err != nil {
		return nil, skip(err.Error())
	}
	names := c.poolNames(func(n *node) bool { return n.sgx })
	if len(names) == 0 {
		return nil, skip("no SGX node pool found")
	}
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return func(p string) bool { return set[p] }, nil
}

// attestationPath checks the full path (DNS, TCP, TLS and an HTTP answer)
// from SGX pools to the endpoints of one check (CC-03 or CC-04).
func attestationPath(ctx context.Context, env *engine.Env, check string) []model.Result {
	filter, skipped := sgxPools(ctx, env)
	if skipped != nil {
		return skipped
	}
	eps, missing := endpointsFor(env, check)
	if len(eps) == 0 {
		return skip(strings.Join(missing, "; "))
	}
	return perPool(env, filter, func(pr poolResult) model.Result {
		ev := stagesFor(pr, eps, protocol.StageDNS, protocol.StageTCP, protocol.StageTLS, protocol.StageHTTP)
		if len(ev) == 0 {
			return noEvidence(pr.pool)
		}
		r := verdict(model.PoolScope(pr.pool), ev...)
		if bad := failedTargets(ev); len(bad) > 0 {
			r.Remediation = fmt.Sprintf("Allow outbound TCP 443 from SGX node pool %s to %s, without TLS inspection.", pr.pool, strings.Join(bad, ", "))
		}
		for _, m := range missing {
			r.Evidence = append(r.Evidence, model.Evidence{Stage: "skipped", OK: false, Detail: m})
			if r.Status == model.StatusPass {
				r.Status = model.StatusWarn
			}
		}
		return r
	})
}

func cc03(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	return attestationPath(ctx, env, "CC-03")
}

func cc04(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	return attestationPath(ctx, env, "CC-04")
}

// reg03: every release image resolves by digest from each pool.
func reg03(_ context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	return perPool(env, nil, func(pr poolResult) model.Result {
		var ev []model.Evidence
		for _, s := range pr.stages {
			if s.Stage == protocol.StageManifest {
				ev = append(ev, toEvidence(s))
			}
		}
		if len(ev) == 0 {
			reason := "no release images to resolve"
			if env.ProbeNotes != nil && env.ProbeNotes.Images != "" {
				reason = env.ProbeNotes.Images
			}
			return poolSkip(pr.pool, reason)
		}
		r := verdict(model.PoolScope(pr.pool), ev...)
		if bad := failedTargets(ev); len(bad) > 0 {
			r.Remediation = fmt.Sprintf("From node pool %s these images do not resolve: %s. Check that the pool can reach the registry and that the credentials are entitled to them.", pr.pool, strings.Join(bad, ", "))
		}
		return r
	})
}

// bak02: the backup credentials can write, read and delete a test blob.
func bak02(_ context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	return perPool(env, nil, func(pr poolResult) model.Result {
		var ev []model.Evidence
		for _, s := range pr.stages {
			switch s.Stage {
			case protocol.StageBlobWrite, protocol.StageBlobRead, protocol.StageBlobDelete:
				ev = append(ev, toEvidence(s))
			}
		}
		if len(ev) == 0 {
			reason := "no backup test was planned"
			if env.ProbeNotes != nil && env.ProbeNotes.Storage != "" {
				reason = env.ProbeNotes.Storage
			}
			return poolSkip(pr.pool, reason)
		}
		return verdict(model.PoolScope(pr.pool), ev...)
	})
}
