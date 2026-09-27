package checks

import (
	"context"
	"strings"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
)

// cc01: every SGX node advertises the SGX device plugin resources.
func cc01(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Kube == nil {
		return noKube(env)
	}
	p := env.Params()
	c, err := discover(ctx, env.Kube.Core, p)
	if err != nil {
		return skip(err.Error())
	}
	sgx := c.sgxNodes()
	if len(sgx) == 0 {
		return skip("no SGX nodes found")
	}
	var out []model.Result
	for _, n := range sgx {
		var evidence []model.Evidence
		for _, res := range p.SGXResources {
			q := quantity(n.n, res)
			if q.IsZero() {
				evidence = append(evidence, ev("allocatable", res, false, "%s does not advertise %s; the SGX device plugin is not running on it", n.name, res))
			} else {
				evidence = append(evidence, ev("allocatable", res, true, "%s advertises %s=%s", n.name, res, q.String()))
			}
		}
		out = append(out, verdict(model.NodeScope(n.name), evidence...))
	}
	return out
}

// cc02: Node Feature Discovery is recent enough and labels SGX nodes.
func cc02(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Kube == nil {
		return noKube(env)
	}
	p := env.Params()
	c, err := discover(ctx, env.Kube.Core, p)
	if err != nil {
		return skip(err.Error())
	}
	sgx := c.sgxNodes()
	if len(sgx) == 0 {
		return skip("no SGX nodes found")
	}
	pods, err := podsWithImage(ctx, env, "node-feature-discovery")
	var nfd model.Evidence
	switch {
	case err != nil:
		nfd = ev("nfd", "", false, "%v", err)
	case len(pods) == 0:
		nfd = ev("nfd", "", false, "Node Feature Discovery is not installed (no node-feature-discovery pods)")
	default:
		version := imageTag(imageMatching(pods[0], "node-feature-discovery"))
		ok, verr := versionAtLeast(version, p.NFDMinVersion)
		switch {
		case verr != nil:
			nfd = ev("nfd", "", false, "cannot read the Node Feature Discovery version from image tag %q; %s or later is required", version, p.NFDMinVersion)
		case !ok:
			nfd = ev("nfd", "", false, "Node Feature Discovery %s is older than %s", version, p.NFDMinVersion)
		default:
			nfd = ev("nfd", "", true, "Node Feature Discovery %s", version)
		}
	}
	key, want := p.NFDSGXLabel, "true"
	var out []model.Result
	for _, n := range sgx {
		label := ev("label", key, true, "%s has %s=%s", n.name, key, want)
		if got, ok := n.n.Labels[key]; !ok {
			label = ev("label", key, false, "%s is missing label %s=%s", n.name, key, want)
		} else if got != want {
			label = ev("label", key, false, "%s has %s=%s, want %s", n.name, key, got, want)
		}
		out = append(out, verdict(model.NodeScope(n.name), nfd, label))
	}
	return out
}

// lower is a helper for case-insensitive comparison.
func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
