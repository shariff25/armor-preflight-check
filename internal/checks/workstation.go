package checks

import (
	"context"
	"strings"

	"github.com/shariff25/armor-preflight-check/internal/catalog"
	"github.com/shariff25/armor-preflight-check/internal/engine"
	"github.com/shariff25/armor-preflight-check/internal/model"
	"github.com/shariff25/armor-preflight-check/internal/redact"
)

// requiredTools are the workstation tools the install needs, with the
// arguments that print their version.
var requiredTools = []struct {
	name string
	args []string
}{
	{"kubectl", []string{"version", "--client"}},
	{"helm", []string{"version", "--short"}},
	{"jq", []string{"--version"}},
	{"openssl", []string{"version"}},
}

// ws01 checks the workstation tools, the kube context and that the API
// server answers. Every Kubernetes check depends on it, so an unreachable
// cluster is reported once, here.
func ws01(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	var evidence []model.Evidence
	for _, tool := range requiredTools {
		path, err := env.Local.LookPath(tool.name)
		if err != nil {
			evidence = append(evidence, ev("tool", tool.name, false, "not found on PATH"))
			continue
		}
		out, err := env.Local.Output(ctx, path, tool.args...)
		version := firstLineOf(string(out))
		if err != nil || version == "" {
			evidence = append(evidence, ev("tool", tool.name, false, "found at %s but `%s %s` failed: %v", path, tool.name, strings.Join(tool.args, " "), err))
			continue
		}
		evidence = append(evidence, ev("tool", tool.name, true, "%s", version))
	}

	if env.Kube == nil {
		evidence = append(evidence, ev("context", "", false, "cannot use the kubeconfig: %v", env.KubeErr))
		return one(verdict(model.ClusterScope(), evidence...))
	}
	server := redact.URL(env.Kube.Server)
	want := env.Settings.KubeContext
	switch {
	case want != "" && want != env.Kube.Context:
		evidence = append(evidence, ev("context", env.Kube.Context, false, "current context is %q (%s) but the settings file expects %q; select it with -c", env.Kube.Context, server, want))
	case want != "":
		evidence = append(evidence, ev("context", env.Kube.Context, true, "matches the settings file (%s)", server))
	default:
		evidence = append(evidence, ev("context", env.Kube.Context, true, "using context %q (%s); set kubeContext in the settings file to enforce it", env.Kube.Context, server))
	}
	v, err := env.Kube.Core.Discovery().ServerVersion()
	if err != nil {
		evidence = append(evidence, ev("api", server, false, "API server did not answer: %v", err))
	} else {
		evidence = append(evidence, ev("api", server, true, "API server answered (Kubernetes %s)", v.GitVersion))
	}
	return one(verdict(model.ClusterScope(), evidence...))
}

func firstLineOf(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
