package checks

import (
	"fmt"
	"regexp"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
)

func ev(stage, target string, ok bool, format string, args ...any) model.Evidence {
	return model.Evidence{Stage: stage, Target: target, OK: ok, Detail: fmt.Sprintf(format, args...)}
}

func result(status model.Status, scope model.Scope, evidence ...model.Evidence) model.Result {
	return model.Result{Status: status, Scope: scope, Evidence: evidence}
}

// verdict passes when every evidence entry is OK, and fails otherwise.
func verdict(scope model.Scope, evidence ...model.Evidence) model.Result {
	for _, e := range evidence {
		if !e.OK {
			return result(model.StatusFail, scope, evidence...)
		}
	}
	return result(model.StatusPass, scope, evidence...)
}

func skip(reason string) []model.Result {
	return []model.Result{model.Result{Scope: model.ClusterScope()}.Skipped(reason)}
}

func one(r model.Result) []model.Result { return []model.Result{r} }

// tbd skips a check whose catalog value Fortanix has not supplied (D-9).
func tbd(param string) []model.Result {
	return skip(fmt.Sprintf("catalog value `%s` is not published yet (TBD); ask Fortanix for a Preflight release that includes it", param))
}

// noKube is the skip for a check that needs the API when the kubeconfig
// could not be loaded. WS-01 fails in that case, so dependants are normally
// skipped before they run; this is a backstop.
func noKube(env *engine.Env) []model.Result {
	if env.KubeErr != nil {
		return skip("no Kubernetes access: " + env.KubeErr.Error())
	}
	return skip("no Kubernetes access")
}

// isTBD reports whether a catalog value is unset or TBD.
func isTBD(v string) bool { return v == "" || v == catalog.TBD }

func compileOrNil(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	return regexp.MustCompile(pattern)
}
