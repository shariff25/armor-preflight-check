package checks

import (
	"fmt"

	"github.com/shariff25/armor-preflight-check/internal/engine"
	"github.com/shariff25/armor-preflight-check/internal/fsutil"
	"github.com/shariff25/armor-preflight-check/internal/probe/protocol"
)

// ProbePlan is what the probes are asked to do.
type ProbePlan struct {
	// Request builds the request for one node pool.
	Request func(pool string) protocol.Request
	// Secret is mounted read-only into every probe (D-3); empty when no
	// probe check needs a credential.
	Secret map[string][]byte
	// Notes explain parts of the plan that were left out, for the checks
	// that would have used them.
	ImagesNote  string
	StorageNote string
}

// Plan builds the probe requests from the catalog endpoints and settings:
// every endpoint for every pool (NET-01, NET-02, CC-03, CC-04, NET-06), the
// release images to resolve (REG-03) and the backup blob test (BAK-02).
func Plan(env *engine.Env, runID string) (*ProbePlan, error) {
	st := env.Settings
	var targets []protocol.Target
	for _, ep := range env.Catalog.ResolveEndpoints(st) {
		if ep.Missing != "" {
			continue
		}
		targets = append(targets, protocol.Target{Host: ep.Host, Port: ep.Port, TCPOnly: ep.TCPOnly, Path: ep.HTTPPath})
	}
	var trustedCA string
	if p := st.Proxy.TrustedCAPath; p != "" {
		b, err := fsutil.ReadCertificatesPEM(p)
		if err != nil {
			return nil, fmt.Errorf("read proxy.trustedCaPath: %w", err)
		}
		trustedCA = string(b)
	}
	sec := st.ResolveSecrets(env.LookupEnv)
	plan := &ProbePlan{Secret: map[string][]byte{}}

	var reg *protocol.Registry
	images, _, err := releaseImages(env)
	switch {
	case err != nil:
		plan.ImagesNote = err.Error()
	case sec.RegistryPassword == "":
		plan.ImagesNote = "no registry password is available (registry.passwordEnv)"
	default:
		reg = &protocol.Registry{Host: st.Registry.URL, Username: st.Registry.Username}
		for _, img := range images {
			img.Host = st.Registry.URL // the registry the nodes pull from, direct or mirror
			reg.Images = append(reg.Images, img.String())
		}
		plan.Secret[protocol.RegistryPasswordKey] = []byte(sec.RegistryPassword)
	}

	var storage *protocol.Storage
	switch {
	case st.Storage.AccountFQDN == "" || st.Storage.Container == "":
		plan.StorageNote = "storage.accountFqdn and storage.container are not set"
	case sec.StorageKey == "":
		plan.StorageNote = "no storage credential is available (storage.credentialsEnv)"
	default:
		storage = &protocol.Storage{AccountFQDN: st.Storage.AccountFQDN, Container: st.Storage.Container}
		plan.Secret[protocol.StorageCredentialKey] = []byte(sec.StorageKey)
	}

	plan.Request = func(pool string) protocol.Request {
		r := protocol.Request{Version: protocol.Version, RunID: runID, NodePool: pool,
			Targets: targets, Registry: reg, Proxy: st.Proxy.HTTPSProxy, NoProxy: st.Proxy.NoProxy, TrustedCAPEM: trustedCA}
		if storage != nil {
			s := *storage
			s.Blob = "armor-preflight-" + runID + "-" + labelSafe(pool) + ".txt"
			r.Storage = &s
		}
		return r
	}
	return plan, nil
}

func labelSafe(s string) string {
	out := []byte(s)
	for i, c := range out {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			out[i] = '-'
		}
	}
	return string(out)
}
