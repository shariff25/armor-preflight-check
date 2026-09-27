// Package checks holds the implementation of each catalog check.
package checks

import "github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"

// Registry returns every implemented check, keyed by catalog ID. Checks are
// added area by area in milestones M3 to M6; until a check is here, runs
// report it as not implemented and exit 3.
func Registry() engine.Registry {
	return engine.Registry{
		"WS-01":  ws01,
		"K8S-01": k8s01,
		"K8S-02": k8s02,
		"K8S-03": k8s03,
		"K8S-04": k8s04,
		"K8S-05": k8s05,
		"K8S-06": k8s06,
		"K8S-07": k8s07,
		"K8S-08": k8s08,
		"K8S-09": k8s09,
		"K8S-10": k8s10,
		"K8S-11": k8s11,
		"K8S-12": k8s12,
		"CC-01":  cc01,
		"CC-02":  cc02,
		"NET-04": net04,
		"NET-05": net05,
		"REG-01": reg01,
		"REG-02": reg02,
		"REG-04": reg04,
		"REG-05": reg05,
		"BAK-01": bak01,
		"PKI-01": pki01,
		"PKI-02": pki02,
		"PKI-03": pki03,
	}
}
