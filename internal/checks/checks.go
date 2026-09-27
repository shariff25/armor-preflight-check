// Package checks holds the implementation of each catalog check.
package checks

import "github.com/shariff25/armor-preflight-check/internal/engine"

// Registry returns every implemented check, keyed by catalog ID.
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
		"CC-03":  cc03,
		"CC-04":  cc04,
		"CC-05":  cc05,
		"NET-01": net01,
		"NET-02": net02,
		"NET-03": net03,
		"NET-06": net06,
		"NET-07": net07,
		"REG-03": reg03,
		"BAK-02": bak02,
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
