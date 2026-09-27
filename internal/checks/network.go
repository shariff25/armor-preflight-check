package checks

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/shariff25/armor-preflight-check/internal/catalog"
	"github.com/shariff25/armor-preflight-check/internal/engine"
	"github.com/shariff25/armor-preflight-check/internal/model"
	"github.com/shariff25/armor-preflight-check/internal/redact"
)

// net04: proxy settings are consistent and NO_PROXY covers the cluster
// CIDRs and the Armor domains.
func net04(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	st := env.Settings
	// The environment's proxy may embed credentials; never print them.
	envProxy := redact.URL(firstEnv(env, "HTTPS_PROXY", "https_proxy"))
	envNoProxy := firstEnv(env, "NO_PROXY", "no_proxy")
	proxy, noProxy, source := st.Proxy.HTTPSProxy, st.Proxy.NoProxy, "settings file"
	if proxy == "" {
		proxy, noProxy, source = envProxy, envNoProxy, "workstation environment"
	}
	if proxy == "" {
		return one(verdict(model.ClusterScope(), ev("proxy", "", true, "no HTTPS proxy is configured in the settings file or the workstation environment")))
	}
	var evidence []model.Evidence
	evidence = append(evidence, ev("proxy", "", true, "HTTPS proxy %s (from the %s)", proxy, source))
	if st.Proxy.HTTPSProxy != "" && envProxy != "" && envProxy != st.Proxy.HTTPSProxy {
		evidence = append(evidence, ev("consistency", "", false, "the settings file uses %s but this workstation's HTTPS_PROXY is %s", st.Proxy.HTTPSProxy, envProxy))
	}

	var required []string
	if env.Kube != nil {
		pods, services, _ := discoverCIDRs(ctx, env)
		required = append(required, pods...)
		required = append(required, services...)
	} else {
		evidence = append(evidence, ev("cidrs", "", false, "cannot read the cluster CIDRs without Kubernetes access"))
	}
	for _, d := range []string{st.Domains.Armor, st.Domains.StaticAssets} {
		if d != "" {
			required = append(required, d)
		}
	}
	entries := splitNoProxy(noProxy)
	var missing []string
	for _, r := range required {
		if !noProxyCovers(entries, r) {
			missing = append(missing, r)
		}
	}
	switch {
	case len(missing) > 0:
		evidence = append(evidence, ev("no_proxy", "", false, "NO_PROXY (%q) does not cover %s", noProxy, strings.Join(missing, ", ")))
	case len(required) > 0:
		evidence = append(evidence, ev("no_proxy", "", true, "NO_PROXY covers %s", strings.Join(required, ", ")))
	}
	r := verdict(model.ClusterScope(), evidence...)
	if len(missing) > 0 {
		r.Remediation = "Add " + strings.Join(missing, ", ") + " to NO_PROXY."
	}
	return one(r)
}

func firstEnv(env *engine.Env, names ...string) string {
	if env.LookupEnv == nil {
		return ""
	}
	for _, n := range names {
		if v, ok := env.LookupEnv(n); ok && v != "" {
			return v
		}
	}
	return ""
}

func splitNoProxy(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// noProxyCovers reports whether a NO_PROXY list covers a CIDR or a domain.
func noProxyCovers(entries []string, target string) bool {
	_, targetNet, targetIsCIDR := net.ParseCIDR(target)
	for _, e := range entries {
		if e == "*" {
			return true
		}
		if targetIsCIDR == nil {
			if _, n, err := net.ParseCIDR(e); err == nil {
				ones, _ := targetNet.Mask.Size()
				eOnes, _ := n.Mask.Size()
				if n.Contains(targetNet.IP) && eOnes <= ones {
					return true
				}
			}
			continue
		}
		host := strings.ToLower(target)
		e = strings.ToLower(e)
		if host == strings.TrimPrefix(e, ".") || strings.HasSuffix(host, "."+strings.TrimPrefix(e, ".")) {
			return true
		}
	}
	return false
}

// net05: the Armor and static-asset domains resolve from the workstation.
func net05(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	domains := []string{env.Settings.Domains.Armor}
	if d := env.Settings.Domains.StaticAssets; d != "" {
		domains = append(domains, d)
	}
	var evidence []model.Evidence
	for _, d := range domains {
		addrs, err := env.DNS.LookupHost(ctx, d)
		if err != nil || len(addrs) == 0 {
			evidence = append(evidence, ev("dns", d, false, "%s is recorded in the settings file but does not resolve yet (%v); create the internal DNS record before the install", d, errOrEmpty(err)))
			continue
		}
		sort.Strings(addrs)
		evidence = append(evidence, ev("dns", d, true, "%s resolves to %s", d, strings.Join(addrs, ", ")))
	}
	return one(verdict(model.ClusterScope(), evidence...))
}

func errOrEmpty(err error) string {
	if err == nil {
		return "no addresses"
	}
	return fmt.Sprint(err)
}
