package checks

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/shariff25/armor-preflight-check/internal/catalog"
	"github.com/shariff25/armor-preflight-check/internal/engine"
)

// cluster is what the node list tells us about pools.
type cluster struct {
	nodes []node
	pools map[string][]*node
	// aks is true when nodes carry AKS markers; other distributions get
	// an explicit "unsupported profile" warning (D-8).
	aks bool
	// modeLabelled is true when some node has the AKS system/user mode label.
	modeLabelled bool
}

type node struct {
	n      corev1.Node
	name   string
	pool   string
	sku    string
	sgx    bool
	system bool
}

func discover(ctx context.Context, env *engine.Env) (*cluster, error) {
	p := env.Params()
	items, err := listNodes(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	var skuRE *regexp.Regexp
	if p.SGXPool.SKUPattern != "" {
		skuRE = regexp.MustCompile(p.SGXPool.SKUPattern)
	}
	c := &cluster{pools: map[string][]*node{}}
	for _, n := range items {
		nd := node{n: n, name: n.Name, sku: n.Labels[p.InstanceTypeLabel]}
		nd.pool = n.Labels[p.NodePoolLabel]
		if nd.pool == "" {
			nd.pool = nd.sku
		}
		if nd.pool == "" {
			nd.pool = "unlabelled"
		}
		if strings.HasPrefix(n.Spec.ProviderID, "azure://") || n.Labels[p.NodePoolLabel] != "" {
			c.aks = true
		}
		if _, ok := n.Labels[p.SystemModeLabel]; ok {
			c.modeLabelled = true
		}
		nd.system = n.Labels[p.SystemModeLabel] == "system"
		nd.sgx = (skuRE != nil && skuRE.MatchString(nd.sku)) || hasSGXResources(n, p) || n.Labels[p.NFDSGXLabel] == "true"
		c.nodes = append(c.nodes, nd)
	}
	sort.Slice(c.nodes, func(i, j int) bool { return c.nodes[i].name < c.nodes[j].name })
	for i := range c.nodes {
		c.pools[c.nodes[i].pool] = append(c.pools[c.nodes[i].pool], &c.nodes[i])
	}
	// A pool is SGX if any node in it is; without mode labels, every
	// non-SGX pool counts as a system pool.
	for _, members := range c.pools {
		sgx := false
		for _, m := range members {
			sgx = sgx || m.sgx
		}
		for _, m := range members {
			m.sgx = sgx
			if !c.modeLabelled {
				m.system = !sgx
			}
		}
	}
	return c, nil
}

func hasSGXResources(n corev1.Node, p catalog.Parameters) bool {
	for _, r := range p.SGXResources {
		if q, ok := n.Status.Allocatable[corev1.ResourceName(r)]; ok && !q.IsZero() {
			return true
		}
	}
	return false
}

func (c *cluster) sgxNodes() []*node {
	var out []*node
	for i := range c.nodes {
		if c.nodes[i].sgx {
			out = append(out, &c.nodes[i])
		}
	}
	return out
}

func (c *cluster) poolNames(filter func(*node) bool) []string {
	var out []string
	for name, members := range c.pools {
		if filter(members[0]) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Topology returns the pools and node IPs for the engine, or an empty
// topology if the nodes cannot be listed.
func Topology(ctx context.Context, env *engine.Env) engine.Topology {
	t := engine.Topology{Pools: map[string][]string{}, NodeIPs: map[string]string{}}
	if env.Kube == nil {
		return t
	}
	c, err := discover(ctx, env)
	if err != nil {
		return t
	}
	for _, n := range c.nodes {
		t.Pools[n.pool] = append(t.Pools[n.pool], n.name)
		for _, a := range n.n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP {
				t.NodeIPs[n.name] = a.Address
				break
			}
		}
	}
	return t
}

const gib = 1 << 30

// sizeOK compares a node's reported capacity with a pool requirement.
func sizeOK(n *node, pool catalog.Pool, tolerance float64) (bool, string) {
	cpu := n.n.Status.Capacity[corev1.ResourceCPU]
	mem := n.n.Status.Capacity[corev1.ResourceMemory]
	cores := cpu.MilliValue() / 1000
	memGiB := float64(mem.Value()) / gib
	desc := fmt.Sprintf("%s: %s, %d vCPU, %.1f GiB", n.name, orUnknown(n.sku), cores, memGiB)
	if int(cores) < pool.MinCPU || memGiB < pool.MinMemoryGiB*tolerance {
		return false, desc + fmt.Sprintf(" (smaller than %s: %d vCPU, %.0f GiB)", pool.MinSKU, pool.MinCPU, pool.MinMemoryGiB)
	}
	return true, desc
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown size"
	}
	return s
}

func quantity(n corev1.Node, name string) resource.Quantity {
	return n.Status.Allocatable[corev1.ResourceName(name)]
}
