package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
)

// blockSet records where a check's parents failed or were skipped. A parent
// that failed for one node pool only blocks that pool's results, so a DNS
// failure on sgxpool1 does not hide results for systempool.
type blockSet struct {
	clusterBy map[string]string            // parent ID -> reason, for cluster-wide blocks
	poolBy    map[string]map[string]string // pool -> parent ID -> reason
	nodeBy    map[string]map[string]string // node -> parent ID -> reason
	order     []string                     // parent IDs in dependsOn order
}

func (r *runner) collectBlocks(def *catalog.Check) *blockSet {
	b := &blockSet{clusterBy: map[string]string{}, poolBy: map[string]map[string]string{}, nodeBy: map[string]map[string]string{}, order: def.DependsOn}
	for _, parent := range def.DependsOn {
		for _, pr := range r.parentResults(parent) {
			var reason string
			switch pr.Status {
			case model.StatusFail:
				reason = "failed"
			case model.StatusSkipped:
				reason = "was skipped"
				if pr.SkippedReason != nil {
					reason += " (" + *pr.SkippedReason + ")"
				}
			default:
				continue
			}
			switch {
			case pr.Scope.Node != "":
				add(b.nodeBy, pr.Scope.Node, parent, reason)
			case pr.Scope.NodePool != "":
				add(b.poolBy, pr.Scope.NodePool, parent, reason)
			default:
				if _, seen := b.clusterBy[parent]; !seen {
					b.clusterBy[parent] = reason
				}
			}
		}
	}
	return b
}

func add(m map[string]map[string]string, key, parent, reason string) {
	if m[key] == nil {
		m[key] = map[string]string{}
	}
	if _, seen := m[key][parent]; !seen {
		m[key][parent] = reason
	}
}

// cluster returns a reason when a parent is blocked cluster-wide.
func (b *blockSet) cluster() string { return b.describe(b.clusterBy, "") }

// any returns a reason when a parent is blocked anywhere.
func (b *blockSet) any() string {
	if r := b.cluster(); r != "" {
		return r
	}
	merged := map[string]string{}
	var where []string
	for _, group := range []struct {
		kind string
		m    map[string]map[string]string
	}{{"node pool", b.poolBy}, {"node", b.nodeBy}} {
		keys := sortedKeys(group.m)
		for _, k := range keys {
			for parent, reason := range group.m[k] {
				if _, seen := merged[parent]; !seen {
					merged[parent] = reason
				}
			}
			where = append(where, group.kind+" "+k)
		}
	}
	if len(merged) == 0 {
		return ""
	}
	return b.describe(merged, " for "+strings.Join(where, ", "))
}

// forScope returns a reason when the result's scope is blocked.
func (b *blockSet) forScope(s model.Scope, topo Topology) string {
	if r := b.cluster(); r != "" {
		return r
	}
	switch {
	case s.Node != "":
		if r := b.describe(b.nodeBy[s.Node], " for node "+s.Node); r != "" {
			return r
		}
		if pool := topo.PoolOf(s.Node); pool != "" {
			return b.describe(b.poolBy[pool], " for node pool "+pool)
		}
	case s.NodePool != "":
		if r := b.describe(b.poolBy[s.NodePool], " for node pool "+s.NodePool); r != "" {
			return r
		}
		for _, node := range topo.Pools[s.NodePool] {
			if r := b.describe(b.nodeBy[node], " for node "+node); r != "" {
				return r
			}
		}
	case s.Cluster:
		return b.any()
	}
	return ""
}

// describe names every blocked parent, in dependsOn order: for example
// "parent REG-03 failed for node pool sgxpool1".
func (b *blockSet) describe(byParent map[string]string, where string) string {
	if len(byParent) == 0 {
		return ""
	}
	var failed, skipped []string
	for _, parent := range b.order {
		reason, ok := byParent[parent]
		if !ok {
			continue
		}
		if reason == "failed" {
			failed = append(failed, parent)
		} else {
			skipped = append(skipped, fmt.Sprintf("parent %s %s", parent, reason))
		}
	}
	var parts []string
	if len(failed) > 0 {
		noun := "parent"
		if len(failed) > 1 {
			noun = "parents"
		}
		parts = append(parts, fmt.Sprintf("%s %s failed%s", noun, strings.Join(failed, ", "), where))
	}
	for _, s := range skipped {
		parts = append(parts, s+where)
	}
	return strings.Join(parts, "; ")
}

func sortedKeys(m map[string]map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
