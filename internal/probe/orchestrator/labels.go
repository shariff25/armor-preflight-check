// Package orchestrator creates Preflight's temporary namespace and probe
// pods, collects their results and removes everything afterwards.
package orchestrator

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Labels on every object Preflight creates.
const (
	LabelManagedBy  = "app.kubernetes.io/managed-by"
	ManagedByValue  = "armor-preflight"
	LabelRunID      = "armor-preflight/run-id"
	LabelNodePool   = "armor-preflight/node-pool"
	NamespacePrefix = "armor-preflight-"
)

// NamespaceName is the run's temporary namespace.
func NamespaceName(runID string) string { return NamespacePrefix + runID }

// Labels returns the labels for an object of this run.
func Labels(runID string) map[string]string {
	return map[string]string{LabelManagedBy: ManagedByValue, LabelRunID: runID}
}

var nonDNS = regexp.MustCompile(`[^a-z0-9-]+`)

// objectName builds a DNS-1123 name from a prefix and a free-form part
// (such as a node pool name), adding a short hash when the part had to be
// changed so two pools never collide.
func objectName(prefix, part string) string {
	clean := strings.Trim(nonDNS.ReplaceAllString(strings.ToLower(part), "-"), "-")
	name := prefix + clean
	if clean != part || len(name) > 57 {
		sum := sha256.Sum256([]byte(part))
		if len(name) > 57 {
			name = strings.TrimRight(name[:57], "-")
		}
		name += "-" + hex.EncodeToString(sum[:])[:5]
	}
	return name
}

// labelValue makes a string safe as a label value.
func labelValue(s string) string {
	v := strings.Trim(regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(s, "-"), "-._")
	if len(v) > 63 {
		v = strings.TrimRight(v[:63], "-._")
	}
	return v
}
