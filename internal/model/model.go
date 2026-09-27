// Package model defines check results and the run verdict. Its JSON form is
// result.json schema version 1.
package model

import (
	"fmt"
	"strings"
)

// SchemaVersion is the result.json schema version. Adding fields keeps the
// version; removing or renaming one bumps it.
const SchemaVersion = "1"

// Severity says how much a failed check matters.
type Severity string

const (
	SeverityBlocker Severity = "blocker"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool {
	return s == SeverityBlocker || s == SeverityWarning || s == SeverityInfo
}

// Status is the outcome of one check for one scope.
type Status string

const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusWarn    Status = "warn"
	StatusSkipped Status = "skipped"
	StatusInfo    Status = "info"
)

// Area groups checks in reports.
type Area string

const (
	AreaWorkstation           Area = "workstation"
	AreaKubernetes            Area = "kubernetes"
	AreaConfidentialComputing Area = "confidential-computing"
	AreaNetwork               Area = "network"
	AreaRegistry              Area = "registry"
	AreaBackup                Area = "backup"
	AreaPKI                   Area = "pki"
)

// Areas lists every area in report order.
var Areas = []Area{AreaWorkstation, AreaKubernetes, AreaConfidentialComputing, AreaNetwork, AreaRegistry, AreaBackup, AreaPKI}

// Valid reports whether a is a known area.
func (a Area) Valid() bool {
	for _, known := range Areas {
		if a == known {
			return true
		}
	}
	return false
}

// Scope is what a result applies to: the whole cluster, one node pool or one
// node. Exactly one field is set.
type Scope struct {
	Cluster  bool   `json:"cluster,omitempty"`
	NodePool string `json:"nodePool,omitempty"`
	Node     string `json:"node,omitempty"`
}

// ClusterScope is the scope of a cluster-wide result.
func ClusterScope() Scope { return Scope{Cluster: true} }

// PoolScope is the scope of a per-node-pool result.
func PoolScope(pool string) Scope { return Scope{NodePool: pool} }

// NodeScope is the scope of a per-node result.
func NodeScope(node string) Scope { return Scope{Node: node} }

func (s Scope) String() string {
	switch {
	case s.Node != "":
		return "node " + s.Node
	case s.NodePool != "":
		return "node pool " + s.NodePool
	default:
		return "cluster"
	}
}

// Evidence is one observation behind a result. Network checks record each
// stage (dns, tcp, tls, http) as a separate entry.
type Evidence struct {
	Stage  string `json:"stage"`
	Target string `json:"target,omitempty"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Result is one check's outcome for one scope.
type Result struct {
	ID            string     `json:"id"`
	Title         string     `json:"title"`
	Area          Area       `json:"area"`
	Severity      Severity   `json:"severity"`
	Status        Status     `json:"status"`
	Scope         Scope      `json:"scope"`
	Evidence      []Evidence `json:"evidence"`
	Remediation   string     `json:"remediation"`
	Owner         string     `json:"owner"`
	DocLink       string     `json:"docLink"`
	DependsOn     []string   `json:"dependsOn"`
	SkippedReason *string    `json:"skippedReason"`
}

// Skipped returns a copy of r marked skipped for reason, with the reason
// also recorded as evidence so the evidence list is never empty.
func (r Result) Skipped(reason string) Result {
	r.Status = StatusSkipped
	r.SkippedReason = &reason
	r.Evidence = []Evidence{{Stage: "skip", OK: false, Detail: reason}}
	return r
}

// Validate checks that every field the report relies on is filled in.
func (r *Result) Validate() error {
	var missing []string
	if r.ID == "" {
		missing = append(missing, "id")
	}
	if r.Remediation == "" {
		missing = append(missing, "remediation")
	}
	if r.Owner == "" {
		missing = append(missing, "owner")
	}
	if r.DocLink == "" {
		missing = append(missing, "docLink")
	}
	if len(r.Evidence) == 0 {
		missing = append(missing, "evidence")
	}
	if r.Status == StatusSkipped && (r.SkippedReason == nil || *r.SkippedReason == "") {
		missing = append(missing, "skippedReason")
	}
	if r.Status != StatusSkipped && r.SkippedReason != nil {
		return fmt.Errorf("result %s: skippedReason set on status %s", r.ID, r.Status)
	}
	if len(missing) > 0 {
		return fmt.Errorf("result %s (%s): empty %s", r.ID, r.Scope, strings.Join(missing, ", "))
	}
	return nil
}
