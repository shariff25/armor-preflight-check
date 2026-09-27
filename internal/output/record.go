// Package output writes a run's results: the terminal summary, result.json,
// report.html, firewall-request.csv and the support bundle.
package output

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/shariff25/armor-preflight-check/internal/model"
)

// File names inside the output directory.
const (
	ResultFile   = "result.json"
	ReportFile   = "report.html"
	FirewallFile = "firewall-request.csv"
	BundleFile   = "bundle.tgz"
)

// VerdictIncomplete is recorded when Preflight could not finish every check
// (unimplemented checks or internal errors); such a run exits 3.
const VerdictIncomplete = "INCOMPLETE"

// Record is result.json, schema version 1 (see schema/result.v1.json).
type Record struct {
	SchemaVersion  string         `json:"schemaVersion"`
	Tool           Tool           `json:"tool"`
	Target         Target         `json:"target"`
	Run            RunInfo        `json:"run"`
	Verdict        string         `json:"verdict"`
	Counts         model.Counts   `json:"counts"`
	Results        []model.Result `json:"results"`
	Unimplemented  []string       `json:"unimplemented"`
	InternalErrors []string       `json:"internalErrors"`
	Probes         []Probe        `json:"probes"`
	RBAC           []string       `json:"rbac"`
}

// Tool identifies the Preflight build.
type Tool struct {
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	CatalogVersion string `json:"catalogVersion"`
}

// Target is what was checked.
type Target struct {
	ArmorVersion      string `json:"armorVersion"`
	KubeContext       string `json:"kubeContext"`
	KubernetesVersion string `json:"kubernetesVersion"`
}

// RunInfo describes the run itself.
type RunInfo struct {
	ID              string    `json:"id"`
	Mode            string    `json:"mode"`
	StartedAt       time.Time `json:"startedAt"`
	DurationSeconds int       `json:"durationSeconds"`
}

// Probe is one probe pod that ran.
type Probe struct {
	NodePool    string `json:"nodePool"`
	Node        string `json:"node,omitempty"`
	Pod         string `json:"pod"`
	Image       string `json:"image"`
	ImageDigest string `json:"imageDigest"`
	// Error is why this probe produced no result, if it did not.
	Error string `json:"error,omitempty"`
}

// NewRecord assembles a record. Slices are never nil, so JSON always has
// arrays rather than nulls.
func NewRecord(tool Tool, target Target, run RunInfo, results []model.Result, unimplemented, internalErrors []string) *Record {
	rec := &Record{
		SchemaVersion:  model.SchemaVersion,
		Tool:           tool,
		Target:         target,
		Run:            run,
		Results:        nonNil(results),
		Unimplemented:  nonNil(unimplemented),
		InternalErrors: nonNil(internalErrors),
		Probes:         []Probe{},
		RBAC:           []string{},
		Counts:         model.Count(results),
	}
	rec.Verdict = string(model.Decide(results))
	if len(unimplemented) > 0 || len(internalErrors) > 0 {
		rec.Verdict = VerdictIncomplete
	}
	return rec
}

// Duration sets the run duration, rounded to whole seconds.
func (r *Record) Duration(d time.Duration) {
	r.Run.DurationSeconds = int(math.Round(d.Seconds()))
}

// VerdictDisplay is the verdict as printed for people.
func (r *Record) VerdictDisplay() string {
	if r.Verdict == VerdictIncomplete {
		return VerdictIncomplete
	}
	return model.Verdict(r.Verdict).Display()
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// MarshalRecord renders result.json.
func MarshalRecord(r *Record) ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ReadRecord loads result.json from an output directory.
func ReadRecord(dir string) (*Record, error) {
	b, err := os.ReadFile(filepath.Join(dir, ResultFile))
	if err != nil {
		return nil, fmt.Errorf("read the latest run: %w (run `armor-preflight run` first)", err)
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", ResultFile, err)
	}
	if r.SchemaVersion != model.SchemaVersion {
		return nil, fmt.Errorf("%s has schema version %q; this build reads %q", ResultFile, r.SchemaVersion, model.SchemaVersion)
	}
	return &r, nil
}

// Redact masks secrets in every free-text field of the record, before it is
// rendered. Rendering escapes characters (JSON, HTML), so masking only the
// rendered bytes could miss a secret containing " < > & or a backslash.
func (r *Record) Redact(red interface{ String(string) string }) {
	for i := range r.Results {
		res := &r.Results[i]
		res.Title = red.String(res.Title)
		res.Remediation = red.String(res.Remediation)
		if res.SkippedReason != nil {
			v := red.String(*res.SkippedReason)
			res.SkippedReason = &v
		}
		for j := range res.Evidence {
			res.Evidence[j].Target = red.String(res.Evidence[j].Target)
			res.Evidence[j].Detail = red.String(res.Evidence[j].Detail)
		}
	}
	for i := range r.InternalErrors {
		r.InternalErrors[i] = red.String(r.InternalErrors[i])
	}
	for i := range r.Probes {
		r.Probes[i].Error = red.String(r.Probes[i].Error)
	}
	r.Target.KubeContext = red.String(r.Target.KubeContext)
}
