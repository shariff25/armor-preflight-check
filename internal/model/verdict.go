package model

import "github.com/shariff25/armor-preflight-check/internal/exitcode"

// Verdict is the overall result of a run.
type Verdict string

const (
	VerdictReady             Verdict = "READY"
	VerdictReadyWithWarnings Verdict = "READY_WITH_WARNINGS"
	VerdictNotReady          Verdict = "NOT_READY"
)

// Counts tallies results by status.
type Counts struct {
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Warn    int `json:"warn"`
	Skipped int `json:"skipped"`
	Info    int `json:"info"`
}

// Count tallies results by status.
func Count(results []Result) Counts {
	var c Counts
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			c.Pass++
		case StatusFail:
			c.Fail++
		case StatusWarn:
			c.Warn++
		case StatusSkipped:
			c.Skipped++
		case StatusInfo:
			c.Info++
		}
	}
	return c
}

// Decide works out the verdict: any failed blocker is NOT_READY; otherwise
// any warning is READY_WITH_WARNINGS; otherwise READY.
func Decide(results []Result) Verdict {
	warned := false
	for _, r := range results {
		if r.Status == StatusFail && r.Severity == SeverityBlocker {
			return VerdictNotReady
		}
		if r.Status == StatusWarn || r.Status == StatusFail {
			warned = true
		}
	}
	if warned {
		return VerdictReadyWithWarnings
	}
	return VerdictReady
}

// ExitCode maps a verdict to the documented process exit code.
func (v Verdict) ExitCode() int {
	switch v {
	case VerdictReady:
		return exitcode.Ready
	case VerdictReadyWithWarnings:
		return exitcode.ReadyWithWarnings
	case VerdictNotReady:
		return exitcode.NotReady
	}
	return exitcode.ToolError
}

// Display is the verdict as printed for people.
func (v Verdict) Display() string {
	switch v {
	case VerdictReadyWithWarnings:
		return "READY WITH WARNINGS"
	case VerdictNotReady:
		return "NOT READY"
	}
	return string(v)
}
