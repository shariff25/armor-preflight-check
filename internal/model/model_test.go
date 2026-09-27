package model

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
)

func res(sev Severity, st Status) Result { return Result{Severity: sev, Status: st} }

func TestDecide(t *testing.T) {
	cases := []struct {
		name string
		in   []Result
		want Verdict
		code int
	}{
		{"empty", nil, VerdictReady, exitcode.Ready},
		{"all pass", []Result{res(SeverityBlocker, StatusPass), res(SeverityInfo, StatusInfo)}, VerdictReady, exitcode.Ready},
		{"skips alone", []Result{res(SeverityBlocker, StatusSkipped)}, VerdictReady, exitcode.Ready},
		{"warning", []Result{res(SeverityBlocker, StatusPass), res(SeverityWarning, StatusWarn)}, VerdictReadyWithWarnings, exitcode.ReadyWithWarnings},
		{"blocker fail", []Result{res(SeverityWarning, StatusWarn), res(SeverityBlocker, StatusFail)}, VerdictNotReady, exitcode.NotReady},
		{"warning-severity fail is a warning", []Result{res(SeverityWarning, StatusFail)}, VerdictReadyWithWarnings, exitcode.ReadyWithWarnings},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Decide(c.in)
			if got != c.want || got.ExitCode() != c.code {
				t.Fatalf("got %s/%d, want %s/%d", got, got.ExitCode(), c.want, c.code)
			}
		})
	}
}

func TestCount(t *testing.T) {
	c := Count([]Result{res("", StatusPass), res("", StatusPass), res("", StatusFail), res("", StatusWarn), res("", StatusSkipped), res("", StatusInfo)})
	if c != (Counts{Pass: 2, Fail: 1, Warn: 1, Skipped: 1, Info: 1}) {
		t.Fatalf("got %+v", c)
	}
}

func TestResultJSONShape(t *testing.T) {
	r := Result{ID: "NET-02", Area: AreaNetwork, Severity: SeverityBlocker, Status: StatusFail, Scope: PoolScope("sgxpool1"),
		Evidence:    []Evidence{{Stage: "tcp", Target: "cr.download.fortanix.com:443", Detail: "connection timed out after 10s"}},
		Remediation: "x", Owner: "Network", DocLink: "https://example", DependsOn: []string{"NET-01"}}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"scope":{"nodePool":"sgxpool1"}`, `"skippedReason":null`, `"ok":false`, `"dependsOn":["NET-01"]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
}

func TestSkippedAndValidate(t *testing.T) {
	base := Result{ID: "CC-05", Remediation: "r", Owner: "o", DocLink: "d", Status: StatusPass, Evidence: []Evidence{{Stage: "x", OK: true, Detail: "d"}}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	s := base.Skipped("parent REG-03 failed")
	if s.Status != StatusSkipped || *s.SkippedReason != "parent REG-03 failed" || len(s.Evidence) != 1 {
		t.Fatalf("got %+v", s)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if base.Status != StatusPass {
		t.Fatal("Skipped mutated the original")
	}
	bad := base
	bad.Owner, bad.Evidence = "", nil
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "owner, evidence") {
		t.Fatalf("got %v", err)
	}
}

func TestNewRunID(t *testing.T) {
	now := time.Date(2026, 9, 26, 15, 12, 4, 0, time.UTC)
	id := NewRunID(now)
	if !regexp.MustCompile(`^20260926-1512-[0-9a-f]{4}$`).MatchString(id) {
		t.Fatalf("got %s", id)
	}
}
