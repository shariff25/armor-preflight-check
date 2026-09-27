package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
)

// WriteTerminal prints the summary: the verdict, counts per area, each
// failure with its owning team, and what was skipped and why.
func WriteTerminal(w io.Writer, rec *Record, files []string) {
	target := "no settings file"
	if rec.Target.ArmorVersion != "" {
		target = "Armor " + rec.Target.ArmorVersion
	}
	meta := []string{"run " + rec.Run.ID, rec.Run.Mode + " mode", target}
	if rec.Target.KubeContext != "" {
		meta = append(meta, "context "+rec.Target.KubeContext)
	}
	fmt.Fprintf(w, "Armor Preflight %s  (%s)\n\n", rec.Tool.Version, strings.Join(meta, ", "))

	blockers, warnings := 0, 0
	for _, r := range rec.Results {
		if r.Status == model.StatusFail && r.Severity == model.SeverityBlocker {
			blockers++
		}
		if r.Status == model.StatusWarn || (r.Status == model.StatusFail && r.Severity != model.SeverityBlocker) {
			warnings++
		}
	}
	fmt.Fprintf(w, "  %s   %s, %s\n\n", rec.VerdictDisplay(), plural(blockers, "blocker failed", "blockers failed"), plural(warnings, "warning", "warnings"))

	fmt.Fprintf(w, "  %-24s %5s %5s %5s %8s %5s\n", "Area", "pass", "fail", "warn", "skipped", "info")
	for _, ac := range AreaCounts(rec.Results) {
		c := ac.Counts
		fmt.Fprintf(w, "  %-24s %5d %5d %5d %8d %5d\n", ac.Area, c.Pass, c.Fail, c.Warn, c.Skipped, c.Info)
	}

	var fixing []Team
	for _, t := range ByTeam(rec.Results) {
		if len(t.ToFix) > 0 {
			fixing = append(fixing, t)
		}
	}
	if len(fixing) > 0 {
		fmt.Fprintf(w, "\nTo fix, by team\n")
		for _, t := range fixing {
			fmt.Fprintf(w, "\n  %s\n", t.Owner)
			for _, r := range t.ToFix {
				fmt.Fprintf(w, "    %-4s %-7s %s: %s\n", strings.ToUpper(string(r.Status)), r.ID, r.Scope, r.Title)
				for _, e := range failedEvidence(r) {
					fmt.Fprintf(w, "           %s\n", formatEvidence(e))
				}
				fmt.Fprintf(w, "           fix: %s\n", r.Remediation)
			}
		}
	}

	if groups := SkipGroups(rec.Results); len(groups) > 0 {
		fmt.Fprintf(w, "\nNot checked\n")
		for _, g := range groups {
			fmt.Fprintf(w, "  %s: %s\n", g.Reason, strings.Join(g.IDs, ", "))
		}
	}

	if len(rec.InternalErrors) > 0 {
		fmt.Fprintf(w, "\nPreflight internal errors (please report these to Fortanix Support)\n")
		for _, e := range rec.InternalErrors {
			fmt.Fprintf(w, "  %s\n", firstLine(e))
		}
	}
	if len(rec.Unimplemented) > 0 {
		fmt.Fprintf(w, "\nThis build does not implement %s: %s\n", plural(len(rec.Unimplemented), "check", "checks"), strings.Join(rec.Unimplemented, ", "))
	}
	if len(files) > 0 {
		fmt.Fprintf(w, "\nWrote %s\n", strings.Join(files, ", "))
	}
}

// failedEvidence returns the entries that explain a failure, or all of them
// when none is marked failed.
func failedEvidence(r model.Result) []model.Evidence {
	var bad []model.Evidence
	for _, e := range r.Evidence {
		if !e.OK {
			bad = append(bad, e)
		}
	}
	if len(bad) == 0 {
		return r.Evidence
	}
	return bad
}

func formatEvidence(e model.Evidence) string {
	s := e.Stage
	if e.Target != "" {
		s += " " + e.Target
	}
	return s + ": " + e.Detail
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
