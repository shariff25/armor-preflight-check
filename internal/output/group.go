package output

import (
	"sort"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
)

// Team is the findings for one owning team.
type Team struct {
	Owner    string
	ToFix    []model.Result // fail and warn, blockers first
	Skipped  []model.Result
	Blockers int
}

// ByTeam groups results needing attention by owner: teams with failed
// blockers first, then teams with warnings, then teams with skipped checks.
func ByTeam(results []model.Result) []Team {
	idx := map[string]*Team{}
	var order []string
	for _, r := range results {
		if r.Status == model.StatusPass || r.Status == model.StatusInfo {
			continue
		}
		t := idx[r.Owner]
		if t == nil {
			t = &Team{Owner: r.Owner}
			idx[r.Owner] = t
			order = append(order, r.Owner)
		}
		if r.Status == model.StatusSkipped {
			t.Skipped = append(t.Skipped, r)
			continue
		}
		t.ToFix = append(t.ToFix, r)
		if r.Status == model.StatusFail && r.Severity == model.SeverityBlocker {
			t.Blockers++
		}
	}
	teams := make([]Team, 0, len(order))
	for _, o := range order {
		t := idx[o]
		sort.SliceStable(t.ToFix, func(i, j int) bool { return rank(t.ToFix[i]) < rank(t.ToFix[j]) })
		teams = append(teams, *t)
	}
	sort.SliceStable(teams, func(i, j int) bool {
		a, b := teams[i], teams[j]
		if (a.Blockers > 0) != (b.Blockers > 0) {
			return a.Blockers > 0
		}
		if (len(a.ToFix) > 0) != (len(b.ToFix) > 0) {
			return len(a.ToFix) > 0
		}
		return a.Owner < b.Owner
	})
	return teams
}

func rank(r model.Result) int {
	switch {
	case r.Status == model.StatusFail && r.Severity == model.SeverityBlocker:
		return 0
	case r.Status == model.StatusFail:
		return 1
	default:
		return 2
	}
}

// AreaCount is the tally for one area.
type AreaCount struct {
	Area   model.Area
	Counts model.Counts
}

// AreaCounts tallies results per area, in report order.
func AreaCounts(results []model.Result) []AreaCount {
	by := map[model.Area][]model.Result{}
	for _, r := range results {
		by[r.Area] = append(by[r.Area], r)
	}
	out := make([]AreaCount, 0, len(model.Areas))
	for _, a := range model.Areas {
		out = append(out, AreaCount{a, model.Count(by[a])})
	}
	return out
}

// SkipGroup is the checks skipped for one reason.
type SkipGroup struct {
	Reason string
	IDs    []string
}

// SkipGroups groups skipped results by reason, so "workstation mode" is
// printed once with every check it applies to.
func SkipGroups(results []model.Result) []SkipGroup {
	var order []string
	ids := map[string][]string{}
	for _, r := range results {
		if r.Status != model.StatusSkipped || r.SkippedReason == nil {
			continue
		}
		reason := *r.SkippedReason
		if _, ok := ids[reason]; !ok {
			order = append(order, reason)
		}
		if n := len(ids[reason]); n == 0 || ids[reason][n-1] != r.ID {
			ids[reason] = append(ids[reason], r.ID)
		}
	}
	out := make([]SkipGroup, 0, len(order))
	for _, reason := range order {
		out = append(out, SkipGroup{reason, ids[reason]})
	}
	return out
}
