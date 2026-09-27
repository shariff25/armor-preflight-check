package output

import (
	"bytes"
	_ "embed"
	"html/template"
	"regexp"
	"strings"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
)

//go:embed report.html.tmpl
var reportTemplate string

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"join":      strings.Join,
	"firstLine": firstLine,
	"scope":     func(s model.Scope) string { return s.String() },
	"deref": func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	},
	"anchor":  func(s string) string { return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(s), "-"), "-") },
	"summary": summary,
}).Parse(reportTemplate))

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// SeverityCount is the tally for one severity.
type SeverityCount struct {
	Severity model.Severity
	Counts   model.Counts
}

type reportData struct {
	Rec        *Record
	Teams      []Team
	ByArea     []AreaCount
	BySeverity []SeverityCount
}

// RenderHTML renders report.html: self-contained, with inline styles only,
// so it opens offline and loads nothing.
func RenderHTML(rec *Record) ([]byte, error) {
	by := map[model.Severity][]model.Result{}
	for _, r := range rec.Results {
		by[r.Severity] = append(by[r.Severity], r)
	}
	data := reportData{Rec: rec, Teams: ByTeam(rec.Results), ByArea: AreaCounts(rec.Results)}
	for _, s := range []model.Severity{model.SeverityBlocker, model.SeverityWarning, model.SeverityInfo} {
		data.BySeverity = append(data.BySeverity, SeverityCount{s, model.Count(by[s])})
	}
	var buf bytes.Buffer
	if err := reportTmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func summary(r model.Result) string {
	if r.SkippedReason != nil {
		return *r.SkippedReason
	}
	parts := make([]string, 0, len(r.Evidence))
	for _, e := range failedEvidence(r) {
		parts = append(parts, formatEvidence(e))
	}
	return strings.Join(parts, "; ")
}
