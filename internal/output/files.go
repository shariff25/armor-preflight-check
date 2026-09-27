package output

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/redact"
)

// WriteFiles writes result.json, report.html and firewall-request.csv to
// dir, masking every registered secret, and returns the paths written.
func WriteFiles(dir string, rec *Record, fw FirewallInputs, r *redact.Redactor) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	jsonBytes, err := MarshalRecord(rec)
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", ResultFile, err)
	}
	htmlBytes, err := RenderHTML(rec)
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", ReportFile, err)
	}
	csvBytes, err := RenderFirewallCSV(FirewallRows(rec.Results, fw))
	if err != nil {
		return nil, fmt.Errorf("render %s: %w", FirewallFile, err)
	}
	var written []string
	for _, f := range []struct {
		name string
		data []byte
	}{{ResultFile, jsonBytes}, {ReportFile, htmlBytes}, {FirewallFile, csvBytes}} {
		p := filepath.Join(dir, f.name)
		if err := writeAtomic(p, r.Bytes(f.data)); err != nil {
			return written, err
		}
		written = append(written, p)
	}
	return written, nil
}

// writeAtomic writes via a temporary file so an interrupted run never
// leaves a half-written report.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// WriteArtifacts writes extra files checks produced (for example
// image-overrides.yaml), masking secrets, and returns the paths written.
func WriteArtifacts(dir string, artifacts map[string][]byte, r *redact.Redactor) ([]string, error) {
	names := make([]string, 0, len(artifacts))
	for name := range artifacts {
		names = append(names, name)
	}
	sort.Strings(names)
	var written []string
	for _, name := range names {
		if filepath.Base(name) != name || strings.HasPrefix(name, ".") {
			return written, fmt.Errorf("refusing artifact name %q", name)
		}
		p := filepath.Join(dir, name)
		if err := writeAtomic(p, r.Bytes(artifacts[name])); err != nil {
			return written, err
		}
		written = append(written, p)
	}
	return written, nil
}
