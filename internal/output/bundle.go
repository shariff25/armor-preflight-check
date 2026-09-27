package output

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/shariff25/armor-preflight-check/internal/redact"
)

// BundleEntry is one file in the support bundle.
type BundleEntry struct {
	Name   string
	Data   []byte
	SHA256 string
}

// Versions is versions.json in the bundle: what Support needs to trust the
// evidence before booking an install.
type Versions struct {
	Tool      Tool    `json:"tool"`
	Target    Target  `json:"target"`
	Run       RunInfo `json:"run"`
	Verdict   string  `json:"verdict"`
	Probes    []Probe `json:"probes"`
	CreatedAt string  `json:"bundleCreatedAt"`
}

// Patterns that must never leave the customer site even when they were not
// registered with the redactor.
var unregisteredSecret = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----|"auths"\s*:|(?i)"(password|token|secret)"\s*:\s*"[^"]`)

// BuildBundle assembles the bundle contents from a run's record: the JSON
// result, versions.json and a manifest of SHA-256 hashes. It contains no
// logs, secret values or workload data.
func BuildBundle(rec *Record, r *redact.Redactor, now time.Time) ([]BundleEntry, error) {
	rec.Redact(r)
	result, err := MarshalRecord(rec)
	if err != nil {
		return nil, err
	}
	versions, err := json.MarshalIndent(Versions{
		Tool: rec.Tool, Target: rec.Target, Run: rec.Run, Verdict: rec.Verdict, Probes: rec.Probes,
		CreatedAt: now.UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	entries := []BundleEntry{
		{Name: ResultFile, Data: r.Bytes(result)},
		{Name: "versions.json", Data: r.Bytes(append(versions, '\n'))},
	}
	var manifest bytes.Buffer
	for i := range entries {
		if loc := unregisteredSecret.FindIndex(entries[i].Data); loc != nil {
			return nil, fmt.Errorf("%w: %s contains something that looks like a credential; not writing the bundle", redact.ErrUnredacted, entries[i].Name)
		}
		sum := sha256.Sum256(entries[i].Data)
		entries[i].SHA256 = hex.EncodeToString(sum[:])
		fmt.Fprintf(&manifest, "%s  %8d  %s\n", entries[i].SHA256, len(entries[i].Data), entries[i].Name)
	}
	entries = append(entries, BundleEntry{Name: "MANIFEST.txt", Data: manifest.Bytes()})
	return entries, nil
}

// ListBundle prints what the bundle will contain, before anything is written.
func ListBundle(w io.Writer, rec *Record, entries []BundleEntry) {
	fmt.Fprintf(w, "Support bundle for run %s (%s mode, %s, verdict %s)\n", rec.Run.ID, rec.Run.Mode, targetLabel(rec), rec.VerdictDisplay())
	fmt.Fprintf(w, "It contains the JSON result and tool and cluster versions. No logs, secrets or workload data.\n\n")
	for _, e := range entries {
		fmt.Fprintf(w, "  %-14s %8d bytes\n", e.Name, len(e.Data))
	}
}

func targetLabel(rec *Record) string {
	if rec.Target.ArmorVersion == "" {
		return "no Armor version"
	}
	return "Armor " + rec.Target.ArmorVersion
}

// WriteBundle writes entries as a gzipped tar under a single directory.
func WriteBundle(path string, rec *Record, entries []BundleEntry, now time.Time) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	root := "armor-preflight-" + rec.Run.ID + "/"
	for _, e := range entries {
		hdr := &tar.Header{Name: root + e.Name, Mode: 0o644, Size: int64(len(e.Data)), ModTime: now.UTC(), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(e.Data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return writeAtomic(path, buf.Bytes())
}

// ReadBundle returns the files in a bundle, keyed by name without the
// top-level directory.
func ReadBundle(r io.Reader) (map[string][]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		name := hdr.Name
		if i := bytes.IndexByte([]byte(name), '/'); i >= 0 {
			name = name[i+1:]
		}
		out[name] = b
	}
}
