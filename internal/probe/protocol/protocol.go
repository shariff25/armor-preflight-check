// Package protocol is the contract between the CLI and probe pods: the
// request the CLI mounts into each pod, and the one-line JSON result the
// probe prints to stdout.
package protocol

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Version is the protocol version. The CLI refuses results from a probe
// that speaks a different version, so a mismatched image is reported
// clearly instead of misread.
const Version = "1"

// Sentinel prefixes the probe's result line in its log.
const Sentinel = "ARMOR-PREFLIGHT-RESULT "

// RequestFile is where the request is mounted in the probe pod.
const RequestFile = "/etc/armor-preflight/request.json"

// Request tells a probe what to test.
type Request struct {
	Version  string        `json:"version"`
	RunID    string        `json:"runId"`
	NodePool string        `json:"nodePool"`
	Timeout  time.Duration `json:"timeout"`
	// Targets and Images are filled in from milestone M5 on.
	Targets []Target `json:"targets,omitempty"`
	Images  []string `json:"images,omitempty"`
}

// Target is an endpoint to test through the DNS, TCP, TLS and HTTP stages.
type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// Path, when set, is requested over HTTPS after the TLS stage.
	Path string `json:"path,omitempty"`
}

// Result is what a probe reports.
type Result struct {
	Version    string    `json:"version"`
	RunID      string    `json:"runId"`
	NodePool   string    `json:"nodePool"`
	Node       string    `json:"node"`
	Pod        string    `json:"pod"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	// Stages holds network observations (milestone M5).
	Stages []Stage `json:"stages,omitempty"`
	Error  string  `json:"error,omitempty"`
}

// Stage is one observation, for example a DNS lookup or TLS handshake.
type Stage struct {
	Target string `json:"target"`
	Stage  string `json:"stage"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	// Data carries structured detail (addresses, certificate chain, clock).
	Data map[string]string `json:"data,omitempty"`
}

// Encode renders the result line, sentinel included.
func Encode(r Result) (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return Sentinel + string(b), nil
}

// Decode finds the last result line in a probe's log.
func Decode(log string) (Result, error) {
	var line string
	sc := bufio.NewScanner(strings.NewReader(log))
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if t := sc.Text(); strings.HasPrefix(t, Sentinel) {
			line = strings.TrimPrefix(t, Sentinel)
		}
	}
	if err := sc.Err(); err != nil {
		return Result{}, err
	}
	if line == "" {
		return Result{}, errors.New("probe log has no result line")
	}
	var r Result
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		return Result{}, fmt.Errorf("parse probe result: %w", err)
	}
	if r.Version != Version {
		return r, fmt.Errorf("probe speaks protocol version %q; this Preflight expects %q (use the probe image built with this release)", r.Version, Version)
	}
	return r, nil
}
