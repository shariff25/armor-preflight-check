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

// Files the credentials Secret provides (D-3), under CredentialsDir.
const (
	CredentialsDir       = "/var/run/armor-preflight"
	RegistryPasswordKey  = "registry-password"
	StorageCredentialKey = "storage-credential"
)

// Request tells a probe what to test.
type Request struct {
	Version  string        `json:"version"`
	RunID    string        `json:"runId"`
	NodePool string        `json:"nodePool"`
	Timeout  time.Duration `json:"timeout"`
	Targets  []Target      `json:"targets,omitempty"`
	Registry *Registry     `json:"registry,omitempty"`
	Storage  *Storage      `json:"storage,omitempty"`
	// Proxy is an HTTPS proxy URL; NoProxy lists hosts reached directly.
	Proxy   string `json:"proxy,omitempty"`
	NoProxy string `json:"noProxy,omitempty"`
	// TrustedCAPEM is a customer CA (for example a TLS-inspecting proxy's)
	// checked separately from the public roots.
	TrustedCAPEM string `json:"trustedCaPem,omitempty"`
	// SGX asks an SGX node probe to generate and verify a quote (CC-05).
	SGX *SGX `json:"sgx,omitempty"`
}

// SGX asks for a quote bound to a fresh nonce, so a replayed quote is
// detected.
type SGX struct {
	// Nonce (hex) must appear at the start of the quote's report data.
	Nonce string `json:"nonce"`
}

// Target is an endpoint to test through the DNS, TCP, TLS and HTTP stages.
type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// TCPOnly skips the TLS and HTTP stages.
	TCPOnly bool `json:"tcpOnly,omitempty"`
	// Path, when set, is requested over HTTPS once the certificate is trusted.
	Path string `json:"path,omitempty"`
}

// Registry asks the probe to resolve image manifests by digest (REG-03).
type Registry struct {
	Host     string   `json:"host"`
	Username string   `json:"username"`
	Images   []string `json:"images"`
}

// Storage asks the probe to write, read and delete a test blob (BAK-02).
type Storage struct {
	AccountFQDN string `json:"accountFqdn"`
	Container   string `json:"container"`
	Blob        string `json:"blob"`
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

// Stage names.
const (
	StageDNS        = "dns"
	StageTCP        = "tcp"
	StageTLS        = "tls"
	StageHTTP       = "http"
	StageClock      = "clock"
	StageManifest   = "manifest"
	StageBlobWrite  = "blob-write"
	StageBlobRead   = "blob-read"
	StageBlobDelete = "blob-delete"
	StageQuote      = "quote"
	StageVerify     = "verify"
)

// Keys in Stage.Data.
const (
	DataAddresses      = "addresses"
	DataChain          = "chain"            // subjects, leaf first, joined by " <- "
	DataIssuer         = "issuer"           // the leaf's issuer
	DataRootIssuer     = "rootIssuer"       // the last presented certificate's issuer
	DataVerified       = "verified"         // "true" when the chain verifies against the public roots
	DataVerifiedCustom = "verifiedCustomCA" // "true" when it verifies against TrustedCAPEM
	DataVerifyError    = "verifyError"
	DataStatus         = "status"
	DataDate           = "date"        // the HTTP Date header, RFC 1123
	DataSkewSeconds    = "skewSeconds" // node clock minus the median Date header
	DataViaProxy       = "viaProxy"
	DataTCBStatus      = "tcbStatus"
	DataAdvisories     = "advisories"
	DataCollateral     = "collateral"
	DataNonceMatches   = "nonceMatches"
)

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
