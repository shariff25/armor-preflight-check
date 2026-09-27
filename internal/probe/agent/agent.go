// Package agent is what runs inside a probe pod. It needs no Kubernetes API
// access and no privileges: it reads its request, runs its tests and prints
// one result line.
package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shariff25/armor-preflight-check/internal/azblob"
	"github.com/shariff25/armor-preflight-check/internal/probe/nettest"
	"github.com/shariff25/armor-preflight-check/internal/probe/protocol"
	"github.com/shariff25/armor-preflight-check/internal/probe/sgx"
	"github.com/shariff25/armor-preflight-check/internal/registry"
	"github.com/shariff25/armor-preflight-check/internal/tlsutil"
)

// Agent runs a probe request. The zero value uses the real network.
type Agent struct {
	Resolver nettest.Resolver
	Dialer   nettest.Dialer
	// Roots replaces the system roots (tests).
	Roots          *x509.CertPool
	CredentialsDir string
	Now            func() time.Time
	// SGX generates and verifies quotes; the standard image has none.
	SGX sgx.Provider
}

// maxParallel bounds concurrent endpoint tests.
const maxParallel = 8

// Run executes a probe request and writes the result line to out.
func Run(ctx context.Context, requestPath string, out io.Writer, now func() time.Time) error {
	return (&Agent{Now: now}).Run(ctx, requestPath, out)
}

// Run executes a probe request and writes the result line to out.
func (a *Agent) Run(ctx context.Context, requestPath string, out io.Writer) error {
	a.defaults()
	res := protocol.Result{
		Version:   protocol.Version,
		Node:      os.Getenv("NODE_NAME"),
		Pod:       os.Getenv("POD_NAME"),
		StartedAt: a.Now().UTC(),
	}
	req, err := readRequest(requestPath)
	switch {
	case err != nil:
		res.Error = err.Error()
	case req.Version != protocol.Version:
		res.RunID, res.NodePool = req.RunID, req.NodePool
		res.Error = fmt.Sprintf("request protocol version %q, probe speaks %q", req.Version, protocol.Version)
	default:
		res.RunID, res.NodePool = req.RunID, req.NodePool
		stages, err := a.test(ctx, req)
		res.Stages = stages
		if err != nil {
			res.Error = err.Error()
		}
	}
	res.FinishedAt = a.Now().UTC()
	line, err := protocol.Encode(res)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, line)
	return err
}

func (a *Agent) defaults() {
	if a.Resolver == nil {
		a.Resolver = net.DefaultResolver
	}
	if a.Dialer == nil {
		a.Dialer = &net.Dialer{}
	}
	if a.CredentialsDir == "" {
		a.CredentialsDir = protocol.CredentialsDir
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.SGX == nil {
		a.SGX = sgx.Unsupported{}
	}
}

func (a *Agent) test(ctx context.Context, req protocol.Request) ([]protocol.Stage, error) {
	if req.SGX != nil {
		return a.quote(ctx, req.SGX), ctx.Err()
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	t := &nettest.Tester{Resolver: a.Resolver, Dialer: a.Dialer, Roots: a.Roots, NoProxy: req.NoProxy, Timeout: timeout}
	if req.Proxy != "" {
		u, err := url.Parse(req.Proxy)
		if err != nil {
			return nil, fmt.Errorf("proxy %q: %w", req.Proxy, err)
		}
		t.Proxy = u
	}
	if req.TrustedCAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(req.TrustedCAPEM)) {
			return nil, fmt.Errorf("the trusted CA in the request is not PEM")
		}
		t.CustomCA = pool
	}

	results := make([][]protocol.Stage, len(req.Targets))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for i, tgt := range req.Targets {
		wg.Add(1)
		go func(i int, tgt protocol.Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = t.Test(ctx, tgt)
		}(i, tgt)
	}
	wg.Wait()
	var stages []protocol.Stage
	for _, r := range results {
		stages = append(stages, r...)
	}
	stages = append(stages, clockStage(stages, a.Now()))

	client := a.httpClient(t, req.TrustedCAPEM, timeout)
	if req.Registry != nil {
		stages = append(stages, a.manifests(ctx, client, req.Registry)...)
	}
	if req.Storage != nil {
		stages = append(stages, a.blob(ctx, client, req.Storage)...)
	}
	return stages, ctx.Err()
}

func clockStage(stages []protocol.Stage, now time.Time) protocol.Stage {
	skew, n, ok := nettest.ClockSkew(stages, now)
	if !ok {
		return protocol.Stage{Stage: protocol.StageClock, OK: false, Detail: "no HTTP responses to compare the node clock with"}
	}
	return protocol.Stage{Stage: protocol.StageClock, OK: true,
		Detail: fmt.Sprintf("node clock differs by %s from the median Date header of %d HTTP responses", skew.Round(100*time.Millisecond), n),
		Data:   map[string]string{protocol.DataSkewSeconds: strconv.FormatFloat(skew.Seconds(), 'f', 1, 64)}}
}

// httpClient trusts the public roots plus the customer CA, honours the
// proxy and NO_PROXY, and uses the agent's dialer.
func (a *Agent) httpClient(t *nettest.Tester, customPEM string, timeout time.Duration) *http.Client {
	var pool *x509.CertPool
	if a.Roots != nil {
		pool = a.Roots.Clone()
	} else if sys, err := x509.SystemCertPool(); err == nil {
		pool = sys
	} else {
		pool = x509.NewCertPool()
	}
	if customPEM != "" {
		pool.AppendCertsFromPEM([]byte(customPEM))
	}
	opts := tlsutil.Options{RootCAs: pool, Timeout: timeout, DialContext: a.Dialer.DialContext}
	opts.Proxy = func(r *http.Request) (*url.URL, error) {
		if t.Proxy == nil || nettest.NoProxyMatch(t.NoProxy, r.URL.Hostname()) {
			return nil, nil
		}
		return t.Proxy, nil
	}
	return tlsutil.NewHTTPClient(opts)
}

func (a *Agent) secret(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(a.CredentialsDir, name))
	if err != nil {
		return "", fmt.Errorf("credential %s is not mounted: %w", name, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// manifests resolves each release image by digest without pulling it.
func (a *Agent) manifests(ctx context.Context, client *http.Client, r *protocol.Registry) []protocol.Stage {
	password, err := a.secret(protocol.RegistryPasswordKey)
	if err != nil {
		return []protocol.Stage{{Target: r.Host, Stage: protocol.StageManifest, OK: false, Detail: err.Error()}}
	}
	c := &registry.Client{HTTP: client, Host: r.Host, Username: r.Username, Password: password}
	var out []protocol.Stage
	for _, img := range r.Images {
		ref, err := registry.ParseReference(img)
		if err != nil {
			out = append(out, protocol.Stage{Target: img, Stage: protocol.StageManifest, OK: false, Detail: err.Error()})
			continue
		}
		c.Host = ref.Host
		found, digest, err := c.Manifest(ctx, ref.Repo, ref.Ref())
		switch {
		case err != nil:
			out = append(out, protocol.Stage{Target: img, Stage: protocol.StageManifest, OK: false, Detail: "could not resolve: " + err.Error()})
		case !found:
			out = append(out, protocol.Stage{Target: img, Stage: protocol.StageManifest, OK: false, Detail: "not found in the registry"})
		default:
			out = append(out, protocol.Stage{Target: img, Stage: protocol.StageManifest, OK: true, Detail: "resolved (" + digest + ")"})
		}
	}
	return out
}

// blob writes, reads back and deletes a small test blob.
func (a *Agent) blob(ctx context.Context, client *http.Client, s *protocol.Storage) []protocol.Stage {
	target := s.AccountFQDN + "/" + s.Container + "/" + s.Blob
	cred, err := a.secret(protocol.StorageCredentialKey)
	if err != nil {
		return []protocol.Stage{{Target: target, Stage: protocol.StageBlobWrite, OK: false, Detail: err.Error()}}
	}
	c := &azblob.Client{HTTP: client, AccountFQDN: s.AccountFQDN, Credential: cred, Now: a.Now}
	payload := []byte("armor-preflight backup test " + a.Now().UTC().Format(time.RFC3339))
	if err := c.Put(ctx, s.Container, s.Blob, payload); err != nil {
		return []protocol.Stage{{Target: target, Stage: protocol.StageBlobWrite, OK: false, Detail: "write failed: " + err.Error()}}
	}
	out := []protocol.Stage{{Target: target, Stage: protocol.StageBlobWrite, OK: true, Detail: fmt.Sprintf("wrote %d bytes", len(payload))}}
	got, err := c.Get(ctx, s.Container, s.Blob)
	switch {
	case err != nil:
		out = append(out, protocol.Stage{Target: target, Stage: protocol.StageBlobRead, OK: false, Detail: "read failed: " + err.Error()})
	case string(got) != string(payload):
		out = append(out, protocol.Stage{Target: target, Stage: protocol.StageBlobRead, OK: false, Detail: "read back different content"})
	default:
		out = append(out, protocol.Stage{Target: target, Stage: protocol.StageBlobRead, OK: true, Detail: "read back the same content"})
	}
	if err := c.Delete(ctx, s.Container, s.Blob); err != nil {
		out = append(out, protocol.Stage{Target: target, Stage: protocol.StageBlobDelete, OK: false, Detail: "delete failed (remove the test blob by hand): " + err.Error()})
	} else {
		out = append(out, protocol.Stage{Target: target, Stage: protocol.StageBlobDelete, OK: true, Detail: "deleted"})
	}
	return out
}

func readRequest(path string) (protocol.Request, error) {
	var req protocol.Request
	b, err := os.ReadFile(path)
	if err != nil {
		return req, fmt.Errorf("read request: %w", err)
	}
	if err := json.Unmarshal(b, &req); err != nil {
		return req, fmt.Errorf("parse request: %w", err)
	}
	return req, nil
}

// quote generates a quote bound to the nonce and verifies it (CC-05).
func (a *Agent) quote(ctx context.Context, r *protocol.SGX) []protocol.Stage {
	nonce, err := hex.DecodeString(r.Nonce)
	if err != nil || len(nonce) == 0 || len(nonce) > 64 {
		return []protocol.Stage{{Stage: protocol.StageQuote, OK: false, Detail: "the request nonce is not 1 to 64 bytes of hex"}}
	}
	q, err := a.SGX.Quote(ctx, nonce)
	if err != nil {
		return []protocol.Stage{{Stage: protocol.StageQuote, OK: false, Detail: "could not generate a quote: " + err.Error()}}
	}
	out := []protocol.Stage{{Stage: protocol.StageQuote, OK: true, Detail: fmt.Sprintf("generated a %d-byte quote", len(q))}}
	v, err := a.SGX.Verify(ctx, q)
	if err != nil {
		return append(out, protocol.Stage{Stage: protocol.StageVerify, OK: false, Detail: "the quote did not verify: " + err.Error()})
	}
	matches := bytes.HasPrefix(v.ReportData, nonce)
	s := protocol.Stage{Stage: protocol.StageVerify, OK: matches,
		Detail: fmt.Sprintf("the quote verified with TCB status %s", v.TCBStatus),
		Data: map[string]string{
			protocol.DataTCBStatus:    v.TCBStatus,
			protocol.DataAdvisories:   strings.Join(v.Advisories, ","),
			protocol.DataCollateral:   v.Collateral,
			protocol.DataNonceMatches: strconv.FormatBool(matches),
		}}
	if !matches {
		s.Detail = "the verified quote does not carry this run's nonce (a replayed or cached quote)"
	}
	return append(out, s)
}
