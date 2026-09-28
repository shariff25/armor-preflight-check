// Package nettest tests one endpoint in stages (DNS, TCP, TLS, HTTP) and
// records each stage separately, so a failure names exactly where the path
// breaks.
package nettest

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shariff25/armor-preflight-check/internal/probe/protocol"
	"github.com/shariff25/armor-preflight-check/internal/tlsutil"
)

// maxHeaderBytes caps how much of a response the probe reads (status line
// and headers), so a hostile endpoint or proxy cannot exhaust its memory.
const maxHeaderBytes = 64 << 10

// Resolver resolves host names.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Dialer opens connections.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Tester runs staged tests.
type Tester struct {
	Resolver Resolver
	Dialer   Dialer
	// Roots are the public roots (nil: the system pool). CustomCA, when
	// set, is a customer CA checked separately (NET-03).
	Roots    *x509.CertPool
	CustomCA *x509.CertPool
	Proxy    *url.URL
	NoProxy  string
	// Timeout bounds each stage.
	Timeout time.Duration
}

func ok(target, stage string, format string, args ...any) protocol.Stage {
	return protocol.Stage{Target: target, Stage: stage, OK: true, Detail: fmt.Sprintf(format, args...)}
}

func fail(target, stage string, format string, args ...any) protocol.Stage {
	return protocol.Stage{Target: target, Stage: stage, OK: false, Detail: fmt.Sprintf(format, args...)}
}

// maxAddresses bounds how many resolved addresses the TCP stage tries.
const maxAddresses = 4

// validTarget refuses hosts and paths that could not appear in a well-formed
// request: both are written into hand-built CONNECT and GET requests, so a
// line break or space would inject a header.
func validTarget(tgt protocol.Target) error {
	if tgt.Host == "" || tgt.Port < 1 || tgt.Port > 65535 {
		return fmt.Errorf("invalid target %q port %d", tgt.Host, tgt.Port)
	}
	for _, c := range tgt.Host {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".-_:", c)) {
			return fmt.Errorf("invalid target host %q", tgt.Host)
		}
	}
	if tgt.Path != "" {
		if tgt.Path[0] != '/' {
			return fmt.Errorf("invalid target path %q", tgt.Path)
		}
		for _, c := range tgt.Path {
			if c <= ' ' || c == 0x7f {
				return fmt.Errorf("invalid target path %q", tgt.Path)
			}
		}
	}
	return nil
}

// Test runs every stage for a target, stopping at the first failure.
func (t *Tester) Test(ctx context.Context, tgt protocol.Target) []protocol.Stage {
	if err := validTarget(tgt); err != nil {
		return []protocol.Stage{fail(tgt.Host, protocol.StageDNS, "%v", err)}
	}
	addr := net.JoinHostPort(tgt.Host, strconv.Itoa(tgt.Port))
	proxied := t.Proxy != nil && !tgt.TCPOnly && !NoProxyMatch(t.NoProxy, tgt.Host)
	var stages []protocol.Stage

	var dialAddrs []string
	if proxied {
		s := ok(tgt.Host, protocol.StageDNS, "not resolved locally: reached through proxy %s", t.Proxy.Host)
		s.Data = map[string]string{protocol.DataViaProxy: t.Proxy.Host}
		stages = append(stages, s)
	} else {
		ctx2, cancel := context.WithTimeout(ctx, t.Timeout)
		addrs, err := t.Resolver.LookupHost(ctx2, tgt.Host)
		cancel()
		if err != nil || len(addrs) == 0 {
			return append(stages, fail(tgt.Host, protocol.StageDNS, "does not resolve: %s", describe(err, t.Timeout)))
		}
		sort.Strings(addrs)
		s := ok(tgt.Host, protocol.StageDNS, "resolves to %s", strings.Join(addrs, ", "))
		s.Data = map[string]string{protocol.DataAddresses: strings.Join(addrs, ",")}
		stages = append(stages, s)
		for _, a := range dialOrder(addrs) {
			dialAddrs = append(dialAddrs, net.JoinHostPort(a, strconv.Itoa(tgt.Port)))
		}
	}

	start := time.Now()
	var conn net.Conn
	var how string
	if proxied {
		c, err := t.connectProxy(ctx, addr)
		if err != nil {
			return append(stages, fail(addr, protocol.StageTCP, "%s", describe(err, t.Timeout)))
		}
		conn, how = c, "connected through proxy "+t.Proxy.Host
	} else {
		c, used, failed := t.dial(ctx, dialAddrs)
		if c == nil {
			return append(stages, fail(addr, protocol.StageTCP, "%s", strings.Join(failed, "; ")))
		}
		conn, how = c, "connected"
		if len(failed) > 0 {
			how = fmt.Sprintf("connected to %s after %s", used, strings.Join(failed, "; "))
		}
	}
	defer conn.Close()
	stages = append(stages, ok(addr, protocol.StageTCP, "%s in %s", how, time.Since(start).Round(time.Millisecond)))
	if tgt.TCPOnly {
		return stages
	}

	tlsStage, tconn, trusted := t.handshake(ctx, conn, tgt.Host, addr)
	stages = append(stages, tlsStage)
	if tconn == nil || tgt.Path == "" {
		return stages
	}
	if !trusted {
		return append(stages, fail(addr, protocol.StageHTTP, "not sent: the server certificate is not trusted"))
	}
	return append(stages, t.get(tconn, tgt.Host, addr, tgt.Path))
}

// dialOrder puts IPv4 addresses first, then IPv6, and keeps at most
// maxAddresses. Many nodes (AKS among them) have no IPv6 route, and string
// order would otherwise put an address such as 2001:db8::1 before
// 203.0.113.1, reporting a reachable endpoint as blocked.
func dialOrder(addrs []string) []string {
	var v4, v6 []string
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
			v6 = append(v6, a)
		} else {
			v4 = append(v4, a)
		}
	}
	out := append(v4, v6...)
	if len(out) > maxAddresses {
		out = out[:maxAddresses]
	}
	return out
}

// dial tries each address in turn within the stage timeout, giving each an
// equal share of what is left, so one blackholed address cannot use up the
// time the next one needs. It returns the connection and the address used,
// or nil and why each address failed.
func (t *Tester) dial(ctx context.Context, addrs []string) (net.Conn, string, []string) {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	var failed []string
	for i, a := range addrs {
		budget := time.Until(deadline) / time.Duration(len(addrs)-i)
		actx, acancel := context.WithTimeout(ctx, budget)
		conn, err := t.Dialer.DialContext(actx, "tcp", a)
		acancel()
		if err == nil {
			return conn, a, failed
		}
		if len(addrs) == 1 {
			return nil, "", []string{describe(err, t.Timeout)}
		}
		failed = append(failed, a+": "+describe(err, budget.Round(time.Millisecond)))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, "", failed
}

// connectProxy opens a tunnel to target through the proxy with CONNECT. An
// https:// proxy is reached over TLS, as Go's HTTP client does, and its
// certificate must verify against the public roots or the customer CA.
func (t *Tester) connectProxy(ctx context.Context, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	scheme := strings.ToLower(t.Proxy.Scheme)
	defaultPort := "80"
	switch scheme {
	case "http", "":
	case "https":
		defaultPort = "443"
	default:
		return nil, fmt.Errorf("proxy %s: the %s scheme is not supported; use an http:// or https:// proxy", t.Proxy.Host, scheme)
	}
	proxyAddr := t.Proxy.Host
	if t.Proxy.Port() == "" {
		proxyAddr = net.JoinHostPort(t.Proxy.Hostname(), defaultPort)
	}
	conn, err := t.Dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", t.Proxy.Host, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if scheme == "https" {
		cfg := tlsutil.Config(nil)
		cfg.ServerName = t.Proxy.Hostname()
		cfg.InsecureSkipVerify = true // verified below, against explicit pools
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy %s: TLS handshake failed: %w", t.Proxy.Host, err)
		}
		if !t.trusted(tc.ConnectionState().PeerCertificates, t.Proxy.Hostname()) {
			tc.Close()
			return nil, fmt.Errorf("proxy %s: its certificate is not trusted (add its CA with proxy.trustedCaPath)", t.Proxy.Host)
		}
		conn = tc
	}
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if u := t.Proxy.User; u != nil {
		p, _ := u.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+p)) + "\r\n"
	}
	if _, err := conn.Write([]byte(req + "\r\n")); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy %s: %w", t.Proxy.Host, err)
	}
	br := bufio.NewReader(io.LimitReader(conn, maxHeaderBytes))
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy %s: %w", t.Proxy.Host, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy %s refused CONNECT %s: %s", t.Proxy.Host, target, resp.Status)
	}
	conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		conn.Close()
		return nil, fmt.Errorf("proxy %s sent unexpected data after CONNECT", t.Proxy.Host)
	}
	return conn, nil
}

// roots are the public roots: the configured pool, else the system's.
func (t *Tester) roots() *x509.CertPool {
	if t.Roots != nil {
		return t.Roots
	}
	if sys, err := x509.SystemCertPool(); err == nil {
		return sys
	}
	return x509.NewCertPool()
}

// trusted reports whether a presented chain verifies for host against the
// public roots or the customer CA.
func (t *Tester) trusted(certs []*x509.Certificate, host string) bool {
	if len(certs) == 0 {
		return false
	}
	if verify(certs, host, t.roots()) == nil {
		return true
	}
	return t.CustomCA != nil && verify(certs, host, t.CustomCA) == nil
}

// handshake completes TLS and records the presented chain. It verifies the
// chain itself (against the public roots, and the customer CA if given)
// instead of letting the handshake fail, so an intercepted chain is
// described rather than just refused. Nothing is sent over an untrusted
// connection.
func (t *Tester) handshake(ctx context.Context, conn net.Conn, host, addr string) (protocol.Stage, *tls.Conn, bool) {
	cfg := tlsutil.Config(nil)
	cfg.ServerName = host
	cfg.InsecureSkipVerify = true // verified below, against explicit pools
	tc := tls.Client(conn, cfg)
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return fail(addr, protocol.StageTLS, "TLS handshake failed: %s", describe(err, t.Timeout)), nil, false
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fail(addr, protocol.StageTLS, "the server presented no certificate"), nil, false
	}
	var subjects []string
	for _, c := range certs {
		subjects = append(subjects, name(c.Subject.Organization, c.Subject.CommonName))
	}
	data := map[string]string{
		protocol.DataChain:      strings.Join(subjects, " <- "),
		protocol.DataIssuer:     name(certs[0].Issuer.Organization, certs[0].Issuer.CommonName),
		protocol.DataRootIssuer: name(certs[len(certs)-1].Issuer.Organization, certs[len(certs)-1].Issuer.CommonName),
	}
	verr := verify(certs, host, t.roots())
	data[protocol.DataVerified] = strconv.FormatBool(verr == nil)
	trusted := verr == nil
	if verr != nil {
		data[protocol.DataVerifyError] = verr.Error()
	}
	if t.CustomCA != nil {
		cerr := verify(certs, host, t.CustomCA)
		data[protocol.DataVerifiedCustom] = strconv.FormatBool(cerr == nil)
		trusted = trusted || cerr == nil
	}
	s := ok(addr, protocol.StageTLS, "handshake completed (%s); certificate issued by %s", tlsVersion(tc.ConnectionState().Version), data[protocol.DataIssuer])
	s.Data = data
	return s, tc, trusted
}

func verify(certs []*x509.Certificate, host string, roots *x509.CertPool) error {
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter})
	return err
}

// get sends one GET over the verified connection and records the status
// and the Date header (used for the clock-skew check, NET-07).
func (t *Tester) get(conn *tls.Conn, host, addr, path string) protocol.Stage {
	conn.SetDeadline(time.Now().Add(t.Timeout))
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: armor-preflight-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return fail(addr, protocol.StageHTTP, "request failed: %s", describe(err, t.Timeout))
	}
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, maxHeaderBytes)), nil)
	if err != nil {
		return fail(addr, protocol.StageHTTP, "no HTTP response: %s", describe(err, t.Timeout))
	}
	resp.Body.Close()
	s := ok(addr, protocol.StageHTTP, "GET %s answered %s", path, resp.Status)
	s.Data = map[string]string{protocol.DataStatus: strconv.Itoa(resp.StatusCode)}
	if d := resp.Header.Get("Date"); d != "" {
		s.Data[protocol.DataDate] = d
	}
	return s
}

func name(org []string, cn string) string {
	if len(org) > 0 && cn != "" {
		return org[0] + " / " + cn
	}
	if len(org) > 0 {
		return org[0]
	}
	if cn != "" {
		return cn
	}
	return "(unnamed)"
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return fmt.Sprintf("TLS 0x%04x", v)
}

// describe turns an error into a short explanation, naming timeouts.
func describe(err error, timeout time.Duration) string {
	if err == nil {
		return "no addresses"
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return fmt.Sprintf("timed out after %s (%v)", timeout, err)
	}
	return err.Error()
}

// NoProxyMatch reports whether host is excluded from the proxy.
func NoProxyMatch(noProxy, host string) bool {
	host = strings.ToLower(host)
	for _, e := range strings.Split(noProxy, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if e == "*" {
			return true
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			if ip := net.ParseIP(host); ip != nil && n.Contains(ip) {
				return true
			}
			continue
		}
		e = strings.TrimPrefix(e, "*")
		d := strings.TrimPrefix(e, ".")
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// ClockSkew computes the node clock's offset from the median Date header
// of the HTTP stages, or false when there were none.
func ClockSkew(stages []protocol.Stage, now time.Time) (time.Duration, int, bool) {
	var skews []time.Duration
	for _, s := range stages {
		if s.Stage != protocol.StageHTTP || s.Data[protocol.DataDate] == "" {
			continue
		}
		d, err := http.ParseTime(s.Data[protocol.DataDate])
		if err != nil {
			continue
		}
		skews = append(skews, now.Sub(d))
	}
	if len(skews) == 0 {
		return 0, 0, false
	}
	sort.Slice(skews, func(i, j int) bool { return skews[i] < skews[j] })
	return skews[len(skews)/2], len(skews), true
}
