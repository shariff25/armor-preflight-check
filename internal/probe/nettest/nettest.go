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
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/protocol"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/tlsutil"
)

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

// Test runs every stage for a target, stopping at the first failure.
func (t *Tester) Test(ctx context.Context, tgt protocol.Target) []protocol.Stage {
	addr := net.JoinHostPort(tgt.Host, strconv.Itoa(tgt.Port))
	proxied := t.Proxy != nil && !tgt.TCPOnly && !NoProxyMatch(t.NoProxy, tgt.Host)
	var stages []protocol.Stage

	var dialAddr string
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
		dialAddr = net.JoinHostPort(addrs[0], strconv.Itoa(tgt.Port))
	}

	start := time.Now()
	conn, err := t.connect(ctx, proxied, dialAddr, addr)
	if err != nil {
		return append(stages, fail(addr, protocol.StageTCP, "%s", describe(err, t.Timeout)))
	}
	defer conn.Close()
	how := "connected"
	if proxied {
		how = "connected through proxy " + t.Proxy.Host
	}
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

func (t *Tester) connect(ctx context.Context, proxied bool, dialAddr, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	if !proxied {
		return t.Dialer.DialContext(ctx, "tcp", dialAddr)
	}
	proxyAddr := t.Proxy.Host
	if t.Proxy.Port() == "" {
		proxyAddr = net.JoinHostPort(t.Proxy.Hostname(), "80")
	}
	conn, err := t.Dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", t.Proxy.Host, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
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
	br := bufio.NewReader(conn)
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
	roots := t.Roots
	if roots == nil {
		var err error
		if roots, err = x509.SystemCertPool(); err != nil {
			roots = x509.NewCertPool()
		}
	}
	verr := verify(certs, host, roots)
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
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
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
