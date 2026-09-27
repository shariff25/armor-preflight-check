package nettest

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/netfixtures"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/protocol"
)

const registry = "cr.download.fortanix.com"

type env struct {
	net    *netfixtures.Network
	public *netfixtures.CA
}

func setup(t *testing.T) *env {
	t.Helper()
	e := &env{net: netfixtures.NewNetwork(), public: netfixtures.NewCA("Public Trust Services", "Public Root CA")}
	t.Cleanup(e.net.Close)
	e.net.AddTLS(registry, e.public, netfixtures.Handler(time.Now))
	e.net.AddTLS("pccs.fortanix.com", e.public, netfixtures.Handler(func() time.Time { return time.Now().Add(-8 * time.Second) }))
	e.net.AddTCP("syslog.example.com")
	return e
}

func (e *env) tester() *Tester {
	return &Tester{Resolver: e.net, Dialer: e.net, Roots: e.public.Pool, Timeout: 300 * time.Millisecond}
}

func stage(stages []protocol.Stage, name string) *protocol.Stage {
	for i := range stages {
		if stages[i].Stage == name {
			return &stages[i]
		}
	}
	return nil
}

func TestAllStagesPass(t *testing.T) {
	e := setup(t)
	st := e.tester().Test(context.Background(), protocol.Target{Host: registry, Port: 443, Path: "/v2/"})
	if len(st) != 4 {
		t.Fatalf("%+v", st)
	}
	for _, s := range st {
		if !s.OK {
			t.Fatalf("%s failed: %s", s.Stage, s.Detail)
		}
	}
	tls := stage(st, "tls")
	if tls.Data[protocol.DataVerified] != "true" || !strings.Contains(tls.Data[protocol.DataIssuer], "Public Trust Services") {
		t.Fatalf("tls data %v", tls.Data)
	}
	http := stage(st, "http")
	if http.Data[protocol.DataStatus] != "401" || http.Data[protocol.DataDate] == "" || stage(st, "tcp").Target != registry+":443" {
		t.Fatalf("%+v", http)
	}
}

func TestDNSFailureStops(t *testing.T) {
	e := setup(t)
	st := e.tester().Test(context.Background(), protocol.Target{Host: "missing.example.com", Port: 443})
	if len(st) != 1 || st[0].OK || !strings.Contains(st[0].Detail, "no such host") {
		t.Fatalf("%+v", st)
	}
}

func TestBlackholedTCPTimesOut(t *testing.T) {
	e := setup(t)
	e.net.Blackhole(registry, 443)
	st := e.tester().Test(context.Background(), protocol.Target{Host: registry, Port: 443, Path: "/v2/"})
	tcp := stage(st, "tcp")
	if tcp == nil || tcp.OK || !strings.Contains(tcp.Detail, "timed out after 300ms") || stage(st, "tls") != nil {
		t.Fatalf("%+v", st)
	}
}

func TestRefusedTCP(t *testing.T) {
	e := setup(t)
	e.net.Refuse(registry, 443)
	st := e.tester().Test(context.Background(), protocol.Target{Host: registry, Port: 443})
	if tcp := stage(st, "tcp"); tcp.OK || !strings.Contains(tcp.Detail, "refused") {
		t.Fatalf("%+v", st)
	}
}

func TestUntrustedCertificateIsDescribedAndNoRequestSent(t *testing.T) {
	e := setup(t)
	tr := e.tester()
	tr.Roots = netfixtures.NewCA("Other", "Other Root").Pool
	st := tr.Test(context.Background(), protocol.Target{Host: registry, Port: 443, Path: "/v2/"})
	tls := stage(st, "tls")
	if !tls.OK || tls.Data[protocol.DataVerified] != "false" || tls.Data[protocol.DataVerifyError] == "" {
		t.Fatalf("tls %+v", tls)
	}
	if h := stage(st, "http"); h == nil || h.OK || !strings.Contains(h.Detail, "not sent") {
		t.Fatalf("http %+v", h)
	}
}

func TestTCPOnlyTarget(t *testing.T) {
	e := setup(t)
	st := e.tester().Test(context.Background(), protocol.Target{Host: "syslog.example.com", Port: 514, TCPOnly: true})
	if len(st) != 2 || !st[1].OK || st[1].Stage != "tcp" {
		t.Fatalf("%+v", st)
	}
}

func TestThroughPlainProxy(t *testing.T) {
	e := setup(t)
	p := e.net.NewProxy(nil)
	tr := e.tester()
	tr.Proxy, _ = url.Parse("http://" + p.Addr)
	st := tr.Test(context.Background(), protocol.Target{Host: registry, Port: 443, Path: "/v2/"})
	for _, s := range st {
		if !s.OK {
			t.Fatalf("%s: %s", s.Stage, s.Detail)
		}
	}
	if stage(st, "dns").Data[protocol.DataViaProxy] == "" || len(p.Connects) != 1 || p.Connects[0] != registry+":443" {
		t.Fatalf("%+v %v", st, p.Connects)
	}
	// NO_PROXY bypasses the proxy.
	tr.NoProxy = ".fortanix.com"
	tr.Test(context.Background(), protocol.Target{Host: registry, Port: 443})
	if len(p.Connects) != 1 {
		t.Fatal("NO_PROXY host went through the proxy")
	}
}

// NET-03 fixture: a TLS-inspecting proxy re-signs with its own CA.
func TestInterceptingProxyIsDetected(t *testing.T) {
	e := setup(t)
	inspect := netfixtures.NewCA("Evil Corp", "Evil Corp Inspection CA")
	p := e.net.NewProxy(inspect)
	tr := e.tester()
	tr.Proxy, _ = url.Parse("http://" + p.Addr)
	st := tr.Test(context.Background(), protocol.Target{Host: registry, Port: 443, Path: "/v2/"})
	tls := stage(st, "tls")
	if tls.Data[protocol.DataVerified] != "false" || !strings.Contains(tls.Data[protocol.DataIssuer], "Evil Corp") {
		t.Fatalf("interception not visible: %+v", tls)
	}
	// With the inspection CA supplied as trusted, the chain verifies against it.
	tr.CustomCA = inspect.Pool
	st = tr.Test(context.Background(), protocol.Target{Host: registry, Port: 443, Path: "/v2/"})
	tls = stage(st, "tls")
	if tls.Data[protocol.DataVerified] != "false" || tls.Data[protocol.DataVerifiedCustom] != "true" || !stage(st, "http").OK {
		t.Fatalf("trusted interception: %+v", st)
	}
}

func TestClockSkew(t *testing.T) {
	e := setup(t)
	tr := e.tester()
	var all []protocol.Stage
	for _, h := range []string{registry, "pccs.fortanix.com", "pccs.fortanix.com"} {
		all = append(all, tr.Test(context.Background(), protocol.Target{Host: h, Port: 443, Path: "/"})...)
	}
	skew, n, ok := ClockSkew(all, time.Now())
	if !ok || n != 3 || skew < 7*time.Second || skew > 10*time.Second {
		t.Fatalf("skew %s from %d responses", skew, n)
	}
	if _, _, ok := ClockSkew(nil, time.Now()); ok {
		t.Fatal("no responses should report no skew")
	}
}

func TestNoProxyMatch(t *testing.T) {
	for host, want := range map[string]bool{"cr.download.fortanix.com": true, "fortanix.com": true, "example.com": false, "10.1.2.3": true} {
		if got := NoProxyMatch(".fortanix.com, 10.0.0.0/8", host); got != want {
			t.Errorf("%s: %v", host, got)
		}
	}
}

// Pen test: an endpoint that streams headers forever cannot exhaust the
// probe's memory; the HTTP stage fails once the header budget is used up.
func TestEndlessHeadersAreBounded(t *testing.T) {
	e := setup(t)
	ca := e.public
	cert := ca.Issue("endless.example.com")
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		bufio.NewReader(c).ReadString('\n')
		c.Write([]byte("HTTP/1.1 200 OK\r\n"))
		line := []byte("X-Flood: " + strings.Repeat("a", 1000) + "\r\n")
		for i := 0; i < 100000; i++ { // ~100 MB if read without a limit
			if _, err := c.Write(line); err != nil {
				return
			}
		}
	}()
	tr := e.tester()
	tr.Timeout = 5 * time.Second
	tr.Dialer = redirect{to: ln.Addr().String()}
	tr.Resolver = staticResolver{}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	st := tr.Test(context.Background(), protocol.Target{Host: "endless.example.com", Port: 443, Path: "/"})
	runtime.ReadMemStats(&after)
	h := stage(st, "http")
	if h == nil || h.OK {
		t.Fatalf("expected the HTTP stage to fail: %+v", st)
	}
	if grown := int64(after.TotalAlloc) - int64(before.TotalAlloc); grown > 20<<20 {
		t.Fatalf("allocated %d MB reading a hostile response", grown>>20)
	}
}

type redirect struct{ to string }

func (r redirect) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, r.to)
}

type staticResolver struct{}

func (staticResolver) LookupHost(context.Context, string) ([]string, error) {
	return []string{"192.0.2.1"}, nil
}
