// Package netfixtures provides local network fixtures for tests: a
// certificate authority, TLS servers standing in for the real endpoints, a
// CONNECT proxy, a TLS-intercepting proxy, and a dialer that can blackhole
// or refuse chosen destinations. It is only imported by tests.
package netfixtures

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"
)

// CA is a test certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	Pool *x509.CertPool
}

// NewCA creates a self-signed CA with the given organisation and name.
func NewCA(org, cn string) *CA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{Organization: []string{org}, CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Cert: cert, Key: key, Pool: pool}
}

// Issue returns a server certificate for hosts.
func (ca *CA) Issue(hosts ...string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: hosts[0]},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: hosts, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	return tls.Certificate{Certificate: [][]byte{der, ca.Cert.Raw}, PrivateKey: key}
}

// Network is a fake internet: names resolve to fake addresses, which the
// Dialer maps to local listeners.
type Network struct {
	mu        sync.Mutex
	names     map[string]string // host -> fake IP
	listeners map[string]string // fake IP -> local addr
	blackhole map[string]bool   // fake IP:port that silently drops
	refuse    map[string]bool   // fake IP:port that refuses
	closers   []io.Closer
	next      int
}

// NewNetwork returns an empty fake network.
func NewNetwork() *Network {
	return &Network{names: map[string]string{}, listeners: map[string]string{}, blackhole: map[string]bool{}, refuse: map[string]bool{}, next: 10}
}

// Close stops every server.
func (n *Network) Close() {
	for _, c := range n.closers {
		c.Close()
	}
}

func (n *Network) register(host, local string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	ip := fmt.Sprintf("203.0.113.%d", n.next)
	n.next++
	n.names[host] = ip
	n.listeners[ip] = local
	return ip
}

// Handler answers the TLS servers: 401 with a registry challenge on /v2/,
// 200 elsewhere, always with a Date header.
func Handler(date func() time.Time) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", date().UTC().Format(http.TimeFormat))
		if strings.HasPrefix(r.URL.Path, "/v2/") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://`+r.Host+`/token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// AddTLS starts an HTTPS server for host with a certificate from ca and
// returns its fake IP.
func (n *Network) AddTLS(host string, ca *CA, h http.Handler) string {
	cert := ca.Issue(host)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: h, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	go srv.ServeTLS(ln, "", "")
	n.closers = append(n.closers, srv)
	return n.register(host, ln.Addr().String())
}

// BlobStore is a fake Azure Blob endpoint: it requires an Authorization
// header or a SAS signature and keeps blobs in memory.
type BlobStore struct {
	mu    sync.Mutex
	Blobs map[string]string
	// Deny makes every request fail with 403 AuthorizationPermissionMismatch.
	Deny bool
}

func (b *BlobStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.URL.Path == "/" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if b.Deny || (r.Header.Get("Authorization") == "" && r.URL.Query().Get("sig") == "") {
		w.Header().Set("x-ms-error-code", "AuthorizationPermissionMismatch")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		b.Blobs[r.URL.Path] = string(body)
		w.WriteHeader(http.StatusCreated)
	case http.MethodGet:
		v, ok := b.Blobs[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, v)
	case http.MethodDelete:
		delete(b.Blobs, r.URL.Path)
		w.WriteHeader(http.StatusAccepted)
	}
}

// AddBlobStore serves a fake blob store at host.
func (n *Network) AddBlobStore(host string, ca *CA) *BlobStore {
	b := &BlobStore{Blobs: map[string]string{}}
	n.AddTLS(host, ca, b)
	return b
}

// AddTCP starts a plain TCP listener for host (a syslog stand-in).
func (n *Network) AddTCP(host string) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	n.closers = append(n.closers, ln)
	return n.register(host, ln.Addr().String())
}

// Blackhole makes connections to host:port hang until they time out, as a
// dropping firewall does.
func (n *Network) Blackhole(host string, port int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.blackhole[n.key(host, port)] = true
}

// key is the dial address for host:port (a fake IP, or host itself when it
// is already an address).
func (n *Network) key(host string, port int) string {
	if ip, ok := n.names[host]; ok {
		host = ip
	}
	return net.JoinHostPort(host, fmt.Sprint(port))
}

// Refuse makes connections to host:port be refused.
func (n *Network) Refuse(host string, port int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.refuse[n.key(host, port)] = true
}

// Forget removes a name, so it no longer resolves.
func (n *Network) Forget(host string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.names, host)
}

// LookupHost resolves fake names.
func (n *Network) LookupHost(_ context.Context, host string) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ip, ok := n.names[host]; ok {
		return []string{ip}, nil
	}
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// DialContext connects to a fake address (any port maps to the host's
// listener), or to a real local address.
func (n *Network) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	if ip, ok := n.names[host]; ok {
		_, port, _ := net.SplitHostPort(address)
		host, address = ip, net.JoinHostPort(ip, port)
	}
	local, known := n.listeners[host]
	hole, refused := n.blackhole[address], n.refuse[address]
	n.mu.Unlock()
	var d net.Dialer
	switch {
	case hole:
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: network, Err: ctx.Err()}
	case refused:
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	case known:
		return d.DialContext(ctx, network, local)
	}
	return d.DialContext(ctx, network, address)
}

// Proxy is an HTTPS CONNECT proxy on the fake network. With an
// intercepting CA it terminates TLS itself, as a TLS-inspecting firewall
// does, and presents certificates from that CA.
type Proxy struct {
	Addr      string
	net       *Network
	intercept *CA
	ln        net.Listener
	mu        sync.Mutex
	Connects  []string
}

// NewProxy starts a proxy. intercept may be nil for a plain tunnel.
func (n *Network) NewProxy(intercept *CA) *Proxy {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	p := &Proxy{Addr: ln.Addr().String(), net: n, intercept: intercept, ln: ln}
	n.closers = append(n.closers, ln)
	go p.serve()
	return p
}

// NewTLSProxy starts a proxy that clients reach over TLS (an https://
// proxy URL), serving a certificate for host from ca, and registers host on
// the network.
func (n *Network) NewTLSProxy(host string, ca *CA, intercept *CA) *Proxy {
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	ln := tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{ca.Issue(host)}})
	p := &Proxy{Addr: raw.Addr().String(), net: n, intercept: intercept, ln: ln}
	n.closers = append(n.closers, ln)
	n.register(host, raw.Addr().String())
	go p.serve()
	return p
}

func (p *Proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *Proxy) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	p.mu.Lock()
	p.Connects = append(p.Connects, req.Host)
	p.mu.Unlock()
	host, port, _ := net.SplitHostPort(req.Host)
	if p.intercept != nil {
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		cert := p.intercept.Issue(host)
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		if tc.Handshake() != nil {
			return
		}
		http.ReadRequest(bufio.NewReader(tc))
		tc.Write([]byte("HTTP/1.1 200 OK\r\nDate: " + time.Now().UTC().Format(http.TimeFormat) + "\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	addrs, err := p.net.LookupHost(context.Background(), host)
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	up, err := p.net.DialContext(context.Background(), "tcp", net.JoinHostPort(addrs[0], port))
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer up.Close()
	c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, br); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// ErrNotFound is returned for names the network does not know.
var ErrNotFound = errors.New("not found")
