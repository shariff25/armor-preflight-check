// Package tlsutil is the one place Preflight builds TLS configurations and
// HTTP clients, so a FIPS build only has to change this package (D-20).
package tlsutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Options tune an HTTP client.
type Options struct {
	// RootCAs replaces the system roots when set (tests, or a customer CA).
	RootCAs *x509.CertPool
	// Proxy chooses the proxy per request; nil means the environment's
	// HTTPS_PROXY / NO_PROXY.
	Proxy func(*http.Request) (*url.URL, error)
	// Timeout bounds each request; zero means no client-side limit beyond
	// the request context.
	Timeout time.Duration
	// DialContext replaces the default dialer (tests).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Config returns the TLS configuration for every outbound connection.
func Config(roots *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
}

// NewHTTPClient returns an HTTP client using Config. It never follows a
// redirect to plain HTTP.
func NewHTTPClient(o Options) *http.Client {
	proxy := o.Proxy
	if proxy == nil {
		proxy = http.ProxyFromEnvironment
	}
	tr := &http.Transport{
		Proxy:                 proxy,
		TLSClientConfig:       Config(o.RootCAs),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		DialContext:           o.DialContext,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   o.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return http.ErrUseLastResponse
			}
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
