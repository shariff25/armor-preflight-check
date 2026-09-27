package catalog

import (
	"net"
	"strconv"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
)

// DefaultPort is used for endpoints without a port.
const DefaultPort = 443

// ResolvedEndpoint is an endpoint with its host and port filled in from the
// settings.
type ResolvedEndpoint struct {
	Host               string
	Port               int
	Purpose            string
	Checks             []string
	SGXOnly            bool
	HTTPPath           string
	InterceptSensitive bool
	TCPOnly            bool
	// Missing is the settings path that must be set before this endpoint
	// can be tested, when it is not set.
	Missing string
}

// ResolveEndpoints fills in hosts and ports from the settings. An endpoint
// whose host comes only from an unset setting is returned with Missing set,
// so checks can report it as skipped rather than drop it.
func (c *Catalog) ResolveEndpoints(st *settings.Settings) []ResolvedEndpoint {
	var out []ResolvedEndpoint
	for _, ep := range c.Endpoints {
		r := ResolvedEndpoint{Host: ep.FQDN, Port: ep.Port, Purpose: ep.Purpose, Checks: ep.Checks, SGXOnly: ep.SGXOnly,
			HTTPPath: ep.HTTPPath, InterceptSensitive: ep.InterceptSensitive, TCPOnly: ep.TCPOnly}
		if ep.FromSetting != "" {
			if v := st.Get(ep.FromSetting); v != "" {
				r.Host = v
				// A registry or mirror URL may carry its own port.
				if h, p, err := net.SplitHostPort(v); err == nil {
					if n, err := strconv.Atoi(p); err == nil {
						r.Host, r.Port = h, n
					}
				}
			} else if r.Host == "" {
				r.Missing = ep.FromSetting
			}
		}
		if ep.PortFromSetting != "" {
			if p := st.GetInt(ep.PortFromSetting); p > 0 {
				r.Port = p
			}
		}
		if r.Port == 0 {
			r.Port = DefaultPort
		}
		out = append(out, r)
	}
	return out
}

// PurposeOf returns the purpose of the endpoint at host, or "".
func (c *Catalog) PurposeOf(st *settings.Settings, host string) string {
	for _, ep := range c.ResolveEndpoints(st) {
		if ep.Host == host {
			return ep.Purpose
		}
	}
	return ""
}

// HasCheck reports whether the endpoint is tested by a check.
func (e ResolvedEndpoint) HasCheck(id string) bool {
	for _, c := range e.Checks {
		if c == id {
			return true
		}
	}
	return false
}

// Address is host:port.
func (e ResolvedEndpoint) Address() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
}
