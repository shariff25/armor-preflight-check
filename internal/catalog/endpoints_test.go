package catalog

import (
	"testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
)

func TestResolveEndpoints(t *testing.T) {
	c := mustLoad(t)
	st, err := settings.Parse([]byte("armorVersion: 1.0.404\nregistry: {url: mirror.example.com}\nstorage: {accountFqdn: s.blob.core.windows.net}\nsyslog: {host: syslog.example.com, port: 6514}\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]ResolvedEndpoint{}
	var missing []string
	for _, ep := range c.ResolveEndpoints(st) {
		if ep.Missing != "" {
			missing = append(missing, ep.Missing)
			continue
		}
		got[ep.Host] = ep
	}
	if got["mirror.example.com"].Port != 443 || got["syslog.example.com"].Port != 6514 || got["s.blob.core.windows.net"].Purpose != "Cassandra backups" {
		t.Fatalf("got %+v", got)
	}
	if _, ok := got["cr.download.fortanix.com"]; ok {
		t.Fatal("registry.url should replace the default registry host")
	}
	if len(missing) != 1 || missing[0] != "attestation.azureAttestationHost" {
		t.Fatalf("missing %v", missing)
	}
	withPort, _ := settings.Parse([]byte("armorVersion: 1.0.404\nregistry: {mode: mirror, url: \"mirror.corp.example:5000\"}\n"))
	for _, ep := range c.ResolveEndpoints(withPort) {
		if ep.HasCheck("REG-01") && (ep.Host != "mirror.corp.example" || ep.Port != 5000) {
			t.Fatalf("registry host:port not split: %+v", ep)
		}
	}
	if c.PurposeOf(st, "pccs.fortanix.com") != "SGX DCAP collateral (Fortanix PCCS)" {
		t.Fatal("PurposeOf")
	}

	def := c.ResolveEndpoints(settings.Default())
	hosts := map[string]bool{}
	for _, ep := range def {
		hosts[ep.Host] = true
	}
	if !hosts["cr.download.fortanix.com"] {
		t.Fatal("default registry host missing")
	}
}
