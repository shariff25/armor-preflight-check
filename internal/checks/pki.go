package checks

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/fsutil"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
)

var fqdnRE = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// pki01: the Armor domain is decided and recorded.
func pki01(_ context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	d := env.Settings.Domains.Armor
	if !fqdnRE.MatchString(d) {
		return one(verdict(model.ClusterScope(), ev("domain", d, false, "%q is not a valid fully qualified domain name", d)))
	}
	return one(verdict(model.ClusterScope(), ev("domain", d, true, "Armor domain %s is recorded; MFA registrations bind to it, so it cannot change after install", d)))
}

// loadChain reads a PEM file of certificates, leaf first.
func loadChain(path string) ([]*x509.Certificate, error) {
	b, err := fsutil.ReadLimited(path, fsutil.MaxPEMBytes)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in %s", path)
	}
	return certs, nil
}

// pki02: the CA is ready, and a sample certificate (if given) carries a
// complete chain: leaf, intermediates and a self-signed root.
func pki02(_ context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	c := env.Settings.Certificates
	evidence := []model.Evidence{ev("worksheet", "certificates.caReady", *c.CAReady, "caReady is %v in the settings file", *c.CAReady)}
	if c.SampleAPICertPath == "" {
		evidence = append(evidence, ev("sample", "", true, "no sample certificate given (certificates.sampleApiCertPath), so the chain was not validated"))
		return one(verdict(model.ClusterScope(), evidence...))
	}
	now := time.Now()
	if env.Now != nil {
		now = env.Now()
	}
	evidence = append(evidence, validateChain(c.SampleAPICertPath, now)...)
	return one(verdict(model.ClusterScope(), evidence...))
}

func validateChain(path string, now time.Time) []model.Evidence {
	certs, err := loadChain(path)
	if err != nil {
		return []model.Evidence{ev("sample", path, false, "cannot read the sample certificate: %v", err)}
	}
	leaf := certs[0]
	var out []model.Evidence
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		out = append(out, ev("validity", leaf.Subject.CommonName, false, "certificate is not valid now (valid %s to %s)", leaf.NotBefore.Format("2006-01-02"), leaf.NotAfter.Format("2006-01-02")))
	}
	serverAuth := len(leaf.ExtKeyUsage) == 0
	for _, u := range leaf.ExtKeyUsage {
		serverAuth = serverAuth || u == x509.ExtKeyUsageServerAuth
	}
	if !serverAuth {
		out = append(out, ev("usage", leaf.Subject.CommonName, false, "certificate is not valid for TLS server authentication"))
	}
	if len(certs) < 3 {
		out = append(out, ev("chain", path, false, "the file has %d certificate(s); include the leaf, every intermediate and the root", len(certs)))
	}
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			out = append(out, ev("chain", certs[i].Subject.CommonName, false, "%q is not signed by the next certificate %q: %v", certs[i].Subject.CommonName, certs[i+1].Subject.CommonName, err))
		}
	}
	root := certs[len(certs)-1]
	if len(certs) > 1 {
		if root.CheckSignatureFrom(root) != nil || !root.IsCA {
			out = append(out, ev("root", root.Subject.CommonName, false, "the last certificate %q is not a self-signed root CA", root.Subject.CommonName))
		}
	}
	if len(out) == 0 {
		names := make([]string, len(certs))
		for i, c := range certs {
			names[i] = c.Subject.CommonName
		}
		out = append(out, ev("chain", path, true, "complete chain: %s", strings.Join(names, " -> ")))
	}
	return out
}

// pki03: the planned API SANs include api.<domain>.
func pki03(_ context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	c := env.Settings.Certificates
	want := "api." + strings.ToLower(env.Settings.Domains.Armor)
	sans, source := c.PlannedAPISans, "certificates.plannedApiSans"
	if len(sans) == 0 && c.SampleAPICertPath != "" {
		certs, err := loadChain(c.SampleAPICertPath)
		if err != nil {
			return one(verdict(model.ClusterScope(), ev("sans", c.SampleAPICertPath, false, "cannot read the sample certificate: %v", err)))
		}
		sans, source = certs[0].DNSNames, "the sample certificate"
	}
	if len(sans) == 0 {
		return skip("no planned API SANs recorded; set certificates.plannedApiSans or certificates.sampleApiCertPath")
	}
	for _, s := range sans {
		if strings.EqualFold(s, want) {
			return one(verdict(model.ClusterScope(), ev("sans", source, true, "%s includes %s", source, want)))
		}
	}
	r := verdict(model.ClusterScope(), ev("sans", source, false, "%s (%s) does not include %s", source, strings.Join(sans, ", "), want))
	r.Remediation = "Add " + want + " to the API certificate's subject alternative names; node agents use it for mTLS."
	return one(r)
}
