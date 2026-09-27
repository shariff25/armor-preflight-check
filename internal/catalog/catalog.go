// Package catalog loads the embedded check catalog: the single source of
// truth for what Preflight checks.
package catalog

import (
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
)

//go:embed catalog.yaml
var embedded []byte

// TBD marks a value Fortanix has not supplied yet.
const TBD = "TBD"

// RunsIn says where a check executes.
type RunsIn string

const (
	RunsInWorkstation  RunsIn = "workstation"
	RunsInClusterWrite RunsIn = "cluster-write"
	RunsInProbe        RunsIn = "probe"
)

// ScopeKind is the granularity of a check's results.
type ScopeKind string

const (
	ScopeCluster  ScopeKind = "cluster"
	ScopeNodePool ScopeKind = "nodePool"
	ScopeNode     ScopeKind = "node"
)

// Target is what a check runs against.
type Target string

const (
	TargetCluster Target = "cluster"
	TargetHost    Target = "host" // Phase 2
)

// Catalog is the parsed check catalog.
type Catalog struct {
	CatalogVersion    string            `json:"catalogVersion"`
	ArmorVersions     []string          `json:"armorVersions"`
	PreflightForArmor []VersionMapping  `json:"preflightForArmor"`
	Parameters        Parameters        `json:"parameters"`
	DocLinks          map[string]string `json:"docLinks"`
	Endpoints         []Endpoint        `json:"endpoints"`
	Checks            []Check           `json:"checks"`

	byID map[string]*Check
}

// VersionMapping names the Preflight release that covers some Armor versions.
type VersionMapping struct {
	ArmorVersions []string `json:"armorVersions"`
	Preflight     string   `json:"preflight"`
}

// Pool is a node pool size requirement. Size is compared on each node's
// reported CPU and memory capacity, so any SKU at least as large passes.
type Pool struct {
	MinNodes     int     `json:"minNodes"`
	MinSKU       string  `json:"minSku"`
	MinCPU       int     `json:"minCpu"`
	MinMemoryGiB float64 `json:"minMemoryGiB"`
	// SKUPattern, when set, is a regular expression the node's instance
	// type must match (the SGX pool must be an SGX-capable family).
	SKUPattern string `json:"skuPattern,omitempty"`
}

// Parameters are the thresholds and names checks use.
type Parameters struct {
	MinKubernetes              string   `json:"minKubernetes"`
	NFDMinVersion              string   `json:"nfdMinVersion"`
	CertManagerVersions        string   `json:"certManagerVersions"`
	SystemPool                 Pool     `json:"systemPool"`
	SGXPool                    Pool     `json:"sgxPool"`
	ValidatedOS                string   `json:"validatedOs"`
	MemoryTolerance            float64  `json:"memoryTolerance"`
	SystemModeLabel            string   `json:"systemModeLabel"`
	InstanceTypeLabel          string   `json:"instanceTypeLabel"`
	ClockSkewSeconds           int      `json:"clockSkewSeconds"`
	PullSecretExpiryWarnDays   int      `json:"pullSecretExpiryWarnDays"`
	LoadBalancerTimeoutSeconds int      `json:"loadBalancerTimeoutSeconds"`
	VolumeBindTimeoutSeconds   int      `json:"volumeBindTimeoutSeconds"`
	SGXResources               []string `json:"sgxResources"`
	NFDSGXLabel                string   `json:"nfdSgxLabel"`
	NodePoolLabel              string   `json:"nodePoolLabel"`
	ArmorOperatorCRDGroup      string   `json:"armorOperatorCrdGroup"`
	OperatorChartRef           string   `json:"operatorChartRef"`
	ProbeImage                 string   `json:"probeImage"`
	K8ssandraCRDGroups         []string `json:"k8ssandraCrdGroups"`
}

// Endpoint is a destination the network checks test from every node pool.
type Endpoint struct {
	FQDN            string   `json:"fqdn,omitempty"`
	Port            int      `json:"port,omitempty"`
	FromSetting     string   `json:"fromSetting,omitempty"`
	PortFromSetting string   `json:"portFromSetting,omitempty"`
	Purpose         string   `json:"purpose"`
	Checks          []string `json:"checks"`
	SGXOnly         bool     `json:"sgxOnly,omitempty"`
	HTTPPath        string   `json:"httpPath,omitempty"`
	// InterceptSensitive endpoints are checked for TLS interception (NET-03).
	InterceptSensitive bool `json:"interceptSensitive,omitempty"`
	// TCPOnly endpoints get no TLS or HTTP stage (syslog).
	TCPOnly bool `json:"tcpOnly,omitempty"`
}

// Check is one catalog entry.
type Check struct {
	ID                    string         `json:"id"`
	Title                 string         `json:"title"`
	Area                  model.Area     `json:"area"`
	Severity              model.Severity `json:"severity"`
	NonProductionSeverity model.Severity `json:"nonProductionSeverity,omitempty"`
	Owner                 string         `json:"owner"`
	Target                Target         `json:"target,omitempty"`
	RunsIn                RunsIn         `json:"runsIn"`
	Scope                 ScopeKind      `json:"scope"`
	Needs                 []string       `json:"needs,omitempty"`
	NeedsEnv              []string       `json:"needsEnv,omitempty"`
	DependsOn             []string       `json:"dependsOn,omitempty"`
	DocLink               string         `json:"docLink"`
	Remediation           string         `json:"remediation"`
	// TimeoutSeconds overrides the per-check timeout for checks that wait
	// on the cluster (a volume binding, a load balancer address).
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
}

// SeverityFor resolves the check's severity for a storage environment.
func (c *Check) SeverityFor(environment string) model.Severity {
	if environment == settings.EnvironmentPOC && c.NonProductionSeverity != "" {
		return c.NonProductionSeverity
	}
	return c.Severity
}

// Load parses and validates the embedded catalog.
func Load() (*Catalog, error) { return Parse(embedded) }

// Parse parses and validates catalog YAML.
func Parse(data []byte) (*Catalog, error) {
	var c Catalog
	if err := yaml.UnmarshalStrict(data, &c); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	for i := range c.Checks {
		if c.Checks[i].Target == "" {
			c.Checks[i].Target = TargetCluster
		}
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("invalid catalog: %w", err)
	}
	return &c, nil
}

// Check returns the entry with the given ID, or nil.
func (c *Catalog) Check(id string) *Check { return c.byID[id] }

// IDs lists every check ID in catalog order.
func (c *Catalog) IDs() []string {
	ids := make([]string, len(c.Checks))
	for i, ch := range c.Checks {
		ids[i] = ch.ID
	}
	return ids
}

var idRE = regexp.MustCompile(`^[A-Z0-9]+-\d{2}$`)

func (c *Catalog) validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.CatalogVersion == "" {
		add("catalogVersion is empty")
	}
	if len(c.ArmorVersions) == 0 {
		add("armorVersions is empty")
	}
	paths := settings.KnownPaths()
	c.byID = map[string]*Check{}
	for i := range c.Checks {
		ch := &c.Checks[i]
		if !idRE.MatchString(ch.ID) {
			add("check id %q is not AREA-NN", ch.ID)
		}
		if _, dup := c.byID[ch.ID]; dup {
			add("duplicate check id %s", ch.ID)
		}
		c.byID[ch.ID] = ch
		for field, v := range map[string]string{"title": ch.Title, "owner": ch.Owner, "remediation": ch.Remediation, "docLink": ch.DocLink} {
			if strings.TrimSpace(v) == "" {
				add("%s: %s is empty", ch.ID, field)
			}
		}
		if ch.DocLink != "" && !strings.HasPrefix(ch.DocLink, "https://") {
			add("%s: docLink %q is not https", ch.ID, ch.DocLink)
		}
		if !ch.Area.Valid() {
			add("%s: unknown area %q", ch.ID, ch.Area)
		}
		if !ch.Severity.Valid() {
			add("%s: unknown severity %q", ch.ID, ch.Severity)
		}
		if ch.NonProductionSeverity != "" && !ch.NonProductionSeverity.Valid() {
			add("%s: unknown nonProductionSeverity %q", ch.ID, ch.NonProductionSeverity)
		}
		switch ch.RunsIn {
		case RunsInWorkstation, RunsInClusterWrite, RunsInProbe:
		default:
			add("%s: unknown runsIn %q", ch.ID, ch.RunsIn)
		}
		switch ch.Scope {
		case ScopeCluster, ScopeNodePool, ScopeNode:
		default:
			add("%s: unknown scope %q", ch.ID, ch.Scope)
		}
		switch ch.Target {
		case TargetCluster, TargetHost:
		default:
			add("%s: unknown target %q", ch.ID, ch.Target)
		}
		for _, p := range append(append([]string{}, ch.Needs...), ch.NeedsEnv...) {
			if !paths[p] {
				add("%s: needs unknown settings path %q", ch.ID, p)
			}
		}
	}
	for _, ch := range c.Checks {
		for _, dep := range ch.DependsOn {
			if dep == ch.ID {
				add("%s depends on itself", ch.ID)
			} else if c.byID[dep] == nil {
				add("%s depends on unknown check %s", ch.ID, dep)
			}
		}
	}
	for i, ep := range c.Endpoints {
		if ep.FQDN == "" && ep.FromSetting == "" {
			add("endpoint %d has neither fqdn nor fromSetting", i)
		}
		for _, p := range []string{ep.FromSetting, ep.PortFromSetting} {
			if p != "" && !paths[p] {
				add("endpoint %d: unknown settings path %q", i, p)
			}
		}
		if ep.Purpose == "" {
			add("endpoint %d has no purpose", i)
		}
		for _, id := range ep.Checks {
			if c.byID[id] == nil {
				add("endpoint %d names unknown check %s", i, id)
			}
		}
	}
	if len(errs) == 0 {
		if _, err := c.Levels(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Levels groups checks so that every check's parents are in an earlier
// level. Checks in one level can run concurrently.
func (c *Catalog) Levels() ([][]*Check, error) {
	level := map[string]int{}
	var visit func(id string, stack []string) (int, error)
	visit = func(id string, stack []string) (int, error) {
		if l, ok := level[id]; ok {
			if l < 0 {
				return 0, fmt.Errorf("dependency cycle: %s -> %s", strings.Join(stack, " -> "), id)
			}
			return l, nil
		}
		level[id] = -1
		l := 0
		for _, dep := range c.byID[id].DependsOn {
			dl, err := visit(dep, append(stack, id))
			if err != nil {
				return 0, err
			}
			if dl+1 > l {
				l = dl + 1
			}
		}
		level[id] = l
		return l, nil
	}
	maxLevel := 0
	for _, ch := range c.Checks {
		l, err := visit(ch.ID, nil)
		if err != nil {
			return nil, err
		}
		if l > maxLevel {
			maxLevel = l
		}
	}
	out := make([][]*Check, maxLevel+1)
	for i := range c.Checks {
		ch := &c.Checks[i]
		out[level[ch.ID]] = append(out[level[ch.ID]], ch)
	}
	return out, nil
}

// Covers reports whether this catalog covers an Armor version.
func (c *Catalog) Covers(armorVersion string) bool {
	for _, v := range c.ArmorVersions {
		if v == armorVersion {
			return true
		}
	}
	return false
}

// CoverageError explains why an Armor version is refused and which Preflight
// release to use instead.
func (c *Catalog) CoverageError(armorVersion, preflightVersion string) error {
	covered := append([]string{}, c.ArmorVersions...)
	sort.Strings(covered)
	msg := fmt.Sprintf("Armor %s is not covered by this Preflight build (%s, catalog %s covers %s)",
		armorVersion, preflightVersion, c.CatalogVersion, strings.Join(covered, ", "))
	for _, m := range c.PreflightForArmor {
		for _, v := range m.ArmorVersions {
			if v == armorVersion {
				return fmt.Errorf("%s; use Preflight %s", msg, m.Preflight)
			}
		}
	}
	return fmt.Errorf("%s; download the Preflight release for Armor %s from the Fortanix support portal", msg, armorVersion)
}
