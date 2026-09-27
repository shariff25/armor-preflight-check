// Package settings loads the optional settings file: the decisions only the
// customer can make. Secrets never live in the file; it names environment
// variables instead.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// Settings mirrors the settings file. Fields marked (D-n) are additions
// recorded in DECISIONS.md.
type Settings struct {
	ArmorVersion    string              `json:"armorVersion,omitempty"`
	KubeContext     string              `json:"kubeContext,omitempty"`     // D-10
	Replicas        int                 `json:"replicas,omitempty"`        // D-11
	ArmorNamespaces []string            `json:"armorNamespaces,omitempty"` // D-11
	StorageClass    string              `json:"storageClass,omitempty"`
	NodePools       map[string]NodePool `json:"nodePools,omitempty"` // D-16
	Domains         Domains             `json:"domains,omitempty"`
	Certificates    Certificates        `json:"certificates,omitempty"`
	Registry        Registry            `json:"registry,omitempty"`
	Storage         Storage             `json:"storage,omitempty"`
	Proxy           Proxy               `json:"proxy,omitempty"`
	Attestation     Attestation         `json:"attestation,omitempty"`
	Syslog          Syslog              `json:"syslog,omitempty"`
}

// NodePool holds per-pool facts Kubernetes does not expose.
type NodePool struct {
	Subnet string `json:"subnet,omitempty"`
}

type Domains struct {
	Armor        string `json:"armor,omitempty"`
	StaticAssets string `json:"staticAssets,omitempty"`
}

type Certificates struct {
	CAReady           *bool    `json:"caReady,omitempty"`
	SampleAPICertPath string   `json:"sampleApiCertPath,omitempty"`
	PlannedAPISans    []string `json:"plannedApiSans,omitempty"`
}

type Registry struct {
	Mode                string `json:"mode,omitempty"`
	URL                 string `json:"url,omitempty"`
	Username            string `json:"username,omitempty"`
	PasswordEnv         string `json:"passwordEnv,omitempty"`
	ReleaseManifestPath string `json:"releaseManifestPath,omitempty"`
}

type Storage struct {
	AccountFQDN    string `json:"accountFqdn,omitempty"`
	Container      string `json:"container,omitempty"`
	CredentialsEnv string `json:"credentialsEnv,omitempty"`
	Environment    string `json:"environment,omitempty"`
	AccountKind    string `json:"accountKind,omitempty"` // D-15
	Performance    string `json:"performance,omitempty"` // D-15
	Replication    string `json:"replication,omitempty"` // D-15
}

type Proxy struct {
	HTTPSProxy    string `json:"httpsProxy,omitempty"`
	NoProxy       string `json:"noProxy,omitempty"`
	TrustedCAPath string `json:"trustedCaPath,omitempty"`
}

type Attestation struct {
	AzureAttestationHost string `json:"azureAttestationHost,omitempty"`
}

type Syslog struct {
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
}

const (
	RegistryModeDirect = "direct"
	RegistryModeMirror = "mirror"

	EnvironmentProduction = "production"
	EnvironmentPOC        = "poc"

	// DefaultRegistryURL is the Fortanix registry named in the prerequisites.
	DefaultRegistryURL = "cr.download.fortanix.com"
	// DefaultSyslogPort is used when syslog.host is set without a port.
	DefaultSyslogPort = 514
)

// Default returns the settings used when no file is given.
func Default() *Settings {
	s := &Settings{}
	s.applyDefaults()
	return s
}

// Load reads and validates a settings file.
func Load(path string) (*Settings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read settings: %w", err)
	}
	return Parse(data)
}

// secretKey matches keys that would hold a secret value inline. Keys ending
// in Env or Path name where the secret lives, so they are allowed.
var secretKey = regexp.MustCompile(`(?i)^(password|passwd|secret|token|key|apikey|accesskey|accountkey|storagekey|credentials?|auth|sas)$`)

// Parse validates settings YAML.
func Parse(data []byte) (*Settings, error) {
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse settings: %w", err)
	}
	if bad := findSecretKeys(raw, ""); len(bad) > 0 {
		return nil, fmt.Errorf("settings must not contain secrets (found %s); put the secret in an environment variable and name it with the matching *Env field", strings.Join(bad, ", "))
	}
	var s Settings
	if err := yaml.UnmarshalStrict(data, &s); err != nil {
		return nil, fmt.Errorf("parse settings: %w", err)
	}
	s.applyDefaults()
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("invalid settings: %w", err)
	}
	return &s, nil
}

func findSecretKeys(v any, prefix string) []string {
	var out []string
	switch m := v.(type) {
	case map[string]any:
		for k, child := range m {
			p := joinPath(prefix, k)
			if secretKey.MatchString(k) {
				out = append(out, p)
			}
			out = append(out, findSecretKeys(child, p)...)
		}
	case []any:
		for _, child := range m {
			out = append(out, findSecretKeys(child, prefix)...)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Settings) applyDefaults() {
	if s.Registry.Mode == "" {
		s.Registry.Mode = RegistryModeDirect
	}
	if s.Registry.URL == "" {
		s.Registry.URL = DefaultRegistryURL
	}
	if s.Storage.Environment == "" {
		s.Storage.Environment = EnvironmentProduction
	}
	if s.Syslog.Host != "" && s.Syslog.Port == 0 {
		s.Syslog.Port = DefaultSyslogPort
	}
}

var versionRE = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func (s *Settings) validate() error {
	var errs []error
	if s.ArmorVersion == "" {
		errs = append(errs, errors.New("armorVersion is required"))
	} else if !versionRE.MatchString(s.ArmorVersion) {
		errs = append(errs, fmt.Errorf("armorVersion %q is not MAJOR.MINOR.PATCH", s.ArmorVersion))
	}
	if s.Registry.Mode != RegistryModeDirect && s.Registry.Mode != RegistryModeMirror {
		errs = append(errs, fmt.Errorf("registry.mode must be %q or %q, got %q", RegistryModeDirect, RegistryModeMirror, s.Registry.Mode))
	}
	if s.Storage.Environment != EnvironmentProduction && s.Storage.Environment != EnvironmentPOC {
		errs = append(errs, fmt.Errorf("storage.environment must be %q or %q, got %q", EnvironmentProduction, EnvironmentPOC, s.Storage.Environment))
	}
	if s.Replicas < 0 {
		errs = append(errs, fmt.Errorf("replicas must not be negative, got %d", s.Replicas))
	}
	if s.Syslog.Port < 0 || s.Syslog.Port > 65535 {
		errs = append(errs, fmt.Errorf("syslog.port %d is out of range", s.Syslog.Port))
	}
	if s.Proxy.HTTPSProxy != "" {
		if u, err := url.Parse(s.Proxy.HTTPSProxy); err != nil || u.Scheme == "" || u.Host == "" {
			errs = append(errs, fmt.Errorf("proxy.httpsProxy %q is not a URL", s.Proxy.HTTPSProxy))
		} else if u.User != nil {
			errs = append(errs, errors.New("proxy.httpsProxy must not contain credentials"))
		}
	}
	for _, env := range []struct{ path, name string }{
		{"registry.passwordEnv", s.Registry.PasswordEnv},
		{"storage.credentialsEnv", s.Storage.CredentialsEnv},
	} {
		if env.name != "" && !envNameRE.MatchString(env.name) {
			errs = append(errs, fmt.Errorf("%s %q is not an environment variable name", env.path, env.name))
		}
	}
	return errors.Join(errs...)
}

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Has reports whether the dotted settings path (for example
// "storage.accountFqdn") has a non-empty value.
func (s *Settings) Has(path string) bool {
	v, ok := s.lookup(path)
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	case float64:
		return t != 0
	}
	return true
}

// Get returns the string value at a dotted path, or "".
func (s *Settings) Get(path string) string {
	v, _ := s.lookup(path)
	str, _ := v.(string)
	return str
}

func (s *Settings) lookup(path string) (any, bool) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, false
	}
	var cur any
	if err := json.Unmarshal(b, &cur); err != nil {
		return nil, false
	}
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// KnownPaths lists every dotted path the settings file accepts, so the
// catalog can be validated against it.
func KnownPaths() map[string]bool {
	out := map[string]bool{}
	walkPaths(reflect.TypeOf(Settings{}), "", out)
	return out
}

func walkPaths(t reflect.Type, prefix string, out map[string]bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		p := joinPath(prefix, name)
		out[p] = true
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			walkPaths(ft, p, out)
		}
	}
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}
