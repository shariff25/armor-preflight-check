package settings

import (
	"strings"
	"testing"
)

// briefExample is the settings file from the build brief.
const briefExample = `armorVersion: "1.0.404"
domains:
  armor: armor.example.com
  staticAssets: static.armor.example.com
certificates:
  caReady: true
  sampleApiCertPath: ./api-cert.pem
registry:
  mode: direct
  url: cr.download.fortanix.com
  username: example-user
  passwordEnv: ARMOR_REGISTRY_PASSWORD
  releaseManifestPath: ./armor-1.0.404-images.txt
storage:
  accountFqdn: examplestorage.blob.core.windows.net
  container: medusa
  credentialsEnv: ARMOR_BACKUP_KEY
  environment: production
proxy:
  httpsProxy: http://proxy.example.com:8080
  noProxy: .example.com,10.0.0.0/8
attestation:
  azureAttestationHost: ""
syslog:
  host: syslog.example.com
  port: 514
`

func TestBriefExampleParses(t *testing.T) {
	s, err := Parse([]byte(briefExample))
	if err != nil {
		t.Fatal(err)
	}
	if s.ArmorVersion != "1.0.404" || s.Registry.PasswordEnv != "ARMOR_REGISTRY_PASSWORD" || s.Syslog.Port != 514 {
		t.Fatalf("got %+v", s)
	}
	if !s.Has("domains.armor") || s.Has("attestation.azureAttestationHost") || !s.Has("certificates.caReady") {
		t.Fatal("Has() wrong")
	}
	if s.Get("storage.container") != "medusa" {
		t.Fatal("Get() wrong")
	}
}

func TestDefaults(t *testing.T) {
	s, err := Parse([]byte("armorVersion: 1.0.404\nsyslog:\n  host: h\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Registry.Mode != RegistryModeDirect || s.Registry.URL != DefaultRegistryURL || s.Storage.Environment != EnvironmentProduction || s.Syslog.Port != 514 {
		t.Fatalf("defaults not applied: %+v", s)
	}
	d := Default()
	if d.Registry.URL != DefaultRegistryURL || d.Has("armorVersion") {
		t.Fatalf("Default() = %+v", d)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"inline password":     {"armorVersion: 1.0.404\nregistry:\n  password: hunter2\n", "registry.password"},
		"inline storage key":  {"armorVersion: 1.0.404\nstorage:\n  key: abc\n", "storage.key"},
		"unknown field":       {"armorVersion: 1.0.404\nbogus: 1\n", "bogus"},
		"no version":          {"domains:\n  armor: a\n", "armorVersion is required"},
		"bad version":         {"armorVersion: v1\n", "MAJOR.MINOR.PATCH"},
		"bad mode":            {"armorVersion: 1.0.404\nregistry:\n  mode: offline\n", "registry.mode"},
		"bad environment":     {"armorVersion: 1.0.404\nstorage:\n  environment: dev\n", "storage.environment"},
		"proxy with password": {"armorVersion: 1.0.404\nproxy:\n  httpsProxy: http://u:p@proxy:8080\n", "credentials"},
		"proxy not url":       {"armorVersion: 1.0.404\nproxy:\n  httpsProxy: proxy\n", "not a URL"},
		"bad env name":        {"armorVersion: 1.0.404\nregistry:\n  passwordEnv: \"not a name\"\n", "environment variable name"},
		"bad port":            {"armorVersion: 1.0.404\nsyslog:\n  host: h\n  port: 70000\n", "out of range"},
		"malformed":           {"armorVersion: [\n", "parse settings"},
		"negative replicas":   {"armorVersion: 1.0.404\nreplicas: -1\n", "replicas"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.in))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want error containing %q", err, c.want)
			}
		})
	}
}

func TestSecrets(t *testing.T) {
	s, _ := Parse([]byte(briefExample))
	env := map[string]string{"ARMOR_REGISTRY_PASSWORD": "pw", "ARMOR_BACKUP_KEY": ""}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	sec := s.ResolveSecrets(lookup)
	if sec.RegistryPassword != "pw" || len(sec.Values()) != 1 {
		t.Fatalf("got %+v", sec)
	}
	if r := s.MissingEnv("registry.passwordEnv", lookup); r != "" {
		t.Fatalf("got %q", r)
	}
	if r := s.MissingEnv("storage.credentialsEnv", lookup); !strings.Contains(r, "ARMOR_BACKUP_KEY") {
		t.Fatalf("got %q", r)
	}
	if r := Default().MissingEnv("registry.passwordEnv", lookup); !strings.Contains(r, "missing setting") {
		t.Fatalf("got %q", r)
	}
}

func TestKnownPaths(t *testing.T) {
	p := KnownPaths()
	for _, want := range []string{"armorVersion", "storage.accountFqdn", "certificates.caReady", "registry.passwordEnv", "nodePools"} {
		if !p[want] {
			t.Errorf("missing %s", want)
		}
	}
	if p["storage"] != true || p["nope"] {
		t.Error("unexpected paths")
	}
}

func TestShippedExampleParses(t *testing.T) {
	s, err := Load("../../examples/settings.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if s.Storage.AccountKind != "StorageV2" || s.Proxy.HTTPSProxy == "" {
		t.Fatalf("got %+v", s)
	}
}
