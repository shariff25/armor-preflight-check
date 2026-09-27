package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/output"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/redact"
)

// Canary secrets. If any encoding of these appears in any output, the
// build fails (R1.4).
const (
	canaryRegistryPassword = "canary-REG-7Hq/9x+Zp=w!"
	canaryStorageKey       = "canary-BAK-Zm9vYmFy/Qk2+tEsT=="
)

// leakyRegistry returns checks that try hard to leak the secrets: raw, in a
// URL, as a docker auth string, in remediation text and in a panic.
func leakyRegistry() engine.Registry {
	cat, _ := catalog.Load()
	reg := fakeRegistry(map[string]model.Status{"REG-01": model.StatusFail, "NET-02": model.StatusFail})()
	auth := base64.StdEncoding.EncodeToString([]byte("u:" + canaryRegistryPassword))
	reg["REG-01"] = func(_ context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
		pw := env.Settings.ResolveSecrets(env.LookupEnv).RegistryPassword
		return []model.Result{{Status: model.StatusFail, Scope: model.ClusterScope(),
			Remediation: "Password " + pw + " was rejected",
			Evidence: []model.Evidence{
				{Stage: "login", Target: "https://u:" + pw + "@cr.download.fortanix.com", Detail: "401 for " + pw},
				{Stage: "auth", Detail: `{"auth":"` + auth + `"}`},
			}}}
	}
	reg["NET-02"] = func(context.Context, *engine.Env, *catalog.Check) []model.Result {
		return []model.Result{{Status: model.StatusFail, Scope: model.PoolScope("sgxpool1"),
			Evidence: []model.Evidence{{Stage: "tcp", Target: "s.blob.core.windows.net:443", Detail: "sig=" + base64.URLEncoding.EncodeToString([]byte(canaryStorageKey)) + " key=" + canaryStorageKey}}}}
	}
	reg["PKI-02"] = func(context.Context, *engine.Env, *catalog.Check) []model.Result {
		panic("storage key " + canaryStorageKey)
	}
	_ = cat
	return reg
}

func TestSeededSecretsNeverAppear(t *testing.T) {
	withFakes(t, leakyRegistry)
	testEnvSaved := testEnv
	testEnv = map[string]string{"REG_PW": canaryRegistryPassword, "BAK_KEY": canaryStorageKey}
	t.Cleanup(func() { testEnv = testEnvSaved })

	settingsPath := writeSettings(t, settingsYAML)
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	root := NewRootCmd(&stdout, &stderr)
	root.SetArgs([]string{"run", "cluster", "-f", settingsPath, "-o", dir})
	runErr := root.Execute()
	if runErr == nil {
		t.Fatal("the panicking check should make the run exit 3")
	}

	bundleOut, err := executeWithInput("", "bundle", "-o", dir, "-f", settingsPath, "--yes")
	if err != nil {
		t.Fatal(err)
	}

	haystacks := map[string][]byte{
		"stdout":        stdout.Bytes(),
		"stderr":        stderr.Bytes(),
		"run error":     []byte(runErr.Error()),
		"bundle stdout": []byte(bundleOut),
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		haystacks[filepath.Base(f)] = b
	}
	f, err := os.Open(filepath.Join(dir, output.BundleFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	inBundle, err := output.ReadBundle(f)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range inBundle {
		haystacks["bundle:"+name] = b
	}

	needles := append(redact.Forms(canaryRegistryPassword), redact.Forms(canaryStorageKey)...)
	needles = append(needles, redact.Forms("u:"+canaryRegistryPassword)...)
	for where, hay := range haystacks {
		for _, n := range needles {
			if bytes.Contains(hay, []byte(n)) {
				t.Errorf("secret form %q leaked into %s", n, where)
			}
		}
	}

	// Sanity: the leaks really were attempted and masked, not dropped.
	if !strings.Contains(string(haystacks[output.ResultFile]), redact.Mask) {
		t.Error("expected masked values in result.json")
	}
	if !strings.Contains(string(haystacks[output.ResultFile]), "Preflight internal error") {
		t.Error("expected the panic to be recorded")
	}
	if len(inBundle) != 3 {
		t.Errorf("bundle has %d files", len(inBundle))
	}
}
