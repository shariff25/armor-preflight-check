package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shariff25/armor-preflight-check/internal/exitcode"
	"github.com/shariff25/armor-preflight-check/internal/output"
)

func executeWithInput(input string, args ...string) (string, error) {
	var out, errOut bytes.Buffer
	root := NewRootCmd(&out, &errOut)
	root.SetIn(strings.NewReader(input))
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func runOnce(t *testing.T) string {
	t.Helper()
	withFakes(t, fakeRegistry(nil))
	dir := t.TempDir()
	if _, err := execute("run", "cluster", "-f", writeSettings(t, settingsYAML), "-o", dir, "-c", "aks-armor-prod"); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBundleListOnly(t *testing.T) {
	dir := runOnce(t)
	out, err := execute("bundle", "-o", dir, "--list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"result.json", "versions.json", "MANIFEST.txt", "Armor 1.0.404"} {
		if !strings.Contains(out, want) {
			t.Errorf("listing missing %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, output.BundleFile)); !os.IsNotExist(err) {
		t.Fatal("--list must not write the bundle")
	}
}

func TestBundleAsksBeforeWriting(t *testing.T) {
	dir := runOnce(t)
	path := filepath.Join(dir, output.BundleFile)

	out, err := executeWithInput("n\n", "bundle", "-o", dir)
	if err != nil || !strings.Contains(out, "Not written.") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("declined bundle was written")
	}

	if _, err := executeWithInput("", "bundle", "-o", dir); exitcode.FromError(err) != exitcode.ToolError || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("no confirmation: got %v", err)
	}

	out, err = executeWithInput("y\n", "bundle", "-o", dir)
	if err != nil {
		t.Fatal(err)
	}
	// The listing comes before the question.
	if strings.Index(out, "result.json") > strings.Index(out, "Write ") {
		t.Fatalf("contents must be listed before asking:\n%s", out)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	files, err := output.ReadBundle(f)
	if err != nil || len(files) != 3 {
		t.Fatalf("%v %d", err, len(files))
	}
}

func TestBundleWithoutRun(t *testing.T) {
	_, err := execute("bundle", "-o", t.TempDir(), "--yes")
	if exitcode.FromError(err) != exitcode.ToolError || !strings.Contains(err.Error(), "run `armor-preflight run` first") {
		t.Fatalf("got %v", err)
	}
}
