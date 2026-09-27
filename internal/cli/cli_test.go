package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/shariff25/armor-preflight-check/internal/exitcode"
)

func execute(args ...string) (string, error) {
	var out, errOut bytes.Buffer
	root := NewRootCmd(&out, &errOut)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestVersionPrintsAllThreeVersions(t *testing.T) {
	out, err := execute("version")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"armor-preflight 0.1.0-dev", "catalog 2026.09", "supported Armor versions: 1.0.404", "probe image: none"} {
		if !strings.Contains(out, want) {
			t.Errorf("version output missing %q:\n%s", want, out)
		}
	}
}

func TestShortFlags(t *testing.T) {
	root := NewRootCmd(&bytes.Buffer{}, &bytes.Buffer{})
	for _, path := range [][]string{{"run", "workstation"}, {"run", "cluster"}} {
		cmd, _, err := root.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		for short, long := range map[string]string{"f": "settings", "k": "kubeconfig", "c": "context", "o": "output", "t": "timeout"} {
			f := cmd.Flags().ShorthandLookup(short)
			if f == nil {
				f = cmd.InheritedFlags().ShorthandLookup(short)
			}
			if f == nil || f.Name != long {
				t.Errorf("%v: -%s should be --%s, got %v", path, short, long, f)
			}
		}
	}
}

func TestDefaults(t *testing.T) {
	root := NewRootCmd(&bytes.Buffer{}, &bytes.Buffer{})
	cmd, _, _ := root.Find([]string{"run", "cluster"})
	if got := cmd.Flags().Lookup("output").DefValue; got != DefaultOutputDir {
		t.Errorf("output default = %s", got)
	}
	if got := cmd.Flags().Lookup("timeout").DefValue; got != "10s" {
		t.Errorf("timeout default = %s", got)
	}
}

func TestBadTimeoutIsToolError(t *testing.T) {
	_, err := execute("run", "workstation", "-t", "0s")
	if exitcode.FromError(err) != exitcode.ToolError || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("got %v", err)
	}
}
