// Package cli wires the armor-preflight commands.
package cli

import (
	"io"
	"time"

	"github.com/spf13/cobra"
)

// DefaultOutputDir is where run and bundle write their files.
const DefaultOutputDir = "./preflight-out"

// DefaultCheckTimeout is the per-check timeout.
const DefaultCheckTimeout = 10 * time.Second

// globalOptions are flags shared by every command that talks to a cluster.
type globalOptions struct {
	kubeconfig  string
	kubeContext string
}

// NewRootCmd builds the command tree. Output goes to out and errOut so tests
// can capture it.
func NewRootCmd(out, errOut io.Writer) *cobra.Command {
	g := &globalOptions{}
	root := &cobra.Command{
		Use:           "armor-preflight",
		Short:         "Check that an environment is ready for a Fortanix Armor on-prem install",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(out)
	root.SetErr(errOut)
	root.PersistentFlags().StringVarP(&g.kubeconfig, "kubeconfig", "k", "", "kubeconfig path (default: $KUBECONFIG or ~/.kube/config)")
	root.PersistentFlags().StringVarP(&g.kubeContext, "context", "c", "", "kube context (default: current context)")

	root.AddCommand(
		newRunCmd(g),
		newBundleCmd(),
		newCleanupCmd(g),
		newVersionCmd(),
	)
	return root
}
