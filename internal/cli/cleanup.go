package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/shariff25/armor-preflight-check/internal/exitcode"
	"github.com/shariff25/armor-preflight-check/internal/kube"
	"github.com/shariff25/armor-preflight-check/internal/model"
	"github.com/shariff25/armor-preflight-check/internal/probe/orchestrator"
)

type cleanupOptions struct {
	*globalOptions
	runID string
	wait  time.Duration
}

func newCleanupCmd(g *globalOptions) *cobra.Command {
	o := &cleanupOptions{globalOptions: g}
	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Delete leftover Preflight objects, found by label",
		Long: "Deletes every namespace labelled app.kubernetes.io/managed-by=armor-preflight whose name starts with\n" +
			"armor-preflight- (and everything in it), plus any persistent volume claimed from one. Use it after a run\n" +
			"was killed before it could clean up.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return o.run(ctx, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&o.runID, "run-id", "", "only delete objects from this run (default: all runs)")
	cmd.Flags().DurationVar(&o.wait, "wait", 2*time.Minute, "how long to wait for namespaces to finish terminating")
	return cmd
}

func (o *cleanupOptions) run(ctx context.Context, out io.Writer) error {
	// The run ID goes into a label selector and a namespace name.
	if o.runID != "" && !model.ValidRunID(o.runID) {
		return exitcode.ToolFailure(fmt.Errorf("--run-id %q is not a run ID (YYYYMMDD-HHMM-xxxx)", o.runID))
	}
	clients, err := loadKube(kube.Options{Kubeconfig: o.kubeconfig, Context: o.kubeContext, Mode: kube.Cleanup})
	if err != nil {
		return exitcode.ToolFailure(err)
	}
	left, err := orchestrator.RemoveLeftovers(ctx, clients.Core, o.runID)
	if left != nil {
		for _, ns := range left.Namespaces {
			fmt.Fprintf(out, "deleting namespace %s\n", ns)
		}
		for _, pv := range left.Volumes {
			fmt.Fprintf(out, "deleted persistent volume %s\n", pv)
		}
	}
	if err != nil {
		return exitcode.ToolFailure(err)
	}

	sel := orchestrator.LabelManagedBy + "=" + orchestrator.ManagedByValue
	if o.runID != "" {
		sel += "," + orchestrator.LabelRunID + "=" + o.runID
	}
	deadline := time.Now().Add(o.wait)
	for {
		nss, err := clients.Core.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: sel})
		if err != nil {
			return exitcode.ToolFailure(fmt.Errorf("list Preflight namespaces: %w", err))
		}
		var remaining []string
		for _, ns := range nss.Items {
			if strings.HasPrefix(ns.Name, orchestrator.NamespacePrefix) {
				remaining = append(remaining, ns.Name)
			}
		}
		if len(remaining) == 0 {
			if len(left.Namespaces)+len(left.Volumes) == 0 {
				fmt.Fprintln(out, "No Preflight objects found.")
			} else {
				fmt.Fprintln(out, "No Preflight objects remain.")
			}
			return nil
		}
		if time.Now().After(deadline) {
			return exitcode.ToolFailure(fmt.Errorf("still terminating after %s: %s", o.wait, strings.Join(remaining, ", ")))
		}
		select {
		case <-ctx.Done():
			return exitcode.ToolFailure(ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
}
