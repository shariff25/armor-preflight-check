package checks

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
)

// listNodes and listPods fetch cluster-wide lists once per run and share
// them between checks (most checks need the nodes; several need all pods).
// Callers must not modify the returned slices.

func listNodes(ctx context.Context, env *engine.Env) ([]corev1.Node, error) {
	v, err := env.Memo("nodes", func() (any, error) {
		l, err := env.Kube.Core.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return l.Items, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]corev1.Node), nil
}

func listPods(ctx context.Context, env *engine.Env) ([]corev1.Pod, error) {
	v, err := env.Memo("pods", func() (any, error) {
		l, err := env.Kube.Core.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return l.Items, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]corev1.Pod), nil
}
