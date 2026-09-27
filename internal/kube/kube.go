// Package kube builds the Kubernetes clients Preflight uses, with every
// request passing through the write Guard.
package kube

import (
	"fmt"
	"net/http"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/shariff25/armor-preflight-check/internal/redact"
)

// Clients are the API clients checks use.
type Clients struct {
	Core    kubernetes.Interface
	Dynamic dynamic.Interface
	// Context is the kube context in use, and Server its API server URL.
	Context string
	Server  string
	// Guard is the write guard on every request (nil for fake clients).
	Guard *Guard
}

// Options select the kubeconfig and context.
type Options struct {
	Kubeconfig string // -k; empty means $KUBECONFIG or ~/.kube/config
	Context    string // -c; empty means the current context
	Mode       GuardMode
	Namespace  string
}

// Load builds clients from a kubeconfig.
func Load(o Options) (*Clients, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if o.Kubeconfig != "" {
		rules.ExplicitPath = o.Kubeconfig
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: o.Context})
	raw, err := cc.RawConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	ctxName := o.Context
	if ctxName == "" {
		ctxName = raw.CurrentContext
	}
	if ctxName == "" {
		return nil, fmt.Errorf("kubeconfig has no current context; select one with -c")
	}
	if _, ok := raw.Contexts[ctxName]; !ok {
		return nil, fmt.Errorf("kube context %q not found in kubeconfig", ctxName)
	}
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kube context %q: %w", ctxName, err)
	}
	return FromConfig(cfg, ctxName, o)
}

// FromConfig builds clients from a REST config, wrapping its transport in
// the Guard.
func FromConfig(cfg *rest.Config, contextName string, o Options) (*Clients, error) {
	cfg = rest.CopyConfig(cfg)
	cfg.UserAgent = "armor-preflight"
	// JSON, not protobuf, so the Guard can read request bodies (it refuses
	// what it cannot parse).
	cfg.ContentType = "application/json"
	cfg.AcceptContentTypes = "application/json"
	guard := &Guard{Mode: o.Mode, Namespace: o.Namespace}
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		guard.Next = rt
		return guard
	})
	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Clients{Core: core, Dynamic: dyn, Context: contextName, Server: redact.URL(cfg.Host), Guard: guard}, nil
}
