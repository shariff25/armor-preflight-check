// Command probe runs inside armor-preflight probe pods. It needs no
// Kubernetes API access and no privileges.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shariff25/armor-preflight-check/internal/probe/agent"
	"github.com/shariff25/armor-preflight-check/internal/probe/protocol"
)

func main() {
	request := flag.String("request", protocol.RequestFile, "request file")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := agent.Run(ctx, *request, os.Stdout, time.Now); err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
}
