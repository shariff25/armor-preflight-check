// Package agent is what runs inside a probe pod. It needs no Kubernetes API
// access and no privileges: it reads its request, runs its tests and prints
// one result line.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/probe/protocol"
)

// Run executes a probe request and writes the result line to out.
func Run(ctx context.Context, requestPath string, out io.Writer, now func() time.Time) error {
	res := protocol.Result{
		Version:   protocol.Version,
		Node:      os.Getenv("NODE_NAME"),
		Pod:       os.Getenv("POD_NAME"),
		StartedAt: now().UTC(),
	}
	req, err := readRequest(requestPath)
	if err != nil {
		res.Error = err.Error()
	} else {
		res.RunID, res.NodePool = req.RunID, req.NodePool
		if req.Version != protocol.Version {
			res.Error = fmt.Sprintf("request protocol version %q, probe speaks %q", req.Version, protocol.Version)
		}
	}
	res.FinishedAt = now().UTC()
	line, err := protocol.Encode(res)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, line)
	return err
}

func readRequest(path string) (protocol.Request, error) {
	var req protocol.Request
	b, err := os.ReadFile(path)
	if err != nil {
		return req, fmt.Errorf("read request: %w", err)
	}
	if err := json.Unmarshal(b, &req); err != nil {
		return req, fmt.Errorf("parse request: %w", err)
	}
	return req, nil
}
