// Package checks holds the implementation of each catalog check.
package checks

import "github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"

// Registry returns every implemented check, keyed by catalog ID. Checks are
// added area by area in milestones M3 to M6; until a check is here, runs
// report it as not implemented and exit 3.
func Registry() engine.Registry {
	return engine.Registry{}
}
