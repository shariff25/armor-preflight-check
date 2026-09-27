package checks

import (
	"testing"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
)

// Every registered check must exist in the catalog, so code cannot drift
// from the catalog. (The reverse, every catalog check implemented, is
// enforced once all milestones have landed.)
func TestRegisteredChecksAreInCatalog(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	for id := range Registry() {
		if cat.Check(id) == nil {
			t.Errorf("check %s is registered but not in the catalog", id)
		}
	}
}
