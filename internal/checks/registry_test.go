package checks

import (
	"testing"

	"github.com/shariff25/armor-preflight-check/internal/catalog"
)

// The registered checks and the catalog are the same set, so a catalog
// entry without code, or code without a catalog entry, fails the build.
func TestRegistryMatchesCatalog(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	reg := Registry()
	for id := range reg {
		if cat.Check(id) == nil {
			t.Errorf("check %s is registered but not in the catalog", id)
		}
	}
	for _, id := range cat.IDs() {
		if reg[id] == nil {
			t.Errorf("catalog check %s has no implementation", id)
		}
	}
	if len(reg) != 35 {
		t.Errorf("%d checks registered, want 35", len(reg))
	}
}
