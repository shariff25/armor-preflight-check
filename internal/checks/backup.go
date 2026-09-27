package checks

import (
	"context"
	"strings"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
)

// Accepted values for the backup storage account (BAK-01).
var (
	storageKinds        = map[string]bool{"storagev2": true}
	storagePerformance  = map[string]bool{"standard": true, "premium": true}
	storageReplications = map[string]bool{"lrs": true, "zrs": true, "grs": true, "ragrs": true, "gzrs": true, "ragzrs": true}
)

// bak01: backup storage account type, from the settings worksheet (D-15).
func bak01(_ context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	s := env.Settings.Storage
	norm := func(v string) string { return strings.ReplaceAll(lower(v), "-", "") }
	return one(verdict(model.ClusterScope(),
		ev("kind", s.AccountFQDN, storageKinds[norm(s.AccountKind)], "account kind %s (StorageV2 required)", s.AccountKind),
		ev("performance", s.AccountFQDN, storagePerformance[norm(s.Performance)], "performance %s (Standard or Premium required)", s.Performance),
		ev("replication", s.AccountFQDN, storageReplications[norm(s.Replication)], "replication %s (LRS or better required)", s.Replication),
		ev("source", "", true, "values from the settings file; not read from Azure"),
	))
}
