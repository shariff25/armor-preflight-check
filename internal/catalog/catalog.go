// Package catalog loads the embedded check catalog.
package catalog

import (
	_ "embed"
	"errors"
	"fmt"

	"sigs.k8s.io/yaml"
)

//go:embed catalog.yaml
var embedded []byte

// Catalog is the parsed check catalog.
type Catalog struct {
	CatalogVersion string   `json:"catalogVersion"`
	ArmorVersions  []string `json:"armorVersions"`
}

// Load parses and validates the embedded catalog.
func Load() (*Catalog, error) { return Parse(embedded) }

// Parse parses and validates catalog YAML.
func Parse(data []byte) (*Catalog, error) {
	var c Catalog
	if err := yaml.UnmarshalStrict(data, &c); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("invalid catalog: %w", err)
	}
	return &c, nil
}

func (c *Catalog) validate() error {
	if c.CatalogVersion == "" {
		return errors.New("catalogVersion is empty")
	}
	if len(c.ArmorVersions) == 0 {
		return errors.New("armorVersions is empty")
	}
	return nil
}
