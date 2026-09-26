package catalog

import "testing"

func TestEmbeddedCatalogLoads(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.CatalogVersion == "" || len(c.ArmorVersions) == 0 {
		t.Fatalf("incomplete catalog: %+v", c)
	}
}

func TestParseRejects(t *testing.T) {
	for name, in := range map[string]string{
		"no version":     "armorVersions: [\"1.0.404\"]\n",
		"no armor":       "catalogVersion: \"x\"\n",
		"unknown field":  "catalogVersion: \"x\"\narmorVersions: [\"1\"]\nbogus: 1\n",
		"malformed yaml": "catalogVersion: [\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(in)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
