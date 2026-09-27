package kube

import (
	"os"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

// R1.4: the published roles grant no write verbs beyond what Preflight's
// own objects need.
func TestPublishedRolesGrantOnlyExpectedWrites(t *testing.T) {
	allowedWrites := map[string]map[string]bool{
		"armor-preflight-workstation":  {},
		"armor-preflight-pull-secrets": {},
		"armor-preflight-cluster": {
			"namespaces": true, "pods": true, "configmaps": true, "secrets": true,
			"persistentvolumeclaims": true, "services": true, "persistentvolumes": true,
		},
	}
	writeVerbs := map[string]bool{"create": true, "update": true, "patch": true, "delete": true, "deletecollection": true, "*": true, "escalate": true, "bind": true, "impersonate": true, "approve": true}
	seen := map[string]bool{}
	for _, file := range []string{"../../deploy/rbac/workstation.yaml", "../../deploy/rbac/cluster.yaml"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, doc := range strings.Split(string(b), "\n---\n") {
			var meta struct {
				Kind string `json:"kind"`
			}
			yaml.Unmarshal([]byte(doc), &meta)
			if meta.Kind != "ClusterRole" && meta.Kind != "Role" {
				continue
			}
			var role rbacv1.ClusterRole
			if err := yaml.UnmarshalStrict([]byte(doc), &role); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			allowed, ok := allowedWrites[role.Name]
			if !ok {
				t.Errorf("unexpected role %s", role.Name)
				continue
			}
			seen[role.Name] = true
			for _, rule := range role.Rules {
				for _, v := range rule.Verbs {
					if !writeVerbs[v] {
						continue
					}
					for _, r := range rule.Resources {
						if !allowed[r] {
							t.Errorf("%s grants %s on %s", role.Name, v, r)
						}
					}
				}
				for _, r := range rule.Resources {
					if r == "*" {
						t.Errorf("%s uses a wildcard resource", role.Name)
					}
				}
			}
		}
	}
	for name := range allowedWrites {
		if !seen[name] {
			t.Errorf("role %s not found", name)
		}
	}
}
