package kube

// WorkstationPermissions are the API permissions workstation mode uses. All
// are reads, apart from SelfSubjectAccessReview, which the API server does
// not persist (D-1). They are listed in the report so a customer security
// team can see exactly what Preflight did.
var WorkstationPermissions = []string{
	"get: /version",
	"list: nodes, pods, namespaces (cluster-wide)",
	"get: namespaces (armorNamespaces)",
	"list: secrets of type kubernetes.io/dockerconfigjson (armorNamespaces only)",
	"list: ingressclasses.networking.k8s.io, servicecidrs.networking.k8s.io",
	"list: customresourcedefinitions.apiextensions.k8s.io",
	"list: clusterissuers.cert-manager.io",
	"create: selfsubjectaccessreviews.authorization.k8s.io (not persisted)",
}

// ClusterPermissions are the additional permissions cluster mode uses. Every
// write is confined to Preflight's own temporary namespace by the shipped
// ValidatingAdmissionPolicy (D-2).
var ClusterPermissions = []string{
	"create, delete: namespaces (armor-preflight-<run id> only)",
	"create, get, list, delete: pods, configmaps, secrets, persistentvolumeclaims, services (in armor-preflight-<run id> only)",
	"get: pods/log (in armor-preflight-<run id> only)",
	"list: events (in armor-preflight-<run id> only)",
	"get, list: storageclasses.storage.k8s.io",
	"list, delete: persistentvolumes (only volumes claimed from armor-preflight-<run id>)",
}
