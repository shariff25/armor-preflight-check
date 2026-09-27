package orchestrator

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/shariff25/armor-preflight-check/internal/probe/protocol"
)

// Names of the objects in the run namespace.
const (
	RequestConfigMapPrefix = "request-"
	CredentialsSecret      = "probe-credentials"
	ContainerName          = "probe"
	// NonRootUID is distroless's nonroot user.
	NonRootUID = 65532
)

// Pool is a node pool to run one probe pod on.
type Pool struct {
	Name        string
	Selector    map[string]string
	Tolerations []corev1.Toleration
}

// PodSpec returns a probe pod that passes the Pod Security Standards
// restricted profile: non-root, read-only root filesystem, all capabilities
// dropped, no privilege escalation, RuntimeDefault seccomp, no host
// namespaces or host paths, and no service account token.
func PodSpec(name, namespace, runID, pool, image string, selector map[string]string, tolerations []corev1.Toleration, requestConfigMap string, withCredentials bool) *corev1.Pod {
	yes, no := true, false
	uid := int64(NonRootUID)
	deadline := int64(300)
	labels := Labels(runID)
	labels[LabelNodePool] = labelValue(pool)

	volumes := []corev1.Volume{{
		Name:         "request",
		VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: requestConfigMap}}},
	}}
	mounts := []corev1.VolumeMount{{Name: "request", MountPath: "/etc/armor-preflight", ReadOnly: true}}
	if withCredentials {
		volumes = append(volumes, corev1.Volume{Name: "credentials", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: CredentialsSecret}}})
		mounts = append(mounts, corev1.VolumeMount{Name: "credentials", MountPath: "/var/run/armor-preflight", ReadOnly: true})
	}

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec: corev1.PodSpec{
			RestartPolicy:                 corev1.RestartPolicyNever,
			AutomountServiceAccountToken:  &no,
			EnableServiceLinks:            &no,
			ActiveDeadlineSeconds:         &deadline,
			TerminationGracePeriodSeconds: new(int64),
			NodeSelector:                  selector,
			Tolerations:                   tolerations,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   &yes,
				RunAsUser:      &uid,
				RunAsGroup:     &uid,
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Volumes: volumes,
			Containers: []corev1.Container{{
				Name:            ContainerName,
				Image:           image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Args:            []string{"--request", protocol.RequestFile},
				Env: []corev1.EnvVar{
					{Name: "NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
					{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
				},
				VolumeMounts: mounts,
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("32Mi")},
					Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("200m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
				},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: &no,
					ReadOnlyRootFilesystem:   &yes,
					RunAsNonRoot:             &yes,
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
					SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
				},
			}},
		},
	}
}

// PoolsFromNodes groups nodes into pools, selecting each pool by its pool
// label (or instance type) and tolerating every taint its nodes carry.
func PoolsFromNodes(nodes []corev1.Node, poolLabel, instanceTypeLabel string) []Pool {
	type acc struct {
		key, value string
		tol        map[string]corev1.Toleration
	}
	byPool := map[string]*acc{}
	var order []string
	for _, n := range nodes {
		key, value := poolLabel, n.Labels[poolLabel]
		if value == "" {
			key, value = instanceTypeLabel, n.Labels[instanceTypeLabel]
		}
		if value == "" {
			key, value = "kubernetes.io/hostname", n.Name
		}
		a := byPool[value]
		if a == nil {
			a = &acc{key: key, value: value, tol: map[string]corev1.Toleration{}}
			byPool[value] = a
			order = append(order, value)
		}
		for _, t := range n.Spec.Taints {
			tol := corev1.Toleration{Key: t.Key, Operator: corev1.TolerationOpExists, Effect: t.Effect}
			a.tol[t.Key+"/"+string(t.Effect)] = tol
		}
	}
	var pools []Pool
	for _, name := range order {
		a := byPool[name]
		p := Pool{Name: name, Selector: map[string]string{a.key: a.value}}
		for _, t := range a.tol {
			p.Tolerations = append(p.Tolerations, t)
		}
		sortTolerations(p.Tolerations)
		pools = append(pools, p)
	}
	return pools
}

func sortTolerations(t []corev1.Toleration) {
	for i := 1; i < len(t); i++ {
		for j := i; j > 0 && t[j].Key+string(t[j].Effect) < t[j-1].Key+string(t[j-1].Effect); j-- {
			t[j], t[j-1] = t[j-1], t[j]
		}
	}
}
