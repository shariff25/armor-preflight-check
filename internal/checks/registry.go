package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/registry"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
)

// ImageOverridesFile is the artifact REG-04 writes in mirror mode.
const ImageOverridesFile = "image-overrides.yaml"

func registryClient(env *engine.Env) *registry.Client {
	sec := env.Settings.ResolveSecrets(env.LookupEnv)
	return &registry.Client{HTTP: env.HTTP, Host: env.Settings.Registry.URL, Username: env.Settings.Registry.Username, Password: sec.RegistryPassword}
}

// reg01: the registry accepts the credentials.
func reg01(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	c := registryClient(env)
	err := c.Ping(ctx)
	switch {
	case err == nil:
		return one(verdict(model.ClusterScope(), ev("login", c.Host, true, "logged in to %s as %s", c.Host, c.Username)))
	case errors.Is(err, registry.ErrUnauthorized):
		return one(verdict(model.ClusterScope(), ev("login", c.Host, false, "%s rejected the credentials for %s: %v", c.Host, c.Username, err)))
	default:
		r := verdict(model.ClusterScope(), ev("login", c.Host, false, "could not reach %s from this workstation: %v", c.Host, err))
		host, port := c.Host, "443"
		if h, p, err := net.SplitHostPort(c.Host); err == nil {
			host, port = h, p
		}
		r.Remediation = fmt.Sprintf("Allow this workstation to reach %s on TCP %s (through the proxy if one is used), then re-run.", host, port)
		return one(r)
	}
}

// chartReference is the operator chart for the target version, moved to the
// mirror host in mirror mode.
func chartReference(env *engine.Env) (registry.Reference, error) {
	base := env.Params().OperatorChartRef
	ref, err := registry.ParseReference(strings.TrimSuffix(base, "/") + ":" + env.Settings.ArmorVersion)
	if err != nil {
		return ref, fmt.Errorf("catalog operatorChartRef %q: %w", base, err)
	}
	if env.Settings.Registry.Mode == settings.RegistryModeMirror {
		ref.Host = env.Settings.Registry.URL
	}
	return ref, nil
}

// reg02: the operator chart for the target version can be fetched.
func reg02(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if isTBD(env.Params().OperatorChartRef) {
		return tbd("parameters.operatorChartRef")
	}
	ref, err := chartReference(env)
	if err != nil {
		return skip(err.Error())
	}
	c := registryClient(env)
	c.Host = ref.Host
	ok, digest, err := c.Manifest(ctx, ref.Repo, ref.Tag)
	switch {
	case err != nil:
		return one(verdict(model.ClusterScope(), ev("chart", ref.String(), false, "could not fetch the chart manifest: %v", err)))
	case !ok:
		return one(verdict(model.ClusterScope(), ev("chart", ref.String(), false, "chart version %s not found; the credentials may not be entitled to it", ref.Tag)))
	}
	return one(verdict(model.ClusterScope(), ev("chart", ref.String(), true, "chart manifest found (%s)", digest)))
}

// releaseImages reads the release manifest, or falls back to the operator
// chart alone, saying which in the returned note.
func releaseImages(env *engine.Env) ([]registry.Reference, string, error) {
	if path := env.Settings.Registry.ReleaseManifestPath; path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, "", fmt.Errorf("read registry.releaseManifestPath: %w", err)
		}
		defer f.Close()
		refs, err := registry.ParseManifestList(f)
		if err != nil {
			return nil, "", fmt.Errorf("parse %s: %w", path, err)
		}
		if len(refs) == 0 {
			return nil, "", fmt.Errorf("%s lists no images", path)
		}
		return refs, fmt.Sprintf("%d images from %s", len(refs), path), nil
	}
	if isTBD(env.Params().OperatorChartRef) {
		return nil, "", errors.New("no release manifest (registry.releaseManifestPath) and the operator chart reference is not published yet (TBD)")
	}
	base := env.Params().OperatorChartRef
	ref, err := registry.ParseReference(strings.TrimSuffix(base, "/") + ":" + env.Settings.ArmorVersion)
	if err != nil {
		return nil, "", err
	}
	return []registry.Reference{ref}, "no release manifest given (registry.releaseManifestPath), so only the operator chart was checked", nil
}

// reg04: in mirror mode, every release image exists in the mirror. Writes
// image-overrides.yaml mapping each release image to its mirror copy.
func reg04(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	if env.Settings.Registry.Mode != settings.RegistryModeMirror {
		return skip("registry mode is direct; REG-04 applies to mirror mode only")
	}
	images, note, err := releaseImages(env)
	if err != nil {
		return skip(err.Error())
	}
	c := registryClient(env)
	evidence := []model.Evidence{ev("manifest", "", true, "%s", note)}
	type override struct {
		Original string `json:"original"`
		Image    string `json:"image"`
	}
	var overrides []override
	var missing []string
	for _, img := range images {
		mirrored := img
		mirrored.Host = env.Settings.Registry.URL
		ok, _, err := c.Manifest(ctx, mirrored.Repo, mirrored.Ref())
		switch {
		case err != nil:
			evidence = append(evidence, ev("mirror", mirrored.String(), false, "could not check: %v", err))
			missing = append(missing, img.String())
		case !ok:
			evidence = append(evidence, ev("mirror", mirrored.String(), false, "not found in the mirror"))
			missing = append(missing, img.String())
		default:
			evidence = append(evidence, ev("mirror", mirrored.String(), true, "present"))
			overrides = append(overrides, override{Original: img.String(), Image: mirrored.String()})
		}
	}
	if len(overrides) > 0 {
		b, err := yaml.Marshal(map[string]any{"imageOverrides": overrides})
		if err == nil {
			env.AddArtifact(ImageOverridesFile, append([]byte("# Generated by armor-preflight REG-04: release images and their mirror copies.\n"), b...))
		}
	}
	r := verdict(model.ClusterScope(), evidence...)
	if len(missing) > 0 {
		r.Remediation = fmt.Sprintf("Mirror these images into %s, keeping their repository paths and digests: %s", env.Settings.Registry.URL, strings.Join(missing, ", "))
	}
	return one(r)
}

// expiryAnnotations are annotation keys that can carry a readable expiry.
var expiryAnnotations = []string{"expires", "expiry", "expiration", "expires-at", "valid-until"}

// reg05: an image pull secret for the registry exists in each Armor
// namespace. Only the registry host names in the secret are read; the
// credentials are never logged.
func reg05(ctx context.Context, env *engine.Env, _ *catalog.Check) []model.Result {
	namespaces := env.Settings.ArmorNamespaces
	if len(namespaces) == 0 {
		return one(result(model.StatusInfo, model.ClusterScope(), ev("namespaces", "", false, "armorNamespaces is not set in the settings file, so pull secrets were not checked")))
	}
	if env.Kube == nil {
		return noKube(env)
	}
	host := env.Settings.Registry.URL
	warnDays := env.Params().PullSecretExpiryWarnDays
	now := time.Now()
	if env.Now != nil {
		now = env.Now()
	}
	var evidence []model.Evidence
	status := model.StatusPass
	downgrade := func(s model.Status) {
		if s == model.StatusFail || (s == model.StatusInfo && status == model.StatusPass) {
			status = s
		}
	}
	for _, ns := range namespaces {
		if _, err := env.Kube.Core.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); apierrors.IsNotFound(err) {
			evidence = append(evidence, ev("namespace", ns, false, "namespace %s does not exist yet; create it with the image pull secret before the install", ns))
			downgrade(model.StatusFail)
			continue
		}
		secrets, err := env.Kube.Core.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{FieldSelector: "type=" + string(corev1.SecretTypeDockerConfigJson)})
		if err != nil {
			evidence = append(evidence, ev("secret", ns, false, "could not list pull secrets in %s: %v", ns, err))
			downgrade(model.StatusFail)
			continue
		}
		var found *corev1.Secret
		for i := range secrets.Items {
			if dockerConfigHasHost(secrets.Items[i].Data[corev1.DockerConfigJsonKey], host) {
				found = &secrets.Items[i]
				break
			}
		}
		if found == nil {
			evidence = append(evidence, ev("secret", ns, false, "no image pull secret for %s in namespace %s", host, ns))
			downgrade(model.StatusFail)
			continue
		}
		exp, ok := secretExpiry(found)
		switch {
		case !ok:
			evidence = append(evidence, ev("secret", ns+"/"+found.Name, true, "pull secret for %s found; it has no readable expiry, so check the credential lifetime with Fortanix Support", host))
			downgrade(model.StatusInfo)
		case exp.Before(now.Add(time.Duration(warnDays) * 24 * time.Hour)):
			evidence = append(evidence, ev("expiry", ns+"/"+found.Name, false, "pull secret for %s expires %s, within %d days", host, exp.Format("2006-01-02"), warnDays))
			downgrade(model.StatusFail)
		default:
			evidence = append(evidence, ev("expiry", ns+"/"+found.Name, true, "pull secret for %s valid until %s", host, exp.Format("2006-01-02")))
		}
	}
	return one(result(status, model.ClusterScope(), evidence...))
}

func dockerConfigHasHost(raw []byte, host string) bool {
	var cfg struct {
		Auths map[string]json.RawMessage `json:"auths"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return false
	}
	for k := range cfg.Auths {
		k = strings.TrimPrefix(strings.TrimPrefix(k, "https://"), "http://")
		k, _, _ = strings.Cut(k, "/")
		if strings.EqualFold(k, host) {
			return true
		}
	}
	return false
}

func secretExpiry(s *corev1.Secret) (time.Time, bool) {
	keys := make([]string, 0, len(s.Annotations))
	for k := range s.Annotations {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name := k
		if i := strings.LastIndex(k, "/"); i >= 0 {
			name = k[i+1:]
		}
		for _, want := range expiryAnnotations {
			if strings.EqualFold(name, want) {
				if t, err := time.Parse(time.RFC3339, s.Annotations[k]); err == nil {
					return t, true
				}
				if t, err := time.Parse("2006-01-02", s.Annotations[k]); err == nil {
					return t, true
				}
			}
		}
	}
	return time.Time{}, false
}
