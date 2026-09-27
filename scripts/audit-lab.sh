#!/usr/bin/env bash
# Runs `armor-preflight run workstation` against a real kube-apiserver with
# audit logging, as an identity bound only to deploy/rbac/workstation.yaml,
# and checks that:
#   1. the audit log shows no create, update, patch or delete from that
#      identity, apart from SelfSubjectAccessReviews (not persisted; D-1);
#   2. no request was forbidden, so the shipped role is sufficient.
#
# Needs Go, curl, openssl and python3. Downloads kube-apiserver, etcd and
# kubectl with setup-envtest. No cluster, container runtime or network
# access beyond that download is needed.
#
#   scripts/audit-lab.sh            # from the armor-preflight directory
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=${WORK:-$(mktemp -d)}
K8S_VERSION=${K8S_VERSION:-1.34.x}
# setup-envtest from controller-runtime release-0.22, which builds with Go 1.24.
SETUP_ENVTEST_VERSION=${SETUP_ENVTEST_VERSION:-v0.0.0-20260125163108-a19ec76a3c5d}
ETCD_PORT=${ETCD_PORT:-23790}
API_PORT=${API_PORT:-16443}
echo "work dir: $WORK"

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

BIN=$(cd "$WORK" && GOFLAGS= GOTOOLCHAIN=local go run "sigs.k8s.io/controller-runtime/tools/setup-envtest@$SETUP_ENVTEST_VERSION" use "$K8S_VERSION" --bin-dir "$WORK/envtest" -p path)
KUBECTL="$BIN/kubectl --kubeconfig $WORK/kubeconfig --context admin"

cd "$WORK"
openssl req -x509 -newkey rsa:2048 -nodes -keyout sa.key -out sa.crt -days 1 -subj /CN=sa 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout tls.key -out tls.crt -days 1 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 2>/dev/null
printf 'admin-token,admin,admin,system:masters\npreflight-token,preflight,preflight\n' > tokens.csv
printf 'apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n  - level: Metadata\n' > audit-policy.yaml

"$BIN/etcd" --data-dir "$WORK/etcd" --listen-client-urls "http://127.0.0.1:$ETCD_PORT" --advertise-client-urls "http://127.0.0.1:$ETCD_PORT" \
  --listen-peer-urls "http://127.0.0.1:$((ETCD_PORT + 10))" > etcd.log 2>&1 &
pids+=($!)
"$BIN/kube-apiserver" --etcd-servers "http://127.0.0.1:$ETCD_PORT" --secure-port "$API_PORT" --bind-address 127.0.0.1 \
  --tls-cert-file tls.crt --tls-private-key-file tls.key --token-auth-file tokens.csv --authorization-mode RBAC \
  --service-account-issuer https://kubernetes.default.svc --service-account-key-file sa.crt --service-account-signing-key-file sa.key \
  --service-cluster-ip-range 10.0.0.0/16 --disable-admission-plugins ServiceAccount \
  --audit-policy-file audit-policy.yaml --audit-log-path "$WORK/audit.log" > apiserver.log 2>&1 &
pids+=($!)
for _ in $(seq 1 60); do
  curl -sk -H "Authorization: Bearer admin-token" "https://127.0.0.1:$API_PORT/readyz" | grep -q ok && break
  sleep 1
done

cat > kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters: [{name: lab, cluster: {server: "https://127.0.0.1:$API_PORT", insecure-skip-tls-verify: true}}]
users: [{name: admin, user: {token: admin-token}}, {name: preflight, user: {token: preflight-token}}]
contexts: [{name: admin, context: {cluster: lab, user: admin}}, {name: aks-armor-lab, context: {cluster: lab, user: preflight}}]
current-context: aks-armor-lab
EOF

# Seed a small AKS-like cluster: 3 system and 3 SGX nodes, the add-ons'
# pods, an IngressClass and a Ready ClusterIssuer.
status='"nodeInfo":{"operatingSystem":"linux","osImage":"Ubuntu 24.04.2 LTS","architecture":"amd64","kernelVersion":"6.8","containerRuntimeVersion":"containerd://1.7","kubeletVersion":"v1.34.8","kubeProxyVersion":"","machineID":"a","systemUUID":"a","bootID":"a"}'
for i in 0 1 2; do
  cat <<EOF | $KUBECTL apply -f - >/dev/null
apiVersion: v1
kind: Node
metadata:
  name: aks-systempool-$i
  labels: {kubernetes.azure.com/agentpool: systempool, kubernetes.azure.com/mode: system, node.kubernetes.io/instance-type: Standard_D4ds_v5}
spec: {providerID: "azure:///lab/aks-systempool-$i", podCIDRs: ["10.244.$i.0/24"]}
---
apiVersion: v1
kind: Node
metadata:
  name: aks-sgxpool1-$i
  labels: {kubernetes.azure.com/agentpool: sgxpool1, kubernetes.azure.com/mode: user, node.kubernetes.io/instance-type: Standard_DC8s_v3, feature.node.kubernetes.io/cpu-security.sgx.enabled: "true"}
spec: {providerID: "azure:///lab/aks-sgxpool1-$i", podCIDRs: ["10.244.1$i.0/24"]}
EOF
  $KUBECTL patch node "aks-systempool-$i" --subresource=status --type=merge -p "{\"status\":{\"capacity\":{\"cpu\":\"4\",\"memory\":\"16374164Ki\"},$status}}" >/dev/null
  $KUBECTL patch node "aks-sgxpool1-$i" --subresource=status --type=merge -p "{\"status\":{\"capacity\":{\"cpu\":\"8\",\"memory\":\"65856844Ki\"},\"allocatable\":{\"sgx.intel.com/enclave\":\"110\",\"sgx.intel.com/provision\":\"110\"},$status}}" >/dev/null
done
for ns in ingress-nginx cert-manager node-feature-discovery armor; do $KUBECTL create namespace "$ns" >/dev/null; done
pod() {
  cat <<EOF | $KUBECTL apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: $2, namespace: $1, labels: {$4}}
spec: {nodeName: aks-systempool-0, containers: [{name: c, image: "$3"}]}
EOF
  $KUBECTL -n "$1" patch pod "$2" --subresource=status --type=merge -p '{"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}}' >/dev/null
}
pod ingress-nginx controller registry.k8s.io/ingress-nginx/controller:v1.11.2 "app.kubernetes.io/name: ingress-nginx"
pod cert-manager cert-manager quay.io/jetstack/cert-manager-controller:v1.15.3 "app: cert-manager"
pod node-feature-discovery nfd-master registry.k8s.io/nfd/node-feature-discovery:v0.16.4 "app: nfd"
cat <<'EOF' | $KUBECTL apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: IngressClass
metadata: {name: nginx}
spec: {controller: k8s.io/ingress-nginx}
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: {name: clusterissuers.cert-manager.io}
spec:
  group: cert-manager.io
  scope: Cluster
  names: {plural: clusterissuers, singular: clusterissuer, kind: ClusterIssuer, listKind: ClusterIssuerList}
  versions: [{name: v1, served: true, storage: true, subresources: {status: {}}, schema: {openAPIV3Schema: {type: object, x-kubernetes-preserve-unknown-fields: true}}}]
EOF
$KUBECTL wait --for condition=established crd/clusterissuers.cert-manager.io >/dev/null
printf 'apiVersion: cert-manager.io/v1\nkind: ClusterIssuer\nmetadata: {name: corp-ca}\nspec: {ca: {secretName: corp-ca}}\n' | $KUBECTL apply -f - >/dev/null
$KUBECTL patch clusterissuer corp-ca --subresource=status --type=merge -p '{"status":{"conditions":[{"type":"Ready","status":"True"}]}}' >/dev/null

# Bind the Preflight identity to the shipped least-privilege role only.
$KUBECTL apply -f "$ROOT/deploy/rbac/workstation.yaml" >/dev/null
$KUBECTL create clusterrolebinding lab-preflight --clusterrole armor-preflight-workstation --user preflight >/dev/null
$KUBECTL -n armor create rolebinding lab-preflight --role armor-preflight-pull-secrets --user preflight >/dev/null

# Workstation tools WS-01 looks for; stand-ins where the host lacks them.
mkdir -p shims
ln -sf "$BIN/kubectl" shims/kubectl
for t in helm jq; do command -v "$t" >/dev/null || printf '#!/bin/sh\necho %s-lab-stand-in\n' "$t" > "shims/$t"; done
chmod +x shims/* 2>/dev/null || true

cat > settings.yaml <<EOF
armorVersion: "1.0.404"
kubeContext: aks-armor-lab
armorNamespaces: [armor]
domains: {armor: armor.lab.invalid}
certificates: {caReady: true, plannedApiSans: [api.armor.lab.invalid]}
# Unreachable on purpose: the lab contacts nothing outside this machine.
registry: {url: "127.0.0.1:1", username: lab-user, passwordEnv: LAB_REGISTRY_PASSWORD}
storage: {accountFqdn: lab.blob.core.windows.net, container: medusa, credentialsEnv: LAB_BACKUP_KEY, accountKind: StorageV2, performance: Standard, replication: LRS}
EOF

(cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/armor-preflight" ./cmd/armor-preflight)
set +e
PATH="$WORK/shims:$PATH" LAB_REGISTRY_PASSWORD=lab-password LAB_BACKUP_KEY=lab-key \
  "$WORK/armor-preflight" run workstation -k "$WORK/kubeconfig" -f settings.yaml -o "$WORK/out" > preflight.txt 2>&1
code=$?
set -e
echo "armor-preflight exited $code (3 is expected until every check is implemented)"

python3 - "$WORK/audit.log" "$WORK/preflight.txt" <<'PY'
import collections, json, sys
audit, output = sys.argv[1], sys.argv[2]
reads, writes, forbidden = collections.Counter(), [], []
for line in open(audit):
    e = json.loads(line)
    if e.get("stage") != "ResponseComplete" or e["user"]["username"] != "preflight":
        continue
    res = e.get("objectRef", {}).get("resource") or e.get("requestURI")
    if e["responseStatus"].get("code") == 403:
        forbidden.append(f'{e["verb"]} {res}')
    if e["verb"] in ("get", "list", "watch"):
        reads[f'{e["verb"]} {res}'] += 1
    elif not (e["verb"] == "create" and res == "selfsubjectaccessreviews"):
        writes.append(f'{e["verb"]} {res}')
print("requests from the Preflight identity:")
for k, n in sorted(reads.items()):
    print(f"  {k} x{n}")
text = open(output).read()
ok = True
if writes:
    print("FAIL: writes found in the audit log:", writes); ok = False
if forbidden or "forbidden" in text.lower():
    print("FAIL: requests were forbidden; deploy/rbac/workstation.yaml is missing a permission:", forbidden); ok = False
if not reads:
    print("FAIL: no requests from the Preflight identity were audited"); ok = False
if ok:
    print("PASS: workstation mode made no writes, and the shipped role covered every request")
sys.exit(0 if ok else 1)
PY
