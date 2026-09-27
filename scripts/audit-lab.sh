#!/usr/bin/env bash
# Runs armor-preflight against a real kube-apiserver with audit logging, as
# an identity bound only to the roles in deploy/rbac, and checks R1.4:
#
# Workstation mode (bound to workstation.yaml only):
#   1. the audit log shows no create, update, patch or delete, apart from
#      SelfSubjectAccessReviews (not persisted; D-1);
#   2. no request was forbidden, so the shipped role is sufficient.
# Cluster mode (plus cluster.yaml, including its admission policy):
#   3. every write is inside armor-preflight-<run id>, or is that namespace
#      itself, or deletes a volume claimed from it;
#   4. probe pods are admitted by the namespace's restricted Pod Security
#      Standards enforcement;
#   5. the admission policy denies the same identity any write elsewhere;
#   6. no Preflight-labelled object remains after a normal exit, after an
#      interrupt, or after a killed run followed by `armor-preflight cleanup`.
#
# envtest has no scheduler, kubelet or controller manager, so a small
# simulator stands in for them: it binds test volumes, gives the test
# LoadBalancer an address and finalizes terminating namespaces, as the real
# controllers would. Probe pods are admitted but never scheduled, so probe
# results are covered by unit tests instead.
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
# setup-envtest from controller-runtime release-0.22 (needs Go 1.24 or later).
SETUP_ENVTEST_VERSION=${SETUP_ENVTEST_VERSION:-v0.0.0-20260125163108-a19ec76a3c5d}
ETCD_PORT=${ETCD_PORT:-23790}
API_PORT=${API_PORT:-16443}
echo "work dir: $WORK"

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

BIN=$(cd "$WORK" && GOFLAGS='' GOTOOLCHAIN=local go run "sigs.k8s.io/controller-runtime/tools/setup-envtest@$SETUP_ENVTEST_VERSION" use "$K8S_VERSION" --bin-dir "$WORK/envtest" -p path)
KUBECTL="$BIN/kubectl --kubeconfig $WORK/kubeconfig --context admin"

cd "$WORK"
openssl req -x509 -newkey rsa:2048 -nodes -keyout sa.key -out sa.crt -days 1 -subj /CN=sa 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout tls.key -out tls.crt -days 1 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 2>/dev/null
# Fresh tokens per run, so a stray process from an earlier run cannot reach this API server.
ADMIN_TOKEN=$(openssl rand -hex 16)
PREFLIGHT_TOKEN=$(openssl rand -hex 16)
printf '%s,admin,admin,system:masters\n%s,preflight,preflight,armor-preflight\n' "$ADMIN_TOKEN" "$PREFLIGHT_TOKEN" > tokens.csv
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
  curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" "https://127.0.0.1:$API_PORT/readyz" | grep -q ok && break
  sleep 1
done

cat > kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters: [{name: lab, cluster: {server: "https://127.0.0.1:$API_PORT", insecure-skip-tls-verify: true}}]
users: [{name: admin, user: {token: $ADMIN_TOKEN}}, {name: preflight, user: {token: $PREFLIGHT_TOKEN}}]
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
preflight() {
  PATH="$WORK/shims:$PATH" LAB_REGISTRY_PASSWORD=lab-password LAB_BACKUP_KEY=lab-key \
    "$WORK/armor-preflight" "$@" -k "$WORK/kubeconfig"
}
# preflight_bg starts Preflight in the background with exec, so $! is the
# Preflight process itself and signals reach it directly.
preflight_bg() {
  ( exec env PATH="$WORK/shims:$PATH" LAB_REGISTRY_PASSWORD=lab-password LAB_BACKUP_KEY=lab-key \
      "$WORK/armor-preflight" "$@" -k "$WORK/kubeconfig" ) &
  pids+=($!)
}
failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

echo "== workstation mode"
set +e
preflight run workstation -f settings.yaml -o "$WORK/out" > preflight.txt 2>&1
code=$?
set -e
echo "armor-preflight exited $code (a verdict; the lab environment is not Armor-ready, so 2 is expected)"
workstation_lines=$(wc -l < "$WORK/audit.log")

python3 - "$WORK/audit.log" "$WORK/preflight.txt" "$workstation_lines" <<'PY' || failures=$((failures + 1))
import collections, json, sys
audit, output, limit = sys.argv[1], sys.argv[2], int(sys.argv[3])
reads, writes, forbidden = collections.Counter(), [], []
for i, line in enumerate(open(audit)):
    if i >= limit:
        break
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

# ---------------------------------------------------------------------------
echo "== cluster mode"
$KUBECTL apply -f "$ROOT/deploy/rbac/cluster.yaml" >/dev/null
$KUBECTL create clusterrolebinding lab-preflight-cluster --clusterrole armor-preflight-cluster --user preflight >/dev/null
cat <<'EOF' | $KUBECTL apply -f - >/dev/null
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: lab-retain
  annotations: {storageclass.kubernetes.io/is-default-class: "true"}
provisioner: lab.invalid/simulated
reclaimPolicy: Retain
volumeBindingMode: Immediate
EOF
PF="$BIN/kubectl --kubeconfig $WORK/kubeconfig"
# Admission policies take a moment to be picked up.
for _ in $(seq 1 30); do
  if ! $PF create configmap vap-check -n default >/dev/null 2>&1; then break; fi
  $KUBECTL delete configmap vap-check -n default >/dev/null 2>&1 || true
  sleep 1
done

# The simulator stands in for the volume binder, the cloud load balancer,
# and the namespace and PV protection controllers.
simulate() {
  while true; do
    for ns in $($KUBECTL get ns -l app.kubernetes.io/managed-by=armor-preflight -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
      for pvc in $($KUBECTL -n "$ns" get pvc -o jsonpath='{range .items[?(@.status.phase!="Bound")]}{.metadata.name}{" "}{end}' 2>/dev/null); do
        printf 'apiVersion: v1\nkind: PersistentVolume\nmetadata: {name: lab-pv-%s}\nspec:\n  capacity: {storage: 1Gi}\n  accessModes: [ReadWriteOnce]\n  persistentVolumeReclaimPolicy: Retain\n  storageClassName: lab-retain\n  hostPath: {path: /tmp/lab}\n  claimRef: {namespace: %s, name: %s}\n' "$ns" "$ns" "$pvc" \
          | $KUBECTL apply -f - >/dev/null 2>&1
        $KUBECTL -n "$ns" patch pvc "$pvc" --type=merge -p "{\"spec\":{\"volumeName\":\"lab-pv-$ns\"}}" >/dev/null 2>&1
        $KUBECTL -n "$ns" patch pvc "$pvc" --subresource=status --type=merge -p '{"status":{"phase":"Bound"}}' >/dev/null 2>&1
      done
      for svc in $($KUBECTL -n "$ns" get svc -o jsonpath='{range .items[?(@.spec.type=="LoadBalancer")]}{.metadata.name}{" "}{end}' 2>/dev/null); do
        $KUBECTL -n "$ns" patch svc "$svc" --subresource=status --type=merge -p '{"status":{"loadBalancer":{"ingress":[{"ip":"10.20.8.40"}]}}}' >/dev/null 2>&1
      done
    done
    # Namespace controller: empty and finalize terminating namespaces.
    for ns in $($KUBECTL get ns -o jsonpath='{range .items[?(@.status.phase=="Terminating")]}{.metadata.name}{" "}{end}' 2>/dev/null); do
      for kind in pods configmaps secrets services persistentvolumeclaims; do
        for obj in $($KUBECTL -n "$ns" get "$kind" -o name 2>/dev/null); do
          $KUBECTL -n "$ns" patch "$obj" --type=merge -p '{"metadata":{"finalizers":null}}' >/dev/null 2>&1
          $KUBECTL -n "$ns" delete "$obj" --grace-period=0 --force --wait=false >/dev/null 2>&1
        done
      done
      $KUBECTL get ns "$ns" -o json 2>/dev/null \
        | python3 -c 'import json,sys; o=json.load(sys.stdin); o["spec"]["finalizers"]=[]; print(json.dumps(o))' \
        | $KUBECTL replace --raw "/api/v1/namespaces/$ns/finalize" -f - >/dev/null 2>&1
    done
    # PV protection: release deleted volumes.
    for pv in $($KUBECTL get pv -o jsonpath='{range .items[?(@.metadata.deletionTimestamp)]}{.metadata.name}{" "}{end}' 2>/dev/null); do
      $KUBECTL patch pv "$pv" --type=merge -p '{"metadata":{"finalizers":null}}' >/dev/null 2>&1
    done
    sleep 1
  done
}
simulate &
pids+=($!)

leftovers() {
  { $KUBECTL get ns -l app.kubernetes.io/managed-by=armor-preflight -o name; $KUBECTL get pv -o name | grep lab-pv- || true; } 2>/dev/null
}
wait_no_leftovers() {
  for _ in $(seq 1 30); do [ -z "$(leftovers)" ] && return 0; sleep 1; done
  return 1
}
wait_for_namespace() {
  for _ in $(seq 1 60); do
    ns=$($KUBECTL get ns -l app.kubernetes.io/managed-by=armor-preflight -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    [ -n "$ns" ] && { echo "$ns"; return 0; }
    sleep 0.5
  done
  return 1
}
PROBE=lab.invalid/armor-preflight-probe:lab
cluster_start=$(wc -l < "$WORK/audit.log")

echo "-- normal exit"
set +e
preflight run cluster -f settings.yaml -o "$WORK/out-cluster" --probe-image "$PROBE" --probe-timeout 10s > cluster.txt 2>&1
code=$?
set -e
echo "armor-preflight exited $code"
grep -q "Removed Preflight's temporary namespace" cluster.txt || fail "normal exit did not report cleanup"
for id in K8S-10 K8S-11; do
  python3 -c "import json,sys; r=[x for x in json.load(open('$WORK/out-cluster/result.json'))['results'] if x['id']=='$id']; sys.exit(0 if r and r[0]['status']=='pass' else 1)" \
    || fail "$id did not pass against the simulated cluster"
done
wait_no_leftovers || fail "objects left after a normal exit: $(leftovers)"

echo "-- admission policy"
$PF create configmap outside -n default >/dev/null 2>&1 && fail "the policy allowed a ConfigMap in default"
$PF create namespace not-preflight >/dev/null 2>&1 && fail "the policy allowed creating namespace not-preflight"
$PF create namespace armor-preflight-unlabelled >/dev/null 2>&1 && fail "the policy allowed an unlabelled armor-preflight-* namespace"
$PF delete namespace armor --wait=false >/dev/null 2>&1 && fail "the policy allowed deleting namespace armor"

echo "-- interrupt"
preflight_bg run cluster -f settings.yaml -o "$WORK/out-int" --probe-image "$PROBE" --probe-timeout 60s > interrupt.txt 2>&1
run_pid=$!
wait_for_namespace >/dev/null || fail "interrupt test: namespace never appeared"
sleep 1
started=$SECONDS
kill -INT "$run_pid"
wait "$run_pid" || true
[ $((SECONDS - started)) -lt 30 ] || fail "interrupt took $((SECONDS - started))s to take effect"
grep -q "interrupted" interrupt.txt || fail "the run did not report the interrupt: $(tail -3 interrupt.txt)"
grep -q "Removed Preflight's temporary namespace" interrupt.txt || fail "interrupt did not clean up: $(tail -3 interrupt.txt)"
wait_no_leftovers || fail "objects left after an interrupt: $(leftovers)"

echo "-- killed, then cleanup"
preflight_bg run cluster -f settings.yaml -o "$WORK/out-kill" --probe-image "$PROBE" --probe-timeout 60s > killed.txt 2>&1
run_pid=$!
ns=$(wait_for_namespace) || fail "kill test: namespace never appeared"
sleep 3
kill -KILL "$run_pid"
wait "$run_pid" 2>/dev/null || true
kill -0 "$run_pid" 2>/dev/null && fail "kill test: Preflight is still running"
sleep 3
[ -n "$(leftovers)" ] || fail "kill test: expected leftovers before cleanup"
preflight cleanup > cleanup.txt 2>&1 || fail "cleanup command failed: $(cat cleanup.txt)"
grep -q "deleting namespace $ns" cleanup.txt || fail "cleanup did not name $ns"
wait_no_leftovers || fail "objects left after cleanup: $(leftovers)"

python3 - "$WORK/audit.log" "$cluster_start" <<'PY' || failures=$((failures + 1))
import json, sys
audit, start = sys.argv[1], int(sys.argv[2])
bad, pods, writes = [], 0, 0
for i, line in enumerate(open(audit)):
    if i < start:
        continue
    e = json.loads(line)
    if e.get("stage") != "ResponseComplete" or e["user"]["username"] != "preflight":
        continue
    if not e.get("userAgent", "").startswith("armor-preflight"):
        continue  # the admission-policy checks above use kubectl
    if e["verb"] in ("get", "list", "watch"):
        continue
    ref = e.get("objectRef", {})
    res, ns, name = ref.get("resource"), ref.get("namespace", ""), ref.get("name", "")
    code = e["responseStatus"].get("code", 0)
    writes += 1
    if res == "selfsubjectaccessreviews":
        continue
    if res == "pods" and e["verb"] == "create":
        pods += 1
        if code >= 400:
            bad.append(f"pod create rejected ({code}): {e['responseStatus'].get('message', '')}")
    ok = (ns.startswith("armor-preflight-")
          or (res == "namespaces" and (name.startswith("armor-preflight-") or e["verb"] == "create"))
          or (res == "persistentvolumes" and e["verb"] == "delete" and name.startswith("lab-pv-armor-preflight-")))
    if not ok:
        bad.append(f"{e['verb']} {res} {ns}/{name}")
    if code == 403:
        bad.append(f"forbidden: {e['verb']} {res} {ns}/{name}")
print(f"cluster mode: {writes} writes audited, {pods} probe pod creates")
for b in bad:
    print("FAIL:", b)
if pods == 0:
    print("FAIL: no probe pods were created"); bad.append("no pods")
if not bad:
    print("PASS: cluster mode wrote only inside its own namespace, and probe pods passed restricted Pod Security admission")
sys.exit(1 if bad else 0)
PY

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "PASS: all audit lab checks"
