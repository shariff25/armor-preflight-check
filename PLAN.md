# Armor Preflight: Phase 1 implementation plan

This plan covers how `armor-preflight` Phase 1 gets built from the build brief. It covers the architecture, the build order, how each acceptance criterion gets tested, and the places where the brief conflicts with itself or leaves a decision open. Those places are listed in §8, each with the default the build uses.

---

## 1. Repository layout

```
armor-preflight/
  cmd/armor-preflight/main.go          # cobra root, wires version/ldflags
  cmd/probe/main.go                    # probe binary (same module, separate image)
  internal/
    cli/                               # run, bundle, cleanup, version commands; flag parsing
    settings/                          # settings.yaml schema, validation, env-var secret resolution
    catalog/
      catalog.yaml                     # THE check catalog (embedded via go:embed)
      catalog.go                       # load, validate (ids unique, deps acyclic, fields non-empty)
      versions.go                      # armorVersion -> supported? / which Preflight to use
    model/                             # Result, Evidence, Status, Severity, Scope, Verdict, schema v1
    engine/                            # DAG scheduler, dependency skip, timeouts, verdict, exit codes
    checks/                            # one file per area; each registers Check funcs by catalog ID
      workstation/ kubernetes/ cc/ network/ registry/ backup/ pki/
    kube/                              # client-go wrapper + MutationGuard round-tripper
    probe/
      orchestrator/                    # namespace, pods, log collection, cleanup, signal handling
      protocol/                        # probe request/response JSON (shared by CLI and probe)
      nettest/                         # DNS -> TCP -> TLS -> HTTP staged dialer (shared)
      sgx/                             # Quoter / Verifier interfaces + fakes
    tlsutil/                           # the ONE place TLS configs are built (FIPS seam)
    redact/                            # secret registry + redacting writers
    output/
      terminal.go  html/ (template + inline CSS)  json.go  csv.go  bundle.go
  deploy/
    rbac/clusterrole.yaml  rbac/admission-policy.yaml   # see D-2
    probe/Dockerfile  probe/Dockerfile.sgx              # see D-5
  test/
    fixtures/                          # fake-clientset fixtures, one per failing check
    netfixtures/                       # local DNS/TCP/TLS/HTTP servers, intercepting proxy
    e2e/                               # kind-based: audit log, cleanup, PSS (CI job)
  .goreleaser.yaml                     # 4 targets, cosign, syft SBOM, checksums
  README.md  DECISIONS.md  SECURITY-BRIEF.md
```

Go 1.24, `client-go`, `cobra`, `sigs.k8s.io/yaml`, `miekg/dns` (tests only), `go-containerregistry` (registry manifest HEAD and chart fetch, no pulls). No other runtime dependencies. There is no telemetry anywhere, and a lint rule rejects any `net/http` client that isn't built through `tlsutil`.

## 2. Core design

### 2.1 Catalog as data

`catalog.yaml` holds everything about a check apart from its logic:

```yaml
catalogVersion: "2026.09"
armorVersions: [">=1.0.400 <1.1.0"]        # what this build covers
preflightForArmor:                          # used for the "use Preflight vX" refusal
  - { armor: ">=1.1.0", preflight: "see support portal" }   # never guessed; D-9
parameters:                                 # thresholds live here, not in code
  minKubernetes: "1.34.8"
  certManagerVersions: ">=1.15.0"           # placeholder, flagged TBD in DECISIONS.md
  nfdMinVersion: "0.15.0"
  systemPool: { minNodes: 3, minSku: Standard_D4d_v5 }
  sgxPool:    { minNodes: 3, minSku: Standard_DC8_v3 }
  clockSkewSeconds: 5
checks:
  - id: NET-02
    title: TCP 443 and TLS handshake to each required egress FQDN
    area: network
    severity: blocker            # or {production: blocker, poc: warning} for BAK-*
    owner: Network
    target: cluster              # cluster | host  (host = Phase 2 CN-*)
    runsIn: probe                # workstation | cluster-write | probe
    scope: nodePool              # cluster | nodePool | node
    needs: []                    # settings keys, e.g. [storage.accountFqdn]
    dependsOn: [NET-01]
    docLink: https://support.fortanix.com/docs/fortanix-armor-on-premises-prerequisites
    remediation: "Allow outbound TCP 443 from {{.SourceSubnet}} to {{.Target}}."
endpoints:
  - { fqdn: cr.download.fortanix.com, port: 443, purpose: "Armor images and Helm charts", checks: [NET-02, REG-01, REG-02, REG-03] }
  - { fqdn: pccs.fortanix.com, ... }
  - { fromSetting: attestation.azureAttestationHost, ... }
```

The loader rejects the catalog at build time (via a unit test) if an ID is duplicated, a `dependsOn` target is missing, the dependency graph has a cycle, or any of remediation, owner or docLink is empty. That covers the R1.1 requirement that no field is empty. The same file can later render the Prerequisites doc page with `armor-preflight catalog render`, which is Phase 2.

### 2.2 Check interface

The interface stays small so a check can be swapped for a Troubleshoot analyzer later:

```go
type Env struct { Kube kube.Reader; Settings *settings.Settings; Params catalog.Params; Probe ProbeResults; Clock clock.Clock; Local LocalTools }
type CheckFunc func(ctx context.Context, env Env, def catalog.Check) []model.Result   // one Result per scope
```

Checks are registered by ID with `checks.Register("K8S-05", k8s05)`. A startup test asserts that the registered IDs and the catalog IDs are the same set, so adding a catalog entry without code, or code without a catalog entry, fails CI. That same test is how the brief's consideration R1.1-1 (catalog living in the operator repo) could be enforced later.

`runsIn: probe` checks don't run in the CLI process. They turn the probe's JSON into Results. Probes return raw observations (stage timings, chains, clock readings), and the CLI decides pass or fail. That keeps thresholds and catalog logic in one place and makes the probe dumb and small.

### 2.3 Engine

- The engine does a topological sort over `dependsOn` and runs each level concurrently, with each check's `ctx` limited by `-t` (default 10s).
- Skip rules apply in order:
  1. A mode mismatch skips with "workstation mode".
  2. Missing settings skip with "missing setting `storage.accountFqdn`".
  3. A parent that failed skips with "parent REG-03 failed".
  4. A skipped parent skips the child with "parent X skipped: <reason>".
  5. A probe image that couldn't be pulled skips with "probe image `<digest>` could not be pulled".
- **Scope-aware dependencies.** A child scoped to node pool A is skipped only if its parent failed for pool A, or at cluster scope. So a NET-01 failure on `sgxpool1` doesn't skip NET-02 on `systempool`.
- **Verdict.** Any blocker with status fail gives NOT_READY. Otherwise, any warn gives READY_WITH_WARNINGS. Otherwise the result is READY. Exit codes are 0, 1, 2, and 3 for an internal error.
- **Warning-severity checks.** These report `warn`, never `fail`, when the condition is violated. That's the "Fail (Warn for Warning-severity)" rule.
- **Settings-conditional severity.** BAK-01 and BAK-02 are blockers when `storage.environment=production` and warnings otherwise. REG-04 is a blocker in mirror mode and skipped in direct mode.

### 2.4 Kubernetes access and the read-only guarantee

`kube.New` wraps the REST config with a **MutationGuard** round-tripper. In workstation mode it rejects every POST, PUT, PATCH and DELETE, and returns an internal error (exit 3) rather than letting one through. SelfSubjectAccessReview is the one exception; see D-1. In cluster mode the guard allows mutations only when they target `namespaces/armor-preflight-<runid>` or objects inside that namespace. This is the automated stand-in for the audit-log criterion, and the kind e2e job checks it against a real audit log.

### 2.5 Probe orchestration (cluster mode)

1. **Run ID.** The run ID has the form `YYYYMMDD-HHMM-<4 hex>`. The namespace is `armor-preflight-<runid>`, labelled with `app.kubernetes.io/managed-by=armor-preflight` and `armor-preflight/run-id`. It also carries `pod-security.kubernetes.io/enforce=restricted`, so the API server itself enforces PSS.
2. **Node pools.** Pools are grouped by `kubernetes.azure.com/agentpool`, falling back to `node.kubernetes.io/instance-type`. If neither label is present, K8S-02 and K8S-03 report the "unsupported profile" warning (D-8).
3. **Pods.** Each node pool gets one pod as a bare Pod, not a Job, which avoids needing batch RBAC. The pod is pinned with a nodeSelector on the pool label and tolerates the pool's taints (copied from the node's taints). Each SGX node gets one additional pod, pinned by `kubernetes.io/hostname`, that requests `sgx.intel.com/enclave: 1` and `sgx.intel.com/provision: 1`.
4. **Probe input.** Probe input goes in through a ConfigMap in the run namespace, holding the endpoints, the image list and the timeouts. Registry credentials go in a Secret (D-3). The probe runs once, prints one JSON document to stdout with a sentinel line, and exits 0.
5. **Collection.** The CLI polls pod phase and reads `pods/log`. If a pod hits `ErrImagePull` or `ImagePullBackOff` within 60s, the CLI records the exact image digest and marks every probe check skipped with the pull reason. Workstation checks still complete, as R1.5 requires.
6. **Cleanup.** Cleanup is registered with `defer` plus a SIGINT/SIGTERM handler that uses a fresh 30s context. It deletes the namespace with foreground propagation, then waits until the namespace is gone. `cleanup` lists namespaces, PVs and Services that carry the managed-by label (all run IDs, or `--run-id`) and deletes them. PVs are included because of the reclaim policy Retain case in K8S-10.
7. **Performance.** All pools and SGX nodes run in parallel. The budget for a 10-node cluster is about 20s scheduling plus image pull, plus probe time (endpoints × stages run in parallel inside the probe, each under 10s), plus about 30s for the namespace delete. The target is well under the 5-minute limit. The e2e job enforces the limit with a timer.

**Probe image.** The probe is a `CGO_ENABLED=0` Go binary on `gcr.io/distroless/static:nonroot`. It runs as UID 65532 with `readOnlyRootFilesystem`, drops `ALL` capabilities, sets `allowPrivilegeEscalation: false`, uses `seccompProfile: RuntimeDefault`, sets `automountServiceAccountToken: false`, and has no hostNetwork or hostPath. The probe needs no Kubernetes API access.

### 2.6 Network test engine (`nettest`)

Every target runs through four stages, each recorded as a separate Evidence entry:

| Stage | What happens |
|---|---|
| **dns** | Uses the pod resolver. Records the addresses and the resolver used. |
| **tcp** | Dials the port and records the latency, or the precise error: timeout, refused, reset. |
| **tls** | Handshakes with SNI, using system roots plus any customer CA bundle. Records the presented chain (subject, issuer, SHA-256 fingerprint) and whether it verified. |
| **http** | Sends a GET or HEAD to a known path. Any HTTP response proves reachability. The expected-response table is in D-6. |

If `HTTPS_PROXY` is set in settings, the probe tunnels with CONNECT, and the evidence records `via proxy`.

**NET-03 interception detection.** The catalog pins the expected issuer organisation for each intercept-sensitive endpoint: the registry, PCCS and attestation hosts. The check fails if the presented chain terminates in a root that isn't in the expected set. The exception is when the settings supply `proxy.trustedCaPath` and that CA signed the chain. In that case the check passes and records that interception is present but trusted. Pinning issuer organisations rather than leaf fingerprints avoids breaking on every cert rotation. The pinned issuer values are TBD from real handshakes and are recorded in DECISIONS.md (D-7).

## 3. Check-by-check implementation notes

| ID | Where it runs | Implementation |
|---|---|---|
| WS-01 | CLI | Uses `exec.LookPath` and `--version` for kubectl, helm, jq and openssl. Prints the current context and server URL. Fails if `settings.kubeContext` is set (D-10) and doesn't match. |
| K8S-01 | CLI | `ServerVersion()` is compared by semver against `minKubernetes`. "Supported upgrade path" can't be verified from inside the cluster, so the check records the version and the doc link. |
| K8S-02/03 | CLI | Node grouping plus an SKU size table (vCPU and memory per SKU family, from the catalog). "Or larger" means vCPU and memory both meet or exceed the minimum. K8S-03 also compares against `settings.replicas` (D-11). |
| K8S-04 | CLI | Uses `nodeInfo.operatingSystem` and `osImage`. Returns warn if the OS isn't Ubuntu 24.x. |
| K8S-05/06 | CLI | Lists CRDs by group (`k8ssandra.io`, `cassandra.datastax.com`; Armor operator group from the catalog, D-9) and deployments by image or label. |
| K8S-07 | CLI | Lists IngressClasses and checks that the controller pods for the class's `spec.controller` are Ready. |
| K8S-08 | CLI | Checks the cert-manager CRDs, the version from the controller image tag, and that at least one ClusterIssuer has condition Ready=True. |
| K8S-09 | CLI | SelfSubjectAccessReview for create customresourcedefinitions, create clusterroles, create namespaces, and update certificatesigningrequests/approval, plus approve on signers. The identity checked is the installer identity (D-12). |
| K8S-10 | cluster-write | Creates a 1Gi PVC in the run namespace with the default StorageClass, or `settings.storageClass`. Passes when it binds; if the binding mode is WaitForFirstConsumer, a probe pod mounts it. Warns if the reclaim policy is Delete. D-4 covers why this can't run in workstation mode. |
| K8S-11 | cluster-write | Creates a LoadBalancer Service with no selector and waits up to 90s for an ingress IP, a longer timeout than the default, set in the catalog. |
| K8S-12 | CLI | Reads `node.spec.podCIDRs` and the `ServiceCIDR` objects (networking.k8s.io/v1, GA in 1.33). Always reports info with the CIDRs as evidence, and saves them for the CSV and for Phase 2 `internalSubnets`. |
| CC-01 | CLI | Reads each SGX node's allocatable `sgx.intel.com/enclave` and `provision`, and checks that the device plugin DaemonSet pods are Ready. Scope is per node, so a missing plugin names that node only. |
| CC-02 | CLI | Reads the NFD version from the image tag and checks each SGX node's `cpu-security.sgx.enabled` label. |
| CC-03/04 | probe | nettest from SGX-pool pods against the PCCS and attestation hosts. If the Azure Attestation host isn't set, only that endpoint is skipped, with the reason. |
| CC-05 | probe (SGX) | Uses the `sgx.Quoter` and `sgx.Verifier` interfaces. The real implementation lives in a separate SGX probe image (D-5). It runs only if CC-01..04 and REG-03 pass, and reports per node. |
| NET-01 | probe | DNS stage for every endpoint, on every pool. |
| NET-02 | probe | TCP and TLS stages for every endpoint, on every pool. A failure names the pool and the target. |
| NET-03 | probe | Chain analysis (§2.6), on intercept-sensitive endpoints only. |
| NET-04 | CLI | Lints the settings proxy against the discovered CIDRs and the Armor domains. Also reads proxy env vars on the workstation, and on nodes where readable (D-13). |
| NET-05 | CLI | Resolves `domains.armor` and `domains.staticAssets` from the workstation. If they don't resolve but are recorded in settings, the result is warn with the text "recorded, not yet in DNS". |
| NET-06 | probe | TCP to the syslog host and port. Skipped if syslog isn't configured. |
| NET-07 | probe | Compares the probe's clock to the HTTP `Date` headers from endpoints already under test (D-14, not NTP). |
| REG-01 | CLI | Docker Registry v2 token authentication against `registry.url` with the username and the password from the named env var. |
| REG-02 | CLI | Fetches the Helm chart's OCI manifest and config for `armorVersion`. The chart reference comes from the catalog, configurable (D-9). |
| REG-03 | probe | HEAD request for each image manifest digest from the release manifest file, from every pool. Without the manifest file, only the operator chart and image are checked, and the evidence says so. |
| REG-04 | CLI | Mirror mode only. HEAD each digest in the customer registry and emit `imageOverrides.yaml` to the output directory. |
| REG-05 | CLI | Looks for a `dockerconfigjson` Secret in each Armor namespace listed in settings (D-11). Warns if a readable expiry is less than 14 days away; otherwise reports info. Only secret metadata and the parsed expiry are read, and the value is never logged. |
| BAK-01 | CLI | Worksheet only in Phase 1, from `storage.kind`, `storage.tier` and `storage.replication` in settings (D-15). |
| BAK-02 | probe | Put, get and delete of `armor-preflight-<runid>.txt` against the container using the storage key or SAS (D-3). |
| PKI-01 | CLI | Checks that `domains.armor` is present and a valid FQDN. The MFA binding can't be verified, so it's recorded as an acknowledgement in the evidence. |
| PKI-02 | CLI | Requires `certificates.caReady: true`. If a sample cert is given, validates that the chain includes the intermediates and root and that key usage is correct. |
| PKI-03 | CLI | Requires the planned SANs (from the sample cert, or `certificates.plannedApiSans`) to include `api.<domain>`. |

## 4. Outputs

- **Terminal.** Prints the verdict banner first, then a count table per area, then the failures grouped by owner. Colour is disabled when output isn't a TTY.
- **result.json.** Follows the brief's schema v1 exactly, plus `probes[]` (pod, node pool, image digest), `rbac` (the effective rules) and `redactions` (a count only). Versioning rules: fields can be added within v1, and removing or renaming a field bumps `schemaVersion`. A JSON Schema file ships as `schema/result.v1.json`, and a golden test validates output against it.
- **report.html.** Built with `html/template`. All CSS is inline and there are no `<script>`, `<link>` or `<img src=http…>` tags. A test parses the output and fails on any `src` or `href` that isn't a `#` anchor. Each owner section uses `break-before: page`. The last section lists the probes, digests and RBAC.
- **firewall-request.csv.** Written with `encoding/csv`, one row per (source pool, destination, port) whose DNS, TCP or TLS stage failed. It is deduplicated per pool and destination and lists the most specific check ID. `source_subnet` comes from `settings.nodePools.<name>.subnet` (D-16) or falls back to the node InternalIPs as /32s. A header comment row isn't allowed in CSV, so a `README-firewall.txt` sits alongside it.
- **bundle.tgz.** Contains result.json, `versions.json` (tool, catalog, Kubernetes, node OS images, add-on versions) and `MANIFEST.txt` with SHA-256 hashes. `bundle` prints the manifest and asks for confirmation (`--yes` skips the prompt). `bundle --list` only prints the manifest. There are no logs, Secret values, pod specs or workload names in the bundle.

## 5. Secret redaction

- `redact.Registry` is filled at settings load with the resolved values of every `*Env` variable, their base64 and URL-encoded forms, and the dockerconfigjson auth string.
- Every output writer and the logger (`slog` handler) wraps an `io.Writer` that replaces registered values with `[REDACTED]`.
- A settings file containing an inline secret-like key (`password:`, `key:`, `token:`) is rejected with exit code 3.
- **Build-gating test** (`test/redaction_test.go`): the test seeds `ARMOR_REGISTRY_PASSWORD` and `ARMOR_BACKUP_KEY` with unique canaries and runs workstation mode and fake cluster mode against fixtures that echo the credentials back in errors. It then greps every file in the output directory and the bundle, plus captured stdout and stderr, for the raw, base64 and URL-encoded forms. Any hit fails the test.

## 6. Build order (milestones)

Each milestone ends green in CI and is committed on its own.

| # | Milestone | Done when |
|---|---|---|
| M0 | Skeleton: go module, cobra commands, `version`, goreleaser snapshot, CI (lint, vet, test) | `armor-preflight version` prints the three version fields |
| M1 | Model, catalog loader with all 35 entries, engine (DAG, skips, timeouts, verdict, exit codes), settings loading and version refusal | Engine tests: dependency skips, scope-aware skips, verdict matrix, exit codes, refusal on an uncovered armorVersion |
| M2 | Outputs: terminal, JSON with schema, HTML, CSV, bundle, redaction layer | Golden-file tests, offline HTML test, CSV row test, redaction test |
| M3 | Workstation checks: WS-01, K8S-01..09, K8S-12, CC-01/02, NET-04/05, REG-01/02/04/05, BAK-01, PKI-01..03 with the MutationGuard | One failing fake-clientset fixture per check; a workstation-mode zero-mutation test |
| M4 | Probe binary, image, orchestrator, cleanup and signals, K8S-10/11 | Unit tests with a fake clientset and a fake pod-log source; kind e2e for cleanup (normal exit, SIGINT, SIGKILL then `cleanup`) and PSS admission |
| M5 | nettest and probe network checks: NET-01/02/03/06/07, CC-03/04, REG-03, BAK-02 | Local fixture servers per stage, an intercepting-proxy fixture, a per-pool blocked-egress test |
| M6 | CC-05 through the `sgx` interfaces, fakes, `Dockerfile.sgx` skeleton, manual test doc | Fake-driven unit tests; README manual steps |
| M7 | Release and security: ClusterRole and admission policy, cosign signing, SBOM, checksums, probe tarball (`docker save`), SECURITY-BRIEF.md, DECISIONS.md complete | `goreleaser release --snapshot` produces signed artifacts; `cosign verify` passes in CI |

## 7. Acceptance criteria → tests

| Criterion | Test |
|---|---|
| R1.1 35 failing fixtures | `checks/*_test.go`: a table of `{id, fixture}` rows, where each row asserts that ID gives fail, or warn for warning-severity checks. A meta-test asserts there are exactly 35 rows, one per catalog ID. |
| R1.1 compliant cluster gives READY | A fake "golden compliant" fixture in CI, plus the reference AKS run as a **manual** test in the README |
| R1.1 verdicts and exit codes | `engine/verdict_test.go` |
| R1.1 child skipped names parent | `engine/deps_test.go` (CC-05 names REG-03, among others) |
| R1.1 no empty fields | Catalog validation test plus a runtime assertion over every Result in the golden runs |
| R1.1 uncovered version refusal | `catalog/versions_test.go` plus a CLI exit-3 test |
| R1.2 blocked from SGX pool only | nettest fixture: a per-pool dialer where the sgx pool is blackholed. The NET-02 result names `sgxpool1`. |
| R1.2 separate stages | Evidence has dns, tcp, tls and http entries (asserted) |
| R1.2 NET-03 intercept | Test MITM proxy with its own CA; asserts it names each endpoint and the presented issuer |
| R1.2 CC-01 one node | Fake clientset with a single node missing allocatable |
| R1.2 CC-05 per node | Fakes in unit tests; **manual** on a real SGX AKS cluster |
| R1.3 all four outputs | CLI integration test on the output directory |
| R1.3 HTML offline | Parser test: no external src/href, no script |
| R1.3 CSV columns and rows | `csv_test.go` |
| R1.3 grouped, per-team print | HTML structure test (sections plus page-break CSS) |
| R1.3 usability 3/3 | **Manual**, protocol in the README |
| R1.4 workstation zero writes | MutationGuard unit test; kind e2e with an audit policy that parses the audit log |
| R1.4 cluster writes only in own namespace | kind e2e audit-log assertion; ClusterRole lint test (no write verbs outside the allow list) |
| R1.4 cleanup ×3 | kind e2e |
| R1.4 PSS restricted | Namespace enforces `restricted`, so the pod create fails if it's violated (kind e2e); also a unit test using `k8s.io/pod-security-admission` policy checks on the rendered pod |
| R1.4 packet capture | Partly automated: the probe and CLI dialers go through a single `Dialer` that records destinations; a test asserts the set equals the endpoints under test. A full pcap is **manual**. |
| R1.4 seeded secrets | `redaction_test.go`, run on every build |
| R1.4 signatures, SBOM | goreleaser snapshot plus `cosign verify-blob` in CI |
| R1.4 security brief approval | **Manual** (Fortanix Security) |
| R1.5 downloads, public image, tarball | Release artifact checks; `docker load` of the tarball in CI |
| R1.5 unpullable probe | Fake pod status `ImagePullBackOff`; asserts the digest is in the output and all workstation checks are present |
| R1.6 bundle contents, list, metadata | `bundle_test.go` |
| R1.6 under 5 minutes on 10 nodes | kind e2e with 10 nodes (timer); **manual** on AKS |

## 8. Conflicts and open decisions in the brief

These are recorded in `DECISIONS.md` as each is implemented.

- **D-1 SelfSubjectAccessReview in workstation mode.** K8S-09 has to POST SelfSubjectAccessReviews, and those show up as `create` in the audit log. That conflicts with "zero create calls" in R1.4. *Default:* allow only `selfsubjectaccessreviews` and `selfsubjectrulesreviews`. They are non-persisted, so nothing is stored. Document this in the security brief, and have the audit-log test exclude those two resources explicitly.

- **D-2 A ClusterRole can't confine writes to a namespace whose name is only known at run time.** RBAC can't express "create pods only in `armor-preflight-*`", and the creator of a namespace gets no rights inside it. *Options:*
  - (a) The ClusterRole grants create and delete on namespaces, pods, PVCs, Services, ConfigMaps and Secrets cluster-wide, and a shipped **ValidatingAdmissionPolicy** (GA in 1.30) limits the Preflight group to namespaces with the `armor-preflight-` prefix and the managed-by label.
  - (b) Use one fixed namespace `armor-preflight`, created once by the admin with a namespaced Role, and give each run its own run-id-labelled objects inside it.

  *Default:* (a). It keeps the brief's per-run namespace and gives an enforced boundary that security teams can read. (b) is the fallback if customers won't install admission policies.

- **D-3 Credentials inside probes.** REG-03 (resolve by digest from each pool) and BAK-02 (blob read and write from the node) need the registry password and storage key inside the probe. The brief's list of written objects doesn't include Secrets. *Default:* create a Secret in the run namespace, mount it read-only, and let the namespace delete remove it. Add `secrets` to the admission-scoped write list.

- **D-4 K8S-10 and K8S-11 create objects.** These checks create objects, so they can't run in workstation mode. *Default:* mark them `runsIn: cluster-write`. They run in cluster mode inside the run namespace, and workstation mode skips them with "workstation mode".

- **D-5 CC-05 can't run on distroless static Go.** Generating an SGX quote needs an enclave plus the DCAP quote library (C, glibc), and verification needs QVL or an equivalent. *Default:* keep the main probe distroless and static. Add a second image, `armor-preflight-probe-sgx`, used only for the per-SGX-node pods, based on an Intel DCAP runtime with a minimal signed test enclave. Its toolchain (EGo, Gramine or Open Enclave) is to be chosen with Fortanix engineering. Phase 1 ships the interface, the fakes and the Dockerfile skeleton, and CC-05 reports skipped ("SGX probe image not configured") until that image is set with `--sgx-probe-image`. It will still pass PSS restricted, because devices come from the device plugin and no privilege is needed.

- **D-6 Which response proves reachability without credentials** (R1.2 consideration 2). *Default:* any completed HTTP response over verified TLS counts as reachable, and the status code is recorded. The expected codes are:

  | Endpoint | Request | Expected code |
  |---|---|---|
  | Registry | `GET /v2/` | 401 with `WWW-Authenticate` |
  | Intel PCS/ITA | `GET /` | any 4xx |
  | PCCS | `GET /sgx/certification/v4/rootcacrl` | 200 |
  | Azure Attestation | `GET /.well-known/openid-configuration` | 200 |

  These paths go in the catalog, not in code, and must be verified against the real services before release.

- **D-7 NET-03 expected issuers.** These are captured from real handshakes during M5, stored in the catalog, and reviewed at each release.

- **D-8 Non-AKS clusters.** When no `kubernetes.azure.com/*` labels or `azure://` providerIDs are found, the run emits K8S-00-style warn results. These use the existing K8S-02 and K8S-03 IDs, with the scope set to cluster and "unsupported profile" in the evidence. Checks still run, and none of them passes silently.

- **D-9 Fortanix names that aren't in the brief.** The operator CRD group, the chart OCI reference, the probe image repository and the Preflight-for-Armor-version map are all catalog or ldflag values, and they're marked `TBD` until Fortanix supplies them. Checks that depend on a `TBD` value report skipped and name the missing catalog value.

- **D-10 "KUBECONFIG targets the intended cluster".** *Default:* add optional `kubeContext` (and optional `apiServer`) to settings. Without them, WS-01 passes on tool presence and prints the context prominently.

- **D-11 Settings fields the brief uses but doesn't define.** These are `replicas` (K8S-03) and `armorNamespaces` (REG-05). They are added as optional fields: without `replicas` the pool minimum of 3 applies, and without `armorNamespaces` REG-05 reports info.

- **D-12 Installer identity for K8S-09.** SSAR checks the caller. *Default:* the caller is the installer, and `--as` is supported to check a different identity. `--as` needs the `impersonate` verb, which isn't in the ClusterRole, so it's opt-in only.

- **D-13 NET-04 node proxy config.** Reading node runtime config needs hostPath, which PSS restricted forbids. *Default:* check the settings, the workstation environment and the probe container environment only, and say so in the evidence.

- **D-14 NET-07 "vs. NTP".** Querying NTP would reach a server that isn't under test, which breaks the packet-capture criterion. *Default:* compare against the HTTPS `Date` headers from endpoints already under test (1s resolution, fine for a 5s threshold) and use the median across endpoints.

- **D-15 BAK-01 through the Azure API.** That route needs Azure credentials and a connection to `management.azure.com`, which isn't under test. *Default:* worksheet only in Phase 1. An opt-in `--azure` flag is deferred.

- **D-16 Firewall source subnet.** Kubernetes doesn't expose the node subnet. *Default:* `nodePools.<pool>.subnet` in settings. The fallback is node InternalIPs as /32s, with a note.

- **D-17 Large clusters** (R1.2 consideration 1). One probe per pool (already a sample), plus one per SGX node because CC-01 and CC-05 are per node. An opt-in `--all-nodes` flag runs a probe on every node for network checks.

- **D-18 Bundle signing** (R1.6 consideration 1). Deferred. The manifest carries SHA-256 hashes now, and signing can reuse cosign later.

- **D-19 Troubleshoot.** A self-contained implementation, as the brief defaults to. The CheckFunc interface is the swap point.

- **D-20 FIPS.** All TLS goes through `internal/tlsutil`, and the build supports `GOEXPERIMENT=boringcrypto`, or the Go 1.24 `GODEBUG=fips140=on` native module, without code changes.

## 9. Phase 2 hooks built in now

- The catalog `target: host` field and a `Runner` abstraction (`cluster` or `host`), so the CN-* checks can run over SSH or locally without engine changes.
- `result.json` carries run IDs and stable check IDs, which lets quick-mode drift comparison diff two results.
- K8S-12 CIDRs and REG-04 `imageOverrides` are stored in a `discovered` block, ready for the `ArmorPlatform` draft.
- An `offline` flag in the engine's skip rules, returning skipped (offline) and never pass, is stubbed and unused.

## 10. Risks

| Risk | Mitigation |
|---|---|
| D-2 and D-3 are rejected by customer security | Fallback option (b) for D-2; weaker workstation-only checks for D-3 |
| CC-05 SGX toolchain choice slips | It's isolated behind the interface and a separate image, so the rest of Phase 1 ships with CC-05 skipped and a documented reason |
| Real endpoint behaviour differs from D-6 or D-7 | Everything is catalog data, and verification is a release checklist item |
| AKS SKU size table goes stale | It's catalog data, and an unknown SKU gives warn ("unknown SKU size, verify manually"), never pass |
