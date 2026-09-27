# Decisions

Decisions made where the build brief was open or conflicted. D-numbers match [PLAN.md](PLAN.md) §8. Entries are added as each decision is implemented.

## M0

- **Module path.** `github.com/shariff25/agent-goverance-OS/armor-preflight`, matching the repository it lives in. Change it if the tool moves to a Fortanix repository.
- **Supported Armor versions are listed, not ranged.** The catalog lists `1.0.404`, the only version the brief names. The range of versions a catalog covers isn't documented, so none is guessed. Add versions as Fortanix confirms them.
- **Catalog version.** `2026.09`, from the brief's example result.
- **Unimplemented commands exit 3.** Until a command is implemented it reports "not implemented yet" and exits 3 ("Preflight failed to run"), so a script never mistakes it for a READY result.
- **Release signing.** goreleaser signs the checksum file with cosign using a key from `COSIGN_KEY`. Signing the checksum file covers every archive listed in it. Whether Fortanix publishes a key pair or uses keyless (OIDC) signing is still open; switching only changes the `signs` args.

## Defaults adopted from PLAN.md without sign-off

The user chose not to gate the build on D-1 to D-3, so the plan's defaults apply:

- **D-1.** Workstation mode allows SelfSubjectAccessReview and SelfSubjectRulesReview requests (non-persisted) and blocks every other write.
- **D-2.** The ClusterRole ships with a ValidatingAdmissionPolicy that limits Preflight's writes to `armor-preflight-*` namespaces carrying the managed-by label.
- **D-3.** Registry and storage credentials reach probes through a Secret in the run namespace, deleted with it.

## M1

- **The version refusal needs a settings file.** `armorVersion` is only known from the settings file, so a run without `-f` can't check coverage and doesn't refuse. A settings file must include `armorVersion`.
- **Which Preflight to use for other Armor versions.** The catalog has a `preflightForArmor` table, shipped empty. Until Fortanix fills it, the refusal points to the support portal instead of naming a version.
- **Settings fields added to the brief's example.** These are all optional:
  - `kubeContext` (D-10)
  - `replicas` and `armorNamespaces` (D-11)
  - `nodePools.<pool>.subnet` (D-16)
  - `storageClass`
  - `storage.accountKind`, `storage.performance` and `storage.replication`, the BAK-01 worksheet (D-15)
  - `proxy.trustedCaPath` (NET-03)
  - `certificates.plannedApiSans` (PKI-03)
- **Settings defaults.**
  - `registry.mode` defaults to `direct`.
  - `registry.url` defaults to `cr.download.fortanix.com`.
  - `storage.environment` defaults to `production`, the stricter choice.
  - `syslog.port` defaults to 514 when a syslog host is set.
- **Inline secrets are rejected.** A settings key that looks like a secret (`password`, `key`, `token`, `secret`, `credentials`, `sas` and similar) stops the run with exit 3 and a message pointing to the `*Env` fields. So does a proxy URL with a username or password in it.
- **An unset secret environment variable skips the check.** It doesn't fail it. For example, REG-01 reports "environment variable ARMOR_REGISTRY_PASSWORD (named by `registry.passwordEnv`) is not set".
- **Scope-aware skipping.** A child result is skipped only where its parent failed or was skipped:
  - A parent result for the whole cluster blocks every child result.
  - A parent result for a node pool blocks child results for that pool and for its nodes.
  - A parent result for a node blocks child results for that node, and for the pool that node belongs to.
  - A cluster-wide child is blocked by a parent failure anywhere.
  - The skip reason names every blocked parent, for example "parent REG-03 failed for node pool sgxpool1".
- **A skipped parent also skips its children,** and the child's reason includes the parent's reason. A result with status `warn` or `info` doesn't block children.
- **How severity shapes status.**
  - For a warning-severity check, the engine turns a `fail` into `warn`.
  - For an info-severity check, the engine turns any result that isn't skipped into `info`.
  - BAK-01 and BAK-02 drop to warning severity when `storage.environment` is `poc`.
- **A check that times out fails** (it reports warn if its severity is warning). The evidence says "check did not finish within 10s". A check that couldn't finish is never reported as passing or silently skipped.
- **Preflight bugs exit 3.** This covers a check that panics or returns malformed results, such as no evidence or a scope that doesn't match the catalog. The affected check is reported as skipped ("Preflight internal error"), the other results are still printed, and the run exits 3 because it can't be trusted.
- **Unimplemented checks exit 3.** Until every catalog check is implemented, a run prints `Result: INCOMPLETE`, lists the missing checks and exits 3, so a partial build never reports READY.
- **Interrupts.** Ctrl-C or SIGTERM stops the run between dependency levels and exits 3. Probe cleanup on interrupt comes with M4.
- **SGX node pool size.** The brief says "DC8_v3", which isn't an exact Azure SKU name (the family is DCsv3/DCdsv3, for example `Standard_DC8s_v3`). The catalog keeps the brief's wording, and K8S-03 in M3 will match on the DCsv3 family and size rather than an exact string. This needs confirming with Fortanix.
- **cert-manager supported versions** are `TBD` in the catalog. K8S-08 will check that cert-manager is installed and has a ready ClusterIssuer, and will name the missing version range until Fortanix supplies one.

## M2

- **`result.json` schema.** `schema/result.v1.json` (JSON Schema 2020-12) is the contract for Support tooling. A test validates every run's JSON against it, and another checks that the schema rejects broken records.
  - Within version 1, fields may be added but not removed or renamed, and consumers should ignore fields they don't know. Any removal or rename bumps `schemaVersion`.
  - Version 1 adds three fields to the brief's outline: `unimplemented`, `internalErrors`, and a verdict value `INCOMPLETE` for runs that exit 3.
- **Result scope in JSON.** The scope is an object with exactly one key: `{"cluster": true}`, `{"nodePool": "..."}` or `{"node": "..."}`. This matches the brief's `{"nodePool": "sgxpool1"}` example.
- **Report links.** `report.html` has no scripts, stylesheets, images, fonts or `url()`, so opening it loads nothing. Doc links are plain `<a href>` links to support.fortanix.com. They load nothing until clicked, and a test fails on any other link.
- **What each team section shows.** Each team section lists that team's failed and warned results, then the checks that weren't run for that team, with the reason. An appendix lists every result, the probes that ran and the permissions used.
- **Firewall CSV rows.** A row is written only for failed TCP or TLS stages, because a DNS or HTTP failure doesn't need a firewall rule. One row per (node pool, destination, port).
  - When NET-02 and a more specific check report the same path, the row names the specific check (for example CC-03 for PCCS), as in the brief's example.
  - The header row is always written, even with no failures.
  - Source subnet comes from `nodePools.<pool>.subnet`. Without it, the node IPs are listed as /32s. Without those, the cell says `UNKNOWN (node pool X; set nodePools.X.subnet)`, which a network engineer can't mistake for a real subnet.
- **Terminal output has no colour.** The output is often pasted into tickets, and plain text survives that.
- **How secrets are masked.** Every secret the settings name is masked everywhere: stdout, error messages, all three output files and the bundle. Each secret is also masked in its base64 and URL-encoded forms, and as `username:password`, which is how it appears in docker auth strings.
  - Secrets are masked however short they are. A very short secret masks some ordinary text too, but the alternative risks a leak.
  - `TestSeededSecretsNeverAppear` has fake checks leak canary secrets in several encodings, including through a panic, and fails the build if any form appears anywhere. With masking switched off, the test reports 21 leaks, so it would catch one.
- **What the bundle contains.** `bundle.tgz` holds `result.json`, `versions.json` (tool, catalog, target, run ID, mode, start time, duration, verdict, probes) and `MANIFEST.txt` with SHA-256 hashes. It contains no logs, no HTML report and no settings file.
  - `bundle` masks secrets again. With `-f`, it also masks the secrets the settings file names.
  - It refuses to write the bundle if the content looks like a private key or a docker `auths` block.
- **How the bundle is confirmed.** `bundle` lists the contents first, then asks before writing. `--list` only lists, and `--yes` skips the question.
  - Answering no exits 0.
  - With no answer (a non-interactive run without `--yes`), it exits 3, so a script can't assume the bundle was written.
- **File writes are atomic** (a temp file, then rename), so an interrupted run never leaves a half-written report.
- **An incomplete run still writes its outputs.** A run that exits 3 because of unimplemented checks or internal errors still writes all three files with verdict `INCOMPLETE`. A refused run (settings rejected, or the Armor version isn't covered) writes nothing.

## M3

- **Kubernetes access.** Preflight uses `client-go` for core resources and the dynamic client for CRDs and ClusterIssuers, so it needs no apiextensions client dependency. Every request passes through `kube.Guard`, an HTTP round-tripper that refuses writes before they leave the process.
  - Workstation mode allows only GET, plus POST to SelfSubjectAccessReview and SelfSubjectRulesReview (D-1).
  - `RunNamespace` mode (used from M4) also allows writes to the run namespace and to objects inside it.
- **Proof of zero writes.** Three layers check it:
  - Unit tests on the guard.
  - A fake-clientset test showing no write actions in workstation mode.
  - `scripts/audit-lab.sh`, a CI job that runs the real binary against a real kube-apiserver 1.34 (from envtest) with audit logging on. The Preflight identity is bound only to `deploy/rbac/workstation.yaml`. The script fails on any write in the audit log, or any forbidden request.
- **A kubeconfig or API problem fails WS-01, not the run.** If the kubeconfig can't be loaded or the API server doesn't answer, WS-01 fails with the reason and every Kubernetes check is skipped, naming WS-01. The run doesn't exit 3 for this, because it's the customer's problem to fix and it belongs in the report.
- **Node size is compared on reported capacity,** not by looking up SKU names. A node passes when its vCPU count is at least the minimum and its memory is at least `memoryTolerance` (0.9) times the minimum; kubelet reports slightly less memory than the VM size. The minimums are:
  - System pool (Standard_D4d_v5): 4 vCPU, 16 GiB.
  - SGX pool (DC8s_v3): 8 vCPU, 64 GiB.
  - SGX nodes must also match the DCsv3/DCdsv3 family (`Standard_DC<n>[d]s_v3`), because a non-SGX VM of the same size won't do.
- **How pools are identified.** Pools come from `kubernetes.azure.com/agentpool`, falling back to the instance type.
  - A pool is an SGX pool if any node in it has the SGX size family, advertises `sgx.intel.com/*` resources, or carries the NFD SGX label.
  - The system pool is identified by `kubernetes.azure.com/mode=system`. On clusters without that label, every non-SGX pool counts as a system pool.
- **Unsupported profile (D-8).** When no node has AKS labels or an `azure://` provider ID, K8S-02 and K8S-03 add "unsupported profile" evidence and report warn instead of pass.
- **K8S-07 (ingress controller).** Well-known controllers are matched by their pod labels: ingress-nginx, Application Gateway, AKS app routing and Traefik. For any other controller, a Ready pod with "ingress" in its app label counts.
- **K8S-08 (cert-manager).** The version comes from the controller image tag. While `certManagerVersions` is TBD, K8S-08 reports warn ("version unverified") rather than pass.
- **K8S-09 checks whoever runs Preflight.** SelfSubjectAccessReview can only check the caller. To check the installer, run Preflight with the installer's credentials; the evidence says so. `--as` impersonation isn't implemented, because it would need the `impersonate` verb (D-12).
- **K8S-12 CIDRs.** Pod CIDRs come from `node.spec.podCIDRs`, and service CIDRs from `ServiceCIDR` objects (GA in 1.33). With Azure CNI without overlay, nodes report no pod CIDR, so K8S-12 says to record the node subnets instead.
- **NET-04 (proxy).** Uses the settings file's proxy if set, otherwise the workstation's `HTTPS_PROXY`/`NO_PROXY`. A CIDR in NO_PROXY covers a subnet it contains. A domain entry covers the domain itself and its subdomains, with or without a leading dot. It warns if the settings file and the workstation environment name different proxies. Node runtime proxy config isn't read (D-13).
- **REG-01 (registry login).** Authenticates to `registry.url` over the Docker Registry v2 API, answering either a bearer-token or a basic-auth challenge, and requires `GET /v2/` to return 200. No layers are pulled. In mirror mode it checks the mirror credentials. The workstation's proxy environment is used.
- **REG-02 and REG-04 (mirror contents).** The chart is checked by a HEAD request for its manifest at `<operatorChartRef>:<armorVersion>`. REG-04 checks each release image by digest in the mirror, assuming the mirror keeps the same repository paths.
  - REG-04 writes `image-overrides.yaml` (a list of `original` and `image` pairs) to the output directory. It's a generic format until the ArmorPlatform schema is available (Phase 2, R2.2).
- **REG-05 (pull secrets).** Reads `kubernetes.io/dockerconfigjson` secrets in each namespace listed in `armorNamespaces`, and looks only at which registry hosts they cover.
  - An expiry is only read from an annotation named `expires`, `expiry`, `expiration`, `expires-at` or `valid-until` (any prefix, RFC 3339 or YYYY-MM-DD). Without one it reports info.
  - Listing secrets is sensitive, so the permission is a namespace-scoped Role, not part of the ClusterRole.
- **PKI-02 (certificate chain).** With `certificates.sampleApiCertPath` set, the PEM file must contain the leaf, at least one intermediate and a self-signed root CA, each signed by the next. The leaf must be currently valid and usable for TLS server authentication.
- **PKI-03 (API SANs).** Reads the planned SANs from `certificates.plannedApiSans`, or else from the sample certificate. With neither, it's skipped with that reason, rather than failed.
- **TLS in one place (D-20).** `internal/tlsutil` builds every outbound TLS configuration (TLS 1.2 minimum). Redirects to plain HTTP aren't followed.

## M4

- **How cluster mode runs.**
  1. The CLI creates `armor-preflight-<run id>`, labelled `app.kubernetes.io/managed-by=armor-preflight` and `armor-preflight/run-id`, and set to enforce the Pod Security Standards `restricted` profile. The API server itself therefore rejects any probe pod that would break the profile.
  2. It runs one probe pod per node pool, then runs the checks.
  3. It deletes the namespace on every exit path: normal exit, error or interrupt. A deferred cleanup with its own 2-minute deadline handles this.
  4. A killed process leaves objects behind, and `armor-preflight cleanup` removes them.
- **Probe pods are bare Pods, not Jobs,** so Preflight needs no batch RBAC. Each pod is pinned with a nodeSelector on the pool label, falling back to the instance type and then the hostname. It tolerates every taint its pool's nodes carry, has `activeDeadlineSeconds: 300`, and doesn't restart.
  - Each pod runs as 65532 with a read-only root filesystem, all capabilities dropped, no privilege escalation and RuntimeDefault seccomp.
  - It has no service-account token, no host namespaces and no service links.
  - A unit test runs the pod spec through the official `k8s.io/pod-security-admission` restricted checks.
  - The probe request goes in through a ConfigMap. Credentials go through a Secret (D-3), which is only created from M5 on, once probe checks need it.
- **Per-SGX-node probe pods** (requesting `sgx.intel.com/*`) are deferred to M6, together with the SGX probe image (D-5). M4 runs one probe per pool.
- **Probe protocol.** The probe prints one line, `ARMOR-PREFLIGHT-RESULT <json>`, carrying a protocol version. The CLI reads the last such line from the pod log. It rejects a result from another run ID, and rejects a different protocol version with "use the probe image built with this release".
- **Probe failures.** An image pull failure (ErrImagePull, ImagePullBackOff, InvalidImageName) is recorded per pool. If no pool could pull the image, every probe check is skipped, naming the image to mirror. Workstation checks still complete (R1.5).
  - An unschedulable pool is recorded with the scheduler's message. So is a pool whose probe doesn't finish within `--probe-timeout` (default 3 minutes).
- **Choosing the probe image.** `--probe-image` wins. Otherwise Preflight uses the release default stamped in with `-ldflags` (`buildinfo.ProbeImage`, pinned by digest at release), and then the catalog value, which is TBD. Without an image, probe checks are skipped ("no probe image is configured"), while K8S-10 and K8S-11 still run.
- **Test objects are named by role:** `storage-test`, `storage-test-consumer`, `loadbalancer-test`, `probe-<pool>` and `request-<pool>`. Pool names are sanitised to DNS-1123, with a short hash added when sanitising changed the name, so two pools never collide.
- **K8S-10 (storage).** Uses the default StorageClass, or `storageClass` from the settings file. It creates a 1 GiB ReadWriteOnce claim and waits up to `volumeBindTimeoutSeconds` (90s) for it to bind.
  - With WaitForFirstConsumer binding, it creates a restricted pod that mounts the claim, using the probe image.
  - A reclaim policy of Delete gives a warning. The check fails with the newest Warning event when the claim never binds.
  - Retained volumes claimed from the run namespace are deleted at cleanup.
- **K8S-11 (load balancer).** The test Service has no selector, so it never routes traffic, and carries `service.beta.kubernetes.io/azure-load-balancer-internal: "true"` so no public IP is allocated. A consequence: if Armor needs a public load balancer, this test won't catch a missing public-IP quota.
- **Per-check timeouts.** A catalog `timeoutSeconds` value overrides `-t` for checks that wait on the cluster; K8S-10 and K8S-11 use 120 seconds.
- **RBAC for cluster mode (D-2).** `deploy/rbac/cluster.yaml` has two parts:
  - A ClusterRole granting create and delete on namespaces, pods, configmaps, secrets, persistentvolumeclaims and services; get on pods/log; list on events and storage classes; list and delete on persistentvolumes.
  - A ValidatingAdmissionPolicy that denies the Preflight identity any of those writes unless the target is an `armor-preflight-*` namespace carrying the managed-by label, an object inside one, or a volume claimed from one.
  - The policy matches members of the group `armor-preflight`, or the service account `armor-preflight/armor-preflight`. Customers edit that expression to name their own identity.
  - A Go test fails if any shipped role grants a write verb outside that list, or uses a wildcard.
- **The write guard in cluster and cleanup modes.**
  - Cluster mode allows writes to the run namespace, to objects inside it, to namespace creation, and to persistentvolume deletes.
  - `cleanup` only allows deleting `armor-preflight-*` namespaces and persistent volumes. It deletes a namespace only if it has both the managed-by label and the name prefix. It deletes a volume only if its claim was in such a namespace.
- **Proof in the audit lab.** `scripts/audit-lab.sh` now also runs cluster mode against the real API server, with a simulator standing in for the volume binder, cloud load balancer and namespace controller. It checks all of the following:
  - Every write stays in the run namespace.
  - Probe pods are admitted under restricted enforcement.
  - The admission policy denies writes elsewhere, including ones RBAC alone would allow.
  - Nothing is left after a normal exit, after SIGINT, or after SIGKILL followed by `cleanup`.
  - Probe pods are never scheduled in envtest, so probe results are covered by unit tests. A real cluster run is a manual test.
- **Probe image.** The Dockerfile is `deploy/probe/Dockerfile`: a static Go build on `gcr.io/distroless/static:nonroot`, user 65532. The runtime image is about 1.8 MB. CI builds it and runs it with a read-only filesystem, all capabilities dropped, no-new-privileges and no network. Signing and the image tarball come with M7.

## M5

- **Staged network test (`internal/probe/nettest`).** Each endpoint is tested DNS, then TCP, then TLS, then HTTP, and each stage is recorded separately. Testing stops at the first failed stage. TCP-only endpoints (syslog) get DNS and TCP only.
  - Through a proxy, DNS is left to the proxy (recorded as such), and TCP means a successful `CONNECT`.
  - `NO_PROXY` supports hosts, domain suffixes and CIDRs.
  - A timeout names the per-stage limit.
- **TLS handshake versus trust.** The handshake is completed without verification, then the presented chain is verified explicitly: against the public roots in the probe image, and separately against the customer CA from `proxy.trustedCaPath`.
  - The TLS stage is OK when the handshake completes. NET-02 therefore measures reachability, and NET-03 measures trust.
  - Nothing is sent over a connection whose chain isn't trusted. The HTTP stage reports "not sent".
- **D-7, NET-03, changed from the plan.** Instead of pinning expected issuers per endpoint, which would be brittle and would need values Fortanix hasn't published, a chain must verify against the public roots in the distroless image. Otherwise the endpoint fails with its presented issuer and chain. A chain that verifies only against `proxy.trustedCaPath` passes, reported as "intercepted, CA trusted".
  - Checked live: the probe image, run against real endpoints through this development environment's TLS-inspecting proxy, reported each endpoint as not trusted and named the inspecting CA.
- **D-6, HTTP paths.** Each endpoint's `httpPath` lives in the catalog: registry `/v2/`, Azure Attestation `/.well-known/openid-configuration`, and `/` for the others. Any HTTP response over trusted TLS counts as reachable, and the status code is recorded. The paths must be confirmed against the live services before release.
- **Every endpoint is tested from every node pool,** as the brief's endpoint table says. NET-02 reports all of them per pool. CC-03 and CC-04 report the same observations for SGX pools only.
- **CC-04 without an attestation host.** When `attestation.azureAttestationHost` isn't set, CC-04 tests the Intel endpoint only, and reports warn instead of pass, with the missing setting in the evidence. It is never a silent pass.
- **NET-07 (clock).** Clock skew is measured against the median `Date` header of the HTTP responses from endpoints already under test (D-14), not NTP. With no HTTP responses, NET-07 is skipped for that pool. Date headers have 1-second resolution, which is enough for the 5-second threshold.
- **REG-03 (image resolution).** Images come from `registry.releaseManifestPath`, or else the operator chart (still TBD). Each is rewritten to `registry.url`, the registry nodes actually pull from, so direct and mirror mode behave the same. Each is resolved with a manifest HEAD using the registry credentials. No layers are pulled.
- **BAK-02 (backup storage).** Each pool writes, reads back and deletes `armor-preflight-<run id>-<pool>.txt` in the backup container.
  - The credential can be the storage account key (Shared Key signing, service version 2021-08-06) or a SAS token; one containing `sig=` is treated as SAS.
  - A failed delete says to remove the blob by hand.
  - The client is tested against a local fake that checks Shared Key signatures independently. A run against real Azure Storage is a manual test.
- **Credentials in probes (D-3).** The registry password and storage credential go into a Secret in the run namespace, mounted read-only at `/var/run/armor-preflight`. The Secret is created only when REG-03 or BAK-02 needs it.
  - The request ConfigMap never carries a credential; a test checks this.
  - The probe never prints one; also tested.
  - The audit lab confirms the Secret is created only in the run namespace.
- **Registry and mirror URLs may include a port** (`host:5000`). Endpoint resolution splits it, instead of appending 443.
- **How the probe checks are tested.** The tests run the real probe agent once per node pool, each against its own fake network (`internal/netfixtures`: a test CA, TLS servers standing in for the real endpoints, a CONNECT proxy, a TLS-intercepting proxy, a blob store, and a dialer that can blackhole or refuse). The results then go through the real checks. Covered this way:
  - The registry blocked from the SGX pool only: NET-02 fails for that pool, names it, and gives one firewall row.
  - Interception with and without a trusted CA.
  - DNS failure skipping NET-02 on that pool only.
  - Refused syslog, a blocked PCCS, refused attestation, a missing image, denied blob access, 8 seconds of clock skew, and a pool whose probe image couldn't be pulled.

## M6

- **CC-05 sits behind `internal/probe/sgx.Provider`** (`Quote` and `Verify`). The standard probe image uses `Unsupported`, which reports that it can't generate quotes. An SGX probe image built with the toolchain Fortanix chooses supplies a real provider (D-5). The image contract is in `docs/sgx-probe.md`. No enclave code is included, because the toolchain isn't decided and there's no SGX hardware to test on here.
- **Per-node SGX probes.** With `--sgx-probe-image`, cluster mode runs one pod on each SGX node, pinned by hostname, tolerating the node's taints, and requesting and limiting `sgx.intel.com/enclave` and `sgx.intel.com/provision`. The pod keeps every restricted Pod Security setting; the device plugin mounts the devices, so no privileges are needed, and a unit test checks this. Without `--sgx-probe-image`, CC-05 is skipped with the reason.
- **Replay protection.** Each node's request carries a fresh 32-byte random nonce. The quote's report data must start with it, which catches a replayed or cached quote.
- **How CC-05 treats TCB status.**
  - `UpToDate` passes.
  - The three "configuration or software hardening needed" statuses warn, listing advisories, because whether Armor accepts them depends on its attestation policy. This needs confirming with Fortanix.
  - `OutOfDate`, `OutOfDateConfigurationNeeded`, `Revoked` and unknown statuses fail.
- **CC-05 results are per node.** A node-level parent failure (CC-01, CC-02) or a pool-level one (CC-03, CC-04, REG-03 for the node's pool) skips CC-05 for that node, naming the parent. The test fixtures now set the node-to-pool map the way the CLI does, so pool-to-node skipping is covered.
- **All 35 checks are implemented.** A test fails the build if the catalog and the registry of implemented checks ever differ, in either direction. A run now always reaches READY, READY WITH WARNINGS or NOT READY, unless Preflight itself hits an internal error.

## M7

**Toolchain and dependencies**

- **Go 1.26.8.** `govulncheck` found vulnerabilities reachable from Preflight in the Go 1.24.7 standard library. Go 1.25 would fix them, but it's out of support now that Go 1.27 has shipped: Go only patches its two newest major releases. So `go.mod` requires Go 1.26.8, the newest 1.26 patch. The probe image builds with `golang:1.26.8`, pinned by digest.
- **Libraries:** `golang.org/x/net` v0.59.0 and `golang.org/x/text` v0.42.0, the current releases, which fix the advisories `govulncheck` reported.
- **Analysis tools:** staticcheck moves to 2026.2.1 (v0.8.1), which supports Go 1.26, and govulncheck to v1.8.0.
- **`govulncheck` blocks merges.** A new advisory can turn CI red with no code change. That's intended: the fix is to upgrade, not to suppress the finding.

**Release**

- **Pipeline.** `scripts/release.sh` builds the probe image, then the binaries with that image's digest as their default, then signs `checksums.txt`. The same script makes CI's snapshot and the real release, so CI tests the release path on every change.
- **One probe image archive.** The image is built once, for both platforms, as an OCI archive. That archive is pushed with `crane` and also published for mirrors, so a mirror holds exactly the digest the binary pins and the release signed. Per-platform `docker save` tarballs were rejected: they can't be pushed without changing the digest.
- **Reproducible probe image.**
  - Timestamps come from the commit time (`SOURCE_DATE_EPOCH`, with layer timestamps rewritten).
  - No buildkit attestations: their provenance differs on every build, which changed the index digest. Provenance comes instead from the keyless certificate, which names the workflow and commit, and from the reproducible digest itself.
  - Tested by building from a cold cache: the digest was identical.
- **One signature covers the whole release.**
  - `checksums.txt` lists every archive, SBOM, the image archive and `probe-image.txt`; one cosign signature over it covers them all. The image is also signed by digest in its registry.
  - The signature is a Sigstore bundle (`checksums.txt.sigstore.json`), so it can be verified offline.
  - `scripts/verify-release.sh` fails on any downloaded file that `checksums.txt` doesn't list. `sha256sum --ignore-missing` would pass such a file silently.
- **Signing identity (Fortanix to decide).** `scripts/sign.sh` supports both options without changes:
  - A key, in a KMS or a file, with the public key published on the support portal. Air-gapped customers can then verify with nothing but that file.
  - Keyless, signed by the release workflow's GitHub identity, which needs no key management.

  The release workflow uses a key when the `COSIGN_KEY` secret is set, and signs keyless otherwise.
- **Snapshot signing stays offline.** CI signs with a throwaway key and writes nothing to the public transparency log. Releases always use the log.
- **Draft releases only.** The release workflow creates a draft GitHub release; a person publishes it and uploads it to the support portal. The probe image is pushed when the tag is built, because the binaries embed its digest. A new GitHub package is private until someone makes it public once.
- **Tags carry a prefix,** `armor-preflight/vX.Y.Z`, because this repository holds other projects. goreleaser can't parse that, so `release.sh` passes the version in and skips goreleaser's tag checks.
- **Pinned by digest or commit:**
  - base images, and the BuildKit image the release builder uses;
  - the registry image used in CI;
  - every GitHub Action.

  Tool versions (cosign, syft, goreleaser, crane) are pinned by version.
- **macOS binaries aren't notarised.** Files fetched with `curl` aren't quarantined, so they run. Apple notarisation needs a Fortanix Apple Developer ID and can be added to the release when Fortanix has one.

**Acceptance**

- **`version` prints the release's probe image,** so the digest to mirror is one command away, before any cluster run.
- **The final audit found two gaps in the evidence and closed them with tests:**
  - `TestClusterRunImagePullFailure` proves R1.5: after a pull failure, every workstation check completes with the same result as a workstation run. The existing test only covered a missing `--probe-image` flag.
  - `TestWorkstationEgressIsOnlyTheEndpointsUnderTest` is the automated half of R1.4's packet capture. It runs every real check through a recording network.
- **The CLI test cluster gains a dynamic client.** Without one, K8S-05 and K8S-08 panicked in CLI tests. The real client always has one, so this was a test gap, not a product bug.
- **[ACCEPTANCE.md](ACCEPTANCE.md)** lists every criterion with its evidence. It separates what CI proves from what needs a manual run or a Fortanix decision.
