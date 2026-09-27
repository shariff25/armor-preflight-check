# armor-preflight

`armor-preflight` checks whether a customer environment is ready for a Fortanix Armor on-prem install, before anyone starts the install. It checks every prerequisite from where Armor will actually run and tells each customer team what it needs to fix.

For how it works inside (the run flow, the check catalog and its dependency graph, engine rules, probes, CC-05,
outputs and the security model), see **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

![armor-preflight architecture overview](docs/architecture.svg)

> **Status: Phase 1 complete (milestone M7).**
> - All 35 checks are implemented.
> - Releases are signed, with checksums, SBOMs and a probe image archive for mirrors.
> - [ACCEPTANCE.md](ACCEPTANCE.md) maps every acceptance criterion to its evidence, and lists what still needs a manual run or a Fortanix decision.
> - For security teams: [SECURITY-BRIEF.md](SECURITY-BRIEF.md) (one page) and [SECURITY-REVIEW.md](SECURITY-REVIEW.md) (the full review).
>
> CC-05 (SGX quote generation) needs an SGX probe image built with the enclave toolchain Fortanix chooses. Pass it with `--sgx-probe-image`; [docs/sgx-probe.md](docs/sgx-probe.md) has the contract that image must meet. Without it, CC-05 is skipped with that reason.

## Commands

| Command | What it does |
|---|---|
| `armor-preflight run workstation` | Runs every check that doesn't need probe pods. Makes no changes to the cluster. |
| `armor-preflight run cluster` | Runs the workstation checks, then probe pods on each node pool. |
| `armor-preflight bundle` | Packages the latest run into a redacted archive for a support ticket. `--list` shows the contents without writing it. |
| `armor-preflight cleanup` | Deletes leftover Preflight objects, found by label. `--run-id` limits it to one run. |
| `armor-preflight version` | Prints the Preflight version, catalog version, supported Armor versions and the release's probe image (the digest to mirror). |

`run cluster` also takes:
- `--probe-image`: the probe image, preferably pinned by digest. A release build defaults to its own signed image; see `armor-preflight version`.
- `--sgx-probe-image`: the SGX probe image for CC-05 (see [docs/sgx-probe.md](docs/sgx-probe.md)).
- `--probe-timeout`: how long to wait for probes (default 3 minutes).

| Flag | Meaning | Default |
|---|---|---|
| `-f`, `--settings` | Settings file | none; settings-dependent checks are skipped |
| `-k`, `--kubeconfig` | kubeconfig path | `$KUBECONFIG` or `~/.kube/config` |
| `-c`, `--context` | kube context | current context |
| `-o`, `--output` | Output directory | `./preflight-out` |
| `-t`, `--timeout` | Per-check timeout | `10s` |

## Settings file

The settings file holds the decisions only the customer can make: the target Armor version, domains, registry mode, backup storage, proxy and syslog. See [`examples/settings.example.yaml`](examples/settings.example.yaml). Without it, Preflight still runs and reports the checks that need those values as skipped, naming the missing setting.

Secrets never go in the file. It names environment variables instead (`registry.passwordEnv`, `storage.credentialsEnv`), and a file that contains a secret-looking key is rejected.

If `armorVersion` isn't covered by this build's catalog, Preflight refuses to run and says which Preflight release to use.

## How checks run

The catalog ([`internal/catalog/catalog.yaml`](internal/catalog/catalog.yaml)) defines every check: its severity, owning team, dependencies, remediation text and doc link. The engine runs checks in dependency order, with a per-check timeout (`-t`, default 10s).

- If a parent check fails, its dependents report skipped and name the parent. This is per node pool: a failure on one pool doesn't hide results for another.
- A violated warning-severity check reports warn.
- A check that times out fails, rather than passing or being skipped.

## Outputs

Each run writes these files to the output directory (`-o`, default `./preflight-out`) and prints a summary:

| File | What it is |
|---|---|
| terminal summary | The verdict, counts per area, each failure with its owning team and fix, and what wasn't checked and why. |
| `report.html` | Self-contained report that opens offline and loads nothing. It opens with the verdict and counts by severity, then has one section per owning team (each prints on its own page), then every result, the probes that ran and the permissions used. |
| `result.json` | Machine-readable result, [schema version 1](schema/result.v1.json). |
| `firewall-request.csv` | One row per failed egress path: `source_subnet,destination,port,protocol,direction,purpose,check_id`. Set `nodePools.<pool>.subnet` in the settings file so the source column holds real subnets. |

`armor-preflight bundle` packages the latest run for a support ticket as `bundle.tgz`: `result.json`, `versions.json` (Preflight, catalog, Armor and Kubernetes versions, context, run ID and time) and a SHA-256 manifest. It lists the contents and asks before writing. Use `--list` to only look, or `--yes` to skip the question.

Secrets the settings file names are masked in everything Preflight prints or writes, including their base64 and URL-encoded forms.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | READY |
| 1 | READY WITH WARNINGS |
| 2 | NOT READY (at least one blocker failed) |
| 3 | Preflight itself failed to run |

## Cluster mode

`run cluster` runs everything workstation mode does, plus the checks that need to act inside the cluster. It creates a temporary namespace, `armor-preflight-<run id>`, which enforces the restricted Pod Security Standards. In that namespace it:

- starts one probe pod per node pool, pinned by node selector and tolerating the pool's taints;
- creates a 1 GiB test volume (K8S-10);
- creates an internal LoadBalancer Service with no selector (K8S-11).

Everything Preflight creates is labelled `app.kubernetes.io/managed-by=armor-preflight` and `armor-preflight/run-id=<run id>`. The namespace is deleted when the run ends, including after Ctrl-C. If the process is killed, `armor-preflight cleanup` removes whatever is left.

Each probe tests every required endpoint from its node pool, one stage at a time: DNS, TCP, TLS, then an HTTP request, sent only once the certificate is trusted. It reports each stage separately. So a blocked firewall path, a missing DNS record and an untrusted TLS-inspecting proxy each show up as exactly that, for the node pool concerned.

Probes also check two things that need credentials:
- that every release image resolves by digest from the pool (REG-03);
- that the backup credentials can write, read and delete a test blob (BAK-02).

Those credentials reach the probe through a Secret in the temporary namespace, which is deleted with it. They never appear in any output.

The probe image ([`deploy/probe/Dockerfile`](deploy/probe/Dockerfile), `make probe-image`) is a static binary of about 1.8 MB on distroless. It runs as a non-root user with a read-only root filesystem and every capability dropped. It needs no Kubernetes API access. If the nodes can't pull it, Preflight names the image to mirror and still finishes every workstation check.

### Mirroring the probe image

Each release publishes the image as `armor-preflight-probe_<version>_oci.tar`, an OCI archive holding both platforms. Pushing it keeps its digest, so the image in your registry is exactly the one the release signed.

1. Verify the release (see [Verifying a release](#verifying-a-release)).
2. Push the archive to your registry, for example with [crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane):

   ```
   mkdir probe && tar -xf armor-preflight-probe_<version>_oci.tar -C probe
   crane push probe registry.example.com/armor-preflight-probe:<version>
   ```

3. Run with `--probe-image registry.example.com/armor-preflight-probe@<digest>`, where the digest is the one in `probe-image.txt`.

`docker load -i` also accepts the archive, on Docker with the containerd image store.

## Permissions

`run workstation` only reads from the cluster. [`deploy/rbac/workstation.yaml`](deploy/rbac/workstation.yaml) is the least-privilege role it needs:
- A read-only ClusterRole.
- A Role for listing image pull secrets in each Armor namespace (REG-05).
- SelfSubjectAccessReviews, which every user may create and the API server doesn't store.

K8S-09 checks the permissions of whoever runs Preflight. Run it with the installer's credentials to check the installer.

`run cluster` and `cleanup` also need [`deploy/rbac/cluster.yaml`](deploy/rbac/cluster.yaml). It adds the write permissions for Preflight's own objects, plus a ValidatingAdmissionPolicy (Kubernetes 1.30 or later) that confines those writes to `armor-preflight-*` namespaces and the volumes claimed from them. Edit the policy's `matchConditions` to name the identity that runs Preflight.

`scripts/audit-lab.sh` proves this. It starts a real kube-apiserver with audit logging, seeds an AKS-like cluster, and runs Preflight as an identity bound only to that role. It then fails if the audit log shows any write, or any forbidden request.

In cluster mode, the lab also checks that:
- every write stays inside the run namespace;
- probe pods pass the API server's restricted admission;
- the admission policy denies writes anywhere else;
- nothing is left after a normal exit, after an interrupt, or after a killed run followed by `cleanup`.

CI runs the lab on every change.

## Verifying a release

Each release ships:
- the two Linux binary archives (amd64, arm64), each with an SPDX SBOM;
- the probe image archive and an SBOM for each of its platforms;
- `probe-image.txt`, the signed image's reference;
- `checksums.txt`, which lists every other file;
- `checksums.txt.sigstore.json`, the cosign signature over `checksums.txt`.

The probe image is also signed in its registry.

Download the files you need into one directory, with `checksums.txt` and its signature, and run [`scripts/verify-release.sh`](scripts/verify-release.sh) (needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/), and jq for the image archive). It checks:
1. the signature on `checksums.txt`;
2. that every file you downloaded is listed there and matches;
3. that the image archive is the image `probe-image.txt` names;
4. that image's signature in its registry. Set `SKIP_REGISTRY=1` if the registry isn't reachable; step 3 already ties the archive to the signed checksums.

Say who must have signed, one of:

```
COSIGN_PUBLIC_KEY=cosign.pub scripts/verify-release.sh ./downloads
```

```
CERT_IDENTITY='^https://github\.com/shariff25/armor-preflight-check/\.github/workflows/armor-preflight-release\.yml@refs/tags/v' \
CERT_OIDC_ISSUER=https://token.actions.githubusercontent.com \
  scripts/verify-release.sh ./downloads
```

The first is for a release signed with a key; use the public key Fortanix publishes. The second is for a keyless release, signed by the release workflow.

## Building

Requires Go 1.26.8 or later. Go supports only its two newest major releases, and this is the oldest supported release without known vulnerabilities that affect this code.

```
make build    # bin/armor-preflight
make test
make lint     # gofmt + go vet
make cross    # static Linux binaries for amd64 and arm64
```

Releases come from [`scripts/release.sh`](scripts/release.sh), run by the release workflow when a tag `vX.Y.Z` is pushed. It:
1. builds the probe image for linux/amd64 and linux/arm64 as one OCI archive;
2. pushes the archive and signs its digest;
3. builds the binaries with that digest as their default probe image, plus archives, SBOMs and `checksums.txt` (goreleaser);
4. signs `checksums.txt`.

The workflow then verifies the result and drafts a GitHub release for a person to publish. Rebuilding a commit gives the same probe image digest.

To build a signed release of any commit locally, you need:
- docker buildx;
- crane, syft, cosign and goreleaser;
- a registry to push to.

For example, with a throwaway key and a local registry:

```
docker run -d -p 5000:5000 registry:3
cosign generate-key-pair
COSIGN_KEY=cosign.key SIGN_OFFLINE=1 PROBE_REPOSITORY=localhost:5000/armor-preflight-probe \
  VERSION=0.0.0-dev make release-snapshot     # writes build/release
```

CI does exactly this on every change (job `release-snapshot`), then verifies the result.

## Manual tests

These criteria need a real SGX cluster, real cloud services or people, so they're tested by hand.

| Criterion | How |
|---|---|
| R1.1 A reference AKS cluster that meets every prerequisite returns READY | Run `run cluster` with both probe images on a compliant AKS cluster with an SGX pool. Expect exit 0 and zero fail results. |
| R1.2 CC-05 generates and verifies a quote on every SGX node | Follow [docs/sgx-probe.md](docs/sgx-probe.md), section "Manual test". |
| R1.2 Probe network checks on a real cluster | Block `cr.download.fortanix.com` for the SGX pool's subnet only (NSG rule), then run. Expect NET-02 to fail for that pool only, with a matching firewall CSV row. |
| R1.3 Usability of the firewall CSV | Give three network engineers who are new to Armor the CSV from a run with blocked paths. Each should identify every required rule from the CSV alone. |
| R1.4 Packet capture | Capture on the workstation and a node during a full run. Outbound connections should go only to the endpoints in the catalog, the registry and the storage account. |
| R1.4 Security brief approval | Fortanix Security reviews the security brief (M7). |
| R1.6 Timing on 10 nodes | Time `run cluster` on a 10-node cluster. It should finish in under 5 minutes. |
| BAK-02 against real Azure Storage | Run with a real storage account key, then with a SAS token. Expect the test blob to be written, read and deleted, and no blob left in the container. |
