# armor-preflight: security brief

`armor-preflight` checks that your environment meets the prerequisites for a Fortanix Armor on-prem install. It runs from an operator's workstation against your Kubernetes cluster, reports what's missing and who needs to fix it, and changes nothing that it doesn't remove itself. This page is for the security team approving it. The full review is in [SECURITY-REVIEW.md](SECURITY-REVIEW.md).

**It never sends data to Fortanix or anyone else.** It has no telemetry, no update check and no licence call. Results stay in a local directory until you choose to share them.

## Two modes

| | `run workstation` | `run cluster` |
|---|---|---|
| Cluster writes | **None.** Only reads, plus access reviews that ask "may I…?" and store nothing. Proven against a real API server's audit log in CI. | Only in a temporary namespace it creates, `armor-preflight-<run id>`, which it deletes on exit. |
| Permissions | [`deploy/rbac/workstation.yaml`](deploy/rbac/workstation.yaml): read nodes, pods, namespaces, a few cluster-scoped types, and list image pull secrets in the Armor namespaces | [`deploy/rbac/cluster.yaml`](deploy/rbac/cluster.yaml): adds create and delete in its own namespace. A ValidatingAdmissionPolicy rejects its writes anywhere else. |

**Pull secrets.** Reading them returns their contents. Preflight only checks that one exists for your registry host and reads its expiry. It never writes a secret's contents anywhere.

## What runs in your cluster (cluster mode)

- **One probe pod per node pool, and one per SGX node.** It's a 2 MB static binary on distroless. It meets the Kubernetes restricted Pod Security Standard, which the namespace enforces:
  - runs as non-root (UID 65532) with a read-only root filesystem;
  - every Linux capability dropped, no privilege escalation, RuntimeDefault seccomp;
  - no service account token, so it has no Kubernetes API access;
  - limited to 200m CPU and 64 MiB of memory.
- **Supporting objects:** a ConfigMap with the probe's instructions, a test volume claim and Service, and a Secret, all in the temporary namespace.
  - The Secret holds only the registry password and storage credential, if you supplied them, so the probe can test them from the node.
  - Anyone who can read Secrets in that namespace can read them while the run lasts.
- **Cleanup:** everything carries a Preflight label. After a normal exit or Ctrl-C, Preflight deletes the namespace. After a killed process, `armor-preflight cleanup` removes whatever is left. It never deletes a namespace it didn't create.

## Network

Preflight connects only to:
- your Kubernetes API server;
- the endpoints under test: Fortanix's published endpoints, and the registry, storage, syslog and proxy you name in the settings file.

Probes test the same endpoints from inside each node pool. Every TLS connection is verified. A request is sent only over a connection that verifies, so a TLS-inspecting proxy is detected and reported, never trusted.

## Secrets

- **Not in the settings file.** It names environment variables instead, and Preflight rejects a file containing a secret-looking key.
- **Masked everywhere:** in the terminal, `result.json`, `report.html`, the CSV and the support bundle. That includes their encoded forms, and any credentials in proxy or kubeconfig URLs.
- **Tested on every build:** an automated test plants known secrets and fails the build if any appear in any output.

## Outputs

Four files go in `./preflight-out`: a JSON result, an offline HTML report (no scripts, no external loads, strict CSP), a firewall request CSV and a terminal summary. The directory is created 0750 and the files 0640.

`armor-preflight bundle` packages the result for Fortanix Support. It shows you the contents and asks before writing anything.

## Supply chain

- **Signed:** every release is signed with cosign.
  - A signed `checksums.txt` covers the binaries, the probe image archive and the SBOMs.
  - The probe image is also signed in its registry.
  - Verify a download with [`scripts/verify-release.sh`](scripts/verify-release.sh) before running it.
- **SBOMs:** an SPDX SBOM ships for each binary archive and each probe image platform.
- **Reproducible:**
  - Rebuilding a release commit gives the same probe image digest.
  - Base images are pinned by digest, and CI actions by commit.
- **Scanned:** every change is scanned for known vulnerabilities (`govulncheck`) and static-analysis findings (`staticcheck`).
- **Offline mirroring:** the probe image is also published as an archive for your own registry. If nodes can't pull it, Preflight names the exact digest to mirror and still completes every workstation check.

## Known limits

- **Probe results come from your nodes.** A compromised node could report a false result. Preflight bounds and sanitises probe output and never gives it credentials beyond the ones it tests, but it can't prove the output is honest.
- **Cluster administrators can read the probe Secret** while a cluster-mode run lasts.
