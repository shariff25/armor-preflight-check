# armor-preflight

`armor-preflight` checks whether a customer environment is ready for a Fortanix Armor on-prem install, before anyone starts the install. It checks every prerequisite from where Armor will actually run and tells each customer team what it needs to fix.

> **Status: milestone M3.** The catalog, engine, outputs and support bundle are in place, and the 23 checks that run from the workstation are implemented. The 12 cluster-mode and probe checks (K8S-10, K8S-11, CC-03 to CC-05, NET-01 to NET-03, NET-06, NET-07, REG-03, BAK-02) arrive in M4 to M6. Until then, `run` lists them as not implemented, writes its outputs with verdict `INCOMPLETE` and exits 3. `cleanup` exits 3 ("not implemented yet"). See [PLAN.md](PLAN.md) for the build order.

## Commands

| Command | What it does |
|---|---|
| `armor-preflight run workstation` | Runs every check that doesn't need probe pods. Makes no changes to the cluster. |
| `armor-preflight run cluster` | Runs the workstation checks, then probe pods on each node pool. |
| `armor-preflight bundle` | Packages the latest run into a redacted archive for a support ticket. `--list` shows the contents without writing it. |
| `armor-preflight cleanup` | Deletes leftover Preflight objects, found by label. `--run-id` limits it to one run. |
| `armor-preflight version` | Prints the Preflight version, catalog version and supported Armor versions. |

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

## Permissions

`run workstation` only reads from the cluster. [`deploy/rbac/workstation.yaml`](deploy/rbac/workstation.yaml) is the least-privilege role it needs:
- A read-only ClusterRole.
- A Role for listing image pull secrets in each Armor namespace (REG-05).
- SelfSubjectAccessReviews, which every user may create and the API server doesn't store.

K8S-09 checks the permissions of whoever runs Preflight. Run it with the installer's credentials to check the installer.

`scripts/audit-lab.sh` proves this. It starts a real kube-apiserver with audit logging, seeds an AKS-like cluster, and runs Preflight as an identity bound only to that role. It then fails if the audit log shows any write, or any forbidden request. CI runs it on every change.

## Building

Requires Go 1.24.

```
make build    # bin/armor-preflight
make test
make lint     # gofmt + go vet
make cross    # static binaries for linux/darwin × amd64/arm64
```

Releases use [goreleaser](https://goreleaser.com) (`.goreleaser.yaml`). It builds the four targets and writes SHA-256 checksums, one SPDX SBOM per archive (needs `syft`) and a cosign signature over the checksum file (needs `cosign` and `COSIGN_KEY`). To build locally without publishing:

```
goreleaser release --snapshot --clean --skip=sign,sbom
```

## Manual tests

Criteria that need a real SGX cluster or people are tested by hand. The steps are added as each milestone lands.
