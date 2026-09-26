# armor-preflight

`armor-preflight` checks whether a customer environment is ready for a Fortanix Armor on-prem install, before anyone starts the install. It checks every prerequisite from where Armor will actually run and tells each customer team what it needs to fix.

> **Status: milestone M0 (skeleton).** The commands and flags exist and `version` works. `run`, `bundle` and `cleanup` exit with code 3 ("not implemented yet"). See [PLAN.md](PLAN.md) for the build order.

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

## Exit codes

| Code | Meaning |
|---|---|
| 0 | READY |
| 1 | READY WITH WARNINGS |
| 2 | NOT READY (at least one blocker failed) |
| 3 | Preflight itself failed to run |

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
