# Security and code review

This covers the Phase 1 code base at the end of milestone M6: about 15,400 lines (8,500 of production Go, 4,800 of tests, and 2,100 of YAML, scripts and docs). There were two passes:

1. **Staff engineer review.** Correctness, best practice, performance and secure coding. It combined static analysis with reading the code by hand.
2. **Penetration test.** Active attacks on the tool: hostile inputs, a hostile cluster, hostile network endpoints and a hostile local filesystem. Each attack became a test that fails if the weakness returns.

Milestone M7 then added the signed release pipeline and moved to a supported Go release (S13). Its evidence is in [ACCEPTANCE.md](ACCEPTANCE.md), and its design choices are in [DECISIONS.md](DECISIONS.md).

Every finding below is fixed and has a regression test. For the important fixes, the test was also run with the fix removed, to confirm it catches the weakness (marked "mutation-checked").

## Tools

| Tool | Result |
|---|---|
| `go vet`, `gofmt` | clean |
| `staticcheck` 2025.1.1, later 2026.2.1 | 1 style issue (C2), fixed. Now clean, and it runs in CI. |
| `gosec` v2.22.4 | "Hardcoded credential" hits are constant key names, not secrets. File-path hits: see S6 and S11. Unhandled-error hits are `Close` on read-only paths. |
| `govulncheck` | Couldn't run here (the build sandbox can't reach `vuln.go.dev`), so it runs in CI as a job of its own. Its first run found 36 reachable vulnerabilities: 33 in the Go 1.24.7 standard library (`crypto/x509`, `crypto/tls`, `net/url`, `net/http`, `html/template` and others) and 3 in `golang.org/x/net` v0.38.0 and `golang.org/x/text` v0.23.0. Fixed (S13); it blocks merges. |
| `shellcheck`, `actionlint` | Release scripts and workflows are clean; both run in CI. |
| `go test -race ./...` | clean |
| `scripts/audit-lab.sh` | passes, against a real kube-apiserver with audit logging |

## Threat model

| Adversary | What they control | What they must not achieve |
|---|---|---|
| Hostile or spoofed registry | Responses to `/v2/`, the token realm | Obtain the customer's registry credentials |
| Hostile network endpoint or TLS-inspecting proxy | Anything the probe reads from the network | Exhaust memory; hide interception; get a request sent over an untrusted connection |
| Compromised node, or someone with write access in Preflight's namespace | Probe output (pod logs) | Exhaust the CLI; inject into reports, the terminal or the CSV; fake a passing CC-05 |
| Hostile cluster tenant | Text that reaches evidence (event messages, API errors) | Inject into reports, the terminal or the CSV |
| Local user sharing the output directory | Planted files and symlinks | Make Preflight overwrite other files |
| Mistakes by the operator | Settings file, environment, paths | Leak secrets; hang on devices; ship private keys into the cluster |

## Findings

Severity is the impact if exploited, before the fix.

### Penetration test

| # | Finding | Severity | Fix | Test |
|---|---|---|---|---|
| P-1 | A secret containing `" < > & '` or `\` got past redaction. It appeared JSON-escaped in `result.json` and HTML-escaped in `report.html`. | **Critical** | Every free-text field of the record is redacted before anything is rendered. The byte-level pass also masks the JSON- and HTML-escaped forms. Either layer alone stops the leak. | `TestPentestRedactionSurvivesEscaping`, mutation-checked for each layer |
| P-2 | The workstation's `HTTPS_PROXY` password was printed in NET-04's evidence. | High | Userinfo is stripped from every printed URL (`redact.URL`), including scheme-less `user:pass@host:port`. | `TestPentestURLCredentialsNotReported`, `TestURL` |
| P-3 | A password in the kubeconfig server URL was printed in WS-01's evidence. | High | `kube.Clients.Server` is sanitised where it's built. | same |
| P-4 | Write-guard paths containing `..`, `//` or `%` escapes could pass the prefix checks and be normalised by the server into another namespace. Preflight never builds such paths, so this is defence in depth. | Medium | Writes are refused unless their path is already clean. | `TestRunNamespaceMode`, mutation-checked |
| P-5 | Control characters in error text reached stderr. | Low | `main` strips control characters. | `TestStripControl` |
| — | A billion-laughs YAML settings file | none | Already refused in 10 ms by the YAML library's alias limit. | `TestPentestYAMLBomb` |
| — | Symlinks planted as `result.json` and the other output files | none | Atomic writes replace the link, never write through it. | `TestPentestOutputSymlinksAreNotFollowed` |
| — | Settings paths pointing at `/dev/zero` | none (after S11) | Refused: not a regular file. | `TestPentestSettingsPathToDevice` |

### Code review

| # | Finding | Severity | Fix | Test |
|---|---|---|---|---|
| S1 | The registry client sent credentials to whatever token realm the registry advertised. A hostile registry, or a network attacker, could name their own server. | **High** | Credentials are only sent to the registry host or its parent domain. Anything else is refused and named. | `TestCredentialsNotSentToForeignRealm`, mutation-checked; `TestSameSite` |
| C1 | CC-05 passed if the SGX probe reported a quote with no verification stage. | **High** | CC-05 fails unless a verification stage confirms this run's nonce. | `TestCC05RequiresVerification`, `TestCC05RequiresNonceConfirmation` |
| S2 | Probe logs were read with no size limit. A hostile probe could exhaust the CLI's memory. | Medium | `limitBytes` of 4 MiB on log reads. | `TestLogReadIsBounded` |
| S3 | HTTP and CONNECT responses were parsed with no header limit. A header flood made the probe allocate 107 MB. | Medium | A 64 KiB budget for the status line and headers. | `TestEndlessHeadersAreBounded`, mutation-checked |
| S4 | CSV formula injection (CWE-1236) via a hostile destination or other value. | Medium | Cells that start with `= + - @`, tab or CR get a leading quote. | `TestCSVFormulaInjection` |
| S5 | ANSI escape injection into terminal output via evidence text. | Medium | Terminal output strips C0 and C1 controls, except newline and tab. | `TestTerminalStripsControlCharacters` |
| S6 | `proxy.trustedCaPath` was copied into a cluster ConfigMap unchecked. Pointed at a key bundle, it would ship a private key. | Medium | Only PEM `CERTIFICATE` blocks are accepted. Anything else is refused before any request. | `TestReadCertificatesPEMRejectsKeys` |
| S7 | The write guard allowed creating any namespace in cluster mode. Only the (optional) admission policy enforced the name. | Medium | The guard reads the create body and allows only the run's own namespace. Clients now use JSON, because client-go defaults to protobuf, which the guard can't parse and so refuses. | `TestRunNamespaceGuardChecksNamespaceName` |
| S8 | Repository names and tags weren't validated before going into registry URLs (path traversal). | Medium | The OCI grammar is enforced for repositories, tags and digests. | `TestManifestRejectsPathTraversal` |
| S9 | `report.html` had no Content-Security-Policy. Escaping was already correct. | Low | A CSP of `default-src 'none'` with inline styles only. | `TestHTMLHasRestrictiveCSP` |
| S10 | The output directory and files were world-readable. | Low | Directory 0750, files 0640. | `TestOutputPermissions` |
| S11 | User-supplied files were read with no size limit, and devices were accepted. | Low | `fsutil.ReadLimited`: regular files only, with a limit per kind of file. | `TestReadLimited`, `TestPentestSettingsPathToDevice` |
| S12 | Base images were pinned by tag only. No dependency CVE scan. | Low | Both images pinned by digest. `govulncheck` and `staticcheck` jobs in CI. | CI |
| S13 | Known vulnerabilities in the toolchain and dependencies (reported by `govulncheck`): the standard library of Go 1.24.7, `golang.org/x/net` v0.38.0 and `golang.org/x/text` v0.23.0. | Medium | Go 1.26.8, the newest patch of a supported Go release (Go 1.25 is out of support since Go 1.27 shipped). It's the minimum in `go.mod` and the probe image's build stage, pinned by digest. `x/net` v0.59.0, `x/text` v0.42.0. | CI `govulncheck` |
| P1 | Performance: every check re-listed all nodes and pods (8 node lists and 4 cluster-wide pod lists per run). | — | A per-run cache (`Env.Memo`). Errors aren't cached, and concurrent callers share one fetch. | `TestClusterWideListsAreShared`, `TestMemo` |
| C2 | An error string started with a capital letter (ST1005). | — | Fixed. | staticcheck |

## Accepted risks

- **A compromised node can fake its own probe results.** Probe output is evidence from inside the customer's cluster. Preflight bounds it, sanitises it and never trusts it with credentials, but it can't prove a result is honest. CC-05's nonce defends against replayed quotes, not against a malicious SGX image.
- **Cluster administrators can read the probe credentials.** The registry password and storage credential sit in a Secret in the run namespace for the length of the run. Anyone who can read Secrets there, meaning cluster administrators, can read them. The Secret is deleted with the namespace.
- **Operator-controlled endpoints.** The settings file decides some endpoints (registry URL, storage account, syslog host). Pointing them at internal services is the operator's choice, not a server-side request forgery.
- **Run IDs are guessable.** A run ID has 16 random bits plus the minute. Someone who can create namespaces could squat on a likely name. Preflight then reports that it couldn't create its namespace, and never deletes a namespace it didn't create.
- **Cleanup trusts volume claim references.** `cleanup` deletes persistent volumes claimed from an `armor-preflight-*` namespace. Only someone who can already create or edit persistent volumes could point one there.
- **Release tools are pinned by version, not digest.** cosign, syft, goreleaser and crane are installed by version. GitHub Actions, base images and the release BuildKit image are pinned by commit or digest.

## Second review (September 2026)

A second pass after the move to this repository: every package read again by hand, with the attacker model above plus one more adversary, **a hostile or careless settings file**. The settings file is designed to be shared (it holds no secrets), yet it decides where the secrets are sent.

Each finding has a regression test that failed before the fix.

### Findings

| # | Finding | Severity | Fix | Test |
|---|---|---|---|---|
| A-1 | Host settings were not validated. `registry.url: cr.download.fortanix.com@collector.example` parses as host `collector.example` with a harmless-looking userinfo, so the registry password (and tokens) would go there. A line break in `syslog.host` or another host reached the hand-written CONNECT and GET requests. | Medium | `registry.url`, `storage.accountFqdn`, `syslog.host` and `attestation.azureAttestationHost` must be a host name or IP address with an optional port. `storage.container` must follow Azure's container naming rules. | `TestRejects` (new cases), `TestValidHosts` |
| A-2 | The probe dialled only the first resolved address, in string order. For a dual-stack endpoint an IPv6 address can sort first (`2001:db8::1` before `203.0.113.1`). On a node with no IPv6 route (common on AKS), NET-02 then reported a reachable endpoint as blocked and asked the network team for a firewall rule it didn't need. | Medium (wrong verdict) | IPv4 addresses first, then IPv6, up to 4, each given an equal share of the remaining stage time. The evidence names any address that failed. | `TestDualStackPrefersIPv4`, `TestNextAddressAfterRefusal` |
| A-3 | An `https://` proxy URL was reached with plaintext CONNECT (on port 80 when no port was given), so every probe network check failed behind an HTTPS proxy. Other schemes were silently treated as HTTP. The Go HTTP client used for REG-03 and BAK-02 already did this correctly. | Low | The staged tester speaks TLS to an `https://` proxy and requires its certificate to verify against the public roots or `proxy.trustedCaPath`. Unsupported schemes are named. | `TestThroughHTTPSProxy` |
| A-4 | Probe targets were not validated before they were written into CONNECT and GET requests (header injection if a request were altered in the cluster). | Low (defence in depth) | Hosts are limited to host-name and IP characters, paths must start with `/` and contain no spaces or controls, and ports must be 1–65535. Nothing is dialled otherwise. | `TestInvalidTargetIsRefused` |
| A-5 | Probe pods always used `imagePullPolicy: IfNotPresent`. With a tag-only `--probe-image`, an image already cached on a node under that tag (stale from an older release, or planted) ran with the registry and storage credentials mounted. | Low | Tag-only images are pulled every run (`Always`). Digest-pinned images, which are immutable, keep `IfNotPresent`. | `TestProbeImagePullPolicy` |
| A-6 | The write guard judged the decoded URL path, while the server receives the escaped one. Namespaced `/apis/…` writes matched on a substring anywhere in the path. Each client built from the same config also rewired the one shared guard's transport. None was reachable from Preflight's own requests. | Low (defence in depth) | Judge the escaped path (a `%2F` is refused). Match `/apis/{group}/{version}/namespaces/{ns}/…` by segment. Bind the guard per transport. | `TestGuardChecksTheEscapedPath`, `TestRunNamespaceMode` (new cases), `TestGuardBindsEachTransport` |
| A-7 | `bundle` read `result.json` with no size limit and followed a symlink to a device (`/dev/zero` hung it). It also named the bundle's tar entries after the run ID in the file without checking it (`../../etc`). | Low | Read with `fsutil.ReadLimited` (regular files, 64 MiB), and require a well-formed run ID. | `TestReadRecordRefusesHostileResults` |
| A-8 | `cleanup --run-id` went unchecked into a label selector. | Low | Must be a run ID (`YYYYMMDD-HHMM-xxxx`). | `TestCleanupRejectsMalformedRunID` |
| A-9 | A CSV cell with leading spaces before `=`, `+`, `-` or `@` escaped the formula guard (spreadsheets still evaluate it). | Low | The guard looks past leading spaces. | `TestCSVFormulaBehindSpaces` |

### Performance

| # | Finding | Fix | Test |
|---|---|---|---|
| P2 | The engine ran checks level by level, with a barrier after each level. One slow check held back every check in the next level. K8S-10 and K8S-11 (up to 120 s waiting for a volume or LoadBalancer) delayed REG-02/03/04, CC-01/02 and BAK-02 although none depends on them. | Each check starts as soon as its own parents finish. Results, skips and their order are unchanged. | `TestSlowCheckDoesNotDelayUnrelatedChecks` (REG-02 started after 500 ms before the change, immediately after) |
| P3 | CI ran the whole suite twice for every commit on a branch with a pull request (`push` and `pull_request` on every branch). | `push` runs on `main` only. | CI |
| P4 | `labelValue` compiled its regular expression on every call. | Compiled once. | existing tests |

### Reviewed and left as is

- **Token realm on shared domains.** The registry client accepts a token realm in the registry's parent domain, so for `myregistry.azurecr.io` any `*.azurecr.io` realm is accepted. The realm comes from the TLS-authenticated registry itself, so only that registry could name another tenant. A public-suffix list would add a dependency for little gain.
- **Credentials through a trusted inspecting proxy.** With `proxy.trustedCaPath` set, REG-03 and BAK-02 send credentials through the TLS-inspecting proxy the customer said to trust. That is the customer's explicit choice, and NET-03 reports the interception.
- **Very short secrets.** Redaction masks every occurrence of a registered secret, so a one-character secret makes reports noisy. It never leaks.
- **Redirects.** Registry and blob requests never follow a redirect to plain HTTP, and Go drops `Authorization` on redirects to another host.
- **Supply chain and CI.** Workflows interpolate no untrusted `${{ }}` into shell steps. Tokens are read-only except in the release job, and base images and actions are pinned.
