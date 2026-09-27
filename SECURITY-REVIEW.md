# Security and code review

This covers the Phase 1 code base at the end of milestone M6: about 15,400 lines (8,500 of production Go, 4,800 of tests, and 2,100 of YAML, scripts and docs). There were two passes:

1. **Staff engineer review.** Correctness, best practice, performance and secure coding. It combined static analysis with reading the code by hand.
2. **Penetration test.** Active attacks on the tool: hostile inputs, a hostile cluster, hostile network endpoints and a hostile local filesystem. Each attack became a test that fails if the weakness returns.

Every finding below is fixed and has a regression test. For the important fixes, the test was also run with the fix removed, to confirm it catches the weakness (marked "mutation-checked").

## Tools

| Tool | Result |
|---|---|
| `go vet`, `gofmt` | clean |
| `staticcheck` 2025.1.1 | 1 style issue (C2), fixed. Now clean, and it runs in CI. |
| `gosec` v2.22.4 | "Hardcoded credential" hits are constant key names, not secrets. File-path hits: see S6 and S11. Unhandled-error hits are `Close` on read-only paths. |
| `govulncheck` | Couldn't run here (the build sandbox can't reach `vuln.go.dev`). It now runs in CI as a job of its own. |
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
| P1 | Performance: every check re-listed all nodes and pods (8 node lists and 4 cluster-wide pod lists per run). | — | A per-run cache (`Env.Memo`). Errors aren't cached, and concurrent callers share one fetch. | `TestClusterWideListsAreShared`, `TestMemo` |
| C2 | An error string started with a capital letter (ST1005). | — | Fixed. | staticcheck |

## Accepted risks

- **A compromised node can fake its own probe results.** Probe output is evidence from inside the customer's cluster. Preflight bounds it, sanitises it and never trusts it with credentials, but it can't prove a result is honest. CC-05's nonce defends against replayed quotes, not against a malicious SGX image.
- **Cluster administrators can read the probe credentials.** The registry password and storage credential sit in a Secret in the run namespace for the length of the run. Anyone who can read Secrets there, meaning cluster administrators, can read them. The Secret is deleted with the namespace.
- **Operator-controlled endpoints.** The settings file decides some endpoints (registry URL, storage account, syslog host). Pointing them at internal services is the operator's choice, not a server-side request forgery.
- **Run IDs are guessable.** A run ID has 16 random bits plus the minute. Someone who can create namespaces could squat on a likely name. Preflight then reports that it couldn't create its namespace, and never deletes a namespace it didn't create.
- **Cleanup trusts volume claim references.** `cleanup` deletes persistent volumes claimed from an `armor-preflight-*` namespace. Only someone who can already create or edit persistent volumes could point one there.
- **GitHub Actions are pinned by version tag, not commit SHA.** SHA pinning is recommended before release (M7).
