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
