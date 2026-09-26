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
