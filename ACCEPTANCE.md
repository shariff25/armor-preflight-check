# Phase 1 acceptance audit

Each Phase 1 acceptance criterion from the build brief, with the evidence that meets it. Status:

- **CI:** proven automatically on every change. The test or CI job is named.
- **Manual:** needs a real AKS cluster, SGX hardware or people. The protocol is in the [README](README.md#manual-tests). Not yet run.
- **Fortanix:** a decision or action only Fortanix can take.

Of the 31 criteria:
- **26 are proven in CI.** Four of them also have a real-world step left: two manual runs (NET-02 on a real cluster, and a full packet capture) and two Fortanix actions (publishing the signing identity, and the support portal upload).
- **4 wait on manual runs.** CI already covers the logic behind three of them.
- **1 needs Fortanix:** Security's approval of the brief.

## R1.1 Detect every published prerequisite gap

| Criterion | Status | Evidence |
|---|---|---|
| A violating fixture for each of the 35 checks reports Fail (Warn for warnings) under its ID | CI | `TestEachCheckFailsOnItsFixture` and `TestEveryProbeCheckHasAFailingCase`. `TestRegistryMatchesCatalog` requires all 35 to be implemented. |
| A compliant reference AKS cluster returns READY with zero Fail | Manual | Logic in CI: `TestCompliantClusterIsReady`, `TestCompliantClusterPasses`, `TestProbeChecksPassOnCompliantNetwork` |
| Blocker fail → NOT READY; warnings alone → READY WITH WARNINGS; distinct, documented exit codes | CI | `TestRunExitCodes`, `TestDecide`, `TestCodesAreDistinct`. Codes are in the README. |
| A failed parent skips every dependent, naming the parent (CC-05 names REG-03) | CI | `TestParentFailureSkipsChildrenAndNamesParent`, `TestCC05NamesREG03`, `TestMultipleFailedParentsAreAllNamed`, `TestScopeAwareSkip` |
| Every result has evidence, remediation, owning team and doc link, none empty | CI | `TestNoEmptyFields`, `TestJSONMatchesSchema`, catalog validation in `internal/catalog` |
| An uncovered Armor version stops the run and names the Preflight version to use | CI | `TestUncoveredArmorVersionIsRefused` |

## R1.2 Test network and attestation from where Armor traffic originates

| Criterion | Status | Evidence |
|---|---|---|
| Registry reachable from the workstation but blocked from the SGX pool: NET-02 fails naming that pool | CI, plus manual | `TestRegistryBlockedFromSGXPoolOnly`. On a real cluster: README manual test. |
| Every egress FQDN tested from a pod on every pool, with DNS, TCP and TLS as separate evidence | CI | One probe per pool: `TestRunProbesCollectsResults`. Separate stages: `TestAllStagesPass`, `TestDNSFailureStops`, `TestRefusedTCP`, `TestTLSInterception`. |
| Behind an untrusted TLS-inspecting proxy, NET-03 fails naming each intercepted endpoint and issuer | CI | `TestInterceptingProxyIsDetected`, `TestUntrustedCertificateIsDescribedAndNoRequestSent`. Also observed live against a real inspecting proxy during M5. |
| SGX device plugin missing on one node: CC-01 fails for that node only, naming it | CI | `TestCC01FailsOnlyForTheBrokenNode` |
| CC-05 generates and verifies a quote on every SGX node, reported per node | Manual | Needs SGX hardware and the SGX probe image ([docs/sgx-probe.md](docs/sgx-probe.md)). Logic in CI: `TestCC05PassesPerNode`, `TestCC05RequiresVerification`, `TestCC05RequiresNonceConfirmation`. |

## R1.3 Route every finding to the team that can fix it

| Criterion | Status | Evidence |
|---|---|---|
| Every run writes a terminal summary, HTML report, JSON result and firewall CSV | CI | `TestRunWritesAllOutputs` |
| The HTML report opens offline and loads nothing external | CI | `TestHTMLIsSelfContained`, `TestHTMLHasRestrictiveCSP` |
| The CSV has one row per failed egress path, with the seven brief columns | CI | `TestFirewallRows`, `TestFirewallIgnoresNonEgressFailures`, `TestFirewallSourceFallbacks` |
| The HTML groups findings by owning team; each team's section prints on its own | CI | `TestHTMLGroupsByTeam` (sections and page breaks) |
| 3 of 3 network engineers new to Armor find every rule from the CSV alone | Manual | README usability protocol |

## R1.4 Customer security teams can approve Preflight without an exception

| Criterion | Status | Evidence |
|---|---|---|
| Workstation mode makes zero create, update, patch or delete calls, per the audit log | CI | CI job `audit-lab`: a real kube-apiserver's audit log, running as an identity bound only to the shipped role. Also `TestWorkstationModeMakesNoWrites`, `TestReadOnlyBlocksWritesBeforeTheyLeave`. |
| Cluster mode writes only in its own namespace, per the audit log; the ClusterRole grants no other writes | CI | `audit-lab` (audit log, and the admission policy denying writes elsewhere). Also `TestPublishedRolesGrantOnlyExpectedWrites`, `TestClusterWriteChecksStayInRunNamespace`, `TestRunNamespaceGuardChecksNamespaceName`. |
| Nothing labelled remains after a normal exit, an interrupt, or a kill followed by `cleanup` | CI | `audit-lab` covers all three against the real API server. Also `TestClusterRunInterruptStillCleansUp`, `TestCleanupCommand`. |
| Probe pods pass the restricted Pod Security Standard | CI | `TestProbePodIsRestricted` (the upstream admission library). `audit-lab` creates the pods in a namespace that enforces `restricted`. |
| A packet capture of a full run shows connections only to the endpoints under test | CI (workstation), plus manual | `TestWorkstationEgressIsOnlyTheEndpointsUnderTest` runs every real check, records each name looked up and address dialled, and fails on anything outside the catalog and settings. The full capture, including probes, is a README manual test. |
| Seeded secrets never appear in any report, log or bundle; tested every build | CI | `TestSeededSecretsNeverAppear`, `TestPentestRedactionSurvivesEscaping`, `TestPentestURLCredentialsNotReported`, `TestBundleRefusesUnregisteredCredentials` |
| Binary and probe image signatures verify against published keys; each release ships checksums and an SBOM | CI, plus Fortanix | CI job `release-snapshot` builds a full release, signs it, verifies it with [`scripts/verify-release.sh`](scripts/verify-release.sh) and shows that a tampered file fails. **Fortanix** chooses and publishes the signing key or identity (see DECISIONS.md, M7). |
| Fortanix Security has approved the one-page security brief | Fortanix | [SECURITY-BRIEF.md](SECURITY-BRIEF.md) is ready for review. |

## R1.5 Preflight is obtainable without Fortanix registry access

| Criterion | Status | Evidence |
|---|---|---|
| Binaries for Linux ~~and macOS~~ (amd64, arm64) download from the support portal without registry credentials | CI, plus Fortanix | **Amended:** Linux only, because Preflight runs on the machine Armor is deployed from (DECISIONS.md, M7). `release-snapshot` builds both Linux archives. **Fortanix** uploads them to the support portal; the release workflow drafts a GitHub release. |
| The probe image pulls from a public registry and loads from a published tarball into a customer mirror | CI | The release workflow pushes the image to a public registry. `release-snapshot` pushes the published archive into a second registry, checks the digest is unchanged, then pulls the image and runs it. |
| An unpullable probe image: the exact digest to mirror is named, and every workstation check still completes | CI | `TestClusterRunImagePullFailure` (the image is named, and all 23 workstation checks give the same result as a workstation run), `TestImagePullFailure`, `TestNodeProbePullFailureNamesTheNode` |

## R1.6 Support can trust the evidence before booking an install

| Criterion | Status | Evidence |
|---|---|---|
| `bundle` makes a redacted archive of the JSON result and versions, with no secrets or workload data | CI | `TestBundle`, `TestBundleRefusesUnregisteredCredentials` |
| The customer can list the contents before sending | CI | `TestBundleListOnly`, `TestBundleAsksBeforeWriting` |
| From the bundle alone, Support sees the Preflight and Armor versions, the context and the run time | CI | `TestBundle` (versions.json) |
| 10-node cluster-mode run in under 5 minutes, with a 10-second default per-check timeout | Manual, plus CI | 10-second default: `TestDefaults`. Timing needs a real 10-node cluster (README manual test). |

## Not yet met

- **Manual runs.** These need a compliant AKS reference cluster with an SGX pool, SGX hardware, three network engineers and a packet capture. The protocols are written; the runs are not done.
- **Fortanix decisions and actions:**
  - the signing key or keyless identity to publish;
  - the public registry for the probe image;
  - the support portal upload;
  - Security's approval of the brief;
  - the values still marked TBD in the catalog. Checks that need them report skipped and name the value.
