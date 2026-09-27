# SGX probe image contract (CC-05)

CC-05 checks that each SGX node can generate an SGX DCAP quote, and that the quote verifies against collateral fetched from the PCCS. Generating a quote needs code running inside an enclave and Intel's DCAP libraries. The standard probe image is a static Go binary on distroless, so it can't do that. CC-05 therefore needs a second image, passed with `--sgx-probe-image`.

Which toolchain builds the enclave is Fortanix's decision (plan item D-5). EGo, Gramine and Open Enclave would all work. This page is the contract such an image must meet. Preflight's own side (orchestration, the check logic and tests using a fake provider) is already built.

## How Preflight runs it

In `run cluster` with `--sgx-probe-image`, Preflight creates one pod per SGX node in its temporary namespace:

- pinned with `nodeSelector: kubernetes.io/hostname=<node>`, and tolerating the node's taints;
- requesting and limiting `sgx.intel.com/enclave: 1` and `sgx.intel.com/provision: 1`, so the SGX device plugin mounts the enclave and provisioning devices;
- under the same Pod Security Standards restricted settings as every probe: runs as UID 65532, read-only root filesystem, all capabilities dropped, no privilege escalation, RuntimeDefault seccomp, no service-account token, no host namespaces or host paths;
- with the request mounted at `/etc/armor-preflight/request.json`;
- with `NODE_NAME` and `POD_NAME` set in the environment.

The image must work within those limits. It can't use a writable root filesystem, `privileged`, host paths or the AESM socket from the host. Anything it needs to write must go to memory.

## Request

```json
{"version": "1", "runId": "20260926-1512-7f3a", "sgx": {"nonce": "<64 hex characters>"}, "timeout": 10000000000}
```

The nonce is 32 random bytes, generated fresh for each node and run.

## What the image must do

1. Generate a DCAP ECDSA quote whose report data starts with the nonce bytes.
2. Verify the quote using collateral from the node's configured PCCS: `global.acccache.azure.net` on Azure, or `pccs.fortanix.com`. Use the quote verification library (QVL) or an equivalent.
3. Print exactly one line to stdout and exit 0:

```
ARMOR-PREFLIGHT-RESULT {"version":"1","runId":"<from the request>","node":"<NODE_NAME>","pod":"<POD_NAME>","startedAt":"...","finishedAt":"...","stages":[
  {"stage":"quote","ok":true,"detail":"generated a 4734-byte quote"},
  {"stage":"verify","ok":true,"detail":"the quote verified with TCB status UpToDate",
   "data":{"tcbStatus":"UpToDate","advisories":"","collateral":"https://global.acccache.azure.net/sgx/certification/v4/","nonceMatches":"true"}}]}
```

On failure, set `"ok": false` on the stage that failed, with a readable `detail`. If the probe couldn't run at all, set a top-level `"error"` instead.

The simplest way to meet this contract in Go is to reuse `internal/probe/agent` unchanged and supply an `sgx.Provider` built with the chosen toolchain. The agent already checks the nonce and formats the stages. Only `Quote` and `Verify` need an enclave implementation.

## How CC-05 reads the result

| Outcome on a node | CC-05 reports |
|---|---|
| Quote verifies, nonce matches, TCB `UpToDate` | pass |
| TCB `SWHardeningNeeded`, `ConfigurationNeeded` or `ConfigurationAndSWHardeningNeeded` | warn, listing any advisories |
| TCB `OutOfDate`, `OutOfDateConfigurationNeeded`, `Revoked` or unknown | fail |
| No quote, verification fails, or the nonce doesn't match (a replayed or cached quote) | fail |
| The probe couldn't be pulled, scheduled or read | skipped, with the reason |
| No `--sgx-probe-image` given | skipped: "no SGX probe image is configured" |

CC-05 depends on CC-01 to CC-04 and REG-03. If any of those fails for a node, or for that node's pool, CC-05 is skipped for that node and names the failed check.

## Manual test

This needs an AKS cluster with an SGX node pool (DCsv3).

1. Build and sign the SGX probe image, then push it where the SGX nodes can pull it.
2. Run `armor-preflight run cluster -f settings.yaml --probe-image <probe> --sgx-probe-image <sgx-probe>`.
3. Expect one CC-05 result per SGX node, each a pass with TCB status `UpToDate`, and one SGX probe per node listed in the report's "Probes and permissions" section.
4. To check failure handling, cordon one SGX node's device plugin (for example by removing its node label so the plugin DaemonSet leaves). Expect CC-01 to fail for that node, and CC-05 to be skipped for it, naming CC-01.
