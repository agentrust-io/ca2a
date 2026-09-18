# Mutual hardware acceptance run

Status: a same-project live diagnostic completed on two GCP SNP guests on
September 17, 2026. Calls succeeded in both directions, with separately collected
receiver logs and matching nonsecret payload digests. A paced run passed one
positive and ten rejection cases per direction. Cross-operator validation and
acceptance under a strict confidentiality platform policy remain open.

Both guests reported `PLATFORM_INFO=0x25`, SVN 0, VMPL0, and DEBUG disabled.
The diagnostic profile allowed SMT and SVN 0; it required alias checking.
Policies forbidding SMT or requiring ciphertext hiding correctly rejected the
hosts. Measurement pins came from owner-SSH bootstrap reports, not a precomputed
application image. Initial burst runs timed out; paced runs exited 0. The
sanitized results are in
[the diagnostic record](https://github.com/agentrust-io/ca2a/blob/main/experiments/hardware-validation/mutual-snp-2026-09-17/README.md).
Raw reports and device-identifying certificates remain private. Both VMs and their
boot disks were deleted after collection. This is not end-to-end inference
confidentiality validation.

Use two non-paravisor SEV-SNP guests for the first run. Each needs a working
configfs-TSM provider and a separately provisioned VCEK/ASK/ARK chain. Pin the
trusted ARK and expected workload measurement through an authenticated deployment
record, not from the peer's offer. The `sev_snp_verifier` helper accepts these
inputs and explicit `require_platform` and `forbid_platform` sets. A sample policy
requires `alias_check_complete` and forbids `smt_enabled`; the prior GCP capture
had SMT enabled, so that policy would correctly refuse that host.

Configure the receiving `PeerNode` with `require_caller_attestation="hardware"`
and that verifier. Configure the sender with its local `SevSnpProvider`, the
recipient's verifier and `send_task(..., require_hardware=True)`. Supply an
authorized delegation chain and its holder key as required by the reference
transport. Both peers must independently pin the other workload; copying one
peer's configuration to both sides does not establish independent administration.

The acceptance record must contain:

- Exact source revision, dependencies, provider, trust-root fingerprints,
  measurement pins and platform policy for each direction.
- A successful task showing caller-side hardware appraisal and receiving-side
  `caller_attestation="hardware"`, with a payload digest checked inside the
  receiver. Do not echo confidential plaintext in the transport response.
- Rejected wrong measurement, stale nonce, substituted channel key, software
  downgrade and prohibited platform state. Record that rejected caller evidence
  precedes decryption and rejected callee evidence precedes sealing/transmission.
- Distinct results for signature/chain/binding verification and platform policy.
  Do not infer collateral revocation status or complete TCB appraisal from them.

Preserve raw evidence privately: SNP reports include per-chip identifiers. Publish
only a sanitized transcript if separately approved. Retain failed controls; do not
label a synthetic injected verifier as a hardware result. Repeat with reversed
sender/receiver roles. This validates sequential mutual appraisal, not simultaneous
attestation or application data-flow containment.

## Runnable two-host harness

`python -m ca2a_runtime.hardware_acceptance` supplies `serve` and `call` modes.
It refuses to run without the real non-paravisor SNP provider and has no software
mode. Run from an installed checkout on each host, with permissions to collect a
configfs-TSM quote. Both hosts require the other's authenticated measurement and
host-specific VCEK chain. Files resolve relative to the configuration file.

Example receiver configuration (`receiver.json`):

```json
{
  "peer": {
    "trusted_roots": "sender-ark.pem",
    "vcek_chain": "sender-vcek-ask-ark.pem",
    "expected_measurement": "REPLACE_WITH_96_HEX_DIGITS",
    "min_guest_svn": 1,
    "require_platform": ["alias_check_complete"],
    "forbid_platform": ["smt_enabled"],
    "reject_unrecognized_platform_bits": true
  },
  "trusted_root_issuers": ["REPLACE_WITH_DELEGATION_AUTHORITY_PUBLIC_KEY"],
  "capabilities": ["read"],
  "host": "0.0.0.0",
  "port": 8443
}
```

The sender configuration (`sender.json`) uses the same `peer` object shape, with
the **receiver's** certificates, measurement and platform policy. Its other keys:

```json
{
  "chain": "authorized-chain.json",
  "holder_key": "leaf-private-key.hex",
  "payload": "probe-input.bin",
  "peer_url": "http://RECEIVER:8443",
  "capability": "read",
  "record_id": "mutual-run-001"
}
```

Combine those keys and the `peer` object into one sender configuration. The chain
file is a JSON array of signed delegation credentials; the key file contains the
32-byte Ed25519 leaf private key as hex. Use a fresh nonsecret probe payload for
acceptance. The harness neither generates trust pins nor changes cloud resources.

```sh
# Receiver, retain this observation independently.
python -m ca2a_runtime.hardware_acceptance serve receiver.json \
  --receipt receiver.jsonl --run-id mutual-run-001
# Sender, on the other SNP guest.
python -m ca2a_runtime.hardware_acceptance call sender.json \
  --receipt sender.jsonl --run-id mutual-run-001
```

Each JSONL receipt records policy, successful/failed peer appraisal, and local
task outcome. Accepted receiver tasks include the payload SHA-256; compare it
with the sender's digest. Reports are represented by hashes, never raw chip IDs
or plaintext. Receipts are unsigned local observations. The sender explicitly
marks the HTTP response as unauthenticated; a remote success assertion alone is
insufficient. Retain the receiver log through a separately trusted collection
path. Archive the exact checkout diff/revision and dependency lock alongside both
receipts. Repeat in the opposite direction and perform the negative controls
listed above. This harness does not claim to automate every negative control.

The new SNP channel verifier always rejects debug-enabled guests (`POLICY.DEBUG`,
bit 19 in the [AMD firmware ABI](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf))
and requires VMPL0 for this non-paravisor profile. `min_guest_svn` must be chosen
from the owner-approved guest release policy; the example value is not a universal
secure version. These fields are checked after signature, chain and binding
verification. They do not establish firmware TCB currency, revocation status or
safe migration policy. Other VMPL deployments require a separately justified
profile and are deliberately refused here.

## Diagnosing interrupted calls

The harness writes `operation_started`, `operation_completed` and
`operation_failed` observations with an operation ID and monotonic elapsed time.
Stages distinguish receiver offer generation, local quote collection, peer quote
verification, receiver task processing and the overall sender call. Nonces are
hashed for correlation; payloads, certificates and raw reports are not logged.

A start without a matching completion identifies unfinished observed work; it
does not identify why it stalled. A sender transport failure records the receiver
outcome as unknown and preserves the original exception. There are no automatic
retries: the receiver may have processed a task before its response was lost.
Collect both hosts' receipts and service/kernel logs before diagnosing a cause.
Operation IDs correlate events within a receipt, not an authenticated distributed
trace. These observations remain unsigned and cannot prove receiver inactivity.

The September 17 burst timeout has not been reproduced locally: 100 consecutive
software-provider calls over the reference HTTP server completed without pacing.
A controlled local test blocks software quote generation to verify that a real
HTTP timeout leaves useful unfinished-stage evidence. That test does not establish
that quote generation caused the historical SNP timeout. Hardware results have
not been rerun or changed by this diagnostic addition.
