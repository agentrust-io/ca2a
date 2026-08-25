# Hardware validation

What `ca2a_verify` has been run against real confidential-computing hardware,
what it has not, and how to reproduce each run. [LIMITATIONS.md](../LIMITATIONS.md)
and [ROADMAP.md](../ROADMAP.md) link here rather than restating it.

The rule: no document describes cA2A as attested for a platform until a genuine
quote from that platform has been verified end to end by the committed verifier,
and the run is recorded below.

## Current state

| Platform | Parsing | Certificate chain | Report signature | Verified against real hardware evidence |
|---|---|---|---|---|
| AMD SEV-SNP (Azure CVM, vTPM-rooted) | Yes | Yes, to the real AMD ARK-Milan root | Yes | **Yes**, 2026-07-27, capture of 2026-07-20 |
| Intel TDX (GCP C3, non-paravisor) | Yes | Yes, to the real Intel SGX Root CA | Yes | **Yes**, 2026-07-27, capture of 2026-07-21 |
| TPM 2.0 (Azure vTPM, Trusted Launch) | Yes | Yes, to a caller-supplied vendor root | Yes | **Partly**, 2026-07-27. Parse, bindings and AK signature yes; certificate chain no, see below |

That table is about *appraisal*. Collection is a separate axis, and a verifier validated on real evidence says nothing about whether this codebase can produce that evidence:

| Platform | Collector | Run on real silicon |
|---|---|---|
| TPM 2.0 | tpm2-pytss, platform AK with a transient fallback | **Yes**, 2026-08-01, Azure Trusted Launch vTPM |
| AMD SEV-SNP (non-paravisor) | configfs-TSM, provider `sev_guest` | **Yes**, 2026-08-24, GCP `n2d-standard-4` (AMD Milan) |
| AMD SEV-SNP (Azure paravisor) | Out of scope: the guest cannot set `REPORT_DATA`, so the channel key is rooted through the vTPM instead | n/a |
| Intel TDX (non-paravisor) | configfs-TSM, provider `tdx_guest` | **Yes**, 2026-08-24, GCP `c3-standard-4` |

## What these runs do and do not establish

They establish that the appraisal path in `ca2a_verify` accepts genuine evidence
from that silicon and fails closed on a tampered copy.

As of 2026-07-27 the `verifier` seam in `ca2a_runtime.attestation` has also been
driven off a live SEV-SNP quote on a running confidential VM, so `verify_offer`
returned `assurance="hardware"` instead of `"none"` for the first time, and a
payload was sealed to a channel key that a hardware-verified measurement vouches
for. See the live-peer section below.

A cross-operator, cross-TEE-family run followed on the same day: an AMD SEV-SNP
peer on Azure calling an Intel TDX peer on GCP, each in a different cloud under a
different operator. See the cross-TEE section below.

Quote generation still requires the platform, so nothing running off a CVM is
attested, and the committed `examples/cross-operator-delegation` harness remains
software-attested with synthetic vectors: the hardware runs are recorded here
rather than shipped as fixtures, because the evidence embeds per-CPU
identifiers.

**As of 2026-08-24 the collectors have been run on real silicon for both SEV-SNP
and TDX**, closing the gap the collection table above used to record as **No**.
Both quotes were produced by this codebase's own providers through configfs-TSM
and then appraised by this codebase's own verifiers to the vendor roots. See the
collection section below.

Verification is also bounded to a remote or rogue-admin adversary, not to one
with physical access: [TEE.fail](https://tee.fail) extracts attestation keys from
fully-patched SEV-SNP and TDX with a sub-$1000 DDR5 interposer.

## SEV-SNP, Azure confidential VM

Evidence: an SNP report and its VCEK plus the AMD ASK/ARK chain, captured from an
Azure DCasv5 CVM (family 0x19 / model 0x01, Milan) via the vTPM NV index
`0x01400001`. Azure SEV-SNP is paravisor-mediated, so `REPORT_DATA` binds the
vTPM attestation key rather than a cA2A-supplied value.

```
CA2A_SNP_FIXTURE_DIR=<capture dir> pytest tests/unit/test_sev_snp.py
```

The directory holds `snp_report.bin`, `vcek.der` and `cert_chain.pem`. Not
committed: the report's 64-byte `CHIP_ID` is a per-CPU hardware identifier, and
zeroing it invalidates the signature, so a redacted vector cannot exercise the
signature path.

## Intel TDX, GCP C3 confidential VM

Evidence: a DCAP v4 ECDSA quote from a GCP C3 CVM (non-paravisor TDX, kernel
6.17, configfs-TSM `tdx_guest` provider).

```
CA2A_TDX_QUOTE=<path to tdx_quote.bin> pytest tests/unit/test_tdx.py
```

Not committed: the PCK certificate identifies the CPU.

This run found the parser defect fixed alongside this page. Genuine DCAP v4
quotes nest the Quoting Enclave material under a type-6
`QE_REPORT_CERTIFICATION_DATA` header; `TdxQuote.parse` read the QE report six
bytes early and threw on every real quote. The synthetic fixture emitted the same
flat layout, so the tests validated the defect. Failure was closed, so this was a
false negative rather than an unsound accept, but the TDX path had never worked
against real evidence. Synthetic self-consistency is not validation.

## Live attested peer on a SEV-SNP confidential VM

Run 2026-07-27 on a `Standard_DC2ads_v5` Azure CVM (Ubuntu 24.04 CVM image,
eastus). The guest reports `Detected confidential virtualization sev-snp` with
`SEV: Status: vTom` and no `/dev/sev-guest`, the expected paravisor shape.

Azure SEV-SNP is paravisor-mediated, so the guest cannot write `REPORT_DATA`
directly. The binding is therefore one hop longer than bare-metal SNP:

```
channel key + caller nonce  ->  AK-signed TPM quote (extraData)
vTPM AK                     ->  SNP REPORT_DATA == sha256(runtime_data)
SNP report                  ->  VCEK -> ASK -> ARK-Milan (AMD KDS)
```

Driving `ca2a_runtime.attestation`'s `verifier` seam off that chain:

| Result | Value |
|---|---|
| `assurance` | `hardware` (previously always `none`) |
| Verified measurement | matches the launch measurement in the live SNP report |
| Sealed payload round trip | opened inside the enclave, 102 bytes of ciphertext |
| Binary swap | rejected, "offered measurement does not match the verified report" |
| Stale nonce | rejected before any hardware work |

This is the item that gated dropping the software-mode caveat on the sealed
channel: the payload was sealed to a key that a hardware-verified measurement
vouches for, not to an unappraised key. The transcript and the bridge script are
kept out of the repository with the other captures.

What it is not: a two-operator run. One peer was attested, by a caller on the
same host. Two independently operated attested peers, ideally on different TEE
families, is the next step and is what the cross-operator claim needs.

## Cross-operator, cross-TEE: Azure SEV-SNP calling GCP TDX

Run 2026-07-27. Peer A is an Azure `Standard_DC2ads_v5` SEV-SNP CVM in eastus.
Peer B is a GCP `c3-standard-4` Intel TDX CVM (`tdx: Guest detected`,
configfs-TSM) in us-central1-a. Different clouds, different operators, unrelated
attestation formats: an AMD VCEK chain on one side, an Intel PCK chain on the
other. B served over HTTP with a firewall rule admitting only A's address.

Non-paravisor TDX is guest-controlled, so B binds its channel key into the quote
directly: `REPORTDATA = sha256(channel_pub || nonce)`, with the nonce chosen by A.

| Step | Result |
|---|---|
| A appraises B's TDX quote | 8,000 bytes, verified against the pinned Intel SGX Root CA |
| Channel key bound to the quote | Yes, `REPORTDATA` matched the recomputed binding |
| B's MRTD | `c1ee9c16e3afc506...` recorded by A |
| Stale nonce | Rejected; freshness is enforced, not assumed |
| Sealed delegated task | 107 bytes sealed by A, opened **inside B's TDX enclave** |
| Delegated capability `tool:search` | Allowed; effective scope `[task:read, tool:search]` |
| Over-scoped `tool:purchase` | Refused, HTTP 403 `SCOPE_NOT_PERMITTED` |
| Denial record | Returned across the trust boundary with `decision: deny`, the requested capability, the effective scope and the reason |

This is the run the cross-operator claim rested on. The four primitives held
simultaneously across a real trust boundary: attenuated delegation (B enforced a
scope narrowed by a chain B did not issue), peer attestation on real hardware
(A refused to seal until B's quote appraised), payload confidentiality (the task
was readable only inside B's measured guest), and provenance (both the allow and
the deny produced linked records).

What it still is not: both peers were driven by one operator's harness, and B's
appraisal of A's SNP report was not exercised in this run, so the attestation was
one-directional. Mutual simultaneous attestation is the remaining step.

## TPM 2.0, Azure Trusted Launch vTPM

Evidence: a `TPMS_ATTEST` quote over PCRs 0-7 (SHA-256) from a `Standard_D2s_v7`
Ubuntu 24.04 VM with Trusted Launch, vTPM and secure boot enabled, with a fresh
32-byte nonce as qualifying data. The AK was created in-guest with
`tpm2_createak` (RSA, RSASSA, SHA-256).

What the run checks: `TPMS_ATTEST` parsing against a real blob (magic
`0xFF544347`, type `0x8018`), the qualifying-data binding equalling the nonce
byte for byte, a non-zero PCR digest matching what the TPM reported at quote
time, the AK's RSA PKCS#1 v1.5 SHA-256 signature over the attest blob, and
rejection of a single flipped bit.

```
pytest tests/unit/test_tpm.py
```

The committed capture is loaded from
`tests/fixtures/hardware/azure-vtpm-2026-07-27` by default. Set
`CA2A_TPM_FIXTURE_DIR=<capture dir>` to replay a newly captured vector instead.

What it does **not** check, which matters: the AK certificate chain. Azure's
pre-provisioned AK certificate (read from vTPM NV index `0x01C101D0`, subject
`CN=<host>.TrustedVM.Azure.windows.net`, issuer `CN=Global Virtual TPM CA - 03`)
certifies a *different* key than the one that signed this quote, so it does not
verify against it, and the certificate carries no AIA extension, so its issuing
intermediate is not fetchable from it. Chain-to-vendor-root therefore remains
unexercised for TPM. This is exactly why the TPM verifier takes caller-supplied
trust roots rather than pinning one, unlike SEV-SNP (AMD ARK) and TDX (Intel SGX
Root CA); the shared `verify_cert_chain` those two use is the same code path and
is exercised against real vendor roots there.

Note also that this is a Hyper-V vTPM, which is what Azure confidential and
Trusted Launch VMs actually present, not a discrete TPM chip.

## Collection on real silicon: SEV-SNP and TDX, GCP, 2026-08-24

Both collectors were run on genuine confidential VMs in GCP `opaque-dev`,
`us-central1-a`, and the evidence each produced was appraised by this codebase's
own verifiers to the vendor roots. The VMs were ephemeral and deleted after the
capture.

**Intel TDX**, `c3-standard-4`, Ubuntu 24.04, kernel `6.17.0-1022-gcp`. The guest
confirmed itself (`tdx: Guest detected`), `/sys/kernel/config/tsm/report` was
present and `/dev/tdx_guest` existed (root-only, so collection needs root).
`TdxProvider.detect()` returned `True` and `TdxProvider.attest` produced an
**8000-byte DCAP v4 quote** whose `REPORTDATA` matched the derived binding and
whose PCK chain arrived inside the quote. `verify_tdx_quote` then appraised it to
the **Intel SGX Root CA** committed in `tests/fixtures`, giving version 4,
`tee_type 0x81`, and a non-zero 48-byte MRTD.

**AMD SEV-SNP**, `n2d-standard-4` pinned to AMD Milan, same image and kernel. The
guest reported `Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP`, with
`/dev/sev-guest` present. `SevSnpProvider.attest` produced a **1184-byte report**
and `auxblob` carried the AMD certificate table, 4763 bytes holding VCEK,
`SEV-Milan` (ASK) and the self-signed `ARK-Milan`. `verify_sev_snp_report`
appraised the report to that ARK and failed closed on a flipped bit in the signed
body.

Reproduce by pointing the gated tests at a capture directory:

```
CA2A_TDX_QUOTE=<dir>/tdx_quote.bin pytest tests/unit/test_tdx.py
CA2A_SNP_FIXTURE_DIR=<dir> pytest tests/unit/test_sev_snp.py
```

where the SNP directory holds `snp_report.bin`, `vcek.der`, and a
`cert_chain.pem` carrying **ASK then ARK only** — the test prepends the VCEK
itself, so including it in the PEM duplicates the leaf and the chain fails to
verify.

The captures are not committed. A SEV-SNP report's 64-byte `CHIP_ID` is a per-CPU
hardware identifier.

### What the real host's PLATFORM_INFO said

The SEV-SNP capture was the first chance to point the appraisal added for the
`Platform state is not appraised` gap at a real cloud host rather than a
synthetic vector. That host reported `PLATFORM_INFO = 0x0000000000000025`:

| Bit | Field | Value |
|---|---|---|
| 0 | `smt_enabled` | **on** |
| 1 | `tsme_enabled` | off |
| 2 | `ecc_enabled` | **on** |
| 3 | `rapl_disabled` | off |
| 4 | `ciphertext_hiding_dram_enabled` | off |
| 5 | `alias_check_complete` | **on** |
| 7 | `tio_enabled` | off |

So `require_platform={"alias_check_complete"}` is accepted on GCP: the firmware
does complete the boot-time DRAM alias check, which is AMD's BadRAM mitigation
(SB-3015). `forbid_platform={"smt_enabled"}` is **rejected**, because these hosts
run with SMT enabled.

Neither of those is a cA2A defect and neither is a GCP defect. The point is that
**before this appraisal existed, that report verified exactly as cleanly as one
from a host with SMT off**, because the signature, the chain and the measurement
say which workload ran and never what the host was doing while it ran. A
deployment that cares now has a way to say so and a way to find out.

## Not yet validated

- **TPM certificate chain**: needs a quote signed by Azure's pre-provisioned AK
  (the one its NV certificate covers) plus Microsoft's `Global Virtual TPM CA`
  intermediate, which is not distributed with the certificate.
- **Mutual simultaneous attestation**: in the cross-TEE run above the attestation
  was one-directional. A appraised B's TDX quote; B's appraisal of A's SNP report
  was not exercised, and both peers were driven by one operator's harness. Two
  independently operated peers attesting each other at the same time is the
  remaining step.
- **The committed cross-operator harness on hardware**:
  `examples/cross-operator-delegation` still runs on synthetic vectors, because
  the real captures embed per-CPU identifiers and cannot ship as fixtures. The
  hardware runs are recorded above rather than committed, so this is an
  evidence-distribution constraint rather than an implementation gap.

Two entries previously listed here, the live attested peer binding and the
cross-operator run on real hardware, were both done on 2026-07-27 and are
recorded above. They are removed rather than left, because a reader who stops at
this section would otherwise conclude the opposite of what the document says.
