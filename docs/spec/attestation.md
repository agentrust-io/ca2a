# Peer Attestation

Before a peer is trusted with a delegated task, it proves it is running attested, measured code. cA2A reuses the pluggable TEE provider abstraction from [cmcp](https://github.com/agentrust-io/cmcp).

## Provider interface

A provider implements `BaseProvider`:

- `detect()` returns whether the provider is available on the current host. Available means `attest` can actually produce evidence here, not merely that the hardware exists: a provider that returns True and then raises would be selected and then fail.
- `attest(public_key, nonce)` returns an `AttestationReport` binding `public_key` to the host's hardware measurement under `nonce`.

An `AttestationReport` carries `platform`, `measurement`, the bound `public_key`, and the `nonce`. Those four fields are what a report *claims*; on their own they are an assertion, since any peer can populate them with any values. Four further fields carry the evidence that makes them checkable, and they are named to match cmcp's report model so evidence is portable between the two runtimes:

| Field | Contents |
|---|---|
| `raw_evidence` | the raw blob the hardware signed (for TPM, the bare `TPMS_ATTEST`) |
| `quote_signature` | the signature over `raw_evidence` (for TPM, a marshalled `TPMT_SIGNATURE`) |
| `attestation_key_pem` | the key that produced that signature |
| `attestation_key_chain_pem` | the leaf-first certificate chain for that key |

All four are absent on `software-only`, which has no evidence by construction. A report claiming a hardware platform with no evidence cannot be verified, so it fails closed rather than being trusted.

## Providers

| Provider | Platform | Status |
|---|---|---|
| `software-only` | none | Available; for development and CI. Reports `platform: software-only`, never a hardware platform string. |
| `sev-snp` | AMD SEV-SNP | Verifier implemented (see below). Report generation requires a real SEV-SNP guest. |
| `tdx` | Intel TDX | Verifier implemented (see below). Quote generation requires a real TDX guest. |
| `tpm` | TPM 2.0 / vTPM | Verifier and collector both implemented (see below). `attest` produces a real quote on a Linux host with a TPM and tpm2-pytss. |
| `opaque` | OPAQUE Confidential Runtime | Tier 3, explicit opt-in, not auto-selected |

## SEV-SNP verification

`ca2a_verify.sev_snp.verify_sev_snp_report` appraises an AMD SEV-SNP attestation report offline, in three fail-closed steps:

1. Certificate chain: the VCEK is verified up to a trusted AMD root (ARK) through `ARK -> ASK -> VCEK`. Each certificate must be validly issued by the next, and the root must match a trusted anchor by fingerprint.
2. Report signature: the ECDSA-P384 signature (stored as little-endian `r` and `s`) is verified against the VCEK public key over the report body (`report[:0x2A0]`).
3. Binding: the launch `measurement` and the `report_data` (which carries the runtime key and nonce) are checked against expected values.

What is validated. The chain-verification path is exercised against the genuine AMD Milan ARK/ASK root chain fetched from AMD KDS (`tests/fixtures/sev_snp/`). The report-signature path is exercised end to end with a synthetic VCEK and report, because a genuine report plus VCEK pair requires real SEV-SNP hardware. Producing a report (`SevSnpProvider.attest`) fails closed off hardware (`AttestationUnsupported`).

Cross-operator use. Two operators in separate trust domains each bind their sealed-channel public key into a report and verify the counterparty's report against a pinned golden measurement. This composes into mutual attestation, confidential cross-operator delegation (seal to the attested key), and binary-swap detection (a changed measurement is rejected), validated in software as claim C6. See the [call graph](call-graph.md) and the `claim6-cross-operator-attestation` experiment.

## TDX verification

`ca2a_verify.tdx.verify_tdx_quote` appraises an Intel TDX quote (DCAP, ECDSA-256) offline in four fail-closed steps: the PCK certificate chain is verified up to a trusted Intel root; the Quoting Enclave report is verified against the PCK; the attestation key is confirmed to be the one the QE report data commits to (SHA-256 of the key and the QE auth data); and the attestation key's signature over the quote body is verified, along with the launch measurement (MRTD) and report data.

What is validated. The chain-verification path accepts the genuine self-signed Intel SGX Root CA fetched from Intel (`tests/fixtures/tdx/`) and rejects an untrusted root. The multi-level signature path (PCK to QE report to attestation key to quote) is exercised end to end with a synthetic self-consistent quote, because a genuine quote requires a TDX guest. Byte offsets follow the Intel DCAP Quote v4 layout; end-to-end validation against a real hardware quote requires a TDX guest and remains open.

## TPM verification

`ca2a_verify.tpm.verify_tpm_report` appraises a peer's TPM report offline: the AK certificate chain is verified to a trusted root, the AK signature over the attest blob is verified (ECDSA-SHA256 or RSA PKCS#1 v1.5), the structure is confirmed to be a TPM-generated quote (magic and type), and the key-and-nonce binding below is checked. `verify_tpm_quote` is the lower-level form taking an attest blob and a bare signature directly.

The cryptography is not implemented in cA2A. Steps 1, 2 and 4 delegate to `agent_manifest.verify_tpm_quote`, the canonical hardware-validated implementation cA2A already depends on; three divergent copies of one TPM verifier is the problem being retired (cmcp#447). What cA2A keeps is the piece agent-manifest does not model: `TPMT_SIGNATURE`, the envelope `tpm2_quote -s` and tpm2-pytss `signature.marshal()` actually emit, which is unwrapped to the bare signature agent-manifest takes.

### The signed binding

A TPM quote commits caller-chosen bytes in its `extraData` (qualifying data) field. cA2A commits **both** the offered channel public key and the nonce:

```
extraData = sha256("ca2a-tpm-v1|" || len32(public_key) || public_key || len32(nonce) || nonce)
```

Committing the nonce alone would sign for freshness only, leaving `public_key` an unsigned assertion, and sealing a payload "to a key from a verified report" would not actually be rooted in hardware. The verifier re-derives this value from the report's own fields and requires equality, which is what promotes `public_key` and `nonce` from claim to signed fact. A report whose key was substituted after the quote was taken is rejected.

Two encoding details are load-bearing. The value is hashed to 32 bytes rather than carried raw because `TPM2B_DATA` is capped below 64 bytes on some platforms (Azure returns `TPM_RC_SIZE`). Each field is length-prefixed rather than delimiter-joined because with a delimiter a value containing it shifts the split without changing the digest, so `("a|b", "c")` and `("a", "b|c")` would commit identical bytes and a peer could bind a key other than the one it appears to offer. `nonce` is an arbitrary caller-supplied string, so that is reachable rather than theoretical.

The measurement is `sha256:` followed by the quote's own `pcrDigest`, over PCRs 0-7 in the SHA-256 bank. The collector separately reads those PCRs and requires its digest to equal the quoted one, which catches a PCR selection mismatch before evidence ships. The verifier returns the measurement read out of the signed quote rather than the report's `measurement` field, and rejects a report where the two disagree.

### Trust anchors

TPM attestation keys chain to per-vendor roots, not to one published root the way SEV-SNP and TDX do. cA2A does not decide which vendors a deployment trusts: the verifier takes caller-supplied roots and consults nothing implicitly. `ca2a_verify.tpm_roots.AZURE_VTPM_ROOT_2023_PEM` is the one root validated against hardware, available so a deployment on that platform need not re-derive it, but trusting it stays an explicit import. Supplying no root at all is refused, because a chain validated against no anchor would accept any self-consistent chain.

### Two deliberate differences from cmcp's collector

cmcp falls back to the SHA-1 PCR bank and downgrades the report to `software-only`; cA2A requires the SHA-256 bank and raises instead, because a report labelled `sha256:` that measured SHA-1 banks is a mislabel waiting to happen. cmcp can also emit a report whose only evidence is an unsigned PCR read, marked software-only; in cA2A, failing to produce a signed quote raises, because the platform string on a cA2A report is the provider's identity and a `tpm` report that can never verify is worse than an honest error.

What is validated. The collector's checks, the TPM interaction shapes, and report verification end to end are exercised against synthetic self-consistent vectors in `tests/unit/test_tpm_attest.py`. A quote from a genuine Azure Trusted Launch vTPM parses and verifies under `CA2A_TPM_FIXTURE_DIR`. What has **not** been demonstrated is a full collect-then-verify pass in one process on hardware: on the Azure test VM, installing `agent-manifest` conflicts with the distribution's `tpm2_pytss`, so the collector and the verifier could not be run together there. See [LIMITATIONS.md](../../LIMITATIONS.md).

## Fail closed

A provider `detect()`s to True only where `attest` works on that host, and verification fails closed when evidence is absent or invalid. `sev-snp` and `tdx` have verifiers but no collector yet, so their `attest` raises `AttestationUnsupported`; `software-only` returns False from `detect` so a no-guarantee posture is always an explicit choice. See [LIMITATIONS.md](../../LIMITATIONS.md).

## Why this is the critical path

Real hardware attestation verification (SEV-SNP VCEK chain from AMD KDS, Intel TDX quote via QVL/PCS, TPM AK cert plus checkquote) is a dependency for any cross-operator trust claim, single-agent or multi-agent. It is shared with cmcp and sequenced first on the roadmap so the demo matches the claim.
