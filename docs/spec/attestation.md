# Peer Attestation

Before a peer is trusted with a delegated task, it proves it is running attested, measured code. cA2A reuses the pluggable TEE provider abstraction from [cmcp](https://github.com/agentrust-io/cmcp).

## Provider interface

A provider implements `BaseProvider`:

- `detect()` returns whether the provider is available on the current host.
- `attest(public_key, nonce)` returns an `AttestationReport` binding `public_key` to the host's hardware measurement under `nonce`.

An `AttestationReport` carries `platform`, `measurement`, the bound `public_key`, and the `nonce`.

## Providers

| Provider | Platform | Status |
|---|---|---|
| `software-only` | none | Available; for development and CI. Reports `platform: software-only`, never a hardware platform string. |
| `sev-snp` | AMD SEV-SNP | Verifier implemented (see below). Report generation requires a real SEV-SNP guest. |
| `tpm` | TPM 2.0 / vTPM | Tier 3, not yet implemented |
| `tdx` | Intel TDX | Tier 3, not yet implemented |
| `opaque` | OPAQUE Confidential Runtime | Tier 3, explicit opt-in, not auto-selected |

## SEV-SNP verification

`ca2a_verify.sev_snp.verify_sev_snp_report` appraises an AMD SEV-SNP attestation report offline, in three fail-closed steps:

1. **Certificate chain.** The VCEK is verified up to a trusted AMD root (ARK) through `ARK -> ASK -> VCEK`. Each certificate must be validly issued by the next, and the root must match a trusted anchor by fingerprint.
2. **Report signature.** The ECDSA-P384 signature (stored as little-endian `r` and `s`) is verified against the VCEK public key over the report body (`report[:0x2A0]`).
3. **Binding.** The launch `measurement` and the `report_data` (which carries the runtime key and nonce) are checked against expected values.

**What is validated.** The chain-verification path is exercised against the genuine AMD Milan ARK/ASK root chain fetched from AMD KDS (`tests/fixtures/sev_snp/`). The report-signature path is exercised end to end with a synthetic VCEK and report, because a genuine report plus VCEK pair requires real SEV-SNP hardware. Producing a report (`SevSnpProvider.attest`) fails closed off hardware (`AttestationUnsupported`).

**Cross-operator use.** Two operators in separate trust domains each bind their sealed-channel public key into a report and verify the counterparty's report against a pinned golden measurement. This composes into mutual attestation, confidential cross-operator delegation (seal to the attested key), and binary-swap detection (a changed measurement is rejected), validated in software as claim C6. See the [call graph](call-graph.md) and the `claim6-cross-operator-attestation` experiment.

## Fail closed

Providers without a backend `detect()` to False, so they are never selected automatically, and verification fails closed when evidence is absent or invalid. This is deliberate: cA2A must not be described as attested across trust domains until a real hardware backend verifies a quote against a golden measurement. TDX and TPM backends remain Tier 3. See [LIMITATIONS.md](../../LIMITATIONS.md).

## Why this is the critical path

Real hardware attestation verification (SEV-SNP VCEK chain from AMD KDS, Intel TDX quote via QVL/PCS, TPM AK cert plus checkquote) is a dependency for any cross-operator trust claim, single-agent or multi-agent. It is shared with cmcp and sequenced first on the roadmap so the demo matches the claim.
