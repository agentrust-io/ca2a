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
| `tpm` | TPM 2.0 / vTPM | Tier 3, not yet implemented |
| `sev-snp` | AMD SEV-SNP | Tier 3, not yet implemented |
| `tdx` | Intel TDX | Tier 3, not yet implemented |
| `opaque` | OPAQUE Confidential Runtime | Tier 3, explicit opt-in, not auto-selected |

## Fail closed

Hardware providers `detect()` to False until their backend lands, so they are never selected automatically, and verification fails closed when evidence is absent. This is deliberate: cA2A must not be described as attested across trust domains until at least one real hardware backend verifies a quote. See [LIMITATIONS.md](../../LIMITATIONS.md).

## Why this is the critical path

Real hardware attestation verification (SEV-SNP VCEK chain from AMD KDS, Intel TDX quote via QVL/PCS, TPM AK cert plus checkquote) is a dependency for any cross-operator trust claim, single-agent or multi-agent. It is shared with cmcp and sequenced first on the roadmap so the demo matches the claim.
