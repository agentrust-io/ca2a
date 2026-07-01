# Experiment: Cross-operator attestation (Claim 6)

**Claim:** Two peer agents in different trust domains, each with independent keys, can mutually attest before exchanging a task, seal the payload to the counterparty's attested key, and a swapped binary on either side changes that side's measurement and is caught by the counterparty.

**Status: validated (software).**

The experiment composes the pieces already built: the SEV-SNP verifier (`ca2a_verify.sev_snp`), measurement pinning, and the sealed channel (`ca2a_runtime.channel`). Two operators A and B, each in its own trust domain, generate independent channel keypairs and VCEK keys chained to a trusted root, and each binds its channel public key into its attestation report. The report-signature and certificate-chain paths use synthetic vectors, exactly as in the SEV-SNP verifier tests, because a genuine report requires SEV-SNP hardware. The cross-operator protocol is exercised end to end.

**What it proves:**

1. **Independent keys.** A and B hold distinct channel keys and distinct VCEKs; neither shares key material or a CA.
2. **Mutual attestation.** Each verifies the other's report against the counterparty's golden measurement, and recovers the channel public key the report vouches for.
3. **Confidential cross-operator delegation.** A seals a delegated task to B's attested key; only B's private key opens it, and the path sees ciphertext.
4. **Binary-swap detection.** When B silently runs a tampered binary, its report is still validly signed by its VCEK but the measurement differs from the golden value, so the counterparty rejects it with `AttestationFailed`.

**What rests on hardware (not proven here):** that the reports come from genuine TEE silicon and that each private key never leaves its enclave. Those are hardware properties established by a real attestation backend on a confidential VM. The cross-operator protocol logic is what this experiment validates; real hardware end to end is tracked on the [roadmap](../../ROADMAP.md).

## Running

```bash
# From repo root, with the package installed editable (pip install -e ".[dev]")
python experiments/claim6-cross-operator-attestation/run.py
```

## Expected output

```
Claim 6: cross-operator attestation (two trust domains)
  [1] independent keys across domains: OK
  [2] mutual attestation binds each channel key: OK
  [3] payload sealed to attested key, opened only by peer: OK
  [4] silently swapped binary detected: OK
KEY RESULT: 4/4 two operators, independent keys, mutual attestation, sealed cross-operator delegation, binary-swap detected (synthetic vectors; real hardware end-to-end pending)
```
