# Experiment: Cross-operator attestation (Claim 6)

**Claim:** Two peer agents in different trust domains, each with independent keys, can mutually attest before exchanging a task, and a swapped binary on either side changes that side's measurement and is caught by the counterparty.

**Status: SKIP (gated on Tier 3).** This experiment does not verify anything yet. Real hardware attestation backends (SEV-SNP VCEK chain, Intel TDX quote via QVL/PCS, TPM AK cert + checkquote) are not implemented in this release. Every `BaseProvider.detect()` returns `False`, so no provider can produce a quote and no counterparty can verify one. See `ROADMAP.md` (Critical path, Tier 3): real hardware attestation verification is a hard dependency for any cross-operator trust claim, and at least one real backend must land before cA2A is marketed as attested across trust domains.

## The two-operator protocol shape

Operator A and Operator B run in separate trust domains. Neither trusts the other's key list up front; trust is established by attestation, not by a shared CA.

1. **Independent keys.** A holds keypair `(a_priv, a_pub)`, B holds `(b_priv, b_pub)`. The keys are generated in each operator's own domain and never shared.
2. **Nonce exchange.** Before attesting, A sends B a fresh random nonce `n_A`, and B sends A a fresh random nonce `n_B`. The nonce makes each report non-replayable: a report bound to `n_A` cannot be reused against a later challenge.
3. **Mutual reports.** A's provider produces `AttestationReport(platform, measurement_A, public_key=a_pub, nonce=n_B)`, binding A's key to A's enclave measurement under B's nonce. B produces the symmetric report binding `b_pub` and `measurement_B` under `n_A`.
4. **Independent verification.** B verifies A's report: the quote signature chains to genuine TEE silicon, the nonce equals `n_B` (freshness), and `measurement_A` matches the expected golden value for the code B agreed to talk to. A verifies B's report symmetrically. Neither side needs the other's operator to vouch for it.
5. **Binary-swap detection.** If A silently swaps its binary (or its enclave config), `measurement_A` changes. B's expected-measurement check fails and B refuses the exchange. The swap is caught by the counterparty, in a different trust domain, without any coordination.

This is the peer-to-peer generalization of single-agent attestation: the same report-binds-key-to-measurement primitive, run in both directions across a trust boundary.

## What blocks it

The `measurement` in an `AttestationReport` is only meaningful if a verifier can prove the report was signed by real TEE silicon and that the measurement reflects the code actually running. That proof is the Tier 3 work that is not yet implemented:

- **AMD SEV-SNP:** VCEK/VLEK cert-chain validation via AMD KDS.
- **Intel TDX:** DCAP quote signature + TCB status via QVL/PCS.
- **TPM:** AK certificate chain to the manufacturer CA + `checkquote`.

Until one of these lands, an `AttestationReport` constructed in software is just a labeled dataclass. It carries no assurance, and step 4 above has nothing to verify against.

## Running

```bash
# From repo root
pip install -e .
python experiments/claim6-cross-operator-attestation/run.py
```

`run.py` is safe to run anywhere. It probes for a hardware provider, finds none (all `detect()` return `False`), prints the protocol shape and a software-only illustration of the report structure clearly labeled as **not hardware-attested**, then prints `SKIP` and exits 0. It never fails CI.

## Expected output

```
============================================================
Experiment: Cross-operator attestation (Claim 6)
Two peers, different trust domains, independent keys, mutual attestation
============================================================

[1] Independent keys in two trust domains
    Operator A public key: <hex>...
    Operator B public key: <hex>...
    Keys are distinct: YES

[2] Provider probe (looking for a real hardware backend)
    No hardware TEE provider detected (all detect() -> False)

[3] Software-only illustration of the report shape (NOT hardware-attested)
    A -> B report: platform=software-only measurement=DEV_ONLY... key=<a_pub> nonce=<n_B>
    B -> A report: platform=software-only measurement=DEV_ONLY... key=<b_pub> nonce=<n_A>

[4] What a verifier would check (once Tier 3 lands)
    - quote signature chains to genuine TEE silicon
    - report nonce equals the counterparty's fresh challenge
    - measurement equals the agreed golden value (swap -> mismatch -> reject)

SKIP: cross-operator attestation is gated on Tier 3 (real hardware
attestation backend). No provider can produce a verifiable quote yet.
See ROADMAP.md. Exiting 0.
```
