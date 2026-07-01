# Reproducing the Claims

Every technical claim in the cA2A profile is backed by a script under `experiments/`. This tutorial runs all six. Three are validated today (C1, C2, C5) and print a `KEY RESULT` line you can check. Three are gated on unbuilt tiers (C3, C4, C6) and SKIP with exit 0, matching what [LIMITATIONS.md](../../LIMITATIONS.md) says is not yet built. Nothing here needs a TEE or any hardware.

Each experiment imports directly from `ca2a_runtime`, so it exercises the real API described in [The Verification Library](../spec/verification-library.md), not a mock.

## 1. Install

Run from the repo root:

```bash
pip install -e ".[dev]"
```

The `[dev]` extra pulls in `pytest`, so the same install runs both the standalone experiment scripts and the CI unit tests. Two of the scripts (`claim3` and `claim6`) import `ca2a_runtime` with no `sys.path` fallback, so the editable install is required for the full suite.

## 2. The map

| Dir | Claim | Status | What it proves |
|-----|-------|--------|----------------|
| `claim1-attenuation-soundness` | C1 | validated | A child grant can never exceed its parent |
| `claim2-cross-chain-replay` | C2 | validated | Replayed or spliced credentials are rejected |
| `claim3-scope-policy-intersection` | C3 | gated (Tier 2) | Delegated scope intersected with local Cedar policy |
| `claim4-sealed-payload-confidentiality` | C4 | gated (Tier 2) | Payload decrypts only inside the attested peer |
| `claim5-provenance-dag-integrity` | C5 | validated | Linked records are tamper-evident, bound to authority |
| `claim6-cross-operator-attestation` | C6 | gated (Tier 3) | Mutual attestation, binary-swap detection |

Gated experiments SKIP (exit 0) until the implementation they depend on lands. Each gated dependency is a line item on [ROADMAP.md](../../ROADMAP.md): Tier 2 is runtime peer-delegation enforcement and the sealed channel; Tier 3 is a real hardware attestation backend.

## 3. C1: attenuation soundness (validated)

```bash
python experiments/claim1-attenuation-soundness/run.py
```

The script builds 200 strictly narrowing chains with `DelegationCredential`, `new_keypair`, and `sign`, then verifies each with `verify_chain`. It then builds 200 escalating variants in which one hop adds a capability no ancestor held, and confirms each is rejected with `ScopeEscalation`.

```text
[1] Narrowing chains accepted
    trials: 200
    accepted: 200/200

[2] Escalation attempts rejected
    trials: 200
    rejected with ScopeEscalation: 200/200
    example: hop 3 scope exceeds parent grant (added: ['cap:escalate-0'])

============================================================
KEY RESULT: 200/200 narrowing chains accepted; 200/200 escalation attempts rejected (ScopeEscalation)
```

Exit code 0. See [Delegation Chain](../spec/delegation-chain.md) for the attenuation rule and [Error Codes](../spec/error-codes.md) for `SCOPE_ESCALATION`.

## 4. C2: cross-chain replay (validated)

```bash
python experiments/claim2-cross-chain-replay/run.py
```

Two independent chains verify as a control. Then a credential is duplicated inside one chain (`CredentialReplay`), and a credential minted for chain A is spliced into chain B, breaking continuity (`BrokenDelegationLink`).

```text
    spliced credential_id: a-1 (from chain A)
    verify_chain raised: BrokenDelegationLink  OK
    error detail: hop 1 parent_id does not match previous credential_id

============================================================
KEY RESULT: 2/2 replay attacks rejected (1 CredentialReplay, 1 BrokenDelegationLink); 2/2 control chains valid
```

Exit code 0. These are the anti-replay invariants in the [Threat Model](../spec/threat-model.md).

## 5. C5: provenance DAG integrity (validated)

```bash
python experiments/claim5-provenance-dag-integrity/run.py
```

The script emits one `DelegationRecord` per hop with `record_for`, chaining `parent_record_hash`, and verifies the DAG with `verify_dag`. It then tampers one record's scope, measures the SHA-256 avalanche across `record_hash()`, and confirms the tamper and a reparent both raise `ProvenanceLinkBroken`. Finally `cross_check_chain` binds each record to its credential and rejects a forged `credential_id`.

```text
[4. cross_check_chain ties record i to credential i]
    aligned records: cross_check_chain passes  OK
    credential_id mismatch: ProvenanceLinkBroken raised  OK

============================================================
KEY RESULT: tamper flips ~50% of hash bits (120/256), ProvenanceLinkBroken raised; reparent detected; provenance bound to authority
```

Exit code 0. The bit count varies run to run around 128/256 because the key material is freshly generated; the property is that it is close to half, not an exact value. See the [Provenance DAG](../spec/provenance-dag.md) page.

## 6. C3: scope-policy intersection (gated on Tier 2)

```bash
python experiments/claim3-scope-policy-intersection/run.py
```

This SKIPs. Two runtime pieces do not exist yet: there is no request-time gate on an inbound peer call, and there is no wiring from a verified delegated scope to a Cedar policy engine. Both are Tier 2 on [ROADMAP.md](../../ROADMAP.md). The script prints a small hard-coded set intersection labeled as illustrative only; it is not the Cedar engine.

```text
SKIP: Tier 2 runtime scope-policy intersection is not implemented.
  - runtime peer-delegation enforcement not built (no call-time gate)
  - Cedar intersection not wired (no delegated-scope AND local-policy path)
See ROADMAP.md. Exiting 0 so CI and dev hosts pass.
...
KEY RESULT: SKIP (gated on Tier 2). Effective permission = delegated scope
            intersected with local Cedar policy; enforcement path not built.
```

Exit code 0. See [Cedar Policy](../spec/cedar-policy.md) for the intended intersection.

## 7. C4: sealed-payload confidentiality (gated on Tier 2)

```bash
python experiments/claim4-sealed-payload-confidentiality/run.py
```

The sealed channel is a fail-closed placeholder. This script does not demonstrate confidentiality; it demonstrates the honest current behavior, that `SealedChannel.seal()` and `open()` raise `SealedChannelError` (code `SEALED_CHANNEL_ERROR`) rather than silently emitting plaintext. The confidentiality property itself is pending Tier 2.

```text
[1. seal() fails closed]
    seal(payload) raised: SealedChannelError  OK
    error code: SEALED_CHANNEL_ERROR  OK
    detail names Tier 2: YES  OK
    plaintext emitted: NO  OK
...
KEY RESULT: SealedChannel fails closed. seal()/open() raise
SEALED_CHANNEL_ERROR instead of emitting plaintext. This is
the honest current behavior. The confidentiality claim itself
(payload decrypts only under the attested peer measurement) is
PENDING Tier 2 and is not demonstrated here.
```

Exit code 0. See the [Sealed Channel](../spec/sealed-channel.md) page.

## 8. C6: cross-operator attestation (gated on Tier 3)

```bash
python experiments/claim6-cross-operator-attestation/run.py
```

This SKIPs. Real hardware attestation backends (SEV-SNP VCEK chain, Intel TDX quote via QVL/PCS, TPM AK cert plus checkquote) are Tier 3 and not implemented. Every `BaseProvider.detect()` returns `False`, so no provider can produce a quote and no counterparty can verify one. The script probes for a provider, finds none, prints a software-only illustration of the `AttestationReport` shape clearly marked as carrying no assurance, then SKIPs.

```text
KEY RESULT: SKIP: cross-operator attestation is gated on Tier 3 (real
hardware attestation backend). No provider can produce a verifiable quote
yet, so mutual attestation and binary-swap detection cannot be demonstrated.
The reports above are software-only and carry no assurance. See ROADMAP.md.
Exiting 0 so CI and dev hosts pass.
```

Exit code 0. See [Attestation](../spec/attestation.md).

## 9. Run them all

```bash
pip install -e ".[dev]"
python experiments/claim1-attenuation-soundness/run.py
python experiments/claim2-cross-chain-replay/run.py
python experiments/claim3-scope-policy-intersection/run.py       # SKIP (Tier 2)
python experiments/claim4-sealed-payload-confidentiality/run.py  # fail-closed (Tier 2)
python experiments/claim5-provenance-dag-integrity/run.py
python experiments/claim6-cross-operator-attestation/run.py      # SKIP (Tier 3)
```

Every script exits 0. The validated three print a `KEY RESULT` asserting their property; the gated three print a SKIP banner and exit 0 so they never break CI or a laptop with no TEE.

## 10. The CI tests

Each claim also has a unit test under `tests/unit/test_claim*.py`, run by the `test` job in `.github/workflows/ci.yml`. The validated claims assert their property directly. For example, `test_claim1_attenuation.py` verifies a known narrowing chain and asserts a re-broadening child raises `ScopeEscalation` at the offending hop.

The gated claims register a `pytest.mark.skip` with a reason that names the tier and points at the roadmap, so CI records them as skipped rather than failed until the dependency lands:

```python
@pytest.mark.skip(
    reason="Tier 2: runtime scope-policy intersection not implemented; see ROADMAP.md"
)
def test_effective_scope_is_delegation_intersect_local_policy() -> None:
    ...
```

Run the suite:

```bash
pytest tests/unit -v
```

You will see the C1, C2, and C5 tests pass and the C3, C4, and C6 tests reported as skipped. That skip count is the honest ledger of what cA2A has not yet built. As Tier 2 and Tier 3 land on [ROADMAP.md](../../ROADMAP.md), those skips flip to real assertions.
