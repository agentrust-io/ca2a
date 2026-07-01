# cA2A Experiments

Reproducible experiments backing the technical claims in the cA2A profile and paper.

Each experiment imports directly from `ca2a_runtime`. Run from the repo root after `pip install -e ".[dev]"`.

## Experiments

| Dir | Claim | Status | Key result |
|-----|-------|--------|-----------|
| [claim1-attenuation-soundness](claim1-attenuation-soundness/) | C1: A child grant can never exceed its parent | working | 200/200 narrowing chains accepted; 200/200 escalation attempts rejected (`ScopeEscalation`) |
| [claim2-cross-chain-replay](claim2-cross-chain-replay/) | C2: Replayed or spliced credentials are rejected | working | Duplicate `credential_id` -> `CredentialReplay`; cross-chain splice -> `BrokenDelegationLink` |
| [claim3-scope-policy-intersection](claim3-scope-policy-intersection/) | C3: Delegated scope intersected with local policy | working | Effective scope = delegated INTERSECT local policy; capability granted only when delegated AND locally allowed (1/1 allowed, 3/3 denied) |
| [claim4-sealed-payload-confidentiality](claim4-sealed-payload-confidentiality/) | C4: Payload decrypts only with the peer's enclave-bound key | working | Sealed to the attested key (X25519 -> HKDF -> ChaCha20-Poly1305); only the peer's private key opens it; path sees ciphertext; tamper fails closed |
| [claim5-provenance-dag-integrity](claim5-provenance-dag-integrity/) | C5: Linked records are tamper-evident, bound to authority | working | Tamper flips ~50% of hash bits (128/256), `ProvenanceLinkBroken` raised; reparent detected; provenance bound to authority |
| [claim6-cross-operator-attestation](claim6-cross-operator-attestation/) | C6: Two domains, independent keys, mutual attestation, binary-swap detection | gated (Tier 3) | SKIPs until a real hardware attestation backend verifies a quote |

Working experiments are fully reproducible on any host with no TEE. Gated experiments SKIP (exit 0) until the implementation they depend on lands, mirroring how cmcp's `claim-hw-attestation` SKIPs without a confidential VM. Each gated dependency is on the [roadmap](../ROADMAP.md).

## Running

```bash
pip install -e ".[dev]"
python experiments/claim1-attenuation-soundness/run.py
python experiments/claim2-cross-chain-replay/run.py
python experiments/claim3-scope-policy-intersection/run.py       # SKIP (Tier 2)
python experiments/claim4-sealed-payload-confidentiality/run.py  # fail-closed today
python experiments/claim5-provenance-dag-integrity/run.py
python experiments/claim6-cross-operator-attestation/run.py      # SKIP (Tier 3)
```

## CI

Each claim has a unit test under `tests/unit/test_claim*.py`. Working claims assert their property; gated claims register a `pytest.mark.skip` so CI records them as skipped, not failed, until the dependency lands. The suite runs in the `test` job of [.github/workflows/ci.yml](../.github/workflows/ci.yml).
