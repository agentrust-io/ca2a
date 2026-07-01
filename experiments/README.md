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
| [claim6-cross-operator-attestation](claim6-cross-operator-attestation/) | C6: Two domains, independent keys, mutual attestation, binary-swap detection | working | Mutual SEV-SNP attestation, sealed cross-operator delegation, and binary-swap detection (4/4); synthetic vectors, real hardware end-to-end pending |

All six claims are validated and fully reproducible on any host with no TEE. The attestation-dependent claims (C4, C6) exercise the SEV-SNP verifier against synthetic report vectors, since a genuine report requires SEV-SNP hardware; validating the report-signature path against real hardware vectors, and driving the whole pipeline off a live A2A transport, remain on the [roadmap](../ROADMAP.md).

## Running

```bash
pip install -e ".[dev]"
python experiments/claim1-attenuation-soundness/run.py
python experiments/claim2-cross-chain-replay/run.py
python experiments/claim3-scope-policy-intersection/run.py
python experiments/claim4-sealed-payload-confidentiality/run.py
python experiments/claim5-provenance-dag-integrity/run.py
python experiments/claim6-cross-operator-attestation/run.py
```

## CI

Each claim has a unit test under `tests/unit/test_claim*.py` that asserts its property. All six run in the `test` job of [.github/workflows/ci.yml](../.github/workflows/ci.yml).
