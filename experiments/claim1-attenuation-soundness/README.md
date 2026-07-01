# Experiment: Attenuation Soundness

**Claim (cA2A Claim 1):** A child delegation grant can never exceed its parent. The confused-deputy path, where an intermediary re-broadens a narrowed grant, is foreclosed by chain verification.

**What this experiment proves:**

1. Valid narrowing chains verify. Many independently generated chains, each hop a strict subset of its parent's scope, are accepted by `verify_chain` 100% of the time.
2. Escalation is rejected. For every narrowing chain, an escalating variant is built in which one child adds a capability its parent never held. `verify_chain` raises `ScopeEscalation` 100% of the time, naming the offending capability.

**What this means for governance:**

Attenuation is enforced structurally, not by trusting the intermediary. A gateway or peer that holds a narrowed credential cannot mint a child that reclaims authority the gateway itself was never granted. The escalating capability is caught at the exact hop that introduces it, so the party that overreached is identified rather than the leaf that ultimately presented the chain. This is the soundness property that closes the confused-deputy hole in multi-hop A2A delegation.

## Running

```bash
# From repo root, with the package installed editable (pip install -e .)
python experiments/claim1-attenuation-soundness/run.py
```

## Expected output

```
============================================================
Experiment: Attenuation Soundness (cA2A Claim 1)
============================================================

[1] Narrowing chains accepted
    trials: 200
    accepted: 200/200

[2] Escalation attempts rejected
    trials: 200
    rejected with ScopeEscalation: 200/200
    example: hop 2 scope exceeds parent grant (added: ['cap:escalate-...'])

============================================================
KEY RESULT: 200/200 narrowing chains accepted; 200/200 escalation attempts rejected (ScopeEscalation)
```

Counts are deterministic across runs. Ed25519 keypairs are freshly generated per chain, so the signatures differ run to run, but the acceptance and rejection counts do not.
