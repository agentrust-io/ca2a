# Rejection with proof

An agent asks for authority nobody delegated to it. The call is refused, and the
refusal is handed over as a linked provenance record that a third party verifies
offline, from the committed files, without trusting the operator that produced
them.

```bash
# From repo root, package installed editable (pip install -e ".[dev]").
# The published ca2a-runtime 0.1.0a1 predates the `delegation` module this
# demo imports, so a PyPI install is not enough yet.
python examples/rejection-with-proof/demo.py
```

```
Delegation chain, narrowing at every hop
  depth 0  orchestrator  scope=['task:read', 'task:write', 'tool:purchase', 'tool:search']
  depth 1  researcher    scope=['task:read', 'tool:purchase', 'tool:search']
  depth 2  retriever     scope=['tool:search']

ALLOW  tool:search    effective scope ['tool:search']
DENY   tool:purchase  capability 'tool:purchase' is not in the effective scope
       requested   tool:purchase
       effective   ['tool:search']
       why         the leaf grant carries ['tool:search']; the callee's own
                   policy would have permitted it, but nobody delegated it
```

Then check it the way an auditor would, with no access to the runtime that
produced it:

```
ca2a verify-chain --chain examples/rejection-with-proof/chain.json
ca2a verify-dag   --dag examples/rejection-with-proof/dag.json \
                  --chain examples/rejection-with-proof/chain.json
```

```json
{"verified": true, "records": 4, "leaf_scope": ["tool:search"],
 "outcome": "denied", "requested_capability": "tool:purchase",
 "effective_scope": ["tool:search"],
 "denial_reason": "capability 'tool:purchase' is not in the effective scope",
 "cross_checked": true}
```

## Why the callee's policy is permissive here

The callee's local policy deliberately **allows** `tool:purchase`. The call is
still refused, because the retriever's delegated scope does not carry it. That is
the distinction cA2A exists to enforce: authorization is the intersection of what
the callee permits and what was actually delegated, and the second half is what
transport-layer auth cannot express. If the demo used a callee that simply did
not support purchasing, the refusal would prove nothing.

## What makes the refusal checkable

1. **The chain is signed and attenuating.** Each hop's scope is a provable
   subset of its parent's, so `sorted(leaf.scope)` is not the callee's word for
   it: it is derivable from signatures the callee did not produce.
2. **The denial record states the gap.** It carries the capability requested and
   the effective scope it fell outside, so a verifier reproduces the decision
   rather than believing the outcome.
3. **The denial links into the same DAG.** It is hash-chained to the preceding
   hop, so it cannot be silently dropped from an audit trail. Reparenting it
   breaks the link, which the demo shows at the end.
4. **A denial is terminal.** `verify_dag` rejects any chain that continues past a
   refused hop, so a trail cannot claim work proceeded after the denial.

## What this example does not claim

Everything here is real and hardware-independent: chain verification, scope
attenuation, the scope-intersect-policy decision, and DAG verification need no
TEE. This example makes **no attestation claim**. It does not seal a payload,
does not attest a peer, and proves nothing about where the code ran. It proves
what was authorized and what was refused.

For the attestation side, see
[`../cross-operator-delegation/`](../cross-operator-delegation/), which is
explicit that its attestation step uses synthetic vectors, and
[`../../docs/hardware-validation.md`](../../docs/hardware-validation.md) for what
has been verified against real silicon.

## Files

| File | What it is |
|---|---|
| `demo.py` | The runnable story. Regenerates the two JSON files. |
| `chain.json` | The signed delegation chain, root to leaf. |
| `dag.json` | The provenance DAG: three hop records plus the terminal denial. |

Keys are generated per run, so re-running the demo rewrites both files with new
signatures. The committed copies are a sample, not a fixture.
