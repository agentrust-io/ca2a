# Experiment: Delegated Scope Intersected with Local Cedar Policy

**Claim:** The capability set a caller may actually exercise is the intersection of its delegated scope with the local Cedar policy of the resource it calls (cA2A Claim 3).

**Status: SKIP (gated on Tier 2).**

This experiment does not run yet. It depends on two runtime pieces that are not built:

1. **Runtime peer-delegation enforcement.** `verify_chain` in `ca2a_runtime.delegation` already checks signature, continuity, attenuation, and anti-replay across a delegation chain. It does not yet gate an actual peer-to-peer call at request time, so there is no enforcement point at which to apply a local decision.
2. **Cedar intersection.** There is no wiring between a verified delegated scope and a local Cedar policy engine. The effective-permission computation (delegated scope AND local policy) is not implemented.

Both land in Tier 2. See `ROADMAP.md`.

**What it will prove once Tier 2 is built:**

1. A verified delegated scope is intersected with the callee's local Cedar policy before any capability is exercised.
2. The effective permission set is never larger than either input: delegation cannot widen local policy, and local policy cannot widen delegation.
3. A capability present in the delegated scope but denied by local policy is dropped from the effective set (defense in depth: the callee's own policy is authoritative on its side).
4. A capability allowed by local policy but absent from the delegated scope is dropped (delegation is authoritative on the caller's side).

**Why the intersection, not a union or an override:** each side owns half of the trust decision. The delegator bounds what the caller was authorized to ask for; the callee's local policy bounds what it will honor regardless of who asks. Neither side can escalate the other, so the safe combination is the set intersection.

## Running

```bash
# From repo root
pip install -e .
python experiments/claim3-scope-policy-intersection/run.py
```

## Expected output

`run.py` prints a SKIP banner explaining the Tier 2 dependency and exits 0, so it does not break CI or a dev host. It also prints a tiny illustrative set-intersection of a delegated scope against a mock local policy set, clearly labeled as illustrative and **not** the Cedar engine, to show the intended shape of the effective-permission computation.

```
Delegated scope intersected with local Cedar policy | Claim 3
========================================================================

SKIP: Tier 2 runtime scope-policy intersection is not implemented.
  - runtime peer-delegation enforcement not built (no call-time gate)
  - Cedar intersection not wired (no delegated-scope AND local-policy path)
See ROADMAP.md. Exiting 0 so CI and dev hosts pass.

Illustrative only (NOT the Cedar engine):
  delegated scope : {cap:read, cap:write, cap:admin}
  local policy    : {cap:read, cap:write, cap:audit}
  effective (∩)   : {cap:read, cap:write}
  dropped by policy   : {cap:admin}
  dropped by delegation: {cap:audit}
```
