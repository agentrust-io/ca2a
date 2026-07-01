# Experiment: Delegated Scope Intersected with Local Policy

**Claim:** The capability set a caller may actually exercise is the intersection of its delegated scope with the local policy of the peer it calls (cA2A Claim 3).

**Status: validated.**

The enforcement decision core is `ca2a_runtime.peer.enforce_peer_call`: it verifies the delegation chain, computes the effective scope as the leaf's delegated scope intersected with the callee's `LocalPolicy`, and grants a requested capability only when it is in that intersection. Binding a full Cedar policy engine as the local policy is tracked separately (issue #10); the intersection semantics are what this claim establishes, and they are policy-language-agnostic.

**What it proves:**

1. The effective permission is the intersection of the verified delegated scope and the callee's local policy.
2. The effective set is never wider than either input: delegation cannot widen local policy, and local policy cannot widen delegation.
3. A capability delegated but not locally allowed is denied (the callee's policy is authoritative on its side).
4. A capability locally allowed but not delegated is denied (delegation is authoritative on the caller's side).

**Why the intersection, not a union or an override:** each side owns half of the trust decision. The delegator bounds what the caller was authorized to ask for; the callee's local policy bounds what it will honor regardless of who asks. Neither side can escalate the other, so the safe combination is the set intersection.

## Running

```bash
# From repo root
pip install -e ".[dev]"
python experiments/claim3-scope-policy-intersection/run.py
```

## Expected output

```
Claim 3: effective permission = delegated scope INTERSECT local policy
  leaf delegated scope: ['read', 'write']
  local policy allows:  ['audit', 'read']
  effective scope:      ['read']
  request read   -> ALLOW  OK
  request write  -> DENY   OK
  request audit  -> DENY   OK
  request admin  -> DENY   OK
KEY RESULT: effective scope ['read']; 1/1 allowed, 3/3 denied; capability granted only when delegated AND locally permitted
```
