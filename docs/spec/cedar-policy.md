# Scope-Policy Intersection (Cedar)

When a peer accepts a delegated task, two independent trust decisions meet. The delegator says what the caller was authorized to ask for; the callee's own policy says what it will honor regardless of who asks. The effective permission the peer exercises is the intersection of the two:

```
effective = delegated_scope ∩ local_policy_allow
```

Status: the intersection semantics are implemented as an enforcement decision core in `ca2a_runtime.peer` (`effective_scope`, `enforce_peer_call`), and the local policy can be either a capability allow set (`ca2a_runtime.policy.LocalPolicy`) or a real Cedar policy engine (`ca2a_runtime.cedar.CedarPolicy`, backed by `cedarpy`, the same engine cMCP runs). Both satisfy the `ca2a_runtime.policy.Policy` protocol, so they are interchangeable in the peer path. Validated by experiment C3 and the Cedar unit tests. What remains is wiring the decision core to a live A2A transport rather than a direct call. See [call-graph.md](call-graph.md) and [ROADMAP.md](../../ROADMAP.md).

## Cedar policy

`CedarPolicy` evaluates each capability as a Cedar authorization request whose action id is the capability name; a capability is permitted iff Cedar returns `Allow`. The effective scope is the delegated leaf scope intersected with the capabilities Cedar permits.

```python
from ca2a_runtime.cedar import CedarPolicy
from ca2a_runtime.peer import effective_scope

policy = CedarPolicy('permit(principal, action == Action::"read", resource);')
effective_scope(chain, policy)   # delegated leaf scope AND what Cedar allows
```

## Why an intersection

Each side owns half of the decision, and neither may escalate the other.

- Delegation is authoritative on the caller's side: a capability that is allowed by the callee's local policy but absent from the verified delegated scope is dropped. The caller was never granted it upstream, so local policy cannot manufacture it.
- Local policy is authoritative on the callee's side: a capability present in the delegated scope but denied by local policy is dropped. The delegator cannot force the callee to honor something the callee's own policy forbids.

The safe combination is therefore the set intersection, not a union and not an override. The effective set is never larger than either input. This is defense in depth: an error or compromise on one side cannot widen what the other side permits.

Attenuation across the chain already guarantees the delegated scope is a provable subset of the root grant (see [delegation chain](delegation-chain.md)). The Cedar intersection adds the callee's local constraint on top of that verified scope.

## Where it attaches

The intersection runs at the runtime peer-delegation enforcement point: the moment a peer accepts an inbound A2A task carrying a delegation credential. That enforcement point does not exist yet. The sequence it will slot into is described in [call-graph.md](call-graph.md). At a high level, on an inbound peer call the runtime will:

1. Verify the delegation chain (signature, continuity, attenuation, anti-replay) with `verify_chain`.
2. Verify the peer's attestation measurement (see [attestation](attestation.md)).
3. Compute `effective = delegated_scope ∩ local_policy_allow` and enforce it before any capability is exercised.

The verified leaf scope from step 1 is the `delegated_scope` input to step 3. Nothing between the two is exercised until the intersection is computed.

## Cedar engine reuse

cA2A does not ship its own policy engine. The local-policy half of the intersection reuses the Cedar policy engine already built and used in [cmcp](https://github.com/agentrust-io/cmcp), listed as a Tier 0 reused primitive on the roadmap. Cedar answers, for the calling principal and a requested action on a resource, whether local policy permits it. The runtime maps each capability string in the delegated scope to a Cedar authorization query and keeps only the capabilities Cedar allows.

The `policy_bundle_path` field on `Ca2aConfig` names the Cedar policy bundle the runtime will load. It is validated and carried through configuration today, but the runtime does not yet consume it because the enforcement point that would evaluate it is not built.

```python
from ca2a_runtime.config import Ca2aConfig

cfg = Ca2aConfig.load("ca2a.yaml")
cfg.policy_bundle_path   # path to the Cedar bundle; parsed but not yet enforced
cfg.enforcement_mode     # "enforcing" | "advisory" | "silent" (see below)
```

## Enforcement mode

`Ca2aConfig.enforcement_mode` selects what the runtime does with the computed effective set once the enforcement point lands:

| Mode | Intended behavior |
|---|---|
| `enforcing` | Deny any capability outside the effective set. This is the default and the fail-closed posture. |
| `advisory` | Compute and record the effective set, emit a warning on a capability outside it, but do not block. For rollout and observation. |
| `silent` | Compute and record only, no warning and no block. |

Today the field is validated by `Ca2aConfig.from_dict` but has no runtime effect, since there is no call-time gate to apply it at.

## Illustrative shape

The following shows the intended computation. It is illustrative only and is not the Cedar engine: it stands in a plain set intersection for what the runtime will do by mapping each capability to a Cedar authorization query. The `experiments/claim3-scope-policy-intersection/run.py` harness prints this same shape behind a SKIP banner, because the real path is gated on Tier 2.

```python
# Illustrative only. NOT the Cedar engine and NOT the runtime path.
delegated_scope = {"cap:read", "cap:write", "cap:admin"}   # verified leaf scope
local_policy_allow = {"cap:read", "cap:write", "cap:audit"} # what Cedar would allow here

effective = delegated_scope & local_policy_allow
# -> {"cap:read", "cap:write"}

dropped_by_policy = delegated_scope - local_policy_allow
# -> {"cap:admin"}       delegated, but local policy denies it

dropped_by_delegation = local_policy_allow - delegated_scope
# -> {"cap:audit"}       locally allowed, but never delegated
```

In the wired implementation `local_policy_allow` is not a precomputed set. Each capability in `delegated_scope` becomes a Cedar authorization query against the loaded bundle, and only the ones Cedar permits survive into `effective`.

## What lands in Tier 2

The scope-policy intersection depends on two Tier 2 runtime pieces, neither of which is built:

- Runtime peer-delegation enforcement: a call-time gate that accepts a delegation credential on a live inbound peer call and runs verification in the request path. `verify_chain` already checks the chain in isolation; there is no point at which it gates an actual peer-to-peer call.
- Cedar binding: the wiring from a verified delegated scope to the cmcp Cedar engine, and the effective-permission computation above.

Until both land, do not describe cA2A as enforcing local policy on delegated calls. See [ROADMAP.md](../../ROADMAP.md).
