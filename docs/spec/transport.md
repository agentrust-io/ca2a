# Transport Binding

cA2A is a profile on A2A, not a competing transport. A2A moves tasks and context between agents and authenticates a peer's domain with the Signed Agent Card. cA2A adds a trust envelope around a delegated task and leaves the wire protocol untouched. This page states how the profile attaches to the transport and what a peer does with the attached data. For the higher-level statement of what the profile adds and where, see [the A2A profile binding](profile.md).

This page describes the intended binding. The live runtime peer path that reads these fields and enforces them on an inbound call is Tier 2 and is not yet built. See [ROADMAP.md](../../ROADMAP.md) and [LIMITATIONS.md](../../LIMITATIONS.md).

## Overlay, not fork

cA2A does not define its own transport, message framing, or handshake. It rides inside A2A. Two pieces of cA2A data travel with a task:

- The **delegation credential** (or the chain root-to-leaf), naming issuer, subject, scope, depth, and parent link. See [the delegation chain](delegation-chain.md).
- The **sealing metadata**, binding the task payload to the peer's attested measurement. Sealing itself is Tier 2 and fails closed today; see [the sealed channel](sealed-channel.md).

Both ride in A2A extension fields. cA2A claims no new wire format and no new endpoint. Removing every cA2A field leaves a valid A2A task.

## Attachment points

The credential and the sealing metadata are carried in A2A extension fields on the task message, alongside the payload A2A already moves. cA2A does not rewrite the A2A message, change its routing, or interpose a new transport under it. The Signed Agent Card remains the A2A identity anchor; cA2A treats it as the anchor the delegation credential's `subject` and the peer's attestation measurement are checked against.

## Ignore versus enforce

Carrying the trust envelope in extension fields is what keeps the profile an overlay:

- A **non-cA2A peer** does not understand the extension fields and ignores them. The task is handled as a plain A2A task. cA2A adds nothing the peer must be upgraded to parse.
- A **cA2A peer** reads the fields and enforces them before accepting the task: it verifies the delegation chain, checks the peer measurement, and (when Tier 2 lands) intersects the delegated scope with local policy and opens the sealed payload.

This asymmetry means a cA2A deployment interoperates with A2A peers that have never heard of cA2A. Trust is enforced wherever both ends speak the profile, without partitioning the network.

## What a cA2A peer enforces on inbound

The intended inbound order on a cA2A peer, once the Tier 2 runtime path exists:

1. Extract the delegation chain from the extension fields and verify it offline with `verify_chain`. Any violation denies the call with the specific error: `INVALID_CREDENTIAL`, `BROKEN_DELEGATION_LINK`, `SCOPE_ESCALATION`, `DELEGATION_DEPTH_EXCEEDED`, or `CREDENTIAL_REPLAY`. See [error codes](error-codes.md).
2. Check the peer's attestation measurement against the expected value. Not yet implemented; attestation fails closed today (`ATTESTATION_UNSUPPORTED` / `ATTESTATION_FAILED`). See [attestation](attestation.md).
3. Intersect the delegated scope with the local Cedar policy. Tier 2; see [Cedar policy](cedar-policy.md).
4. Open the payload sealed to the peer measurement. Tier 2; the sealed channel raises `SEALED_CHANNEL_ERROR` rather than send plaintext today. See [the sealed channel](sealed-channel.md).
5. Emit a linked TRACE record referencing the parent record hash and `credential_id`, forming the delegation DAG. See [the TRACE A2A profile](trace-a2a-profile.md).

Steps 1 and 5 are the verifiable, offline parts and are what `ca2a-verify` checks today. Steps 2 through 4 are the runtime enforcement path that Tier 2 introduces.

The verifier that step 1 uses is exactly the one exposed for offline use. A chain extracted from the transport is the same `list[DelegationCredential]` the CLI verifies from a file:

```python
from ca2a_runtime.delegation.credential import DelegationCredential, verify_chain

# chain reconstructed from the A2A extension fields, root to leaf
chain = [DelegationCredential.from_dict(hop) for hop in inbound_hops]
verify_chain(chain, max_depth=8)  # raises the specific CA2AError on any violation
```

## Enforcement is a peer decision

How strictly a cA2A peer acts on the extension fields is local configuration, not a transport-level flag. `Ca2aConfig.enforcement_mode` selects the behavior:

- `enforcing`: an unverifiable chain or a missing required credential denies the call. This is the default and the fail-closed posture the profile calls for.
- `advisory`: the failure is recorded but the call proceeds.
- `silent`: the check runs without a visible signal.

```yaml
# ca2a config
attestation:
  provider: auto
  enforcement_mode: enforcing
max_delegation_depth: 8
```

`max_delegation_depth` bounds the chain length a peer will accept and is passed through to `verify_chain`. The config surface is defined and validated today; the runtime that consumes it on a live inbound call is Tier 2. See [failure modes](failure-modes.md) for how each mode behaves under a denied call.

## Transport stability

This binding targets A2A v1.x extension points. A2A is now stable at v1.x, which clears the precondition the profile depended on. The delegation-link block that the TRACE A2A profile adds also targets those extension points; see [the TRACE A2A profile](trace-a2a-profile.md). Confirming the specific extension fields cA2A occupies remain stable across A2A point releases is tracked on [ROADMAP.md](../../ROADMAP.md).
