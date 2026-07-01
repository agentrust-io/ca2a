# Delegation Chain

A delegation chain is a root-to-leaf list of signed credentials. It is the primitive that lets Agent A hand a bounded slice of its authority to B, and B a still-smaller slice to C, with each grant provably within the one above it.

## Credential

A `DelegationCredential` has the following signed body plus a detached signature:

| Field | Type | Meaning |
|---|---|---|
| `credential_id` | string | Unique id of this hop |
| `issuer` | hex | Ed25519 public key of the delegator |
| `subject` | hex | Ed25519 public key of the delegate |
| `scope` | set of strings | Capabilities granted at this hop |
| `depth` | int | 0 at the root, +1 per hop |
| `parent_id` | string or null | `credential_id` of the parent hop; null at the root |
| `signature` | hex | Ed25519 over the canonical body, by the issuer |

## Canonicalization

The signed bytes are a deterministic JSON encoding of the body: sorted keys, compact separators, UTF-8, `scope` as a sorted array. This is the byte string signed and verified. It is a practical subset of RFC 8785 sufficient for the ASCII fields used here; full RFC 8785 alignment with agent-manifest is tracked on the roadmap.

## Verification invariants

`verify_chain` raises the specific error for the first invariant that fails:

| Invariant | Error on violation |
|---|---|
| Every hop's signature verifies against its issuer | `INVALID_CREDENTIAL` |
| Root has no parent and depth 0 | `BROKEN_DELEGATION_LINK` |
| Each hop's `parent_id` equals the previous `credential_id` | `BROKEN_DELEGATION_LINK` |
| Each hop's issuer equals the previous hop's subject | `BROKEN_DELEGATION_LINK` |
| Each hop's depth is previous + 1, and at most `max_depth` | `BROKEN_DELEGATION_LINK` / `DELEGATION_DEPTH_EXCEEDED` |
| Each hop's scope is a subset of its parent's scope | `SCOPE_ESCALATION` |
| No `credential_id` repeats | `CREDENTIAL_REPLAY` |

## Attenuation is the whole point

Attenuation, the guarantee that a child grant cannot exceed its parent, is the confused-deputy defense. Without it, B could accept a narrow task from A and then act with authority A never granted. The subset check on `scope` at every hop is what forecloses that.

## Relationship to agent-manifest

These semantics mirror the signed A2A delegation chain implemented and tested in [agent-manifest](https://github.com/agentrust-io/agent-manifest), including cross-manifest replay protection and HITL approval signing. cA2A's runtime calls that verifier on inbound peer requests; this module is the runtime-side model.
