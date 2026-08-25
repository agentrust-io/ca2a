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
| `not_before` | int, optional | Unix epoch seconds; the credential is not valid before this time (inclusive) |
| `not_after` | int, optional | Unix epoch seconds; the credential is not valid after this time (inclusive) |

## Canonicalization

The signed bytes are the RFC 8785 (JSON Canonicalization Scheme) encoding of the body: keys sorted by UTF-16 code units, JCS minimal string escaping, non-ASCII emitted literally as UTF-8, integers in shortest decimal form, `scope` as a sorted array. This is the byte string signed and verified. Using JCS makes the signed bytes deterministic and independently reproducible by conforming implementations of the cA2A credential schema. It does not make differently structured delegation objects signature-interchangeable. See `ca2a_runtime.canonical`.

The wire object is strict: fields are not coerced, unknown fields are rejected,
keys and signatures must use their exact lowercase hex encodings, `depth` must
be a non-negative JSON integer (not a boolean or float), and `scope` must be a
non-empty array of unique non-empty strings. This ensures the object accepted by
one implementation is the same signed object another implementation sees.

An absent validity bound is omitted from the body, not encoded as null: emitting
nulls would change the canonical bytes of every credential signed before the
fields existed. A bound that is present is part of the signed body (and must be
a non-negative JSON integer, never null), so it cannot be stripped or altered
without invalidating the signature.

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
| Each hop's validity window, when present, contains the evaluation time | `CREDENTIAL_NOT_YET_VALID` / `CREDENTIAL_EXPIRED` |
| The root issuer is pinned by the callee for runtime authorization | `UNTRUSTED_DELEGATION_ROOT` |

Signature validity establishes who issued a chain; it does not establish that
the issuer is trusted. A live callee therefore supplies its local
`trusted_root_issuers` set when verifying a request and fails closed when the
root is absent. Offline tooling may omit that set when it only needs to check a
chain's internal structure, but structural verification alone does not authorize
work.

## Validity window

`not_before` / `not_after` bound when a credential may be used, as Unix epoch
seconds, inclusive at both ends. Either bound may appear alone; an absent bound
means unbounded on that side, which is exactly what every credential issued
before these fields existed already says.

`verify_chain` checks every hop's window against a single evaluation time:
`at_time` when the caller supplies one, the current time otherwise. Live
authorization always evaluates now. Offline audit of recorded evidence should
pass the time the action was decided (`ca2a verify-chain --at-time`), because a
window that has lapsed by audit time says nothing about validity at decision
time.

Windows are not required to nest across hops. A chain is usable only at times
inside every hop's window, so the effective window is already the intersection
of the hops'; requiring structural nesting would add no authority bound.

## Attenuation is the whole point

Attenuation, the guarantee that a child grant cannot exceed its parent, is the confused-deputy defense. Without it, B could accept a narrow task from A and then act with authority A never granted. The subset check on `scope` at every hop is what forecloses that.

## Relationship to agent-manifest

The cA2A delegation model shares security goals and delegation semantics with
[agent-manifest](https://github.com/agentrust-io/agent-manifest), including
signed delegation and scope attenuation. The wire objects are nevertheless
distinct. cA2A signs `DelegationCredential` bodies, while agent-manifest signs
`DelegationHop` objects with a different field set and signature pre-image.

Sharing RFC 8785 canonicalization therefore does not make the two credential
formats directly signature-interchangeable. Interoperability is at the level of
delegation semantics and invariants unless an explicit cross-format binding is
defined.
