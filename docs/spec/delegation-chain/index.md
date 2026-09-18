# Delegation Chain

A delegation chain is a root-to-leaf list of signed credentials. It is the primitive that lets Agent A hand a bounded slice of its authority to B, and B a still-smaller slice to C, with each grant provably within the one above it.

## Credential

A `DelegationCredential` has the following signed body plus a detached signature:

| Field           | Type           | Meaning                                                                      |
| --------------- | -------------- | ---------------------------------------------------------------------------- |
| `credential_id` | string         | Unique id of this hop                                                        |
| `issuer`        | hex            | Ed25519 public key of the delegator                                          |
| `subject`       | hex            | Ed25519 public key of the delegate                                           |
| `scope`         | set of strings | Capabilities granted at this hop                                             |
| `depth`         | int            | 0 at the root, +1 per hop                                                    |
| `parent_id`     | string or null | `credential_id` of the parent hop; null at the root                          |
| `signature`     | hex            | Ed25519 over the canonical body, by the issuer                               |
| `not_before`    | int, optional  | Unix epoch seconds; the credential is not valid before this time (inclusive) |
| `not_after`     | int, optional  | Unix epoch seconds; the credential is not valid after this time (inclusive)  |

## Canonicalization

The signed bytes are the RFC 8785 (JSON Canonicalization Scheme) encoding of the body: keys sorted by UTF-16 code units, JCS minimal string escaping, non-ASCII emitted literally as UTF-8, integers in shortest decimal form, `scope` as a sorted array. This is the byte string signed and verified. Using JCS makes the signed bytes deterministic and independently reproducible by conforming implementations of the cA2A credential schema. It does not make differently structured delegation objects signature-interchangeable. See `ca2a_runtime.canonical`.

The wire object is strict: fields are not coerced, unknown fields are rejected, keys and signatures must use their exact lowercase hex encodings, `depth` must be a non-negative JSON integer (not a boolean or float), and `scope` must be a non-empty array of unique non-empty strings. This ensures the object accepted by one implementation is the same signed object another implementation sees.

An absent validity bound is omitted from the body, not encoded as null: emitting nulls would change the canonical bytes of every credential signed before the fields existed. A bound that is present is part of the signed body (and must be a non-negative JSON integer, never null), so it cannot be stripped or altered without invalidating the signature.

## Verification invariants

`verify_chain` raises the specific error for the first invariant that fails:

| Invariant                                                                                                      | Error on violation                                     |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| Every hop's signature verifies against its issuer                                                              | `INVALID_CREDENTIAL`                                   |
| Root has no parent and depth 0                                                                                 | `BROKEN_DELEGATION_LINK`                               |
| Each hop's `parent_id` equals the previous `credential_id`                                                     | `BROKEN_DELEGATION_LINK`                               |
| Each hop's issuer equals the previous hop's subject                                                            | `BROKEN_DELEGATION_LINK`                               |
| Each hop's depth is previous + 1, and at most `max_depth`                                                      | `BROKEN_DELEGATION_LINK` / `DELEGATION_DEPTH_EXCEEDED` |
| Each hop's scope is a subset of its parent's scope                                                             | `SCOPE_ESCALATION`                                     |
| No `credential_id` repeats                                                                                     | `CREDENTIAL_REPLAY`                                    |
| Each hop's validity window, when present, contains the evaluation time                                         | `CREDENTIAL_NOT_YET_VALID` / `CREDENTIAL_EXPIRED`      |
| The root issuer is pinned by the callee for runtime authorization                                              | `UNTRUSTED_DELEGATION_ROOT`                            |
| No hop is revoked by its issuer or by an issuer above it (checked only when a revocation snapshot is supplied) | `CREDENTIAL_REVOKED`                                   |
| A snapshot no older than `max_revocation_staleness` was supplied (only when that bound is set)                 | `REVOCATION_STATUS_UNKNOWN`                            |

Signature validity establishes who issued a chain; it does not establish that the issuer is trusted. A live callee therefore supplies its local `trusted_root_issuers` set when verifying a request and fails closed when the root is absent. Offline tooling may omit that set when it only needs to check a chain's internal structure, but structural verification alone does not authorize work.

## Validity window

`not_before` / `not_after` bound when a credential may be used, as Unix epoch seconds, inclusive at both ends. Either bound may appear alone; an absent bound means unbounded on that side, which is exactly what every credential issued before these fields existed already says.

`verify_chain` checks every hop's window against a single evaluation time: `at_time` when the caller supplies one, the current time otherwise. Live authorization always evaluates now. Offline audit of recorded evidence should pass the time the action was decided (`ca2a verify-chain --at-time`), because a window that has lapsed by audit time says nothing about validity at decision time.

Windows are not required to nest across hops. A chain is usable only at times inside every hop's window, so the effective window is already the intersection of the hops'; requiring structural nesting would add no authority bound.

## Revocation

A validity window bounds how long a grant lasts. Revocation lets a party with authority over a grant withdraw it before `not_after`. See `ca2a_runtime.delegation.revocation`.

### Revocation statement

A `RevocationStatement` is a signed body plus a detached Ed25519 signature, canonicalized with the same RFC 8785 helper as credentials:

| Field            | Type   | Meaning                                                                                                                                            |
| ---------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `type`           | string | Always `ca2a.delegation-revocation.v1`. Signed, so a revocation signature cannot be taken for a signature over any other object the same key signs |
| `revoked_digest` | string | `sha256:` followed by the lowercase hex SHA-256 of the revoked credential's canonical body (the bytes its issuer signed)                           |
| `revoker`        | hex    | Ed25519 public key of the party withdrawing the grant                                                                                              |
| `issued_at`      | int    | Unix epoch seconds, as claimed by the revoker                                                                                                      |
| `signature`      | hex    | Ed25519 over the canonical body, by `revoker`                                                                                                      |

The wire object is strict in the same way a credential is: unknown or missing fields are rejected, so there is no field that could express an un-revoke.

### Who may revoke

A statement is effective against hop `i` of a chain only when `revoker` is the issuer of hop `i` or of an earlier hop. The delegator can withdraw what it granted, and any issuer above it can withdraw a grant made below it. The subject of hop `i` is not in that set, so a delegate cannot revoke the grant it received or anything above it. A validly signed statement from any other key has no effect on the chain. Authority is judged against the presented chain at verification time, after its structure has verified, because a statement names a credential rather than a chain.

Revoking hop `i` refuses every chain that contains it, which is every chain through which a grant beneath it could be exercised. The error names the first revoked hop.

Revocation is monotonic. A hop is revoked when any effective statement for it is present, so no statement, earlier or later, can reverse it.

### Snapshots and what verification reports

`verify_chain` takes an optional `RevocationSnapshot`: a set of statements plus `as_of`, the time its supplier last brought it up to date. Every statement's signature is checked when the snapshot is built, and a snapshot containing an unsigned or forged statement is refused as a whole with `INVALID_REVOCATION` rather than having the bad entry dropped, since dropping it would let tampering with the feed act as an un-revocation. `as_of` is asserted by the supplier and is not signed by any revoker.

`verify_chain` returns a `RevocationStatus`. With no snapshot, verification is exactly as before, still offline under P-4, and the status has `checked=False` (`not_checked`): the chain may have been revoked and the verifier would not know. With a snapshot and no revoked hop, the status has `checked=True` and carries the snapshot's `as_of` (`not_revoked`). `ChainResult`, `PeerResult` and the `ca2a verify-chain` output carry the same status, and the CLI prints it on every successful verification.

`max_revocation_staleness` (seconds, default unset) makes revocation checking mandatory. With it set, a missing snapshot, or one whose `as_of` is more than that many seconds before the evaluation time, raises `REVOCATION_STATUS_UNKNOWN`. It is unset by default so that offline verification with no revocation data keeps working. A stale snapshot can still prove a hop revoked, since revocation is monotonic, so a revoked hop is reported as `CREDENTIAL_REVOKED` before staleness is judged.

When `at_time` is supplied, only statements with `issued_at` at or before it count, so an audit of a past decision is not rewritten by a revocation issued afterwards. Without `at_time` (a live decision), every statement the verifier holds applies, whatever the revoker's clock said.

### Out of scope

cA2A defines no protocol for publishing or fetching revocation statements. Getting current snapshots to verifiers is the deployment's job. A verifier with no snapshot cannot learn of a revocation; it is told that it did not check. A snapshot supplier can withhold statements. `PeerNode` accepts a `revocation_source` callable that it consults on every call, but the config-driven `ca2a start` does not load one.

## Attenuation is the whole point

Attenuation, the guarantee that a child grant cannot exceed its parent, is the confused-deputy defense. Without it, B could accept a narrow task from A and then act with authority A never granted. The subset check on `scope` at every hop is what forecloses that.

## Relationship to agent-manifest

The cA2A delegation model shares security goals and delegation semantics with [agent-manifest](https://github.com/agentrust-io/agent-manifest), including signed delegation and scope attenuation. The wire objects are nevertheless distinct. cA2A signs `DelegationCredential` bodies, while agent-manifest signs `DelegationHop` objects with a different field set and signature pre-image.

Sharing RFC 8785 canonicalization therefore does not make the two credential formats directly signature-interchangeable. Interoperability is at the level of delegation semantics and invariants unless an explicit cross-format binding is defined.
