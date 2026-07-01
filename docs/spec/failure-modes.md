# Failure Modes

cA2A fails closed. Every check on the delegation path either produces positive, verifiable evidence that a request is authorized, or it denies. There is no third state where a request proceeds with a warning attached. The guiding principle is this:

**Absence of evidence is denial, not a warning.**

An unsigned credential, a measurement that cannot be checked, a provenance record whose parent link does not resolve: each of these is treated as a failure, not a soft signal. This page enumerates the failure paths, the error each one raises, and which paths are enforced today versus which fail closed pending Tier 2/3 work.

Each failure below names its error code. The codes and their HTTP mappings are defined in [error-codes.md](error-codes.md); the adversary these defenses assume is in [threat-model.md](threat-model.md).

## Delegation chain failures (enforced today)

`verify_chain` walks a root-to-leaf list of credentials and raises the specific error for the first invariant that fails. It never returns a partial or "mostly valid" result. See [delegation-chain.md](delegation-chain.md) for the full invariant table.

### Unsigned or invalid credential

A credential with an empty `signature`, or one whose signature does not verify against the `issuer` public key, is rejected.

```python
from ca2a_runtime.delegation import DelegationCredential, verify_chain
from ca2a_runtime.errors import InvalidCredential

try:
    verify_chain(chain)
except InvalidCredential as exc:
    # code == "INVALID_CREDENTIAL"
    deny(exc)
```

`verify_signature` raises `InvalidCredential` on an unsigned credential ("credential is unsigned") and on a signature that fails Ed25519 verification. `DelegationCredential.from_dict` raises the same error on a malformed body (missing or wrong-typed fields). A credential the verifier cannot authenticate is not trusted, full stop.

### Scope escalation

A child hop whose `scope` is not a subset of its parent's `scope` is rejected with `SCOPE_ESCALATION`. This is the confused-deputy defense: a delegate cannot act with authority its delegator never held.

```python
from ca2a_runtime.errors import ScopeEscalation

try:
    verify_chain(chain)
except ScopeEscalation as exc:
    # exc.detail names the capabilities that were added, e.g. "added: ['payments:write']"
    deny(exc)
```

The subset check runs at every hop. Adding even one capability the parent did not grant fails the whole chain.

### Broken link

`BROKEN_DELEGATION_LINK` covers every break in chain continuity:

- the root names a parent, or the root's `depth` is not 0;
- a hop's `parent_id` does not equal the previous hop's `credential_id`;
- a hop's `issuer` is not the previous hop's `subject`;
- a hop's `depth` is not the previous hop's `depth` plus 1;
- the chain is empty.

Any one of these means the chain is not a single unbroken delegation from root issuer to leaf subject, so it is denied.

### Depth exceeded

A hop whose `depth` exceeds `max_depth` (default 8) raises `DELEGATION_DEPTH_EXCEEDED`. This bounds the length of any accepted delegation and caps the blast radius of a runaway re-delegation.

```python
verify_chain(chain, max_depth=8)  # raises DelegationDepthExceeded past the limit
```

### Replay

If any `credential_id` appears more than once in a chain, verification raises `CREDENTIAL_REPLAY`. A credential minted for one hop cannot be spliced back into the same chain or reused to fabricate a loop. Cross-chain replay protection is the sibling guarantee carried over from [agent-manifest](https://github.com/agentrust-io/agent-manifest); this module enforces the within-chain uniqueness half.

## Provenance failures (enforced today)

The provenance DAG is verifiable offline. `verify_dag` recomputes each record's hash and confirms the stored parent link matches. See [provenance-dag.md](provenance-dag.md) for the record model.

### Tamper or reparent

Each `DelegationRecord` links to its parent by the SHA-256 hash of the parent record's canonical body. Changing any field of a record (its `scope`, `subject`, `record_id`, or its own parent link) changes that record's hash, which breaks the link the child stored. `verify_dag` raises `PROVENANCE_LINK_BROKEN`:

```python
from ca2a_runtime.provenance import verify_dag
from ca2a_runtime.errors import ProvenanceLinkBroken

try:
    verify_dag(records)
except ProvenanceLinkBroken as exc:
    # code == "PROVENANCE_LINK_BROKEN"
    deny(exc)
```

`verify_dag` denies when:

- the record list is empty;
- the first record carries a parent link (a root must not reference a parent);
- any later record's `parent_record_hash` does not equal the recomputed hash of the immediately preceding record (this catches both tampering and reparenting);
- a `record_id` repeats.

`cross_check_chain` ties provenance back to authority: record `i` must reference credential `i` and carry the same `subject`. A mismatch in length, `credential_id`, or `subject` raises `PROVENANCE_LINK_BROKEN`. A verified DAG that does not line up with the delegation chain it claims to describe is not accepted as evidence.

## Attestation failures (fails closed; hardware pending Tier 3)

Peer attestation proves a peer runs measured code before a task is trusted to it. Two error codes govern the failure paths, defined in [attestation.md](attestation.md):

- `ATTESTATION_UNSUPPORTED` (`AttestationUnsupported`): no attestation backend is available for the requested platform.
- `ATTESTATION_FAILED` (`AttestationFailed`): a backend ran but the measurement or quote did not verify.

Real hardware providers (`tpm`, `sev-snp`, `tdx`, `opaque`) return `False` from `detect()` in this release, so they are never auto-selected, and verification against an absent backend fails closed rather than assuming a peer is trustworthy. The `software-only` provider is for development and CI and never reports a hardware platform string. Until at least one real hardware backend verifies a quote, cA2A must not be described as attested across a trust boundary. This is Tier 3 on the [roadmap](../../ROADMAP.md) and a shared critical path with cmcp.

## Missing or failed attestation is denial

The same principle applies with force here: a peer that cannot produce a verifiable measurement is denied the task, not granted it "unless proven bad." A valid A2A Signed Agent Card is not a substitute for attestation. A card says the domain owner issued it; it says nothing about whether the code behind the card is the code that was measured.

## Sealed channel (not yet implemented; fails closed)

The sealed peer channel binds a payload key to a peer's attested measurement so the task decrypts only inside the peer's verified enclave. It is Tier 2 and **not yet implemented**. Critically, the placeholder does not degrade to plaintext. `SealedChannel.seal` and `SealedChannel.open` raise `SealedChannelError` rather than pass a payload in the clear:

```python
from ca2a_runtime.channel.sealed import SealedChannel
from ca2a_runtime.errors import SealedChannelError

channel = SealedChannel(peer_measurement="...")
try:
    wire = channel.seal(payload)
except SealedChannelError as exc:
    # code == "SEALED_CHANNEL_ERROR"
    # No plaintext was emitted. Do not send the payload.
    abort(exc)
```

Instantiation is allowed so the runtime can be wired against the interface, but the sealing operations fail closed. Do not send confidential task payloads across a trust boundary and assume they are protected until this lands. See [sealed-channel.md](sealed-channel.md) and [LIMITATIONS.md](../../LIMITATIONS.md).

## What is enforced today versus pending

| Failure mode | Error | Status |
|---|---|---|
| Unsigned or invalid credential | `INVALID_CREDENTIAL` | Enforced today |
| Scope escalation | `SCOPE_ESCALATION` | Enforced today |
| Broken delegation link | `BROKEN_DELEGATION_LINK` | Enforced today |
| Depth exceeded | `DELEGATION_DEPTH_EXCEEDED` | Enforced today |
| Credential replay (within chain) | `CREDENTIAL_REPLAY` | Enforced today |
| Provenance tamper or reparent | `PROVENANCE_LINK_BROKEN` | Enforced today |
| Runtime peer-delegation enforcement in the live request path | `SCOPE_ESCALATION` / others | Pending Tier 2 |
| Cedar scope intersection at the peer | (design) | Pending Tier 2 |
| Sealed channel (fails closed, never emits plaintext) | `SEALED_CHANNEL_ERROR` | Interface only, Tier 2 |
| Missing or failed attestation | `ATTESTATION_UNSUPPORTED` / `ATTESTATION_FAILED` | Fails closed; hardware backend Tier 3 |

The failures marked "enforced today" are exercised by the offline verifiers (`verify_chain`, `verify_chain_file`, `verify_dag`, `cross_check_chain`). The Tier 2/3 rows fail closed by design: the sealed channel raises instead of sending plaintext, and hardware attestation denies instead of trusting an unmeasured peer. What is not present is the live inbound request path that would apply chain verification, Cedar intersection, and sealing to a real peer call. That is Tier 2. See [LIMITATIONS.md](../../LIMITATIONS.md) and the [roadmap](../../ROADMAP.md) for sequencing.
