# Authoring a Delegation Credential

The [verify-a-delegation-chain](verify-a-delegation-chain.md) tutorial takes an existing chain apart. This one builds one from scratch: generate keys, construct a `DelegationCredential`, sign it, extend it into a narrowing multi-hop chain, and verify the result. Then we make a child over-scope and watch `verify_chain` reject it with `SCOPE_ESCALATION`. No hardware needed.

Everything here uses `ca2a_runtime.delegation`. For the field semantics and the full invariant table, see [the delegation chain spec](../spec/delegation-chain.md).

## 1. Generate keypairs

Each hop is signed by its issuer and names a subject. Both are Ed25519 public keys, encoded as raw hex. `new_keypair()` returns the private key object and its public key hex.

```python
from ca2a_runtime.delegation import new_keypair

a_priv, a_pub = new_keypair()  # root agent A
b_priv, b_pub = new_keypair()  # agent B
c_priv, c_pub = new_keypair()  # agent C
```

`a_pub` is the string you will place in a credential's `issuer` or `subject` field. Keep the private keys; you sign with them.

## 2. Build and sign the root credential

A `DelegationCredential` is a frozen dataclass. Construct it unsigned, then call `.sign()` with the issuer's private key. `sign()` returns a new signed copy; it does not mutate the original.

```python
from ca2a_runtime.delegation import DelegationCredential

root = DelegationCredential(
    credential_id="cred-0",
    issuer=a_pub,
    subject=b_pub,
    scope=frozenset({"cap:read", "cap:write", "cap:admin"}),
    depth=0,
    parent_id=None,
).sign(a_priv)
```

The root credential must have `depth=0` and `parent_id=None`; `verify_chain` rejects a root that names a parent or carries a non-zero depth. `scope` is a `frozenset[str]` of capability strings. The signature is computed over the canonical body (sorted keys, compact separators, UTF-8, `scope` as a sorted array), so the exact set of scope strings is bound into the signature.

`sign()` checks that the signing key matches the `issuer` field. Signing with the wrong key raises `INVALID_CREDENTIAL`:

```python
root_wrong = DelegationCredential(
    credential_id="cred-0",
    issuer=a_pub,
    subject=b_pub,
    scope=frozenset({"cap:read"}),
    depth=0,
).sign(b_priv)  # raises InvalidCredential: signing key does not match credential issuer
```

## 3. Extend the chain with narrowing scope

Each subsequent hop is issued by the previous hop's subject. Continuity is the rule that a hop's `issuer` equals the previous hop's `subject`, its `parent_id` equals the previous hop's `credential_id`, and its `depth` is the previous depth plus one. B, holding `read+write+admin`, delegates a narrower `read+write` slice to C:

```python
mid = DelegationCredential(
    credential_id="cred-1",
    issuer=b_pub,               # == root.subject
    subject=c_pub,
    scope=frozenset({"cap:read", "cap:write"}),  # subset of root.scope
    depth=1,                    # root.depth + 1
    parent_id="cred-0",         # == root.credential_id
).sign(b_priv)                  # signed by B, the issuer

d_priv, d_pub = new_keypair()   # agent D

leaf = DelegationCredential(
    credential_id="cred-2",
    issuer=c_pub,               # == mid.subject
    subject=d_pub,
    scope=frozenset({"cap:read"}),  # subset of mid.scope
    depth=2,
    parent_id="cred-1",
).sign(c_priv)                  # signed by C
```

Scope narrows at every hop: `{read, write, admin}` to `{read, write}` to `{read}`. Attenuation requires each hop's `scope` to be a subset of its parent's; it may stay the same or shrink, never grow.

## 4. Verify the chain

Order the credentials root to leaf and call `verify_chain`. It returns `None` on success and raises the specific `CA2AError` subtype on the first invariant that fails.

```python
from ca2a_runtime.delegation import verify_chain

chain = [root, mid, leaf]
verify_chain(chain)  # returns None: all invariants hold
print("verified", len(chain), "hops; leaf scope", sorted(leaf.scope))
```

`verify_chain` takes an optional `max_depth` keyword (default `8`). A hop whose `depth` exceeds it raises `DELEGATION_DEPTH_EXCEEDED`.

```python
verify_chain(chain, max_depth=1)  # raises DelegationDepthExceeded at hop 2
```

## 5. Watch a child over-scope

Now make C claim authority B never granted it. B delegated `{read, write}`; the leaf tries to grant `cap:admin`:

```python
over = DelegationCredential(
    credential_id="cred-2",
    issuer=c_pub,
    subject=d_pub,
    scope=frozenset({"cap:read", "cap:admin"}),  # admin was never in mid.scope
    depth=2,
    parent_id="cred-1",
).sign(c_priv)

from ca2a_runtime.errors import ScopeEscalation

try:
    verify_chain([root, mid, over])
except ScopeEscalation as exc:
    print(exc.code, "-", exc, "|", exc.detail)
    # SCOPE_ESCALATION - hop 2 scope exceeds parent grant | added: ['cap:admin']
```

The signature on `over` is valid; C really did sign it. That is the point. A well-formed signature proves only that C authored the grant, not that C was entitled to make it. The subset check on `scope` is what forecloses the confused-deputy move where a delegate quietly widens its own authority. See [the delegation chain spec](../spec/delegation-chain.md#attenuation-is-the-whole-point).

## 6. Serialize for the wire

`.body()` returns the signed portion as a plain dict; add the `signature` to get the full JSON object. `DelegationCredential.from_dict()` reverses it. This is the shape the [`ca2a verify-chain` CLI](verify-a-delegation-chain.md) and `ca2a_verify.verify_chain_file` consume.

```python
import json

record = root.body() | {"signature": root.signature}
wire = json.dumps({"chain": [record]})

restored = DelegationCredential.from_dict(json.loads(wire)["chain"][0])
restored.verify_signature()  # raises InvalidCredential if the body was tampered with
```

A malformed dict (missing field, wrong type) raises `INVALID_CREDENTIAL` from `from_dict`; a body that was altered after signing raises `INVALID_CREDENTIAL` from `verify_signature`, because the canonical bytes no longer match the detached signature.

## What you built

You produced a three-hop chain of delegated authority whose scope provably narrows at each hop, and you confirmed that a child cannot silently widen its grant. This chain verifies offline, with no trust in whoever produced it, using only the issuers' public keys embedded in the credentials.

The cA2A runtime calls this same verifier on the inbound peer path. Runtime peer enforcement, intersecting a verified scope against the peer's local Cedar policy, is Tier 2 and not yet implemented; see [LIMITATIONS](../../LIMITATIONS.md) and the [Cedar policy](../spec/cedar-policy.md) design. To carry these credentials into a checkable provenance DAG, continue to [emit and verify provenance](emit-and-verify-provenance.md).
