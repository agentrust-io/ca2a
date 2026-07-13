# Quick Start

This walkthrough builds a delegation chain and verifies it offline. It needs no hardware TEE and no network. It exercises the part of cA2A that is built today: attenuated delegation and offline chain verification.

## Install

```
pip install --pre ca2a-runtime
```

cA2A is in alpha, so `--pre` is required to opt into the pre-release. Contributors working from a checkout can instead install from source: `pip install -e ".[dev]"`.

## Build an example chain

The repo ships a generator that produces a valid three-hop chain (`admin` narrows to `read+write` narrows to `read`):

```
python scripts/gen_example_chain.py
# wrote examples/minimal/chain.json
```

Each hop is a signed `DelegationCredential`. The scope of each hop is a subset of its parent, continuity is preserved (each issuer is the previous subject), and each hop links to its parent by `credential_id`.

## Verify it

```
ca2a verify-chain --chain examples/minimal/chain.json
# {"verified": true, "hops": 3, "leaf_scope": ["cap:read"]}
```

Verification checks four invariants and fails on the first violation:

1. **Signature** on every hop against the issuer's Ed25519 public key.
1. **Continuity**: each hop's issuer is the previous hop's subject.
1. **Attenuation**: each hop's scope is a subset of its parent's scope.
1. **Anti-replay**: `parent_id` links to the previous `credential_id` and every `credential_id` is unique.

## Try to break it

Edit `examples/minimal/chain.json` so a child hop adds a capability its parent did not hold, then re-run:

```
ca2a verify-chain --chain examples/minimal/chain.json
# {"verified": false, "code": "SCOPE_ESCALATION", "error": "hop 1 scope exceeds parent grant"}
```

## Build a chain in code

```
from ca2a_runtime.delegation import DelegationCredential, new_keypair, verify_chain

root_priv, root_pub = new_keypair()
mid_priv, mid_pub = new_keypair()
_, leaf_pub = new_keypair()

root = DelegationCredential("c0", root_pub, mid_pub, frozenset({"cap:a", "cap:b"}), 0).sign(root_priv)
child = DelegationCredential("c1", mid_pub, leaf_pub, frozenset({"cap:a"}), 1, parent_id="c0").sign(mid_priv)

verify_chain([root, child])  # raises on any violation
```

## What is not in this walkthrough

The runtime peer path (accepting a delegation credential on a live inbound A2A call, attesting the peer, sealing the payload) is under construction. See [ROADMAP.md](https://ca2a.agentrust-io.com/ROADMAP/index.md) and [LIMITATIONS.md](https://ca2a.agentrust-io.com/LIMITATIONS/index.md).
