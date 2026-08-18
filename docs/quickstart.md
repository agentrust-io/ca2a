# Quick Start

This walkthrough builds a delegation chain and verifies it offline. It needs no hardware TEE and no network. It exercises the part of cA2A that is built today: attenuated delegation and offline chain verification.

## Install

```bash
pip install ca2a-runtime
```

Or run the published rootless container with a read-only configuration mount:

```bash
docker run --rm -p 8443:8443 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -v "$PWD/ca2a-config.yaml:/etc/ca2a/config.yaml:ro" \
  ghcr.io/agentrust-io/ca2a-runtime:v0.2.0 \
  start --config /etc/ca2a/config.yaml
```

The image runs as UID/GID 10001. Hardware-backed providers additionally need
the relevant device passed through with permissions for that identity; do not
run the whole container as root to obtain device access.

cA2A 0.2 is published as a normal release. Contributors working from a checkout can instead install from source: `pip install -e ".[dev]"`.

## Build an example chain

The repo ships a generator that produces a valid three-hop chain (`admin` narrows to `read+write` narrows to `read`):

```bash
python scripts/gen_example_chain.py
# wrote examples/minimal/chain.json
```

Each hop is a signed `DelegationCredential`. The scope of each hop is a subset of its parent, continuity is preserved (each issuer is the previous subject), and each hop links to its parent by `credential_id`.

## Verify it

```bash
ca2a verify-chain --chain examples/minimal/chain.json
# {"verified": true, "hops": 3, "leaf_scope": ["cap:read"]}
```

Verification checks four invariants and fails on the first violation:

1. **Signature** on every hop against the issuer's Ed25519 public key.
2. **Continuity**: each hop's issuer is the previous hop's subject.
3. **Attenuation**: each hop's scope is a subset of its parent's scope.
4. **Anti-replay**: `parent_id` links to the previous `credential_id` and every `credential_id` is unique.

## Try to break it

Edit `examples/minimal/chain.json` so a child hop adds a capability its parent did not hold, then re-run:

```bash
ca2a verify-chain --chain examples/minimal/chain.json
# {"verified": false, "code": "SCOPE_ESCALATION", "error": "hop 1 scope exceeds parent grant"}
```

## Build a chain in code

```python
from ca2a_runtime.delegation import DelegationCredential, new_keypair, verify_chain

root_priv, root_pub = new_keypair()
mid_priv, mid_pub = new_keypair()
_, leaf_pub = new_keypair()

root = DelegationCredential("c0", root_pub, mid_pub, frozenset({"cap:a", "cap:b"}), 0).sign(root_priv)
child = DelegationCredential("c1", mid_pub, leaf_pub, frozenset({"cap:a"}), 1, parent_id="c0").sign(mid_priv)

verify_chain([root, child])  # raises on any violation
```

## What is not in this walkthrough

The runtime peer path accepts a delegation credential on a live inbound A2A call, appraises the peer, seals the payload, enforces local policy, and emits signed provenance. The walkthrough defaults to software assurance; see [ROADMAP.md](../ROADMAP.md) and [LIMITATIONS.md](../LIMITATIONS.md) before making hardware-backed claims.
