# Verify your first delegation chain

Build a two-hop grant: a root gives an intermediary `read` and `write`, and the intermediary gives the leaf only `read`. Verify it, then reject an untrusted root and a correctly signed grant that exceeds its parent's authority. After installation, this example needs no network, hardware, or running peer.

## Install

Use Python 3.11+, Git, and Bash on Linux, macOS, or Windows with WSL. Install from the current source checkout so the example uses the verification behavior documented here.

```bash
git clone https://github.com/agentrust-io/ca2a.git ca2a-quickstart
cd ca2a-quickstart
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Build an example chain

Save this complete block as `first_chain.py`, then run `python first_chain.py`:

```python
import json
import time
from pathlib import Path

from ca2a_runtime.delegation import DelegationCredential, new_keypair, verify_chain
from ca2a_runtime.errors import CA2AError

root_priv, root_pub = new_keypair()
mid_priv, mid_pub = new_keypair()
_, leaf_pub = new_keypair()
now = int(time.time())
root = DelegationCredential(
    "demo-root", root_pub, mid_pub, frozenset({"cap:read", "cap:write"}), 0,
    not_before=now - 5, not_after=now + 3600,
).sign(root_priv)
child = DelegationCredential(
    "demo-child", mid_pub, leaf_pub, frozenset({"cap:read"}), 1,
    parent_id="demo-root", not_before=now - 5, not_after=now + 1800,
).sign(mid_priv)

# Retain the approved issuer separately from the chain being inspected.
trusted_roots = {root_pub}
verify_chain([root, child], trusted_root_issuers=trusted_roots)
print("PASS: two-hop chain verified; leaf scope is cap:read")

try:
    verify_chain([root, child], trusted_root_issuers=set())
except CA2AError as exc:
    assert exc.code == "UNTRUSTED_DELEGATION_ROOT", exc.code
    print("PASS: untrusted root rejected")
else:
    raise AssertionError("An untrusted root was accepted")

# Sign the invalid grant so this tests authorization, not edited signature bytes.
escalated = DelegationCredential(
    "demo-escalated", mid_pub, leaf_pub, frozenset({"cap:admin"}), 1,
    parent_id="demo-root", not_before=now - 5, not_after=now + 1800,
).sign(mid_priv)
try:
    verify_chain([root, escalated], trusted_root_issuers=trusted_roots)
except CA2AError as exc:
    assert exc.code == "SCOPE_ESCALATION", exc.code
    print("PASS: signed scope escalation rejected")
else:
    raise AssertionError("An escalated grant was accepted")

Path("demo-chain.json").write_text(json.dumps({
    "chain": [item.body() | {"signature": item.signature} for item in [root, child]]
}, indent=2))
Path("trusted-root.txt").write_text(root_pub)
print("Saved demo-chain.json and trusted-root.txt; private keys were not saved")
```

Expected output:

```text
PASS: two-hop chain verified; leaf scope is cap:read
PASS: untrusted root rejected
PASS: signed scope escalation rejected
Saved demo-chain.json and trusted-root.txt; private keys were not saved
```

## Verify it

Use the separately retained issuer key:

```bash
ca2a verify-chain --chain demo-chain.json --trusted-root-issuer "$(cat trusted-root.txt)"
```

Expected exit code: `0`.

```json
{"verified": true, "hops": 2, "leaf_scope": ["cap:read"]}
```

In production, the relying party obtains trusted roots through its own approval process. Copying the issuer from an arbitrary incoming chain into the trust list would let that chain choose its own authority.

## Try to break it

The script signs an overbroad child credential and expects `SCOPE_ESCALATION`. Editing a signed JSON field instead should fail the signature check first. These are different checks; an invalid signature does not demonstrate scope attenuation.

The verifier also checks issuer-to-subject continuity, parent links, unique credential IDs, depth, and validity windows. These offline checks do not keep a global ledger of previously accepted requests. Live request replay handling is a separate runtime concern.

## Build a chain in code

The complete script above uses the same `DelegationCredential` and `verify_chain` APIs as the runtime. `trusted_root_issuers` is required for a successful verification. Keep the root grant and each child grant bounded by your own authorization policy.

## What is not in this walkthrough

This example verifies signed grants. It does not execute tasks, appraise hardware, seal a network payload, or verify a TRACE provenance DAG. Follow [How It Works](concepts.md) for the live peer path and [Limitations](../LIMITATIONS.md) for the evidence that has been demonstrated.

## Troubleshooting

- **Module not found:** activate `.venv` in the terminal running the example.
- **File not found:** run `first_chain.py` from the same directory as the CLI command.
- **Untrusted root:** use this demo's retained key. Do not trust keys solely because an incoming chain supplies them.
- **Expired credential:** the child lasts 30 minutes. Rerun the script to generate a fresh demo chain.

## Next steps

- [Architecture](concepts.md): trust checks and runtime boundaries.
- [Delegation specification](spec/delegation-chain.md): validation rules.
- [Limitations](../LIMITATIONS.md): software and hardware assurance boundaries.
