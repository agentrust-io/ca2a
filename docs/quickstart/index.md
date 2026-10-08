# Verify your first delegation chain

This page is for anyone who wants to see cA2A's core check working on their own computer. You build a chain of two handoffs: a starting authority (the root) gives a middle agent permission to `read` and `write`, and the middle agent passes only `read` on to a final agent (the leaf). You then check the chain, and watch it refuse two bad cases: a root you never agreed to trust, and a correctly signed grant that asks for more than its parent had.

After installation, this example needs no network, no special hardware, and no running agents.

## Install

Use Python 3.11+, Git, and Bash on Linux, macOS, or Windows with WSL. Install from the current source checkout so the example uses the verification behavior documented here.

```
git clone https://github.com/agentrust-io/ca2a.git ca2a-quickstart
cd ca2a-quickstart
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Build an example chain

Save this complete block as `first_chain.py`, then run `python first_chain.py`:

```
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

```
PASS: two-hop chain verified; leaf scope is cap:read
PASS: untrusted root rejected
PASS: signed scope escalation rejected
Saved demo-chain.json and trusted-root.txt; private keys were not saved
```

## Verify it

Check the saved chain with the command-line tool. You pass in the root key you kept separately, which is how the checker knows which starting authority you trust:

```
ca2a verify-chain --chain demo-chain.json --trusted-root-issuer "$(cat trusted-root.txt)"
```

Expected exit code: `0`.

```
{"verified": true, "hops": 2, "leaf_scope": ["cap:read"], "revocation": "not_checked"}
```

In real use, the agent receiving the work (the relying party) decides which roots to trust through its own approval process. Copying the root out of an incoming chain and trusting it would let that chain choose its own authority.

## Try to break it

The script signs a child grant that asks for more than its parent had, and expects `SCOPE_ESCALATION` (scope is the list of permissions in a grant). If you instead edit a field in the saved JSON by hand, the signature check fails first. These are two different checks: a broken signature shows the file was changed, while the scope check shows a correctly signed grant still cannot widen its own permissions.

The checker also confirms that each grant was issued by the agent the previous grant was given to, that parent links and credential IDs line up, that the chain is not too long, and that each grant is inside its valid time window. It does not keep a list of every request it has seen before; stopping a live request from being replayed is a separate job for the running service.

## Build a chain in code

The script above uses the same `DelegationCredential` and `verify_chain` functions the running service uses. `trusted_root_issuers` is required: with no trusted root, nothing verifies. Keep the root grant and each child grant within your own authorization rules.

## What is not in this walkthrough

This example checks signed grants only. It does not run a task, check hardware, encrypt a task for another agent, or check the signed records each handoff leaves (the TRACE provenance chain). Read [How It Works](https://ca2a.agentrust-io.com/docs/concepts/index.md) for what happens on a live call between agents, and [Limitations](https://ca2a.agentrust-io.com/LIMITATIONS/index.md) for what has been shown on real hardware.

## Troubleshooting

- **Module not found:** activate `.venv` in the terminal running the example.
- **File not found:** run `first_chain.py` from the same directory as the CLI command.
- **Untrusted root:** use this demo's retained key. Do not trust keys solely because an incoming chain supplies them.
- **Expired credential:** the child lasts 30 minutes. Rerun the script to generate a fresh demo chain.

## Next steps

- [Architecture](https://ca2a.agentrust-io.com/docs/concepts/index.md): trust checks and runtime boundaries.
- [Delegation specification](https://ca2a.agentrust-io.com/docs/spec/delegation-chain/index.md): validation rules.
- [Limitations](https://ca2a.agentrust-io.com/LIMITATIONS/index.md): software and hardware assurance boundaries.
