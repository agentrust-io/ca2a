# Tutorial: Verify a Delegation Chain

This tutorial verifies a chain, then deliberately breaks each invariant to see the verifier reject it. No hardware needed.

## 1. Generate a valid chain

```bash
python scripts/gen_example_chain.py
ca2a verify-chain --chain examples/minimal/chain.json
# {"verified": true, "hops": 3, "leaf_scope": ["cap:read"]}
```

The chain grants `admin` at the root, narrows to `read+write`, then to `read`.

## 2. Break attenuation

Open `examples/minimal/chain.json` and add `"cap:admin"` to the `scope` of the last hop (the leaf held only `cap:read`). Re-run:

```bash
ca2a verify-chain --chain examples/minimal/chain.json
# {"verified": false, "code": "SCOPE_ESCALATION", ...}
```

The leaf claimed authority its parent did not hold. Regenerate to restore.

## 3. Break the link

Regenerate, then change the `parent_id` of the middle hop to `"nope"`:

```bash
ca2a verify-chain --chain examples/minimal/chain.json
# {"verified": false, "code": "BROKEN_DELEGATION_LINK", ...}
```

## 4. Tamper with a signed field

Regenerate, then change any signed field (for example a `scope` entry) without re-signing:

```bash
ca2a verify-chain --chain examples/minimal/chain.json
# {"verified": false, "code": "INVALID_CREDENTIAL", ...}
```

The signature no longer matches the canonical body.

## 5. Verify in code

```python
from ca2a_verify import verify_chain_file
from ca2a_runtime.errors import CA2AError

try:
    result = verify_chain_file("examples/minimal/chain.json")
    print(f"verified {result.hops} hops, leaf scope {result.leaf_scope}")
except CA2AError as exc:
    print(f"rejected: {exc.code}: {exc}")
```

## What you proved

You verified a chain of delegated authority, offline, without trusting whoever produced it. That is the property cA2A carries into the runtime peer path once attestation and sealing land.
