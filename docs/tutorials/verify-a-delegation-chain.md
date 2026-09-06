# Verify a Saved Delegation Chain

Save a locally generated chain, verify it using a separately retained root key, then detect an edited signature. This walkthrough builds on [authoring a delegation credential](authoring-a-delegation-credential.md): install that checkout and run its Python blocks first, in the same session. They define `chain`, `a_pub`, and `trusted_roots`, and already test a correctly signed scope escalation.

## Save and verify

```python
import json
from pathlib import Path
from ca2a_verify import verify_chain_file

Path("chain.json").write_text(json.dumps({
    "chain": [credential.body() | {"signature": credential.signature} for credential in chain]
}), encoding="utf-8")
Path("trusted-root.txt").write_text(a_pub, encoding="utf-8")

result = verify_chain_file("chain.json", trusted_root_issuers=trusted_roots)
assert result.hops == 3
assert result.leaf_scope == ["cap:read"]
print("verified 3 hops; leaf scope cap:read")
```

The trusted root was retained when you created the local authority. For an incoming production chain, obtain the approved root through your own trust configuration. Reading its issuer field and trusting it would let the chain authorize itself.

## Change a signed field

```python
from ca2a_runtime.errors import InvalidCredential

document = json.loads(Path("chain.json").read_text(encoding="utf-8"))
document["chain"][-1]["scope"].append("cap:admin")
Path("tampered-chain.json").write_text(json.dumps(document), encoding="utf-8")

try:
    verify_chain_file("tampered-chain.json", trusted_root_issuers=trusted_roots)
except InvalidCredential:
    print("edited signature rejected: INVALID_CREDENTIAL")
else:
    raise AssertionError("edited signed field accepted")
```

This checks signature integrity. To exercise attenuation, the overbroad grant must have a valid signature; the authoring walkthrough does that. Editing a signed `parent_id` also fails signature verification before it can demonstrate a continuity error.

## Use the CLI

In Bash:

```bash
ca2a verify-chain --chain chain.json --trusted-root-issuer "$(cat trusted-root.txt)"
```

In PowerShell:

```powershell
ca2a verify-chain --chain chain.json --trusted-root-issuer (Get-Content trusted-root.txt -Raw)
```

Expect exit 0 and `{"verified": true, "hops": 3, "leaf_scope": ["cap:read"]}`. Substituting `tampered-chain.json` should exit nonzero with `INVALID_CREDENTIAL`.

## What this establishes

You checked signed grants against a trusted issuer and rejected an edited credential. This does not execute a task, establish caller possession of the leaf key, or appraise hardware. Continue to [inbound peer-call decision](../spec/call-graph.md) for those runtime checks.
