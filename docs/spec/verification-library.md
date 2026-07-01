# Verification Library

`ca2a-verify` verifies a delegation chain, and eventually the delegation DAG, offline. It does not require trusting any operator: a chain is checked against the issuers' public keys and the attenuation invariants alone.

## API

```python
from ca2a_verify import verify_delegation_chain, verify_chain_file, ChainResult

result: ChainResult = verify_chain_file("chain.json")
# result.hops, result.root_issuer, result.leaf_subject, result.leaf_scope
```

- `verify_delegation_chain(chain, max_depth=8)` verifies a list of `DelegationCredential` and returns a `ChainResult` summary, or raises a `CA2AError` subtype.
- `verify_chain_file(path, max_depth=8)` loads a chain from JSON (a bare list, or `{"chain": [...]}`) and verifies it.

## Errors

All verification failures are subtypes of `CA2AError`, re-exported as `VerificationError`. Each carries a stable `code` and an HTTP status. The specific codes and the invariants they map to are in [delegation chain](delegation-chain.md).

## Offline by design

The verifier reads only the chain document. It contacts no server, trusts no operator signature over the transport, and produces the same verdict anywhere. This is what makes a delegation chain usable as evidence in an audit or a procurement review, not just at runtime.

## Not yet implemented

The delegation DAG verifier, which links each hop's TRACE record to its parent and checks the whole tree, lands with the Tier 2 provenance work. See [ROADMAP.md](../../ROADMAP.md).
