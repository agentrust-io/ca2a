# Verification Library

`ca2a-verify` checks delegation credentials and signed TRACE record paths offline. The caller supplies trusted credential issuers and record-signing keys; cryptographic consistency alone does not establish authorization.

## API

```python
from ca2a_verify import verify_delegation_chain, verify_chain_file, ChainResult

result: ChainResult = verify_chain_file(
    "chain.json", trusted_root_issuers={"<trusted-root-issuer-hex>"}
)
# result.hops, result.root_issuer, result.leaf_subject, result.leaf_scope
```

- `verify_delegation_chain(chain, trusted_root_issuers=..., max_depth=8, at_time=None)` verifies a list of `DelegationCredential` against an explicit local root trust set and returns a `ChainResult` summary, or raises a `CA2AError` subtype.
- `verify_chain_file(path, trusted_root_issuers=..., max_depth=8, at_time=None)` loads a chain from JSON (a bare list, or `{"chain": [...]}`) and verifies it against that trust set.

Root trust is mandatory. A self-consistent chain from an unknown root is cryptographically well formed but is not authorized and therefore does not produce a successful verification result.

`at_time` is the Unix time validity windows are evaluated at; `None` means the current time. An auditor replaying recorded evidence passes the time the action was decided, not its own. See [delegation chain](delegation-chain.md).

## Errors

All verification failures are subtypes of `CA2AError`, re-exported as `VerificationError`. Each carries a stable `code` and an HTTP status. The specific codes and the invariants they map to are in [delegation chain](delegation-chain.md).

## Offline by design

Chain verification contacts no server. For reproducible historical checks, preserve the document, trust set, verifier version, and evaluation time. The default current-time validity check can change its verdict as credentials expire.

## Signed TRACE record paths

`verify_trace_dag(records, trusted_keys=..., max_age_seconds=None)` verifies signatures from trusted keys, record structure, and parent hashes along one ordered root-to-leaf path. It returns a `TraceDagResult`. The default omits a record-age limit for historical audits; supply `max_age_seconds` when freshness is required.

`cross_check_trace_dag(records, chain)` then checks path length and non-root credential IDs. Run credential and signed-record verification first. This cross-check does not independently bind TRACE subjects to credential subjects or prove task completion.

The API name uses DAG terminology, but the input is one ordered path, not an arbitrary branching tree. The unsigned `DelegationRecord` helper has a separate `verify_dag` consistency check; it is not a substitute for signature verification. See [provenance DAG](provenance-dag.md) and [TRACE A2A profile](trace-a2a-profile.md).
