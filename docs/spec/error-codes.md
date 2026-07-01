# Error Codes

Every failure the cA2A runtime and verifier raise is a subclass of `CA2AError`. Each subclass carries a stable `code` string and an `http_status`. The code is what you match on in tests and callers. The HTTP status is what a service should return when the error crosses an A2A boundary. Both are defined in `ca2a_runtime/errors.py` and are the authoritative values below.

An error also carries a human-readable message and an optional `detail`. The message and detail are not stable and are for diagnostics only. Match on `code`, never on message text.

## Registry

| Class | `code` | HTTP | When raised |
|---|---|---|---|
| `CA2AError` | `CA2A_ERROR` | 500 | Base class for all cA2A runtime and verifier errors. Not raised directly; caught to handle any cA2A failure generically. |
| `ConfigError` | `CONFIG_ERROR` | 500 | `Ca2aConfig` construction or `verify_chain_file` config load failed: unknown field, `max_delegation_depth` not a positive integer, missing config file, invalid YAML, or a non-mapping config root. |
| `InvalidCredential` | `INVALID_CREDENTIAL` | 400 | A `DelegationCredential` is malformed or its Ed25519 signature does not verify: unsigned credential, bad signature, malformed fields, or a chain document that is not a list or `{"chain": [...]}`, a missing chain file, or invalid JSON. |
| `ScopeEscalation` | `SCOPE_ESCALATION` | 403 | A child grant claims authority its parent did not hold. Raised by `verify_chain` when a hop's scope is not a subset of its parent's scope. |
| `BrokenDelegationLink` | `BROKEN_DELEGATION_LINK` | 409 | A hop does not chain to its stated parent, or continuity is broken: empty chain, a root credential that names a parent or has nonzero depth, a hop whose parent link or subject does not match the previous hop, or a hop depth that is not previous + 1. |
| `DelegationDepthExceeded` | `DELEGATION_DEPTH_EXCEEDED` | 403 | A chain is longer than the configured `max_delegation_depth`. Raised by `verify_chain`. |
| `CredentialReplay` | `CREDENTIAL_REPLAY` | 409 | A `credential_id` appears more than once in a single chain. Raised by `verify_chain`. |
| `AttestationUnsupported` | `ATTESTATION_UNSUPPORTED` | 500 | An attestation provider was requested that the host cannot supply. Raised by `SevSnpProvider.attest` off SEV-SNP hardware; also reserved for the TDX/TPM backends. See [Peer Attestation](attestation.md). |
| `AttestationFailed` | `ATTESTATION_FAILED` | 412 | Attestation evidence was present but did not verify. Raised by the SEV-SNP verifier on a malformed report, an untrusted or broken certificate chain, a bad report signature, or a measurement / report-data mismatch. See [Peer Attestation](attestation.md). |
| `SealedChannelError` | `SEALED_CHANNEL_ERROR` | 500 | The sealed peer channel could not construct or open a payload: an invalid peer public key, a malformed or unsupported sealed blob, a wrong key, or a tampered ciphertext (AEAD authentication failure). Fails closed; never returns unauthenticated plaintext. See [Sealed Channel](sealed-channel.md). |
| `ProvenanceLinkBroken` | `PROVENANCE_LINK_BROKEN` | 409 | A `DelegationRecord` does not chain to its stated parent record, or a record was tampered with so its hash no longer matches a child's link: empty provenance chain, duplicate `record_id`, a root record that references a parent, a broken parent hash link, or a record whose `credential_id` or subject does not match the chain. Raised by `verify_dag` and `cross_check_chain`. |
| `ScopeNotPermitted` | `SCOPE_NOT_PERMITTED` | 403 | A requested capability is not in the effective scope (the delegated leaf scope intersected with the callee's local policy). Raised by `enforce_peer_call`. |

## Which errors are live today

`ConfigError`, `InvalidCredential`, `ScopeEscalation`, `BrokenDelegationLink`, `DelegationDepthExceeded`, `CredentialReplay`, and `ProvenanceLinkBroken` are raised by shipping code paths: attenuated delegation, offline chain verification, and the provenance DAG. `ScopeNotPermitted` is raised by the peer-call enforcement decision core (`enforce_peer_call`), and `SealedChannelError` by the sealed channel (`SealedChannel.seal`, `open_sealed`), both of which are implemented.

`AttestationFailed` is raised by the SEV-SNP verifier (chain, report signature, and measurement binding), and `AttestationUnsupported` by `SevSnpProvider.attest` off hardware. Producing a real report requires a SEV-SNP guest, and the TDX/TPM backends are not yet implemented. See [Peer Attestation](attestation.md) and [ROADMAP.md](../../ROADMAP.md).

## Handling errors

Catch the base class to handle any cA2A failure, or a specific subclass to react to one condition. The `code` attribute gives you the stable identifier and `http_status` the status to surface.

```python
from ca2a_runtime.errors import CA2AError, ScopeEscalation
from ca2a_verify.verify import verify_chain_file

try:
    verify_chain_file("chain.json")
except ScopeEscalation as exc:
    # A hop claimed more than its parent granted.
    print(exc.code, exc.http_status)  # SCOPE_ESCALATION 403
except CA2AError as exc:
    # Any other cA2A failure.
    print(exc.code, exc.http_status, exc.detail)
```

Verification fails closed. `verify_chain`, `verify_dag`, and `cross_check_chain` raise the first error they find rather than returning a partial result, so a caught `CA2AError` means the chain or DAG was rejected.

## See also

- [Delegation Chain](delegation-chain.md) for the checks behind `ScopeEscalation`, `BrokenDelegationLink`, `DelegationDepthExceeded`, and `CredentialReplay`.
- [Provenance DAG](provenance-dag.md) for the checks behind `ProvenanceLinkBroken`.
- [Verification Library](verification-library.md) for `verify_chain`, `verify_chain_file`, `verify_dag`, and `cross_check_chain`.
- [Failure Modes](failure-modes.md) for how these errors map to observable runtime behavior.
