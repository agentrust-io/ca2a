# cA2A Conformance Suite

## Overview

A conforming cA2A implementation passes all MUST-level tests in this suite.
Implementations SHOULD also pass all SHOULD-level tests. Passing the MUST-level
tests for a given version is the bar for claiming **cA2A-compatible** for that
version, per the trademark language in [CHARTER.md](../../CHARTER.md).

Each test references the spec section it validates. Test IDs are stable: once
assigned, an ID is never reused even if the test is removed. This document is the
normative definition of what a conforming implementation must do; the runnable
checks in `test_profile_conformance.py` exercise these behaviors against the
reference implementation, and a third-party implementation is expected to satisfy
the same behaviors.

Run the suite:

```bash
pip install -e ".[dev]"
pytest tests/conformance/ -v
```

---

## Group 1: Delegation

Spec: [delegation-chain.md](../../docs/spec/delegation-chain.md)

| ID | Level | Requirement | Expected outcome |
|---|---|---|---|
| DELEG-001 | MUST | An unsigned or signature-tampered credential is rejected. | `INVALID_CREDENTIAL`. |
| DELEG-002 | MUST | A child scope that is not a subset of its parent is rejected. | `SCOPE_ESCALATION`. |
| DELEG-003 | MUST | A hop whose parent link or issuer breaks continuity, or whose depth is not previous + 1, is rejected. | `BROKEN_DELEGATION_LINK`. |
| DELEG-004 | MUST | A chain deeper than the configured maximum is rejected. | `DELEGATION_DEPTH_EXCEEDED`. |
| DELEG-005 | MUST | A `credential_id` that repeats within a chain is rejected. | `CREDENTIAL_REPLAY`. |
| DELEG-006 | MUST | A well-formed, strictly narrowing chain is accepted. | Verification succeeds. |

## Group 2: Scope-policy intersection

Spec: [cedar-policy.md](../../docs/spec/cedar-policy.md), [call-graph.md](../../docs/spec/call-graph.md)

| ID | Level | Requirement | Expected outcome |
|---|---|---|---|
| POLICY-001 | MUST | The effective scope is the delegated leaf scope intersected with the local policy, never wider than either. | Effective set equals the intersection. |
| POLICY-002 | MUST | A capability delegated but not locally allowed is denied. | `SCOPE_NOT_PERMITTED`. |
| POLICY-003 | MUST | A capability locally allowed but not delegated is denied. | `SCOPE_NOT_PERMITTED`. |

## Group 3: Attestation

Spec: [attestation.md](../../docs/spec/attestation.md)

| ID | Level | Requirement | Expected outcome |
|---|---|---|---|
| ATTEST-001 | MUST | Hardware providers without a backend are never auto-selected. | `detect()` returns False; generating a report fails closed with `ATTESTATION_UNSUPPORTED`. |
| ATTEST-002 | MUST | An attestation report whose measurement differs from the expected value is rejected. | `ATTESTATION_FAILED`. |
| ATTEST-003 | MUST | A report whose certificate chain does not reach a trusted root is rejected. | `ATTESTATION_FAILED`. |
| ATTEST-004 | MUST | A report with a tampered body or signature is rejected. | `ATTESTATION_FAILED`. |
| ATTEST-005 | MUST | A TDX quote whose MRTD differs from the expected value is rejected. | `ATTESTATION_FAILED`. |

## Group 4: Sealed channel

Spec: [sealed-channel.md](../../docs/spec/sealed-channel.md)

| ID | Level | Requirement | Expected outcome |
|---|---|---|---|
| SEAL-001 | MUST | A payload sealed to a peer's attested key opens only with that peer's private key. | Peer recovers the payload; any other key fails. |
| SEAL-002 | MUST | The sealed blob does not contain the plaintext. | Plaintext bytes absent from the sealed output. |
| SEAL-003 | MUST | A tampered sealed payload fails closed rather than returning plaintext. | `SEALED_CHANNEL_ERROR`. |

## Group 5: Provenance

Spec: [provenance-dag.md](../../docs/spec/provenance-dag.md), [trace-a2a-profile.md](../../docs/spec/trace-a2a-profile.md)

| ID | Level | Requirement | Expected outcome |
|---|---|---|---|
| PROV-001 | MUST | A well-formed linked-record DAG verifies. | Verification succeeds. |
| PROV-002 | MUST | A tampered or reparented record is detected. | `PROVENANCE_LINK_BROKEN`. |
| PROV-003 | MUST | Provenance is bound to authority: record i must match credential i. | Mismatch raises `PROVENANCE_LINK_BROKEN`. |

## Group 6: Inbound pipeline

Spec: [call-graph.md](../../docs/spec/call-graph.md)

| ID | Level | Requirement | Expected outcome |
|---|---|---|---|
| PIPE-001 | MUST | The handler grants only a capability in the effective scope and emits a linked provenance record. | Accepted call returns a verifiable record. |
| PIPE-002 | MUST | A sealed payload with no enclave key available fails closed. | `SEALED_CHANNEL_ERROR`; no payload returned. |
| PIPE-003 | MUST | An invalid delegation chain is rejected before any authorization or payload step. | The chain error is raised; no payload returned. |
