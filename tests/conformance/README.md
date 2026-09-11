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
| DELEG-007 | MUST | A credential whose `not_after` is before the evaluation time is rejected. | `CREDENTIAL_EXPIRED`. |
| DELEG-008 | MUST | A credential whose `not_before` is after the evaluation time is rejected. | `CREDENTIAL_NOT_YET_VALID`. |
| DELEG-009 | MUST | A well-formed chain whose evaluation time falls within every hop's validity window is accepted. | Verification succeeds. |

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
| ATTEST-001 | MUST | A hardware provider is never selected on a host where it cannot produce evidence. | `detect()` returns False wherever collection is impossible, and `attest()` fails closed with `ATTESTATION_UNSUPPORTED` naming the missing piece rather than the platform. |
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

## Group 7: Delegation-linked action evidence

Spec: [trace-a2a-profile.md](../../docs/spec/trace-a2a-profile.md), [provenance-dag.md](../../docs/spec/provenance-dag.md), [call-graph.md](../../docs/spec/call-graph.md)

The ACTION helper checks delegation-linked action evidence and reports its
verdict on three separate axes, so a correct denial or a correct rejection
is never confused with a broken or absent provenance chain:

| Field | Question it answers | Values |
|---|---|---|
| `provenance_status` | Did the delegation chain and its linked TRACE/provenance records check out? | `verified`, `invalid`, `missing`, `not_evaluated` |
| `authorization_decision` | Was the requested capability actually allowed by the delegated scope and local policy? | `allowed`, `denied`, `not_evaluated` |
| `controller_outcome` | What did the controller report for the action? | `accepted`, `rejected`, `not_evaluated` |

**Security order.** `provenance_status` is checked first. `authorization_decision`
is only reported once provenance is verified; a provenance failure reports
authorization and controller as `not_evaluated` rather than guessing at
either. `controller_outcome` is reported only once authorization allows the
request, for the same reason. A local-policy or scope denial (ACTION-005,
ACTION-006) is `verified` / `denied` / `not_evaluated`: the denial shows the
control worked correctly, and is not evidence of bad provenance.

**`provenance_status` boundary.** `invalid` means the chain or its records
were present and a check found a defect in them (a tampered signature, a
broken or mismatched link, scope escalation, or a credential outside its
validity window). `missing` means a chain is claimed but the record set
needed to complete the check was never fully supplied — for example a
non-root record without its parent — which is a different fact from a
check that ran and failed. `not_evaluated` means no delegation chain was
claimed at all (ACTION-016): there is nothing here for a delegation-
provenance check to evaluate, which is a different fact again from evidence
that is missing or invalid. `verified` means every check this helper
performs on the chain and its records passed. `provenance_status` does not
cover holder-proof binding: this helper replays recorded evidence offline,
so it does not check whether the original caller proved it held the leaf
key, and it never claims that absence as either `verified` or `invalid`.

**`controller_outcome` boundary.** `controller_outcome` is currently a
claimed test-helper input (`_ActionEvidence.controller_decision`), not
evidence cryptographically proven by a signed ACTION or TRACE record.

`classification` and `code` are the pre-existing broad category and exact
reason, kept on the result for compatibility with callers that only look at
those two fields.

The five minimum reporting cases agreed for this issue:

1. Policy denial: `verified` / `denied` / `not_evaluated` (ACTION-005, ACTION-006).
2. Controller rejection: `verified` / `allowed` / `rejected` (ACTION-007).
3. Invalid signature: `invalid` / `not_evaluated` / `not_evaluated` (ACTION-008).
4. Missing evidence: `missing` / `not_evaluated` / `not_evaluated` (ACTION-003).
5. Outside helper scope: `not_evaluated` / `not_evaluated` / `not_evaluated`
   (ACTION-016) — a check this helper is deliberately not evaluating, never
   reported as `verified` or `invalid`.

| ID | Level | Requirement | Expected outcome |
|---|---|---|---|
| ACTION-001 | MUST | A delegated action with a parent-linked TRACE/provenance record, matching credential id, and permitted capability verifies. | `verified` / `allowed` / `accepted` (`verified`, `ACCEPTED`). |
| ACTION-002 | MUST | A child action record whose parent record hash does not match the canonical parent record hash is rejected as provenance-invalid. | `invalid` / `not_evaluated` / `not_evaluated` (`provenance_invalid`, `PROVENANCE_LINK_BROKEN`). |
| ACTION-003 | MUST | A non-root delegated action record without its parent record is rejected as provenance-missing. | `missing` / `not_evaluated` / `not_evaluated` (`provenance_invalid`, `PROVENANCE_LINK_BROKEN`). |
| ACTION-004 | MUST | Action evidence naming a delegation credential id that is not the verified leaf credential is rejected as provenance-invalid. | `invalid` / `not_evaluated` / `not_evaluated` (`provenance_invalid`, `PROVENANCE_LINK_BROKEN`). |
| ACTION-005 | MUST | A requested action outside the effective delegated scope is classified as authorization-invalid, not malformed provenance. | `verified` / `denied` / `not_evaluated` (`authorization_invalid`, `SCOPE_NOT_PERMITTED`). |
| ACTION-006 | MUST | A valid delegated action denied by local policy is classified as authorization-invalid, not malformed provenance. | `verified` / `denied` / `not_evaluated` (`authorization_invalid`, `SCOPE_NOT_PERMITTED`). |
| ACTION-007 | MUST | A valid delegated action whose controller outcome is negative remains valid evidence of a negative outcome. | `verified` / `allowed` / `rejected` (`valid_negative_outcome`, `CONTROLLER_REJECTED`). |
| ACTION-008 | MUST | An action whose delegation chain contains a credential with an invalid signature is rejected as provenance-invalid before authorization or outcome handling. | `invalid` / `not_evaluated` / `not_evaluated` (`provenance_invalid`, `INVALID_CREDENTIAL`). |
| ACTION-009 | MUST | A delegated action with a strictly attenuating multi-hop credential chain verifies. | `verified` / `allowed` / `accepted` (`verified`, `ACCEPTED`). |
| ACTION-010 | MUST | An action evidence chain with scope widening at an intermediate hop is rejected as provenance-invalid. | `invalid` / `not_evaluated` / `not_evaluated` (`provenance_invalid`, `SCOPE_ESCALATION`). |
| ACTION-011 | MUST | Action evidence whose delegatee differs from the subject of the referenced credential is rejected as provenance-invalid. | `invalid` / `not_evaluated` / `not_evaluated` (`provenance_invalid`, `PROVENANCE_LINK_BROKEN`). |
| ACTION-012 | MUST | Action evidence whose delegation chain contains an expired credential is rejected as provenance-invalid. | `invalid` / `not_evaluated` / `not_evaluated` (`provenance_invalid`, `CREDENTIAL_EXPIRED`). |
| ACTION-013 | MUST | Action evidence whose delegation chain contains a not-yet-valid credential is rejected as provenance-invalid. | `invalid` / `not_evaluated` / `not_evaluated` (`provenance_invalid`, `CREDENTIAL_NOT_YET_VALID`). |
| ACTION-016 | MUST | Action evidence naming no delegation chain at all is outside this helper's scope, not a failed or incomplete check. | `not_evaluated` / `not_evaluated` / `not_evaluated` (`outside_helper_scope`, `NO_DELEGATION_CHAIN`). |

ACTION-014 and ACTION-015 are reserved for the historical-replay work
tracked separately; this issue does not use them.

## Group 8: Holder binding

Spec: [profile.md](../../docs/spec/profile.md) P-4a, [delegation-chain.md](../../docs/spec/delegation-chain.md)

Holder binding is independent of caller attestation (Group 3). Appraisal establishes what the caller is running; these establish whose authority it holds. HOLD-006 is the one that says why both are needed.

| ID | Level | Requirement | Expected outcome |
|---|---|---|---|
| HOLD-001 | MUST | A delegation chain presented without a holder proof is refused. | `HOLDER_PROOF_INVALID`. |
| HOLD-002 | MUST | A proof signed by a key other than the leaf `subject` is refused. | `HOLDER_PROOF_INVALID`. |
| HOLD-003 | MUST | A proof answering a challenge this callee did not issue is refused. | `HOLDER_PROOF_INVALID`. |
| HOLD-004 | MUST | A proof naming a different audience is refused, so a proof made for one peer cannot be presented to another. | `HOLDER_PROOF_INVALID`. |
| HOLD-005 | MUST | A proof does not transfer across requested capabilities. | `HOLDER_PROOF_INVALID`. |
| HOLD-006 | MUST | A caller whose own attestation appraises successfully is still refused when it presents a chain issued to another party. | `HOLDER_PROOF_INVALID`. |
