# Authenticated response requirements

Status: proposed requirements and acceptance matrix for [#188](https://github.com/agentrust-io/ca2a/issues/188).
The [live response authentication profile](response-authentication.md) now
implements a session-MAC verifier and reference adapter against this contract.
It selects live-caller authentication, not portable signatures. The requirements
below remain the acceptance basis; hardware validation is separate.

## Current boundary

At `0d2327600e66be4988706ef52b68a893ebebf603`, the reference client
`transport.client.send_task` appraises the callee offer, binds the outgoing
request to the holder proof, submits it, then returns a parsed HTTP 200 body.
It does not authenticate that response against the appraised callee or bind it
to the submitted request. Non-200 bodies become peer errors without that binding.
HTTPS can protect a connection to its configured endpoint; it does not by itself
bind a response to the workload appraised during the cA2A handshake.

The server returns provenance through `wire.serialize_peer_result`, not the
opened confidential payload. The earlier decision to withdraw response sealing
in [mutual attestation](mutual-attestation.md) therefore remains applicable.
Readable evidence can still require authentication. Any future confidential
task output requires a separate recipient-bound encryption decision.

## Required contract

A response-required relying-party policy must be chosen locally before sending
the request. A peer cannot lower it by omitting a field or choosing an older
profile. Legacy mode must remain visibly lower assurance.

The future authenticated statement must commit to:

- A versioned response profile and a domain distinct from requests and other signatures.
- The responder key and its independently verified relationship to the appraised
  workload and effective policy. The existing X25519 channel key cannot simply
  be treated as a signing key.
- The intended recipient and one request occurrence, with an unambiguous commitment
  to the complete security-relevant request. Record ID equality alone is insufficient.
- The session/handshake context, including freshness and identity inputs needed
  to prevent substitution across sessions or peers.
- The response kind, authenticated outcome and exact response content commitment.
  Any status that affects interpretation must be inside the authenticated statement.

The design must define canonical bytes, field types, duplicate-field rejection,
encoding and size limits, key establishment/rotation and verification ordering.
If request bytes are committed directly, both sides must agree on those exact
bytes; if a canonical representation is used, specify it before producing vectors.
Do not introduce an ad hoc encoding through the test generator.

Portable signatures and session authentication have different verification
audiences. The design must choose whether offline third parties can authenticate
the response, or whether only the live caller can do so. It must not claim the
former from a shared session MAC. Neither choice by itself fixes the separate
execution-lineage issue [#168](https://github.com/agentrust-io/ca2a/issues/168).

## Outcomes and state

Keep four outcomes distinguishable:

| Outcome | Permitted interpretation |
|---|---|
| Authenticated acknowledgement/result | The bound peer made this statement about this request; execution or external completion requires the corresponding evidence. |
| Authenticated denial | The bound peer reports a denial at a defined stage; absence of side effects requires a stated and supported pre-execution boundary. |
| Unauthenticated response or transport failure | No authenticated peer verdict is established. |
| Timeout or lost response after submission | The receiver's execution outcome remains unknown; automatic retry is not justified by the timeout. |

Define request occurrence identity separately from an idempotency key. A replay
policy must cover concurrent responses, duplicate delivery, expiry, restart,
multiple client instances and persistence/rollback assumptions. If replay state
is unavailable, a strict client cannot silently accept a previously consumed
response. A receiver's replay defense and a caller's response replay defense are
separate controls.

## Acceptance matrix

These are contract requirements. The implemented live-session profile exercises
them in `tests/unit/test_response_authentication.py`, using software evidence;
it does not establish hardware behavior. Each negative case needs a valid
control under the same policy. Refusal means no authenticated
result is exposed to the application; it does not assert that the receiver did
not execute the submitted request.

| ID | Case | Required observation |
|---|---|---|
| RESP-001 | Valid response from the appraised responder for the current occurrence | Accepted with explicit response assurance and bound context. |
| RESP-002 | Response contents changed after authentication | Refused before application consumption. |
| RESP-003 | Valid proof from another responder | Refused, even if the response body is otherwise identical. |
| RESP-004 | Valid response moved to another request with a reused record ID | Refused using the complete request-occurrence binding. |
| RESP-005 | Response moved across sessions or intended recipients | Refused despite a valid proof under the original context. |
| RESP-006 | Missing proof, unknown profile or legacy response under strict policy | Refused without fallback. |
| RESP-007 | Success/denial kind or interpreted status substituted | Refused; the outer HTTP status alone cannot supply an authenticated verdict. |
| RESP-008 | Previously accepted response delivered again, including concurrent delivery | Replay policy enforced atomically within its declared state scope. |
| RESP-009 | Expired response, restarted verifier or unavailable replay state | Declared freshness/recovery policy enforced; no silent assurance promotion. |
| RESP-010 | Authenticated denial versus unsigned error body | The former is a peer statement; the latter remains unverified. |
| RESP-011 | Submission followed by timeout or truncated response | Unknown execution outcome retained; no blind resubmission. |
| RESP-012 | Duplicate fields, ambiguous encoding, oversized proof or malformed envelope | Bounded parsing refusal without treating input as authenticated. |
| RESP-013 | Responder key rotated without an approved binding to the appraised workload | Refused; approved rotation has a separate positive control. |
| RESP-014 | Confidential output added to otherwise readable provenance | Not released until a separately approved encrypted-output profile binds the recipient. |

Run the contract through an actual HTTP exchange as well as verifier unit tests.
Observe whether unverified content reaches the application. Removing body,
request, peer or replay verification must fail the corresponding regression.
Synthetic cryptography, captured hardware evidence and live hardware execution
must be labeled separately.

## Implementation state

The [profile](response-authentication.md) selects X25519/HKDF/HMAC with the
existing JCS subset, live-caller verification and process-local one-use state.
Public synthetic vectors, a strict verifier, the HTTP adapter, compatibility
behavior and causal checks are included in the same handoff follow-up PR.
Portable signing, confidential outputs and hardware deployment validation remain
outside this profile. Issue #188 stays open during implementation review.
