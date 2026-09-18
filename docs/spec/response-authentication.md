# Live response authentication

`ca2a-response-mac-v1` implements the live-caller branch of
[the response requirements](response-binding-requirements.md), tracked in
[#188](https://github.com/agentrust-io/ca2a/issues/188). This is an opt-in
reference-transport extension. It does not sign the execution lineage or create
third-party-verifiable receipts.

## Using the profile

Call `transport.client.send_task` with `require_authenticated_response=True`.
Configure `require_hardware=True` and an independently pinned verifier when a
hardware-appraised peer is required. These are separate controls: authenticated
responses to a software-only handshake still have `peer_assurance="none"`.

The caller uses the existing handshake and holder-bound request, then submits an
envelope to `POST /ca2a/task/authenticated`. The server validates its response
context before admitting the nested task. An old server or unsigned reply cannot
downgrade a strict caller to the legacy endpoint. The legacy endpoint and default
client behavior remain available, without authenticated-response assurance.

Successful strict calls return the ordinary provenance body plus locally added
`response_authentication` metadata containing `profile`, `peer_assurance`,
`request_sha256` and `audience="live-caller-only"`. Legacy calls strip this
reserved field so a peer cannot inject local verification metadata. Applications
must set the strict option themselves; a dict received from another source is
not a verified object merely because it carries the same field names.

Authenticated denials raise `response.AuthenticatedPeerError`, with the bound
HTTP status, peer error code and `response_authentication`. Unauthenticated,
malformed, expired or tampered replies raise `ResponseAuthenticationFailed`.
Transport failure after submission has an unknown execution outcome. Neither a
timeout nor a MAC failure proves non-execution. The client does not retry or
follow POST redirects and ignores ambient proxy settings for this submission.

## Wire and key derivation

The request envelope has exactly these fields:

| Field | Value |
|---|---|
| `profile` | `ca2a-response-mac-v1` |
| `peer` | Appraised responder X25519 public key, 32 bytes in lowercase hex. |
| `recipient` | Fresh caller X25519 public key for this occurrence, same encoding. |
| `session` | Fresh random 32-byte occurrence identifier, lowercase hex. |
| `request` | Complete cA2A A2A message, including delegation, holder proof, challenge, requested action and sealed payload where present. |

Both endpoints compute `request_sha256 = SHA256(JCS(envelope))`. The key and
session fields are therefore inside the commitment, alongside the request's
challenge and security-relevant contents. The server requires `peer` to match
its current channel key. Restart/rotation invalidates old contexts; a new call
must appraise the new key.

Use [X25519](https://www.rfc-editor.org/rfc/rfc7748) between the fresh caller key
and appraised responder key. Reject an invalid/all-zero shared secret. Derive
32 bytes with [HKDF-SHA256](https://www.rfc-editor.org/rfc/rfc5869): salt is the
raw request digest; info is ASCII `ca2a/response-mac/v1/key`. The request digest
commits both public keys. No Ed25519 key is inferred from the X25519 key.

The response statement has exactly `profile`, `request_sha256`, `status`,
`kind` and `body`. `kind` is `provenance` for status 200 and `denial` for
400 through 599. Other kinds, including confidential output, are unsupported.
`body` is an object: provenance has `accepted: true`; denial has an `error`
object. The reference server never echoes the opened task payload.

Append `mac`, the lowercase hex HMAC-SHA256 under the derived key over:

```text
ASCII("ca2a/response-mac/v1/statement") || 0x00 || JCS(statement)
```

The verifier checks the exact field set, profile, request digest, integer status,
actual HTTP status, MAC, kind and body shape before returning content. Merely
changing the outer HTTP status cannot turn an authenticated result into a denial.

This uses the repository's integer-only [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785)
subset: strings, objects, arrays, booleans, null and safe integers. Floating
point, nonfinite values, duplicate object fields, non-string object keys and
invalid Unicode are refused. The authenticated request/response path is bounded
to 1 MiB and nesting depth 64; unknown envelope fields are refused. HTTP input
is byte-bounded before decoding. These limits do not provide admission rate limits.

## Replay, time and compatibility

`PendingResponse` is process-local state for one occurrence. It consumes its
verification opportunity atomically even on failure, and checks its monotonic
deadline before and after authentication. The default is 30 seconds, configurable
on the primitive within `(0, 300]`. Nonfinite or backward clock observations
fail closed. Simultaneous deliveries have at most one accepted response per
pending object. Copying or serializing pending state is rejected.

A fresh call generates a new recipient key and session, even if record IDs or
request content repeat. A response captured for an earlier call cannot satisfy
the new commitment. There is no pending-state persistence, multi-process recovery
or automatic resubmission after restart. Losing the pending object loses the
ability to authenticate its reply. Cloning a whole process/VM snapshot is outside
this software guarantee and requires rollback-resistant deployment controls.

This is response replay protection. The server's holder challenge remains
stateless and replayable within its documented window. Duplicating an incoming
request can still execute it again. Applications needing idempotent/exactly-once
effects must supply an authoritative request-execution store; neither record ID
reuse nor a response MAC establishes that property.

## Evidence and limits

The committed `tests/fixtures/response-mac-v1.json` contains public synthetic test
keys, canonical request bytes, a derived key, a valid response and negative
mutations. Its HKDF/MAC values were calculated independently using direct HMAC
extract/expand and ASCII JSON canonicalization. Unit tests also cross-check that
derivation independently of the production HKDF helper. These fixtures contain
no hardware evidence or production secrets.

Real-HTTP tests exercise successful provenance, authenticated denial, legacy
behavior, content/status substitution, cross-request replay, unsigned replies,
redirect refusal and reply loss after successful execution. Unit tests cover
concurrent delivery, expiry, malformed input, key rotation and unsupported output
kinds. Removing MAC verification, single-use enforcement or deadline checks makes
their regressions fail. This software result has not been rerun on live hardware.

Both session parties can compute the MAC. It authenticates a live reply against
network substitution for the caller that retains its secret; it cannot convince
an independent third party which party authored the statement. It does not fix
unsigned execution history in #168. The MAC also does not encrypt provenance,
whose metadata can be sensitive. HTTPS and access controls remain deployment
requirements where that metadata needs confidentiality.

Hardware assurance inherits the configured verifier and its approved measurement
and policy. No measured application identity, protected clock, rollback-resistant
memory, secure erasure, model execution or business completion follows from the
MAC itself. A future confidential-output profile needs explicit recipient-bound
encryption and disclosure rules; this profile does not add one.
