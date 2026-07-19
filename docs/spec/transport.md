# Transport Binding

cA2A is a profile on A2A, not a competing transport. A2A moves tasks and context between agents and authenticates a peer's domain with the Signed Agent Card. cA2A adds a trust envelope around a delegated task and leaves the wire protocol untouched. This page states how the profile attaches to the transport and what a peer does with the attached data. For the higher-level statement of what the profile adds and where, see [the A2A profile binding](profile.md).

## What ships today versus what does not

| Piece | Status |
|---|---|
| Extension URI + namespaced metadata keys (below) | Specified |
| `ca2a_runtime.transport` adapter: A2A metadata ↔ `PeerRequest` | Implemented (parse/attach) |
| Hand-off into `handle_peer_request` once a `PeerRequest` exists | Implemented |
| HTTP/JSON-RPC serving / `ca2a start` | Implemented (live serving only) |
| Live attestation handshake on an inbound call | Not yet — separate Tier 2/3 checkbox |
| Seal bound to a **verified** attestation measurement on a live call | Not yet — separate Tier 2/3 checkbox |

Live serving wires parse → `handle_peer_request` end to end on `message/send`. It is **not** evidence that cA2A is attested across trust domains: there is still no attestation handshake on the call, and sealed open uses a configured software/enclave key rather than a key bound to a verified measurement. See [LIMITATIONS.md](../../LIMITATIONS.md) and [ROADMAP.md](../../ROADMAP.md).

## Overlay, not fork

cA2A does not define its own transport, message framing, or handshake. It rides inside A2A. Two pieces of cA2A data travel with a task:

- The **delegation credential** (or the chain root-to-leaf), naming issuer, subject, scope, depth, and parent link. See [the delegation chain](delegation-chain.md).
- The **sealing metadata**, carrying an opaque sealed ciphertext when the caller seals the task payload. Sealing crypto is implemented; binding that seal to a verified peer measurement on a live call is still Tier 2/3. See [the sealed channel](sealed-channel.md).

Both ride in A2A extension fields. cA2A claims no new wire format and no new endpoint. Removing every cA2A field leaves a valid A2A task.

## Extension URI and metadata keys

Per [A2A v1.0 extensions](https://a2a-protocol.org/v1.0.0/topics/extensions/), agents advertise support in the Agent Card and clients opt in with the `A2A-Extensions` header (HTTP/JSON-RPC) or equivalent binding metadata.

| Item | Value |
|---|---|
| Extension URI | `https://agentrust.io/extensions/ca2a/v0.1` |
| Opt-in header | `A2A-Extensions: https://agentrust.io/extensions/ca2a/v0.1` |

Namespaced keys on A2A `metadata` (message and/or params):

| Metadata key | JSON type | Meaning |
|---|---|---|
| `https://agentrust.io/extensions/ca2a/v0.1/delegation_chain` | array of credential objects | Root-to-leaf delegation chain |
| `https://agentrust.io/extensions/ca2a/v0.1/requested_capability` | string | Capability the callee must grant |
| `https://agentrust.io/extensions/ca2a/v0.1/record_id` | string | Provenance record id for this hop |
| `https://agentrust.io/extensions/ca2a/v0.1/parent_record_hash` | string or `null` | Parent TRACE/provenance hash; `null` for a root hop |
| `https://agentrust.io/extensions/ca2a/v0.1/sealed_payload` | string (base64url) or omitted | Opaque sealed ciphertext only — **not** a verified measurement binding |

Constants and helpers live in `ca2a_runtime.transport`.

## Attachment points

The credential and sealing metadata are carried in A2A `metadata` maps on the task message (and optionally params-level metadata), alongside the payload A2A already moves. cA2A does not rewrite the A2A message, change its routing, or interpose a new transport under it. The Signed Agent Card remains the A2A identity anchor; cA2A treats it as the anchor the delegation credential's `subject` and the peer's attestation measurement are checked against (attestation check on the live path is not yet wired).

## Ignore versus enforce

Carrying the trust envelope in extension fields is what keeps the profile an overlay:

- A **non-cA2A peer** does not understand the extension fields and ignores them. The task is handled as a plain A2A task.
- A **cA2A-aware peer** that sees **no** cA2A keys treats the message as ordinary A2A input (`parse_peer_request` returns `None`). It must not invent a partial trust state.
- A **cA2A-aware peer** that sees **any** cA2A key fails closed on malformed or incomplete cA2A metadata (`TransportError`), then — once parsed — runs the inbound enforcement pipeline.

## Adapter API

```python
from ca2a_runtime.peer import handle_peer_request
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.transport import attach_ca2a_metadata, parse_peer_request

# Inbound: A2A SendMessage JSON (or message dict) -> PeerRequest | None
request = parse_peer_request(send_message_body)
if request is None:
    # ordinary A2A — no cA2A trust envelope
    ...
else:
    result = handle_peer_request(request, policy=LocalPolicy.of(["read"]))

# Outbound: attach the same namespaced fields without changing parts/routing
message = attach_ca2a_metadata(message, request)
```

`sealed_payload` is base64url-decoded into opaque `bytes` on `PeerRequest`. That decode step does not imply the ciphertext is bound to a verified attestation report.

## What a cA2A peer enforces on inbound

Once a `PeerRequest` has been parsed, the intended inbound order is:

1. Verify the delegation chain (`verify_chain` / `handle_peer_request`). Any violation denies the call with the specific error: `INVALID_CREDENTIAL`, `BROKEN_DELEGATION_LINK`, `SCOPE_ESCALATION`, `DELEGATION_DEPTH_EXCEEDED`, or `CREDENTIAL_REPLAY`. See [error codes](error-codes.md).
2. Check the peer's attestation measurement against the expected value. Not yet wired on the live path. See [attestation](attestation.md).
3. Intersect the delegated scope with the local policy (allow-set or Cedar). Implemented in `handle_peer_request`. See [Cedar policy](cedar-policy.md).
4. Open any sealed payload with the enclave-held key. Crypto implemented; live seal-to-verified-measurement binding is not. See [the sealed channel](sealed-channel.md).
5. Emit a linked provenance/TRACE record referencing the parent record hash and `credential_id`. See [the TRACE A2A profile](trace-a2a-profile.md).

Steps 1, 3, and 5 (and sealed open when a key is supplied) run inside `handle_peer_request` after the adapter produces a `PeerRequest`, including on the live `ca2a start` listener. Steps 2 and the measurement-bound seal are remaining Tier 2/3 work.

## Live listener (`ca2a start`)

```bash
pip install 'ca2a-runtime[serve]'
ca2a start --config examples/minimal/ca2a-config.yaml
```

The listener accepts JSON-RPC `message/send` (and `SendMessage`) on `POST /` and `POST /rpc`:

1. `parse_peer_request` on the envelope.
2. If no cA2A keys: return `{"ca2a": null, ...}` (ordinary A2A; no invented trust state).
3. If cA2A keys present: `handle_peer_request` with the configured policy and optional enclave key; map `CA2AError` to a JSON-RPC error with `data.ca2a_code`.

Config for the listener needs either `local_policy` (capability allow set) or `policy_bundle_path` (Cedar). Optional `enclave_private_key_hex` (or `--enclave-key-hex` / `CA2A_ENCLAVE_PRIVATE_KEY_HEX`) opens sealed payloads. That key is software-configured for this slice; it is not proven enclave-bound or measurement-linked.

## Enforcement is a peer decision

How strictly a cA2A peer acts on the extension fields is local configuration, not a transport-level flag. `Ca2aConfig.enforcement_mode` selects the intended behavior:

- `enforcing`: an unverifiable chain or a missing required credential denies the call. This is the default and the fail-closed posture the profile calls for. The live listener always uses this posture today.
- `advisory`: the failure is recorded but the call proceeds.
- `silent`: the check runs without a visible signal.

```yaml
# ca2a config
attestation:
  provider: software-only
  enforcement_mode: enforcing
max_delegation_depth: 8
listen_addr: "127.0.0.1:8443"
local_policy: ["read", "write"]
# policy_bundle_path: policy.cedar   # alternative to local_policy
# enclave_private_key_hex: "..."     # optional; for sealed_payload open
```

`max_delegation_depth` bounds the chain length a peer will accept and is passed through to `verify_chain`. `listen_addr` is the HTTP bind address for `ca2a start`. See [failure modes](failure-modes.md).

## Transport stability

This binding targets A2A v1.x extension points. A2A is now stable at v1.x. Confirming the specific extension fields cA2A occupies remain stable across A2A point releases is tracked on [issue #18](https://github.com/agentrust-io/ca2a/issues/18) and [ROADMAP.md](../../ROADMAP.md).
