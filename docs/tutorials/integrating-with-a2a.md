# Integrating with A2A

This example connects the official Python A2A SDK's client and HTTP server to
cA2A's existing Agent Card and peer-verification APIs. It exercises an actual
loopback connection with `a2a-sdk==1.1.2`. The operator owns the card, server,
application routing, and tool handler; cA2A supplies the extension metadata and
checks the delegated request before the application acts.

The runnable implementation is
[`examples/a2a-sdk/loopback.py`](https://github.com/agentrust-io/ca2a/blob/main/examples/a2a-sdk/loopback.py), with its
released SDK dependencies in
[`requirements.txt`](https://github.com/agentrust-io/ca2a/blob/main/examples/a2a-sdk/requirements.txt). This is a
software-only integration example. It needs no model service, external credentials,
TPM, or confidential-computing host.

## Run the example

From the repository root, with a virtual environment activated:

```bash
uv pip install -e '.[dev]' -r examples/a2a-sdk/requirements.txt
python examples/a2a-sdk/loopback.py
python -m pytest tests/unit/test_a2a_sdk_loopback.py -v
```

The example starts an SDK server on an ephemeral loopback port, fetches its
Agent Card through the SDK, and sends ordinary and cA2A messages through the
SDK client. The scenarios distinguish a harmless public-information reply,
an authorized read, and a write refused by local policy. The server is closed
when the run ends.
The tests in
[`test_a2a_sdk_loopback.py`](https://github.com/agentrust-io/ca2a/blob/main/tests/unit/test_a2a_sdk_loopback.py) check
the wire path and the application handler's invocation count.

The successful run prints a JSON summary with:

- `ordinary: "ordinary"`, for the public-information reply;
- `allowed`, containing item `"widget"` and quantity `3`;
- `denied: "SCOPE_NOT_PERMITTED"`, for the requested write;
- `protected_handler_invocations: 1`;
- `callee_assurance: "none"` and `caller_attestation: "not_offered"`.

## Keep ownership explicit

The operator constructs an unsigned `AgentCard` with the application's own
identity, interface, URL, and skills. `merge_agent_card(card, node)` copies it
and adds cA2A's declaration, derived from the `PeerNode` that will check calls.
The extension remains `required=false`, so an ordinary A2A caller can ignore it.
The official SDK serves the card; this example adds no card-serving behavior
to `ca2a start` or the reference cA2A transport.

The SDK client fetches that card, and `inspect_agent_card` reports its cA2A
declaration. Discovery establishes what a card advertises, not whether its
publisher is trusted. The example neither signs nor authenticates the card,
and does not bind its identity to the delegation keys.

For protected requests, this application requires both the HTTP
`A2A-Extensions` opt-in and the extension URI in `Message.extensions`.
That is an explicit example routing policy, not a new profile requirement.
An incomplete cA2A request is refused rather than treated as ordinary traffic.
Ordinary messages receive only a harmless public-information response; they
cannot dispatch the protected inventory lookup. The example implements no
write operation: a write request is refused before the lookup handler runs.

## What the protected request verifies

The harness creates a root issuer, a delegate, and a holder, with two signed
credentials at depths 0 and 1. Both credentials carry validity bounds. The
holder's grant includes read and write, while the callee's local policy permits
only read. This makes the write refusal a local-policy decision rather than
a capability the holder was never granted.

The callee's trusted issuer set is configured from the harness's authorized
root key, independently of the received request. A presented chain cannot
authorize its own root. The same rule applies when using `verify_chain`
directly: pass the verifier's explicit `trusted_root_issuers` set; the default
empty set trusts no issuer.

The example's `/demo/channel` bootstrap endpoint returns the callee's
software-only channel offer and holder challenge. This is an application
endpoint, separate from the SDK's standard card and message routes. The client
checks the offer's nonce, confirms `assurance="none"`, and seals the public
fixture bytes `b"widget"` to the offered channel key.

The holder then signs a proof for the callee's issued challenge and channel-key
audience, binding the credential, requested capability, record ID, parent link,
and sealed payload. No caller attestation offer is supplied, and the proof's
caller-channel binding is `None`. The callee uses the default
`require_caller_attestation="none"`, so its caller-attestation outcome is
`not_offered`. This is not a successful hardware appraisal.

On receipt, the application's SDK executor converts message metadata with
`metadata_from_sdk_message` and calls `node.handle` before its private tool
handler. Existing cA2A code verifies the chain and holder proof, applies local
policy, and opens the sealed payload. The executor requires the returned
plaintext to equal `b"widget"` before calling its private `_lookup` method.
That method returns the fixed stock quantity. A refusal does not increment
its invocation count.

The SDK carries metadata through protobuf `Struct`, whose numbers are doubles.
The existing bridge restores integral `depth`, `not_before`, and `not_after`
values before strict credential parsing. The loopback regression checks that
the signed chain still verifies after the real client/server serialization.

## Payload and evidence limits

The fixed inventory lookup takes its input from the opened **sealed payload**.
It does not interpret `Message.parts` as authenticated tool arguments: those
parts are outside the holder proof. Applications adding arguments must define
their binding and use the verified payload before acting; copying unbound
message text into a protected handler would exceed what this example establishes.

The public `b"widget"` fixture passes through the real sealing and opening
code, but no secret data is sent. Bootstrap and message traffic use loopback
HTTP, and the offered channel key has only software assurance. This run
establishes neither endpoint authentication nor confidentiality across an
adversarial trust boundary.

Challenges are stateless and expire after their TTL. They are not consumed:
the same valid challenge and proof can be used repeatedly before expiry.
Neither this example nor that challenge mechanism provides at-most-once
redemption or exactly-once execution.

The accepted response contains an unsigned diagnostic provenance record;
refusals return an error code. Diagnostic record hashes and links can support
consistency checks, but do not authenticate the operator
or prove that a tool executed. The signed credentials and holder proof establish
different, narrower facts; they do not turn these diagnostics into signed
decision receipts or authenticated TRACE execution evidence.

This establishes the exercised Python SDK integration path and its local
authorization behavior. It does not establish authenticated network transport,
hardware provenance, key residency, agent/TPM co-location, runtime integrity,
or safe agent behavior. The upstream A2A TCK and cross-language interoperability
work in [the roadmap](../../ROADMAP.md) remains pending. See
[the transport specification](../spec/transport.md) and
[LIMITATIONS.md](../../LIMITATIONS.md) for the wider protocol boundaries.
