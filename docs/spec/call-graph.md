# Inbound Peer-Call Decision

The inbound handler checks a caller's authority and identity before returning a task payload to the application. The reference HTTP transport and `PeerNode` use this handler; the profile does not mandate that transport.

## Decision flow

For a parsed `PeerRequest`, `ca2a_runtime.peer.handle_peer_request` runs these steps:

1. Verify the chain against locally trusted root issuers.
2. Verify the caller holds the leaf subject key (required by default).
3. Intersect delegated scope with local policy.
4. Appraise the caller's runtime under the configured requirement.
5. Decide the capability and construct an allow or denial record.
6. Open any sealed payload with the callee's private key.
7. Return `PeerResult` to the application.

An exception stops the pipeline. A denial never returns the payload. An allow record describes an authorization decision; it does not prove the application completed the task. The decision record is constructed **before** payload opening, which can itself fail.

## Checks and trust inputs

| Step | Implementation | Required context |
|---|---|---|
| Chain | `verify_chain` | Locally approved `trusted_root_issuers`, depth limit, credential validity windows |
| Holder proof | `verify_caller_holds_leaf` | Callee audience and challenge secret; proof commits to the requested operation |
| Policy | `policy.intersect` | `LocalPolicy` allow set or `CedarPolicy` |
| Caller appraisal | `appraise_caller_runtime` | Challenge context, verifier, and `require_caller_attestation` |
| Capability | `decide_capability` | Requested capability must be in the effective scope |
| Payload | `open_sealed` | Callee's channel private key; authenticated ciphertext |

Chain verification checks signatures, continuity, attenuation, depth, validity, and duplicate credential IDs within the supplied chain. It does not maintain a global history that makes each credential single-use. Root keys must come from local policy, not from an untrusted incoming chain.

Holder proof establishes that this caller controls the key named as the leaf subject. Attestation establishes a separate claim about its runtime. `require_holder_proof=False` exists for offline replay and must not be used on a live peer path. Chain and holder failures occur before policy evaluation and emit no decision record.

## Caller appraisal

The default `require_caller_attestation="none"` accepts a caller that offers no attestation and records `not_offered`. `"any"` requires an appraisable offer, including software assurance. `"hardware"` requires hardware assurance. A present but invalid offer is rejected at every setting.

The record carries the appraisal outcome: `not_offered`, `software-only`, `hardware`, or `failed`. Appraisal refusal and capability denial can carry linked denial records. See [mutual attestation](mutual-attestation.md) for the challenge protocol and assurance requirements.

## Sending is a separate path

Before sending, the **caller** appraises the **callee's** channel offer and seals the payload to its verified channel key. On receipt, the **callee** checks the caller and opens that payload. These are separate directions of trust; a successful outbound appraisal does not establish inbound caller authority.

The encrypted channel works in software mode. Protection from a host operator additionally depends on verified hardware evidence, expected measurements, and private-key custody in the measured environment. See [sealed channel](sealed-channel.md) and [hardware validation](../hardware-validation.md) for the evidence and remaining deployment gaps.

## Decision core versus full handler

`effective_scope` and `enforce_peer_call` are lower-level helpers for chain verification and policy decisions. They do not perform the full handler's holder proof, caller appraisal, or payload opening. Integrations should use the full peer path described in [transport binding](transport.md).

For a runnable local example, start with the [quick start](../quickstart.md). For signed evidence verification, see the [verification library](verification-library.md).
