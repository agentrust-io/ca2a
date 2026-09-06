# Component Model

cA2A composes delegation verification, local policy, caller authentication, attestation, encrypted payloads, and evidence records. The reference runtime and HTTP transport implement this path; hardware assurance depends on the provider and evidence available in the deployment.

## Components

| Component | Module | Responsibility |
|---|---|---|
| Delegation | `ca2a_runtime.delegation.credential` | Signed credentials; root trust, continuity, scope attenuation, depth and validity checks |
| Holder proof | `ca2a_runtime.delegation.holder` | Bind the caller to the leaf subject key and challenged request |
| Policy | `ca2a_runtime.policy`, `ca2a_runtime.cedar` | Allow-set or Cedar policy evaluation |
| Inbound handler | `ca2a_runtime.peer` | Verify, authenticate, appraise, authorize, and open the payload |
| Channel | `ca2a_runtime.channel` | X25519 key agreement and authenticated encryption; reject wrong keys and altered ciphertext |
| Attestation | `ca2a_runtime.attestation` | Challenge-bound channel offers and peer appraisal |
| Providers | `ca2a_runtime.tee` | Software evidence or hardware collection for TPM, SEV-SNP, and TDX; OPAQUE has no collector |
| Provenance | `ca2a_runtime.provenance` | Hash-linked decision records and consistency checks |
| TRACE binding | `ca2a_runtime.trace_binding` | Signed TRACE records carrying delegation links |
| Offline verification | `ca2a_verify.verify`, `ca2a_verify.dag` | Verify credentials and signed TRACE record paths against caller-supplied trust anchors |
| Configuration | `ca2a_runtime.config`, `ca2a_runtime.bootstrap` | Validate configuration and build a node with policy, provider, and trusted roots |
| Node and transport | `ca2a_runtime.node`, `ca2a_runtime.transport` | Compose the handler with reference HTTP and A2A adapters |
| CLI | `ca2a_runtime.cli` | Offline validation commands and `ca2a start` |

## How they compose

The caller appraises a callee's channel offer and seals the task to that key. The callee receives a parsed `PeerRequest`, checks its delegation and holder proof, evaluates policy and caller appraisal, and decides whether to open the payload. [Inbound peer-call decision](call-graph.md) gives the exact order and failure behavior.

`enforce_peer_call` is a lower-level authorization helper. Calling it directly does not perform the full handler's holder proof or caller appraisal.

## Evidence has two forms

`DelegationRecord` is an unsigned, hash-linked decision record. `verify_dag` checks one ordered root-to-leaf path; `cross_check_chain` checks its credential IDs and subjects. These consistency checks do not authenticate the record producer or prove task completion.

The separate TRACE binding and `verify_trace_dag` add signed-record verification against trusted keys. The current APIs check ordered paths, not an arbitrary branching graph. See [provenance DAG](provenance-dag.md) and [verification library](verification-library.md).

## Deployment boundaries

Software mode exercises delegation, policy, encryption, and signed evidence without hardware isolation. A hardware platform name alone is insufficient: the verifier needs valid evidence, an accepted trust chain, and the expected measurement. Provider collection, verifier support, and end-to-end deployment validation are separate facts; consult [hardware validation](../hardware-validation.md).

The configuration accepts three enforcement-mode names, but all currently enforce denial on the peer path. The reference transport is an implementation option; the [profile](profile.md) remains transport-independent.
