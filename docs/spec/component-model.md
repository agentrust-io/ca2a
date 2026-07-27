# Component Model

The cA2A runtime is a set of small, composable modules under `src/`. Each maps to one primitive in [How It Works](../concepts.md). This page describes what each component is, what it exposes, and whether it is implemented today or a placeholder for pending Tier 2/Tier 3 work. Nothing here describes behavior that is not in the source.

## Components

### delegation

`ca2a_runtime.delegation.credential` holds the credential model and the offline chain verifier. `DelegationCredential` is a frozen dataclass with a signed `body()` (everything but the signature) and a detached Ed25519 `signature`. `new_keypair()` returns a fresh `Ed25519PrivateKey` and its raw-hex public key. `verify_chain(chain, *, max_depth=8)` walks a root-to-leaf list and raises the specific error for the first failed invariant: signature, continuity, attenuation, depth, and anti-replay. This is the implemented core. See [delegation chain](delegation-chain.md).

### provenance

`ca2a_runtime.provenance` is the runtime-evidence side. `DelegationRecord` is a frozen dataclass whose `record_hash()` is a SHA-256 over its canonical body, so any field change breaks a child's link. `record_for(credential, record_id, parent_record_hash)` builds the record a hop emits. `verify_dag(records)` confirms a root-to-leaf provenance chain (root has no parent link, each later record's `parent_record_hash` equals the recomputed hash of the previous record, no repeated `record_id`). `cross_check_chain(records, chain)` ties provenance to authority: record `i` must reference credential `i` and carry the same subject. Implemented. The full TRACE binding lands with Tier 2. See [TRACE A2A profile](trace-a2a-profile.md) and [provenance DAG](provenance-dag.md).

### verify

`ca2a_verify.verify` is a thin offline wrapper over the delegation verifier. `verify_delegation_chain(chain, *, max_depth=8)` returns a `ChainResult` (`hops`, `root_issuer`, `leaf_subject`, `leaf_scope`); `verify_chain_file(path, *, max_depth=8)` loads a chain from JSON (a list, or `{"chain": [...]}`) and verifies it. `VerificationError` is re-exported as `CA2AError` so callers catch one type. This layer trusts no operator: it works from signed credentials alone. Implemented. See [verification library](verification-library.md).

### channel

`ca2a_runtime.channel` defines `SealedChannel`, `generate_channel_keypair`, and `open_sealed`: HPKE-style sealing (X25519 ECDH, HKDF-SHA256, ChaCha20-Poly1305) of a payload to the peer's channel key. Only the holder of that key opens it; a wrong key or tampered ciphertext fails closed. The cryptography is implemented. What is *not* yet true is the hardware property: until the key is bound to a hardware-verified measurement, do not assume a payload is confined to a specific attested enclave. See [sealed channel](sealed-channel.md) and [LIMITATIONS.md](../../LIMITATIONS.md).

### peer, policy and cedar

`ca2a_runtime.peer` is the inbound decision core. `effective_scope(chain, policy)` verifies the chain and returns the delegated leaf scope intersected with local policy; `enforce_peer_call(...)` enforces a requested capability against it and emits a linked provenance record, raising `SCOPE_NOT_PERMITTED` (carrying a denial record) when the capability falls outside. `handle_peer_request(request, ...)` composes the full transport-agnostic pipeline: verify, enforce, open any sealed payload with the enclave key, emit the record. `ca2a_runtime.policy` defines the `Policy` protocol and `LocalPolicy` (allow set); `ca2a_runtime.cedar.CedarPolicy` is the Cedar-engine implementation, interchangeable with it. Implemented. See [Cedar policy](cedar-policy.md) and [call graph](call-graph.md).

### tee

`ca2a_runtime.tee.base` defines the provider interface and evidence model. `AttestationReport` is a frozen dataclass binding a `public_key` to a `measurement` under a `nonce` on a named `platform`. `BaseProvider` is an ABC with `detect()` and `attest(public_key, nonce)`. Verifiers for SEV-SNP, Intel TDX and TPM 2.0 are implemented in `ca2a_verify` and appraise real evidence, all fail-closed; `ca2a_runtime.tee.software.SoftwareProvider` supplies a no-hardware provider that is never auto-selected. Quote *generation* requires the corresponding hardware, so each hardware provider's `detect()` returns False off that platform. The OPAQUE provider is not implemented. See [attestation](attestation.md) and [hardware validation](../hardware-validation.md).

### transport, node and attestation handshake

`ca2a_runtime.transport.a2a_adapter` parses cA2A extension metadata on an A2A message into a `PeerRequest` and attaches it in the reverse direction, failing closed on malformed metadata (`TRANSPORT_ERROR`) and returning `None` when no cA2A keys are present. `ca2a_runtime.transport.server`/`client` are a standard-library reference HTTP transport, and `ca2a_runtime.node.PeerNode` composes provider, policy, adapter and handler. `ca2a_runtime.attestation` (offer, verify, seal) gates sealing on a channel key the caller has appraised under a fresh nonce. All implemented and exercised end to end in software mode; the reference transport is a convenience, not part of the profile. See [transport](transport.md).

### trace_binding and canonical

`ca2a_runtime.trace_binding` lifts each hop into a signed TRACE Trust Record carrying the A2A `delegation` block (`build_trace_record`, `sign_trace_record`, `emit_dag`, `trace_record_hash`, `HopContext`), built on `agentrust-trace`. `ca2a_verify.verify_trace_dag` verifies a signed DAG offline and `cross_check_trace_dag` ties it to the chain. `ca2a_runtime.canonical` is the RFC 8785 JCS canonicalizer the signatures are computed over. Implemented. See [TRACE A2A profile](trace-a2a-profile.md).

### config

`ca2a_runtime.config` holds `Ca2aConfig`, a frozen dataclass validated by `from_dict()` / `load()`. It defines the surface the runtime peer path will consume: `provider` (from `VALID_PROVIDERS`), `enforcement_mode` (from `VALID_ENFORCEMENT`), `max_delegation_depth`, `policy_bundle_path`, and `listen_addr`. Invalid values raise `CONFIG_ERROR`. The config surface is implemented and validated; the peer path that consumes `enforcement_mode`, `policy_bundle_path`, and `listen_addr` is Tier 2 and not yet built.

### errors

`ca2a_runtime.errors` is the central registry. Every error is a `CA2AError` subclass carrying a stable `code` and an `http_status`: `CONFIG_ERROR`, `INVALID_CREDENTIAL`, `SCOPE_ESCALATION`, `BROKEN_DELEGATION_LINK`, `DELEGATION_DEPTH_EXCEEDED`, `CREDENTIAL_REPLAY`, `ATTESTATION_UNSUPPORTED`, `ATTESTATION_FAILED`, `SEALED_CHANNEL_ERROR`, `PROVENANCE_LINK_BROKEN`, `SCOPE_NOT_PERMITTED`, `TRACE_RECORD_INVALID`, `TRANSPORT_ERROR`. See [error codes](error-codes.md).

### cli

`ca2a_runtime.cli` exposes the `ca2a` command with three subcommands: `validate-config --config` (loads and validates a `Ca2aConfig`), `verify-chain --chain [--max-depth]` (calls `verify_chain_file` and prints a JSON result), and `verify-dag --dag [--chain] [--max-depth]` (verifies a provenance DAG, optionally cross-checking it against the chain, and reports `outcome: denied` when the leaf documents a refusal). All implemented and offline.

## Component map

| Component | Module | Key API | Status |
|---|---|---|---|
| delegation | `ca2a_runtime.delegation.credential` | `DelegationCredential`, `new_keypair`, `verify_chain` | Implemented |
| provenance | `ca2a_runtime.provenance` | `DelegationRecord`, `record_for`, `verify_dag`, `cross_check_chain` | Implemented |
| verify | `ca2a_verify.verify` | `verify_delegation_chain`, `verify_chain_file`, `ChainResult` | Implemented |
| config | `ca2a_runtime.config` | `Ca2aConfig` | Implemented |
| errors | `ca2a_runtime.errors` | `CA2AError` and subclasses | Implemented |
| cli | `ca2a_runtime.cli` | `validate-config`, `verify-chain`, `verify-dag` | Implemented |
| channel | `ca2a_runtime.channel` | `SealedChannel`, `generate_channel_keypair`, `open_sealed` | Crypto implemented; binding to a hardware-verified measurement pending |
| peer | `ca2a_runtime.peer` | `effective_scope`, `enforce_peer_call`, `handle_peer_request` | Implemented |
| policy | `ca2a_runtime.policy`, `ca2a_runtime.cedar` | `Policy`, `LocalPolicy`, `CedarPolicy` | Implemented |
| transport | `ca2a_runtime.transport`, `ca2a_runtime.node` | `parse_peer_request`, `serve`, `PeerNode` | Implemented (reference transport, software mode) |
| attestation | `ca2a_runtime.attestation` | offer, verify, seal | Implemented; appraisal is `assurance="none"` off hardware |
| tee | `ca2a_runtime.tee` | `BaseProvider`, `AttestationReport`, `SoftwareProvider` | Interface and software provider implemented; quote generation needs the platform |
| verifiers | `ca2a_verify.sev_snp`, `.tdx`, `.tpm` | `verify_sev_snp_report`, `verify_tdx_quote`, `verify_tpm_quote` | Implemented and fail-closed. SEV-SNP and TDX appraise real hardware evidence; TPM is synthetic-vector validated only |
| trace_binding | `ca2a_runtime.trace_binding`, `ca2a_verify.dag` | `emit_dag`, `verify_trace_dag`, `cross_check_trace_dag` | Implemented |

## How they compose on an inbound peer call

1. A hands B a child credential with `scope ⊆` A's scope. This is the [delegation](delegation-chain.md) model. Implemented.
2. B appraises the peer's attestation evidence before sealing anything to its channel key. The handshake and the verifiers are implemented, and the SEV-SNP and TDX verifiers appraise genuine hardware evidence, but on a live call the appraisal runs in software mode at `assurance="none"`. See [attestation](attestation.md) and [hardware validation](../hardware-validation.md).
3. The runtime verifies the chain with `verify_chain` and intersects the delegated scope with B's local policy (`LocalPolicy` or `CedarPolicy`), enforcing the requested capability. Implemented. See [Cedar policy](cedar-policy.md).
4. The task payload is sealed to B's channel key through `SealedChannel` and opened with B's enclave-bound key. The cryptography is implemented; binding the seal to a hardware-verified measurement is the remaining hardware step.
5. B emits a `DelegationRecord` linking to A's record, or a denial record if the call was refused, and any verifier runs `verify_dag` and `cross_check_chain` offline. Implemented. See [TRACE A2A profile](trace-a2a-profile.md).

What ships today runs the whole path live in software mode, and everything except steps 2 and 4's hardware property is verifiable offline by a party trusting neither operator. What does not ship is a peer whose channel key is bound to a hardware-verified measurement on a live call, which is why cA2A is not described as attested across trust domains. See [failure modes](failure-modes.md), [ROADMAP.md](../../ROADMAP.md), and [LIMITATIONS.md](../../LIMITATIONS.md).
