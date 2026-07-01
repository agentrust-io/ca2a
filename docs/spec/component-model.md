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

`ca2a_runtime.channel.sealed` defines `SealedChannel`, the measurement-bound peer channel. Instantiation is allowed so the runtime can be wired against the interface, but `seal()` and `open()` fail closed with `SEALED_CHANNEL_ERROR` today. This is Tier 2 and not yet implemented; do not send confidential payloads across a trust boundary and assume they are protected. See [sealed channel](sealed-channel.md) and [LIMITATIONS.md](../../LIMITATIONS.md).

### tee

`ca2a_runtime.tee.base` defines the provider interface and evidence model. `AttestationReport` is a frozen dataclass binding a `public_key` to a `measurement` under a `nonce` on a named `platform`. `BaseProvider` is an ABC with `detect()` and `attest(public_key, nonce)`. Real hardware providers (TPM, SEV-SNP, TDX, OPAQUE) are Tier 3 and not implemented; their `detect()` returns False so they are never auto-selected, and verification fails closed. See [attestation](attestation.md).

### config

`ca2a_runtime.config` holds `Ca2aConfig`, a frozen dataclass validated by `from_dict()` / `load()`. It defines the surface the runtime peer path will consume: `provider` (from `VALID_PROVIDERS`), `enforcement_mode` (from `VALID_ENFORCEMENT`), `max_delegation_depth`, `policy_bundle_path`, and `listen_addr`. Invalid values raise `CONFIG_ERROR`. The config surface is implemented and validated; the peer path that consumes `enforcement_mode`, `policy_bundle_path`, and `listen_addr` is Tier 2 and not yet built.

### errors

`ca2a_runtime.errors` is the central registry. Every error is a `CA2AError` subclass carrying a stable `code` and an `http_status`: `CONFIG_ERROR`, `INVALID_CREDENTIAL`, `SCOPE_ESCALATION`, `BROKEN_DELEGATION_LINK`, `DELEGATION_DEPTH_EXCEEDED`, `CREDENTIAL_REPLAY`, `ATTESTATION_UNSUPPORTED`, `ATTESTATION_FAILED`, `SEALED_CHANNEL_ERROR`, `PROVENANCE_LINK_BROKEN`. See [error codes](error-codes.md).

### cli

`ca2a_runtime.cli` exposes the `ca2a` command with two subcommands: `validate-config --config` (loads and validates a `Ca2aConfig`) and `verify-chain --chain [--max-depth]` (calls `verify_chain_file` and prints a JSON result). Both are implemented and operate offline.

## Component map

| Component | Module | Key API | Status |
|---|---|---|---|
| delegation | `ca2a_runtime.delegation.credential` | `DelegationCredential`, `new_keypair`, `verify_chain` | Implemented |
| provenance | `ca2a_runtime.provenance` | `DelegationRecord`, `record_for`, `verify_dag`, `cross_check_chain` | Implemented |
| verify | `ca2a_verify.verify` | `verify_delegation_chain`, `verify_chain_file`, `ChainResult` | Implemented |
| config | `ca2a_runtime.config` | `Ca2aConfig` | Surface implemented; peer path pending (Tier 2) |
| errors | `ca2a_runtime.errors` | `CA2AError` and subclasses | Implemented |
| cli | `ca2a_runtime.cli` | `ca2a validate-config`, `ca2a verify-chain` | Implemented |
| channel | `ca2a_runtime.channel.sealed` | `SealedChannel` | Placeholder, fails closed (Tier 2) |
| tee | `ca2a_runtime.tee.base` | `BaseProvider`, `AttestationReport` | Interface only; hardware backends pending (Tier 3) |

## How they compose on an inbound peer call

The intended peer path threads these components together. Steps 2 through 5 below are the target composition; the implemented parts today are the chain and provenance verification an offline verifier can run over signed evidence.

1. A hands B a child credential with `scope ⊆` A's scope. This is the [delegation](delegation-chain.md) model, implemented.
2. Before B accepts, the runtime verifies the chain with `verify_chain` and intersects the delegated scope with a local Cedar policy under B's `enforcement_mode`. Chain verification is implemented; runtime enforcement and Cedar scope intersection are Tier 2 and not yet built. See [Cedar policy](cedar-policy.md).
3. B's `tee` provider produces an `AttestationReport`; the runtime checks the measurement. The interface exists, but no hardware backend verifies a quote yet (Tier 3), so this fails closed. See [attestation](attestation.md).
4. The task payload is sealed to B's measurement through `SealedChannel`. Tier 2, fails closed today. See [sealed channel](sealed-channel.md).
5. B emits a `DelegationRecord` linking to A's record via `record_for`, and any verifier can later run `verify_dag` and `cross_check_chain` offline. Implemented. See [TRACE A2A profile](trace-a2a-profile.md).

What ships today is the offline path: given signed credentials and records, `ca2a_verify` and `provenance` reconstruct and check the delegation tree without trusting the operators that produced it. The runtime peer enforcement, sealed channel, Cedar intersection, and hardware attestation that would gate a live call are pending. See [failure modes](failure-modes.md), [ROADMAP.md](../../ROADMAP.md), and [LIMITATIONS.md](../../LIMITATIONS.md).
