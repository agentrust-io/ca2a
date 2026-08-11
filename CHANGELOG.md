# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Runtime authorization now requires the delegation chain's root issuer to be
  present in the callee's `trusted_root_issuers`. Previously, any party could
  mint a self-consistent root chain granting itself a locally allowed capability;
  every signature and attenuation check passed because no local trust anchor was
  consulted. `ca2a start` now refuses to launch without at least one pinned root.

- Delegation credential parsing now rejects type coercion, unknown fields,
  malformed key/signature encodings, duplicate or invalid scopes, and non-integer
  depths. Previously a different JSON representation (for example `0.9`) could
  normalize to the signed model (`0`) and verify, creating cross-implementation
  ambiguity about what the issuer signed.

- Hardened the unauthenticated reference HTTP boundary. Malformed
  `Content-Length` values and invalid UTF-8 now receive bounded 400 responses
  instead of escaping the handler, incomplete bodies time out, and handshake
  requests must carry exactly one nonce no longer than 256 characters. Provider
  failures during the handshake also use the structured cA2A error path.

- PyPI publication now runs only from a published GitHub Release whose tag
  exactly matches the project version. The workflow validates metadata, installs
  and smoke-tests both the wheel and source distribution in clean environments,
  and publishes only after those gates pass. Runtime `__version__` now comes from
  installed package metadata instead of a stale independent constant.

- Added the missing release container as a multi-stage, rootless image. Runtime
  installation is offline from the builder wheelhouse and the build context
  excludes VCS, tests, docs, and local environments. Pull requests now build the
  image without registry/signing privileges, while tagged releases retain
  version and `latest` tags, keyless signing, and provenance attestation. All
  third-party container actions are pinned to immutable commits.

- Raised dependency floors past newly disclosed vulnerable releases:
  `cryptography>=50.0` (PYSEC-2026-3552/3553/3554), `aiohttp>=3.14.3`
  (PYSEC-2026-3545/3546/3547) for the A2A SDK extra, and
  `pymdown-extensions>=11.0.1` (PYSEC-2026-3654) for documentation builds.

- **A delegation chain was a bearer credential: any party holding a copy was granted the leaf's authority.** The inbound path verified signatures, continuity, attenuation, depth and replay, then granted, without ever requiring the caller to demonstrate a relationship to the chain it presented. `PeerRequest` had no field that could carry such a proof, and `subject` — an Ed25519 public key — was only ever compared as a string for continuity, never used as a key.

  Chains are published deliberately: handed to auditors for offline verification, embedded in provenance DAGs, and shipped in `examples/`. So the credential intended for publication was the credential that granted authority. A chain lifted from any of those and replayed verbatim was accepted, and the provenance record emitted afterwards named the legitimate subject, so the audit trail attributed the call to the wrong party. Nothing was forged, so nothing failed a check and nothing anomalous reached a log; verbatim replay leaves no tamper evidence to find. `CREDENTIAL_REPLAY` does not cover it, catching only a duplicate `credential_id` inside one chain rather than replay of a whole valid chain by a different party.

  **Caller attestation does not close it.** An appraised `caller_offer` establishes what the caller is running; it makes no claim about the delegation subject. A caller could attest itself honestly, at hardware assurance, and still exercise a chain issued to somebody else, because the Ed25519 delegation subject and the X25519 channel key were never joined. `require_caller_attestation` also defaults to `REQUIRE_NONE`, so by default nothing was asked of the caller at all.

  The fix uses the key that was already there. A callee now issues a challenge and the caller answers with an Ed25519 signature under `chain[-1].subject`, over the RFC 8785 canonical form of a body committing to the callee's channel key, the challenge, the leaf `credential_id` and `subject`, the requested capability, the `record_id`, the sealed payload digest, and **the caller's own offered channel key**. That last field is the join: with both mechanisms in play, the attested runtime and the delegated principal are provably the same party, which neither established alone. A proof therefore does not transfer between peers, calls, capabilities, records, payloads, or between attesting and not attesting.

  Order is load-bearing. The chain is verified first, so the leaf subject is a key someone was genuinely delegated rather than one the caller asserted; then the caller is bound to it; only then is the effective scope computed. A caller that has proved nothing never reaches policy evaluation and never elicits a signed denial record — and unlike an appraisal refusal, a holder-proof refusal deliberately emits no provenance, because a caller with no shown relationship to the credential should not get a signed statement about it.

  New error `HolderProofInvalid` / `HOLDER_PROOF_INVALID` at **401**, not 403: the chain may well carry the authority requested, but the caller has not shown it is the party that authority was delegated to. This is RFC 7800 `cnf` semantics — the confirmation pattern `ca2a_verify.dag` already applies to TRACE records — applied to the credential that gates authority.

  Required by default, unlike caller attestation, and the asymmetry is deliberate: attesting a runtime is a capability not every caller has, whereas holding the key you were delegated is not optional, it is what being the delegate means. `require_holder_proof=False` reproduces the old behaviour for offline replay of recorded evidence, where no live caller exists to challenge, and must not be used on a live peer path. `client.send_task` gains a required `holder_key`.

  Reuses `ca2a_runtime.challenge` rather than adding a second challenge mechanism. That scheme is stateless and so cannot be consumed, which would leave a captured proof usable until its challenge expired, so single-use comes from remembering the proof instead: `ProofReplayCache`, which `PeerNode` uses by default with a TTL matching its own challenge TTL. A proof is recorded only after it has verified, so a party holding none of the keys can neither fill the store nor insert a signature to lock the real delegate out of its own proof. The cache is bounded and says what that costs: past capacity the oldest entry is evicted, so a flood degrades the property to the challenge window rather than turning into an outage. `seen_proofs=None` opts out for a deployment across several instances, which wants a shared store or sticky routing, the same caveat the challenge secret already carries.

  Profile requirement **P-4a**, conformance **HOLD-001** through **HOLD-006**, and an adversary and defence row in the threat model.

### Added

- **A bridge to the official `a2a-sdk`, so cA2A reaches the SDK that A2A agents actually run (#91).** cA2A describes itself as a profile on A2A and, until now, integrated with no A2A implementation: `transport.a2a_adapter` parsed A2A-shaped dicts and `transport.server` was a bespoke standard-library HTTP server. Both are honest about being a *reference*, but the practical effect was that a team already running the official SDK could only adopt the profile by replacing their transport with ours, which nobody does to try an alpha. A2A reached v1.0 in April 2026 under the Linux Foundation with SDKs in six languages, and is wired into Google ADK, Azure AI Foundry, Amazon Bedrock AgentCore and Copilot Studio; the profile reached none of it.

  `ca2a_runtime.transport.a2a_sdk` is deliberately thin. The SDK carries A2A `metadata` as a `google.protobuf.Struct`, so converting that to a plain mapping hands the existing adapter exactly what it already parses: one parser, one set of tests, and the profile stays transport-agnostic. Optional extra (`pip install 'ca2a[a2a-sdk]'`); the base install still depends on no A2A implementation.

  **The protobuf round trip nearly broke every chain, and the reason it does not is worth knowing.** `Struct` has no integer type, so a credential's `depth` of `0` arrives as `0.0` — and a credential signature covers the RFC 8785 canonical bytes of its body, where `canonicalize` *refuses floats outright*. Chains verify because `DelegationCredential.from_dict` coerces `depth` with `int()` before anything is canonicalized, so what gets verified is the integer form the signer signed. A non-integral float cannot be smuggled past it either: it coerces to a *different* integer and the signature then fails. Both directions are tested against the real SDK, over multi-hop chains so the non-zero depths actually cross the boundary.

  The SDK is in the `dev` extra rather than only the optional one, so these tests run in CI instead of skipping. A bridge whose tests only ever skip is a bridge nobody has exercised.

- **The callee now appraises the caller, not just its authority (mutual attestation).** The reference transport was one-directional: the callee verified the caller's delegation chain, which says what a peer is *allowed to ask for*, and had no way to know whether the peer sending it a task was an enclave or a laptop. The handshake response now carries a callee-issued challenge, the caller binds its own channel key into a report under it (`caller_offer` in the A2A metadata), and the callee appraises that report **before it opens the sealed payload**. That ordering is the property: the payload is sealed to the callee's own key, so appraising afterwards would mean an unattested caller had already had its work done. `tests/unit/test_mutual_attestation.py` fails if the two calls are swapped, verified by making the swap.

  Off by default and opt-in one rung at a time (`require_caller_attestation`: `"none"` → `"any"` → `"hardware"`), because almost no caller can attest yet and a callee that refused them out of the box is a callee nobody can talk to. `"hardware"` without a verifier is refused at construction rather than on every call. An offer that is *present and does not appraise* is refused at every rung including `"none"`: demanding nothing means accepting a caller that proves nothing, not accepting a broken proof, otherwise a misconfigured attestation path is indistinguishable from a caller that never had one. See `docs/spec/mutual-attestation.md`.

- **A test above the 1 MiB request-body bound.** `_MAX_BODY` was declared and documented in the reference server and no test had ever crossed it. It now declares an oversized `Content-Length` over a raw socket, which is what the guard actually inspects: the server refuses before reading, so the oversized body is never buffered.

- **The committed example DAGs are verified as committed.** The demos regenerate `chain.json` / `dag.json` when they run, so the existing example tests were verifying whatever the demo had just written rather than what is in the repository. `tests/unit/test_committed_examples_verify.py` reads the blobs out of git instead. The gap was not hypothetical: the record-body change below left `examples/cross-operator-delegation/dag.json` broken on disk with the whole suite still green and the README still quoting `ca2a verify-dag` as working.

### Changed

- **BREAKING: every provenance record hash changed.** `DelegationRecord` carries `caller_attestation` in its **hashed body**, always, as one of `not_offered`, `failed`, `software-only`, `hardware`. It is deliberately not omitted when nothing was appraised: absence would leave an auditor unable to tell a peer that checked and found nothing from a peer that never checked, which is the reading the field exists to prevent. Four values rather than three because a peer that offered nothing and a peer whose offer did not appraise are different facts. Records written before this field are read as `not_offered`, the only thing their emitter could honestly have claimed, and the example DAGs were regenerated. `ca2a verify-dag` prints `leaf_caller_attestation` on every run, including when it is `not_offered`.

### Fixed

- **Corrected the Azure vTPM trust-anchor claim after measuring it on hardware (2026-08-01).** `ca2a_verify/tpm_roots.py` presented `AZURE_VTPM_ROOT_2023_PEM` as "the one root cA2A has validated on hardware", which does not hold fleet-wide. On a `Standard_D2s_v7` in eastus2 the AK certificate at NV `0x01C101D0` is 994 bytes, is issued by `CN=Global Virtual TPM CA - 03`, and carries **no AIA extension**, so no intermediates can be fetched (and none are stored elsewhere in NV), no chain reaches the pinned root, and `verify_tpm_report` fails closed with "AK chain root is not among the supplied trusted TPM roots". A different host (`Standard_D2s_v5`, eastus) presented a 1596-byte certificate under `Azure Cloud Virtual TPM CA - 11` whose AIA chain does reach that root. Both are real: Azure runs more than one vTPM CA generation. The constant stays, now documented as one observed hierarchy rather than a guarantee, and a deployment must pin the hierarchy its own hosts present. `LIMITATIONS.md` and the attestation spec say so too.

  The same run **retires** the caveat that collector and verifier could not run in one process: building `tpm2-pytss` from source inside a venv resolves the conflict with `agent-manifest`'s `cryptography`. What blocks end-to-end verification on that host is the missing certificate chain, not tooling.

- **`docs/hardware-validation.md` listed two runs it documents as "not yet validated".** The live attested peer run and the cross-operator cross-TEE run each have a section in that file, and both were still in the outstanding list below them. The list now names what is actually outstanding: hardware runs of the two new collectors, mutual simultaneous attestation, and operator independence.

### Added

- **`SevSnpProvider.attest` and `TdxProvider.attest` now produce real evidence.** Both had the defect #74 fixed for TPM: `detect()` returned True wherever the platform's device node existed while `attest()` raised unconditionally, so on a bare-metal SNP or TDX guest the provider was selected and then failed, with an error claiming the platform was absent on a machine that had it. `BaseProvider` states that pair must agree, and two of the three hardware providers broke it. Both now collect through the kernel configfs-TSM interface (`/sys/kernel/config/tsm/report`, Linux 6.7+), which is one interface for both platforms and supersedes the per-platform ioctls, and `detect()` probes what its collector actually needs.

  Detection also missed Azure entirely. Azure runs SEV-SNP behind a Hyper-V paravisor, so the guest sees no `/dev/sev-guest`; on the very CVM this project ran its attested-peer validation on, `SevSnpProvider.detect()` returned False. Azure remains out of scope for this collector, because a paravisor-mediated guest cannot set `REPORT_DATA` at all, but `attest()` now says that instead of reporting a generic absence, and points at the vTPM path that does work there.

  Neither collector has been run on real SEV-SNP or TDX silicon. They are exercised against a simulated configfs tree and synthetic reports, so they are code that should work rather than a validated capability, and `docs/hardware-validation.md` records exactly that.
- **A key-and-nonce binding for SEV-SNP and TDX.** `REPORT_DATA` carries `sha256("ca2a-snp-v1|" || len32(public_key) || public_key || len32(nonce) || nonce)`, zero-padded to the 64-byte field, and TDX the same under `ca2a-tdx-v1|`. Only TPM had one, so the other two platforms had no defined way to commit the offered channel key and their verifiers' `expected_report_data` had nothing to compare against. Each collector confirms the returned report commits the binding it asked for before shipping it. The three prefixes are domain-separated so a report from one platform cannot be replayed as another's evidence.
- **`TpmProvider.attest` now produces a real TPM quote.** Previously `detect()` returned True on any host with a TPM device node while `attest()` raised unconditionally, so on every Azure Trusted Launch VM and most modern client hardware the provider was selected and then failed, with an error that claimed no TPM was present when one was (#73). The collector is ported from cmcp's hardware-validated path: it prefers the platform attestation key at persistent handle `0x81000003` with its certificate chunk-read from NV `0x01C101D0` (a single read of a 1596-byte certificate fails with `TPM_RC_VALUE`, because `TPM2_NV_Read` is bounded by `TPM2_PT_NV_BUFFER_MAX`), assembles the chain by walking each certificate's AIA extension so verification stays offline later, and falls back to a transient restricted signing key where no certified platform key exists. `detect()` now returns True only where `attest()` can actually run, and `AttestationUnsupported` names the piece that is actually missing.
- **`AttestationReport` can carry evidence.** Four optional fields (`raw_evidence`, `quote_signature`, `attestation_key_pem`, `attestation_key_chain_pem`), named to match cmcp's model so evidence is portable between the runtimes. Without them a report was `platform`, `measurement`, `public_key` and `nonce` with nothing signed behind it, so a relying party could not verify anything and the hardware tier could not supply verifiable evidence by construction. Absent on `software-only`, which has no evidence.
- **The quote commits the offered key, not just the nonce.** `extraData` carries `sha256("ca2a-tpm-v1|" || len32(public_key) || public_key || len32(nonce) || nonce)`, and `ca2a_verify.tpm.verify_tpm_report` re-derives it from the report's own fields and requires equality. That is what promotes `public_key` and `nonce` from assertion to signed fact, so sealing to "a key from a verified report" is actually rooted in hardware; committing the nonce alone would sign for freshness only. Fields are length-prefixed rather than delimiter-joined because a delimiter lets a value containing it shift the split without changing the digest, and `nonce` is an arbitrary caller-supplied string. The returned measurement is read out of the signed quote, and a report whose `measurement` disagrees with it is rejected.
- **`ca2a_verify.tpm.tpm_verifier(roots)`** returns a `Verifier` for `verify_offer`, so a TPM peer reaches `assurance="hardware"`. `ca2a_verify.tpm_roots.AZURE_VTPM_ROOT_2023_PEM` carries the one root validated on hardware as an opt-in constant; nothing is trusted implicitly, and supplying no root is refused rather than treated as trust-anything.

### Changed

- **One derivation for the key-and-nonce binding**, in `ca2a_runtime.tee.binding`, shared by all three providers so the platforms cannot drift apart. `tpm_qualifying_data` keeps its signature and its bytes; only the prefix differs per platform. Conformance requirement ATTEST-001 now states the durable invariant (a provider is never selected where it cannot produce evidence) rather than the temporary fact that SEV-SNP and TDX had no collector.
- **TPM quote cryptography now delegates to `agent_manifest.verify_tpm_quote`** instead of being cA2A's own third copy of one verifier (cmcp#447). cA2A keeps only what agent-manifest does not model: `TPMT_SIGNATURE`, the envelope `tpm2_quote -s` and tpm2-pytss `signature.marshal()` emit, unwrapped to the bare signature agent-manifest takes. `verify_tpm_quote` keeps its signature and behavior, including the magic and attest-type checks, which agent-manifest enforces too.
- **No SHA-1 PCR fallback and no unsigned-PCR-read tier**, both deliberate departures from cmcp's collector. cmcp downgrades to `software-only` in each case; cA2A raises. A report labelled `sha256:` that measured SHA-1 banks is a mislabel waiting to happen, and a `tpm` report that can never verify is worse than an honest error. The collector also cross-checks its own PCR read against the quote's `pcrDigest`, so a PCR selection mismatch is caught before evidence ships.
- Docs corrected where they stated the opposite of the code: `detect()` returning False for every hardware provider was asserted in the attestation spec, the component model, failure modes, and two tutorials.

### Added

- **`ca2a start`**: run the reference transport from a config file. It resolves
  the policy (`local_policy` or a Cedar `policy_bundle_path`, the latter relative
  to the config file) and the attestation provider, builds a
  `ca2a_runtime.node.PeerNode`, and serves it with
  `ca2a_runtime.transport.server`. The wiring lives in `ca2a_runtime.bootstrap`
  (`load_policy`, `select_provider`, `build_peer_node`) so a program that already
  has a `Policy` and a provider can keep constructing a `PeerNode` directly; the
  CLI adds no capability the library did not have. No new dependencies: the
  reference transport is standard library only. Provider selection fails closed.
  `software-only` has no hardware guarantee, so `auto` refuses to start when no
  confidential-computing platform is detected rather than silently choosing it,
  and a named hardware provider whose device node is absent is a startup error.
  Software mode prints what a caller will appraise the channel key as
  (`assurance="none"`) instead of letting the operator assume otherwise. This
  closes the `ca2a start` gap the transport spec listed. See issue #47.

### Changed

- `Ca2aConfig.listen_addr` now defaults to `127.0.0.1:8443` and must name a host
  explicitly. It was `0.0.0.0:8443` while nothing read it; now that `ca2a start`
  binds it, defaulting to every interface would put a peer on the network by
  omission. `transport.server.serve` already defaulted to loopback, so the two
  agree. Bracketed IPv6 (`[::1]:8443`) parses, and a malformed address fails
  `ca2a validate-config` rather than at bind time.
- Dropped `enclave_private_key_hex` from the config. A `PeerNode` generates its
  own X25519 channel keypair and publishes the public half through the
  attestation handshake, so the caller seals to a key the node attested. A
  pre-shared key in a config file would be sealing to something nobody appraised.

### Changed

- **BREAKING: TRACE records now carry the v0.2 profile** `tag:agentrust-io.com,2026:trace-v0.2`. Pins move to `agentrust-trace>=0.5` and `agentrust-trace-tests>=0.4,<0.5`, which have to move together: the conformance suite cut over rather than dual-accepting, so 0.4.0 of the suite fails a v0.1 record and 0.3.x fails a v0.2 one. The v0.1 URI named `agentrust.io`, a domain this project never controlled, which RFC 4151 does not permit for a tag URI (agentrust-io/trace-spec#107). Nothing else about the record format changed.

### Changed

- **Extension URI moved to `https://agentrust-io.com/extensions/ca2a/v0.1`.** The previous `agentrust.io` host is not ours: it resolves to parked AWS addresses. An extension identifier is something we are asking other operators to copy into their Agent Cards, so it must not depend on a domain we do not control. A2A treats these URIs as identifiers rather than fetchable URLs, so nothing breaks functionally, but any peer pinning the old string must update. The adapter constant, the transport spec, the fixture, and the test that pins the constant all move together.

### Fixed

- Two spec pages contradicted `hardware-validation.md` after the live hardware run landed. `profile.md` P-6 still read "not yet met ... `assurance="none"`" and `call-graph.md` still called hardware appraisal "the remaining hardware step", when `verify_offer` had already returned `assurance="hardware"` off a live SEV-SNP quote on 2026-07-27. Both now state what is true, including the two limits that remain: the appraisal is one-directional (the caller appraised the callee, not the reverse), and the committed examples stay software-attested because genuine evidence embeds per-CPU identifiers.

### Added

- **A refusal is now evidence.** `enforce_peer_call` previously raised on an over-scoped call and emitted nothing, so a denial left no artifact and an auditor saw a gap where a hop should be. It now builds a linked denial record (`provenance.denial_record_for`) carrying the requested capability, the effective scope it fell outside, and the reason, and attaches it to `ScopeNotPermitted.record`. The call still fails closed; the record is evidence of the refusal, not a way to continue. `verify_dag` treats a denial as terminal and rejects any chain that continues past a refused hop, `cross_check_chain` matches only hop records positionally against the chain while still requiring a denial to name a credential that is in it, and `ca2a verify-dag` reports `outcome: denied` with the requested capability and effective scope. Denial fields are omitted from an allow record's hashed body, so existing allow-record hashes are unchanged.
- **`examples/rejection-with-proof/`**: the front-door demo. An agent asks for authority nobody delegated to it, is refused, and the refusal verifies offline through the shipped CLI against the committed chain and DAG. The callee's local policy deliberately permits the capability, so the refusal turns on delegation rather than on the callee not supporting it. The example runs in CI (`tests/unit/test_example_rejection_with_proof.py`) so the README cannot promise something the code stopped doing. It makes no attestation claim and says so.

### Changed

- Certificate-chain verification now delegates to agent-manifest's shared generic verifier (`agent-manifest>=0.5`) instead of ca2a's own copy. `ca2a_verify.verify_cert_chain` (used by the SEV-SNP VCEK, TDX PCK, and TPM AK chains alike) is now a thin wrapper over `agent_manifest.verify_cert_chain`, re-raising `CertChainError` as `AttestationFailed` to preserve ca2a's contract. This removes the org's last duplicated cert-chain verifier; ca2a keeps its own report/quote parsers, per-format signature checks, appraisal shapes, trust-root pinning, and `verify_offer` semantics. Behavior unchanged (all 201 tests pass unchanged).
- Bumped `agentrust-trace` to `>=0.4`. The previous `<0.4` cap worked around the
  published 0.3.0 lacking the TRACE A2A `delegation` block that cA2A records
  carry; 0.4.0 ships that block, so the cap is removed. cA2A still owns the
  delegation-block semantics natively (`trace_binding`/`ca2a_verify.dag`); no
  code shim was needed. All tests pass against 0.4.0.

### Added

- A2A transport adapter (`ca2a_runtime.transport`): parse/attach cA2A extension
  metadata on A2A `SendMessage`-shaped messages into `PeerRequest` (and the
  reverse). Extension URI `https://agentrust-io.com/extensions/ca2a/v0.1`. Fail closed
  on malformed cA2A metadata; absence of all cA2A keys returns `None` (ordinary
  A2A). The adapter itself adds no HTTP serving or seal-to-verified-measurement
  binding; the reference transport below adds serving, and hardware measurement
  binding is still pending. New error `TRANSPORT_ERROR`. See issue #47.
- Reference HTTP transport and attestation handshake, software mode (Tier 2):
  `ca2a_runtime.transport.server`/`client` (standard library only) run a live
  inbound A2A-profile call end to end over HTTP, `ca2a_runtime.node.PeerNode`
  composes the provider, policy, adapter, and `handle_peer_request`, and
  `ca2a_runtime.attestation` (offer/verify/seal) gates the seal on a channel key
  the caller appraises under a fresh nonce. `ca2a_runtime.tee.software.SoftwareProvider`
  supplies the no-hardware provider (never auto-selected). This is a **reference**
  transport, not part of the profile: the profile mandates no wire protocol. In
  software mode the peer key is `assurance="none"`; binding the seal to a
  hardware-verified measurement (the `verifier` seam wrapping `ca2a_verify`) is
  the remaining hardware step. Exercised end to end by `tests/unit/test_live_call.py`.

## [0.1.0a1] - 2026-07-09

First public alpha. Everything in this release is verifiable offline or in
software today. cA2A is a profile in active design: the delegation semantics and
the TEE verifiers are implemented and tested, but the profile is not yet attested
across trust domains on real hardware and there is no live A2A transport. That
milestone gates the first non-alpha release. See LIMITATIONS.md for the exact
built/stubbed boundary.

### What this release provides

- Initial cA2A profile draft: attested, attenuated agent-to-agent delegation on top of A2A
- `ca2a-verify`: offline delegation-chain verification skeleton (scope attenuation, signature, depth, replay checks)
- `ca2a-runtime`: config, error registry, and delegation credential model
- `ca2a_runtime.provenance`: linked delegation-record DAG with tamper and reparent detection, bound to authority via `cross_check_chain`
- `experiments/`: reproducible claim suite C1-C6. C1 (attenuation), C2 (cross-chain replay), and C5 (provenance DAG) are fully reproducible; C3, C4, C6 SKIP until their Tier 2/3 dependency lands. Each claim has a CI test.
- SEV-SNP attestation backend (Tier 3): `ca2a_runtime.tee.sev_snp` (report parsing, `SevSnpProvider`) and `ca2a_verify.sev_snp` (VCEK chain verification, ECDSA-P384 report-signature verification, measurement/report-data binding), all fail-closed. Chain path validated against the real AMD Milan root; report-signature path validated with synthetic vectors. Report generation requires a real SEV-SNP guest.
- Peer-call enforcement decision core (Tier 2): `ca2a_runtime.policy.LocalPolicy` and `ca2a_runtime.peer` (`effective_scope`, `enforce_peer_call`). Effective permission is the delegated leaf scope intersected with the callee's local policy; a granted call emits a linked provenance record. New error `SCOPE_NOT_PERMITTED`. Claim C3 (scope-policy intersection) is now a validated experiment. Cedar-engine binding of the local policy and live A2A transport wiring remain open.
- Sealed peer channel (Tier 2): `ca2a_runtime.channel` (`SealedChannel`, `generate_channel_keypair`, `open_sealed`). HPKE-style X25519 -> HKDF-SHA256 -> ChaCha20-Poly1305 sealing a payload to the peer's attested key; only the peer's private key opens it, and a wrong key or tampered ciphertext fails closed. Claim C4 (sealed-payload confidentiality) is now a validated experiment at the cryptographic layer. The enclave-binding of the private key (a hardware property) and live-path wiring remain open.
- Cross-operator attestation (Claim C6) validated in software: a two-operator harness composing the SEV-SNP verifier, measurement pinning, and the sealed channel demonstrates independent keys, mutual attestation, confidential cross-operator delegation, and binary-swap detection. Synthetic report vectors (a genuine report needs SEV-SNP hardware); real hardware end to end remains open. **All six claims (C1-C6) are now validated experiments.**
- cA2A-compatible conformance suite: `tests/conformance/` with a normative README (stable MUST/SHOULD test IDs across delegation, scope-policy, attestation, sealed channel, provenance, and the inbound pipeline) and runnable checks that exercise every MUST-level requirement. Wired into CI and documented at `docs/spec/conformance.md`; ties to the CHARTER trademark language.
- TPM 2.0 attestation backend: `ca2a_runtime.tee.tpm` (TPMS_ATTEST parsing, `TpmProvider`) and `ca2a_verify.tpm.verify_tpm_quote` (AK chain to a caller-supplied vendor root, AK signature over the attest blob (ECDSA or RSA), magic/type checks, and qualifying-data/PCR-digest binding), all fail-closed. Synthetic-vector validated; TPM AK roots are per-vendor so the caller supplies its trusted roots. Quote generation requires a real TPM.
- Intel TDX attestation backend: `ca2a_runtime.tee.tdx` (DCAP Quote v4 parsing, `TdxProvider`) and `ca2a_verify.tdx.verify_tdx_quote` (PCK chain to a trusted Intel root, QE report signature, attestation-key binding, quote signature, and MRTD/report-data binding), all fail-closed. Chain path validated against the genuine Intel SGX Root CA; multi-level signature path validated with a synthetic self-consistent quote. Quote generation requires a real TDX guest.
- AGT governance gate is now **blocking** (was advisory): CI installs `agent-governance-toolkit[full]`, so the OWASP ASI 2026 coverage modules load and `agt verify` reports 10/10 coverage with 6/6 runtime checks (COMPLETE). The enforcement descriptor now declares cA2A's `governed_capabilities`, reported as the registered-tools inventory. A governance or coverage regression now fails CI.
- Real Cedar policy engine binding: `ca2a_runtime.cedar.CedarPolicy` (backed by `cedarpy`, the engine cMCP runs) evaluates each capability as a Cedar authorization request. A new `ca2a_runtime.policy.Policy` protocol makes `LocalPolicy` (allow set) and `CedarPolicy` interchangeable in the peer path. Adds the `cedarpy` dependency.
- Transport-agnostic inbound peer request handler: `ca2a_runtime.peer.handle_peer_request` with `PeerRequest` / `PeerResult`. Composes the full pipeline (verify chain, intersect scope and enforce, open a sealed payload with the enclave key, emit a linked provenance record) fail-closed. A transport parses its wire format into a `PeerRequest`; cA2A does not define the transport (profile, not protocol).
- TRACE binding for the delegation DAG (Tier 2): `ca2a_runtime.trace_binding` lifts each delegation hop into a signed TRACE Trust Record carrying the A2A profile `delegation` block (`build_trace_record`, `sign_trace_record`, `emit_dag`, `trace_record_hash`, `HopContext`). Records are produced and signed with `agentrust-trace` (Ed25519 over RFC 8785), so TRACE canonicalization and signing are reused, not reimplemented. `ca2a_verify.verify_trace_dag` verifies a signed root-to-leaf DAG offline (structural validity, trusted-key signature, unbroken parent links over the full signed parent record) and `cross_check_trace_dag` ties it to the delegation chain; new error `TRACE_RECORD_INVALID`. Software-mode records are Level 0 (platform `software-only`); a hardware TEE run is what lifts them to Level 1. Adds the `agentrust-trace` dependency (and `agentrust-trace-tests` for dev). See `examples/trace-dag/`.
- RFC 8785 (JSON Canonicalization Scheme) canonicalization: `ca2a_runtime.canonical.canonicalize`. Credential and provenance bodies are now signed over the JCS encoding (UTF-16 key ordering, JCS string escaping, literal non-ASCII, shortest-decimal integers), so cA2A signatures are cross-verifiable with agent-manifest. ASCII credentials are byte-identical to the previous encoding, so existing signatures still verify.
- Repository scaffold: governance, CI/CD, docs framework, and packaging at parity with the agentrust-io house standard

### What this release does NOT yet claim

- Not attested or confidential across trust domains on real hardware: all attestation validation is software / synthetic-vector. No real SEV-SNP, TDX, or TPM quote has been verified end to end against a golden measurement on a confidential VM.
- No live A2A transport: the peer-enforcement decision core and sealed channel run in-process. Nothing parses real A2A wire messages into a `PeerRequest` yet, and the seal is not bound to a verified attestation report on a live inbound call.
- The sealed channel does not by itself establish the enclave-held-private-key property; that is a hardware attestation guarantee that lands with real-hardware validation.
- Alpha schemas: the delegation credential and TRACE link schemas are not yet stable or versioned, and peer attestation evidence is not yet RATS/EAT conformant.

[Unreleased]: https://github.com/agentrust-io/ca2a/compare/v0.1.0a1...main
[0.1.0a1]: https://github.com/agentrust-io/ca2a/releases/tag/v0.1.0a1
