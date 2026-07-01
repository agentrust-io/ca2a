# Limitations

cA2A is a pre-release profile in active design. This document states plainly what is built, what is stubbed, and what is out of scope, so no claim in the documentation runs ahead of the code. This is a deliberate discipline: proof, not promises.

## What is built

- The delegation credential model and the offline chain verifier skeleton: signature checks, scope attenuation (a child grant must be a provable subset of its parent), depth limits, and cross-chain replay rejection. The hardest of these semantics is reused from [agent-manifest](https://github.com/agentrust-io/agent-manifest), where it is implemented and tested.
- Configuration, error registry, and the CLI surface.

## What is stubbed or not yet implemented

- **Runtime peer-delegation enforcement.** The runtime does not yet accept a delegation credential on a live inbound peer call, verify it in the request path, and intersect the delegated scope with a local Cedar policy. This is Tier 2 on the roadmap.
- **Sealed peer channel.** Payloads are not yet sealed to a peer's attested measurement. Until this lands, do not send confidential task payloads across a trust boundary and assume they are protected.
- **Real hardware attestation.** Attestation verification fails closed and the hardware signature/quote step is not implemented (SEV-SNP VCEK chain, Intel TDX quote via QVL/PCS, TPM AK cert + checkquote). Until at least one real backend lands, cA2A must not be described as attested across trust domains. This is Tier 3 and is a shared critical path with cmcp.

## Out of scope

- The A2A transport itself. cA2A is a profile on A2A, not a replacement for it.
- Agent identity issuance beyond delegation.
- AI model governance beyond delegation and provenance.
- Hardware TEE platform SDKs and firmware.

## Dependencies on sibling projects

cA2A composes primitives from [agent-manifest](https://github.com/agentrust-io/agent-manifest), [cmcp](https://github.com/agentrust-io/cmcp), and [trace-spec](https://github.com/agentrust-io/trace-spec). Version skew across those repos can change cA2A behavior; pin compatible versions before relying on cross-repo guarantees.
