# Limitations

cA2A is a pre-release profile in active design. This document states plainly what is built, what is stubbed, and what is out of scope, so no claim in the documentation runs ahead of the code. This is a deliberate discipline: proof, not promises.

## What is built

- The delegation credential model and the offline chain verifier skeleton: signature checks, scope attenuation (a child grant must be a provable subset of its parent), depth limits, and cross-chain replay rejection. The hardest of these semantics is reused from [agent-manifest](https://github.com/agentrust-io/agent-manifest), where it is implemented and tested.
- Configuration, error registry, and the CLI surface.

## What is stubbed or not yet implemented

- **Runtime peer-delegation enforcement.** The runtime does not yet accept a delegation credential on a live inbound peer call, verify it in the request path, and intersect the delegated scope with a local Cedar policy. This is Tier 2 on the roadmap.
- **Sealed peer channel.** Payloads are not yet sealed to a peer's attested measurement. Until this lands, do not send confidential task payloads across a trust boundary and assume they are protected.
- **Real hardware attestation.** The **SEV-SNP verifier is implemented**: report parsing, VCEK certificate chain verification, ECDSA-P384 report-signature verification, and measurement/report-data binding, all fail-closed. The chain path is validated against the genuine AMD Milan root chain; the report-signature path is validated with synthetic vectors, since a real report plus VCEK pair needs SEV-SNP hardware. Report generation (`SevSnpProvider.attest`) still requires a real SEV-SNP guest. **Intel TDX and TPM backends are not yet implemented (Tier 3).** Until a backend verifies a real quote end to end against a golden measurement on hardware, cA2A must not be described as fully attested across trust domains.

## Out of scope

- The A2A transport itself. cA2A is a profile on A2A, not a replacement for it.
- Agent identity issuance beyond delegation.
- AI model governance beyond delegation and provenance.
- Hardware TEE platform SDKs and firmware.

## Dependencies on sibling projects

cA2A composes primitives from [agent-manifest](https://github.com/agentrust-io/agent-manifest), [cmcp](https://github.com/agentrust-io/cmcp), and [trace-spec](https://github.com/agentrust-io/trace-spec). Version skew across those repos can change cA2A behavior; pin compatible versions before relying on cross-repo guarantees.
