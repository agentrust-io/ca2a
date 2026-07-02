# cA2A Profile Specification

**Status**: draft, v0.1. This document describes the cA2A profile: a binding on A2A that makes agent-to-agent delegation attested, attenuated, confidential, and provable.

## Scope of this document

cA2A is a profile, not a transport. It does not define how tasks are moved between agents; A2A does that. It defines the trust envelope around a delegated task: what credential accompanies it, what a peer must prove before accepting it, how the payload is protected in transit and at rest in the peer, and what record is left behind.

## Design tenets

1. **Profile, not protocol.** Bind to A2A and to IETF RATS, EAT, and SCITT rather than reinvent them.
1. **Neutral by construction.** No coupling to a single silicon vendor, cloud, or AI platform. This is the claim a vendor-anchored verifier cannot make.
1. **Fail closed.** Absence of evidence is denial, not a warning. A missing attestation or an unverifiable chain denies the call.
1. **Offline verifiable.** A third party can verify a delegation chain and its provenance DAG without contacting or trusting any operator.

## Components

| Component            | Specification                                                                                    |
| -------------------- | ------------------------------------------------------------------------------------------------ |
| A2A binding          | [profile.md](https://ca2a.agentrust-io.com/docs/spec/profile/index.md)                           |
| Delegation chain     | [delegation-chain.md](https://ca2a.agentrust-io.com/docs/spec/delegation-chain/index.md)         |
| Peer attestation     | [attestation.md](https://ca2a.agentrust-io.com/docs/spec/attestation/index.md)                   |
| Sealed peer channel  | [sealed-channel.md](https://ca2a.agentrust-io.com/docs/spec/sealed-channel/index.md)             |
| TRACE A2A profile    | [trace-a2a-profile.md](https://ca2a.agentrust-io.com/docs/spec/trace-a2a-profile/index.md)       |
| Verification library | [verification-library.md](https://ca2a.agentrust-io.com/docs/spec/verification-library/index.md) |
| Threat model         | [threat-model.md](https://ca2a.agentrust-io.com/docs/spec/threat-model/index.md)                 |

## Conformance

An implementation may claim "cA2A-compatible" for a given version when it enforces, on an inbound peer call: delegation chain verification (signature, continuity, attenuation, anti-replay), peer attestation against an expected measurement, payload sealing to that measurement, and emission of a linked TRACE record. These requirements are defined as a numbered, runnable conformance suite; see [conformance](https://ca2a.agentrust-io.com/docs/spec/conformance/index.md).

## Relationship to sibling specs

cA2A reuses the delegation semantics of [agent-manifest](https://github.com/agentrust-io/agent-manifest), the TEE and policy primitives of [cmcp](https://github.com/agentrust-io/cmcp), and the record format of [trace-spec](https://github.com/agentrust-io/trace-spec). The delegation-link fields are added to TRACE under the A2A profile.
