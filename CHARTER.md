# Technical Charter: cA2A

**Proposed hosting**: Agentic AI Foundation (AAIF).
**Status**: Pre-acceptance draft: effective upon host organization acceptance.

> **Note for external contributors:** This charter is a working draft and has not yet been accepted by a host organization. Governance terms, IP policy, and trademark ownership described here are proposed, not final. Do not assume binding foundation commitments until formal acceptance.

**Version**: 0.1

---

## 1. Mission

The cA2A project develops and maintains an open trust profile for confidential agent-to-agent delegation, layered on top of the A2A protocol. The mission is to make inter-agent delegation cryptographically verifiable and confidential by any party, without trusting the operator, without a competing transport, and without lock-in to any silicon vendor, cloud provider, or AI platform.

## 2. Scope

The project includes:

- **cA2A Profile**: the binding that layers attested, attenuated delegation, sealed peer channels, and provenance records on A2A. Published as a profile, not a protocol.
- **cA2A Runtime**: the reference open-source implementation of peer-delegation enforcement and the sealed peer channel (`ca2a-runtime`).
- **cA2A Verify**: the offline verifier for delegation chains and the delegation DAG (`ca2a-verify`).
- **TRACE A2A profile integration**: the delegation-link fields added to TRACE records (see [agentrust-io/trace-spec](https://github.com/agentrust-io/trace-spec)).
- **agent-manifest binding**: reuse of the signed, attenuated delegation chain (see [agentrust-io/agent-manifest](https://github.com/agentrust-io/agent-manifest)).

Out of scope: the A2A transport itself, agent identity issuance beyond delegation, AI model governance, hardware TEE platform SDKs, and any attempt to rebuild or fork A2A.

## 3. Technical Steering Committee

Upon host organization acceptance, governance transitions from the current Project Lead model to a Technical Steering Committee (TSC).

**Composition**: 3-7 members. No single organization may hold more than 40% of TSC seats. The founding Project Lead (Imran Siddique, OPAQUE Systems) holds one founding seat for the v1.0 release cycle.

**Election**: TSC members are elected annually by active contributors (at least one merged pull request in the preceding 12 months). Each contributor has one vote.

**Quorum**: Two-thirds of TSC members must participate for a vote to be valid.

**Decisions**:
- Patch releases and editorial changes: simple TSC majority
- Minor releases (new primitives, new TEE providers): two-thirds TSC majority + 7-day public comment
- Breaking profile changes (delegation credential format, TRACE link fields): two-thirds TSC majority + 30-day public comment + explicit migration guide

**Meetings**: Monthly public TSC meeting. Notes published within 5 business days.

## 4. Intellectual Property Policy

All contributions must be made under the terms of [LICENSE](LICENSE). Contributors must sign commits with the Developer Certificate of Origin (DCO). No contribution may incorporate material covered by a patent the contributor is unwilling to license royalty-free to conforming implementations.

## 5. Trademark Policy

"cA2A" and "cA2A-compatible" as project and conformance marks are currently held by OPAQUE Systems, Inc. Upon host organization acceptance, trademark ownership transfers to AAIF under their standard trademark policy.

Use of "cA2A-compatible" to describe a deployment requires that the implementation satisfies the attestation, attenuation, and provenance requirements defined in the project documentation for the version being claimed.

## 6. Relationship to other projects

cA2A builds on and does not replace:

- **A2A (Agent2Agent, Linux Foundation / AAIF)**: the underlying agent-to-agent transport that cA2A profiles with attestation and attenuated delegation
- **TRACE** ([agentrust-io/trace-spec](https://github.com/agentrust-io/trace-spec)): provenance record emitted per delegation hop
- **agent-manifest** ([agentrust-io/agent-manifest](https://github.com/agentrust-io/agent-manifest)): the signed, attenuated delegation chain
- **cMCP** ([agentrust-io/cmcp](https://github.com/agentrust-io/cmcp)): shared TEE provider abstraction, Cedar policy engine, and audit chain
- **RATS / EAT (RFC 9711)** and **SCITT**: attestation evidence and transparency formats

## 7. Transition timeline

| Milestone | Target |
|---|---|
| v0.1 profile draft and delegation-chain verifier | Q3 2026 |
| Runtime peer-delegation enforcement and sealed channel | Q4 2026 |
| AAIF project proposal submission | Q4 2026 |
| v1.0 stable profile under TSC governance | 2027 |

## 8. Amendments

Amendments to this charter require a two-thirds TSC majority and a 30-day public comment period. Before host organization acceptance, amendments require Project Lead approval and 14-day notice to contributors.
