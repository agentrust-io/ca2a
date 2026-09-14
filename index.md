[03 · Actions: was each delegation checked inside attested hardware?](https://agentrust-io.com/#chain)

# Verify who delegated what to each agent

cA2A is a profile on A2A that adds signed attenuated delegation, peer appraisal, a sealed peer channel and a TRACE provenance record per hop, checkable offline against a root you trust.

[Verify your first delegation chain](https://ca2a.agentrust-io.com/docs/quickstart/index.md) [What this proves, and what it does not](https://ca2a.agentrust-io.com/LIMITATIONS/index.md)

TL;DR

[ca2a-runtime](https://pypi.org/project/ca2a-runtime/) 0.2.0 (MIT developer preview; the PyPI name `ca2a` belongs to an unrelated project) rejects scope escalation offline with no hardware or running peer. SEV-SNP and TDX appraisal ran on real Azure and GCP evidence, including an Azure SEV-SNP peer calling a GCP TDX peer on 2026-07-27, but peer appraisal is one-directional so far and binding the seal to a verified measurement on a live call is on the roadmap.

- **Run it**

  ______________________________________________________________________

  Verify a narrowed grant and reject both an untrusted issuer and signed scope escalation, then stand up the live peer runtime.

  [Quick Start](https://ca2a.agentrust-io.com/docs/quickstart/index.md)

- **What it proves, and what it does not**

  ______________________________________________________________________

  What has run against real silicon, what is one-directional, and what is not appraised at all.

  [Limitations](https://ca2a.agentrust-io.com/LIMITATIONS/index.md)

- **Hardware evidence**

  ______________________________________________________________________

  SEV-SNP on Azure and Intel TDX on GCP C3, validated 2026-07-27, with the collectors run on real silicon on 2026-08-24.

  [Hardware validation](https://ca2a.agentrust-io.com/docs/hardware-validation/index.md)

- **The chain**

  ______________________________________________________________________

  Before it: [Agent Manifest](https://manifest.agentrust-io.com) issues the attenuated delegation credential. Alongside: [cMCP](https://cmcp.agentrust-io.com) covers tool calls. Each hop's record is written in [TRACE](https://trace.agentrust-io.com). Check a real TDX quote at [agentrust-io.com/verify](https://agentrust-io.com/verify/).

  [See the chain](https://agentrust-io.com/#chain)

## The gap it closes

An agent identity does not by itself establish delegation authority. When A delegates to B and B delegates to C, the relying party needs to authenticate the root and check each grant. Live calls also need caller authentication, local policy, and any required runtime appraisal.

## The four primitives

| Mechanism              | What to check                                                 | Start here                                                                              |
| ---------------------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Delegation credentials | Trusted root, signatures, continuity, bounded scope and depth | [Offline quickstart](https://ca2a.agentrust-io.com/docs/quickstart/index.md)            |
| Runtime appraisal      | Evidence and measurements required by the relying party       | [Attestation](https://ca2a.agentrust-io.com/docs/spec/attestation/index.md)             |
| Sealed peer channel    | Payload encryption to the appraised peer key                  | [Sealed channel](https://ca2a.agentrust-io.com/docs/spec/sealed-channel/index.md)       |
| Linked provenance      | Record signatures and parent links                            | [TRACE A2A profile](https://ca2a.agentrust-io.com/docs/spec/trace-a2a-profile/index.md) |

Software and hardware modes provide different assurance. Peer appraisal has been demonstrated one-directionally; mutual simultaneous hardware attestation remains outstanding. Read [Limitations](https://ca2a.agentrust-io.com/LIMITATIONS/index.md) before relying on a hardware claim.

For the architecture and trust boundaries, read [How It Works](https://ca2a.agentrust-io.com/docs/concepts/index.md). The normative profile, with the delegation chain, sealed channel, and conformance rules, is in [Profile](https://ca2a.agentrust-io.com/docs/spec/profile/index.md).

**Status:** ca2a-runtime 0.2.0 developer preview · MIT · hosting at the Agentic AI Foundation proposed, not accepted · Sponsored by OPAQUE, which funds the engineering, infrastructure and confidential-computing work behind these projects.
