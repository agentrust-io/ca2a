---
hide:
  - navigation
  - toc
title: "cA2A: verify who delegated what, hop by hop"
description: cA2A adds delegation and peer trust checks to A2A. Start with an offline chain that accepts a narrowed grant and rejects scope escalation.
---

[03 · Actions: was each delegation checked inside attested hardware?](https://agentrust-io.com/#chain)

# Verify who delegated what to each agent

cA2A is a profile on A2A that adds signed attenuated delegation, peer appraisal, a sealed peer channel and a TRACE provenance record per hop, checkable offline against a root you trust.

[Verify your first delegation chain](docs/quickstart.md){ .md-button .md-button--primary }
[What this proves, and what it does not](LIMITATIONS.md){ .md-button }

!!! tip "TL;DR"
    [ca2a-runtime](https://pypi.org/project/ca2a-runtime/) 0.3.1 (MIT developer preview; the PyPI name `ca2a` belongs to an unrelated project) rejects scope escalation offline with no hardware or running peer. SEV-SNP and TDX appraisal ran on real Azure and GCP evidence, including an Azure SEV-SNP peer calling a GCP TDX peer on 2026-07-27, but peer appraisal is one-directional so far and binding the seal to a verified measurement on a live call is on the roadmap.

<div class="grid cards" markdown>

-   __Run it__

    ---

    Verify a narrowed grant and reject both an untrusted issuer and signed scope escalation, then stand up the live peer runtime.

    [Quick Start](docs/quickstart.md)

-   __What it proves, and what it does not__

    ---

    What has run against real silicon, what is one-directional, and what is not appraised at all.

    [Limitations](LIMITATIONS.md)

-   __Hardware evidence__

    ---

    SEV-SNP on Azure and Intel TDX on GCP C3, validated 2026-07-27, with the collectors run on real silicon on 2026-08-24.

    [Hardware validation](docs/hardware-validation.md)

-   __The chain__

    ---

    Before it: [Agent Manifest](https://manifest.agentrust-io.com) issues the attenuated delegation credential. Alongside: [cMCP](https://cmcp.agentrust-io.com) covers tool calls. Each hop's record is written in [TRACE](https://trace.agentrust-io.com). Check a real TDX quote at [agentrust-io.com/verify](https://agentrust-io.com/verify/).

    [See the chain](https://agentrust-io.com/#chain)

</div>

## The gap it closes

An agent identity does not by itself establish delegation authority. When A delegates to B and B delegates to C, the relying party needs to authenticate the root and check each grant. Live calls also need caller authentication, local policy, and any required runtime appraisal.

## The four primitives

| Mechanism | What to check | Start here |
|---|---|---|
| Delegation credentials | Trusted root, signatures, continuity, bounded scope and depth | [Offline quickstart](docs/quickstart.md) |
| Runtime appraisal | Evidence and measurements required by the relying party | [Attestation](docs/spec/attestation.md) |
| Sealed peer channel | Payload encryption to the appraised peer key | [Sealed channel](docs/spec/sealed-channel.md) |
| Linked provenance | Record signatures and parent links | [TRACE A2A profile](docs/spec/trace-a2a-profile.md) |

Software and hardware modes provide different assurance. Peer appraisal has been demonstrated one-directionally; mutual simultaneous hardware attestation remains outstanding. Read [Limitations](LIMITATIONS.md) before relying on a hardware claim.

For the architecture and trust boundaries, read [How It Works](docs/concepts.md). The normative profile, with the delegation chain, sealed channel, and conformance rules, is in [Profile](docs/spec/profile.md).

**Status:** ca2a-runtime 0.3.1 developer preview · MIT · hosting at the Agentic AI Foundation proposed, not accepted · Sponsored by OPAQUE, which funds the engineering, infrastructure and confidential-computing work behind these projects.
