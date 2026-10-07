---
hide:
  - navigation
  - toc
title: "cA2A: verify who delegated what, hop by hop"
description: cA2A adds delegation and peer trust checks to A2A. Start with an offline chain that accepts a narrowed grant and rejects scope escalation.
---

[03 · Actions: was each delegation checked inside attested hardware?](https://agentrust-io.com/#chain)

# Verify who delegated what to each agent

When one AI agent hands work to another, cA2A records who gave which permission to whom, and lets anyone check that no agent quietly gave itself more. It sits on top of A2A, the common protocol agents use to talk to each other (see [the terms, in plain English](https://agentrust-io.com/#plain-terms)). Each handoff carries a signed permission slip that can only shrink, each agent can be asked for hardware proof of what it is running, the task can be encrypted so only the checked agent can read it, and each step leaves a signed record you can check offline against a starting authority you chose to trust.

[Verify your first delegation chain](docs/quickstart.md){ .md-button .md-button--primary }
[What this proves, and what it does not](LIMITATIONS.md){ .md-button }

!!! tip "TL;DR"
    [ca2a-runtime](https://pypi.org/project/ca2a-runtime/) 0.4.0 (MIT developer preview; the PyPI name `ca2a` belongs to an unrelated project) catches an agent that tries to pass on more permission than it was given, offline, with no special hardware and no running agents. Checks of AMD SEV-SNP and Intel TDX hardware reports ran on real Azure and GCP machines, including an Azure agent calling a GCP agent on 2026-07-27, but across clouds the check has only run in one direction so far, and tying the encrypted task to a checked hardware measurement on a live call is on the roadmap.

<div class="grid cards" markdown>

-   __Run it__

    ---

    Check a two-step handoff where the permission narrows, then watch it refuse a starting authority you never trusted and a correctly signed grant that asks for too much. No hardware needed.

    [Quick Start](docs/quickstart.md)

-   __What it proves, and what it does not__

    ---

    What has been checked on real hardware, what has only been checked in one direction, and what is not checked at all.

    [Limitations](LIMITATIONS.md)

-   __Hardware evidence__

    ---

    Real AMD SEV-SNP reports from Azure and Intel TDX reports from GCP C3 machines, checked on 2026-07-27. The code that requests those reports ran on real chips on 2026-08-24.

    [Hardware validation](docs/hardware-validation.md)

-   __The chain__

    ---

    Before it: [Agent Manifest](https://manifest.agentrust-io.com) describes the agent and issues the narrowed permission. Alongside: [cMCP](https://cmcp.agentrust-io.com) covers an agent's tool calls. Each handoff's record is written in [TRACE](https://trace.agentrust-io.com). Check a real Intel TDX hardware report yourself at [agentrust-io.com/verify](https://agentrust-io.com/verify/).

    [See the chain](https://agentrust-io.com/#chain)

</div>

## The gap it closes

Knowing an agent's name does not tell you what it is allowed to do. When agent A hands a task to B, and B hands part of it to C, the agent receiving the work (the relying party) needs to confirm where the permission started and check every handoff along the way. On a live call it also needs to confirm the caller is who the permission names, apply its own rules, and, if it asks for one, check hardware proof of what the caller is running.

## The four primitives

| Mechanism | In plain terms | What to check | Start here |
|---|---|---|---|
| Delegation credentials | A signed permission slip per handoff that can only narrow | Trusted root, signatures, continuity, bounded scope and depth | [Offline quickstart](docs/quickstart.md) |
| Runtime appraisal | Hardware proof of what the other agent is running | Evidence and measurements required by the relying party | [Attestation](docs/spec/attestation.md) |
| Sealed peer channel | The task encrypted so only the checked agent can read it | Payload encryption to the appraised peer key | [Sealed channel](docs/spec/sealed-channel.md) |
| Linked provenance | A signed record per handoff, each pointing at the one before | Record signatures and parent links | [TRACE A2A profile](docs/spec/trace-a2a-profile.md) |

Running without special hardware (software mode) gives weaker guarantees than running on confidential-computing hardware. Hardware checks have run in one direction across two clouds, and in both directions between two machines run by one operator on 2026-09-17; both agents proving themselves to each other at the same moment is still open. Read [Limitations](LIMITATIONS.md) before relying on a hardware claim.

For how the pieces fit together, read [How It Works](docs/concepts.md). The formal rules, with the delegation chain, sealed channel, and conformance requirements, are in [Profile](docs/spec/profile.md).

**Status:** ca2a-runtime 0.4.0 developer preview · MIT · hosting at the Agentic AI Foundation proposed, not accepted · Sponsored by OPAQUE, which funds the engineering, infrastructure and confidential-computing work behind these projects.
