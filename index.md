---
title: Verify who delegated what to each agent
description: cA2A adds delegation and peer trust checks to A2A. Start with an offline chain that accepts a narrowed grant and rejects scope escalation.
---

# Verify who delegated what to each agent

cA2A adds signed delegation credentials, peer appraisal, sealed channels, and linked provenance to agent-to-agent communication. A verifier checks who issued a grant and whether each child stays within its parent's authority.

[Verify your first delegation chain](docs/quickstart.md){ .md-button .md-button--primary }
[See the runtime boundaries](docs/concepts.md){ .md-button }

The first example runs locally with Python 3.11+. It verifies a narrowed grant and rejects both an untrusted issuer and signed scope escalation. No hardware or running peer is needed.

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

## Where to start

<div class="grid cards" markdown>

-   __Run it__

    ---

    Verify a delegation chain offline, then stand up the live peer runtime.

    [Quick Start](docs/quickstart.md)

-   __Understand it__

    ---

    The architecture, the trust boundaries, and how a hop becomes a provenance record.

    [How It Works](docs/concepts.md)

-   __Read the profile__

    ---

    The normative cA2A profile on A2A, with the delegation chain, sealed channel, and conformance rules.

    [Profile](docs/spec/profile.md)

-   __Check the bounds__

    ---

    What has run against real silicon, what is one-directional, and what is not appraised at all.

    [Limitations](LIMITATIONS.md)

</div>

## How it fits the rest of the stack

cA2A is the delegation layer of the AgenTrust chain. [Agent Manifest](https://manifest.agentrust-io.com) declares what an agent is and what it may do, and supplies the attenuated delegation credential. [cMCP](https://cmcp.agentrust-io.com) enforces policy at the agent-to-tool boundary and shares the TEE provider abstraction. [TRACE](https://trace.agentrust-io.com) is the evidence format each hop's provenance record is written in.
