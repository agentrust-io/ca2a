# Verify who delegated what to each agent

cA2A adds signed delegation credentials, peer appraisal, sealed channels, and linked provenance to agent-to-agent communication. A verifier checks who issued a grant and whether each child stays within its parent's authority.

[Verify your first delegation chain](https://ca2a.agentrust-io.com/docs/quickstart/index.md) [See the runtime boundaries](https://ca2a.agentrust-io.com/docs/concepts/index.md)

The first example runs locally with Python 3.11+. It verifies a narrowed grant and rejects both an untrusted issuer and signed scope escalation. No hardware or running peer is needed.

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

## Where to start

- **Run it**

  ______________________________________________________________________

  Verify a delegation chain offline, then stand up the live peer runtime.

  [Quick Start](https://ca2a.agentrust-io.com/docs/quickstart/index.md)

- **Understand it**

  ______________________________________________________________________

  The architecture, the trust boundaries, and how a hop becomes a provenance record.

  [How It Works](https://ca2a.agentrust-io.com/docs/concepts/index.md)

- **Read the profile**

  ______________________________________________________________________

  The normative cA2A profile on A2A, with the delegation chain, sealed channel, and conformance rules.

  [Profile](https://ca2a.agentrust-io.com/docs/spec/profile/index.md)

- **Check the bounds**

  ______________________________________________________________________

  What has run against real silicon, what is one-directional, and what is not appraised at all.

  [Limitations](https://ca2a.agentrust-io.com/LIMITATIONS/index.md)

## How it fits the rest of the stack

cA2A is the delegation layer of the AgenTrust chain. [Agent Manifest](https://manifest.agentrust-io.com) declares what an agent is and what it may do, and supplies the attenuated delegation credential. [cMCP](https://cmcp.agentrust-io.com) enforces policy at the agent-to-tool boundary and shares the TEE provider abstraction. [TRACE](https://trace.agentrust-io.com) is the evidence format each hop's provenance record is written in.
