---
title: Secure, confidential agent-to-agent delegation
description: cA2A is a trust profile on top of the Agent2Agent protocol. It adds attested, attenuated delegation, a sealed peer channel, and an offline-verifiable provenance record, without replacing the transport.
---

# cA2A

cA2A (Confidential A2A) is the secure, confidential way to do agent-to-agent delegation on the [Agent2Agent (A2A)](https://a2a-protocol.org/) protocol. It layers attested, attenuated delegation, a sealed peer channel, and an offline-verifiable provenance record on top of A2A, without replacing the transport.

**Agent A delegates to B. B delegates part of it to C. Who authorized what, did B stay inside the authority A actually held, and can you prove it for every hop?**

!!! tip "TL;DR"
    - A2A's Signed Agent Card answers one question: did the domain owner issue this card. It does not cover integrity, authority, confidentiality, or provenance.
    - cA2A is a profile on top of A2A, not a competing transport, the way TRACE profiles RATS and EAT rather than reinventing them.
    - Install with `pip install ca2a-runtime`. The same package does offline chain verification and runs the live peer runtime.
    - Developer Preview. One bound worth reading before you rely on it: peer appraisal has been demonstrated one-directional, so mutual simultaneous attestation is still outstanding. See [Limitations](LIMITATIONS.md).

```bash
pip install ca2a-runtime
ca2a verify-chain --chain ./examples/minimal/chain.json
```

## The gap it closes

A2A won the agent-to-agent transport war. Its trust model stops at the front door.

The Signed Agent Card proves the domain owner issued the card. It does not answer:

- **Integrity.** Is the peer running attested, unmodified, governed code, or a tampered agent wearing a valid card.
- **Authority.** When A delegates to B, does A actually hold the authority it is passing, and is B's grant a provable subset of it.
- **Confidentiality.** The task payload A sends B crosses a network and lands in B's memory. If B is in another trust domain, nothing seals that payload to B's attested measurement.
- **Provenance.** Across A to B to C, there is no unbroken, offline-verifiable chain of who delegated what to whom under which policy.

A2A leaves the runtime credential layer to implementers. The common answers, mTLS and OAuth scopes, secure the pipe and assert an identity. They do not attenuate authority, attest runtime integrity, or seal payloads to a measurement.

## The four primitives

1. **Attenuated delegation.** Each hop carries a signed delegation credential whose scope is a provable subset of its parent. Child scope cannot exceed parent, depth is bounded, and replay across chains is rejected.
2. **Runtime attestation.** A peer proves it is running attested, measured code before it is trusted with a delegated task.
3. **Sealed peer channel.** The task payload is sealed to the peer's attested measurement, so it decrypts only inside the verified enclave.
4. **Provenance record.** Each hop emits a TRACE record referencing the parent record hash and delegation credential id, producing an offline-verifiable delegation DAG.

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
