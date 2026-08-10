# Mutual Attestation

---
Status: Implemented in the reference transport
Written: 2026-08-09
Stability: Unstable
---

> **State of this document.** The design below is built. The callee issues a
> challenge on the handshake endpoint, the caller binds its own channel key into a
> report under it, and the callee appraises that before it opens the sealed
> payload. What is *not* done is a hardware run in both directions: see
> [What this still does not give you](#what-this-still-does-not-give-you), which
> has not moved.

## What is one-directional, and what is not

The primitives are symmetric. Either peer can bind a channel key into a report
(`attest_channel`) and either can appraise one (`verify_offer`); the
`claim6-cross-operator-attestation` experiment drives both directions and is why
[attestation.md](attestation.md) says the design composes into mutual attestation.

**The reference transport is what is one-directional.** In `ca2a_runtime.transport`:

```
caller                                   callee
  │  GET /channel?nonce=N_caller  ───────▶
  │  ◀─────────── ChannelOffer bound to N_caller
  │  appraise, seal payload to callee key
  │  POST /task  ─────────────────────────▶
  │                                        verify delegation chain, act
```

The callee verifies the caller's **delegation chain**, which is authorization: it
proves the caller holds a credential whose scope covers the request. It says
nothing about what the caller is running. A callee has no way to know whether the
peer sending it a task is an enclave or a laptop.

## The change

A callee-issued challenge, and a caller offer bound to it.

```
caller                                   callee
  │  GET /channel?nonce=N_caller  ───────▶
  │  ◀── ChannelOffer(N_caller) + challenge C
  │  appraise callee, seal payload
  │  attest own channel key under C
  │  POST /task + ChannelOffer(C)  ──────▶
  │                                        appraise caller BEFORE opening payload
  │  ◀───── provenance record (readable, so it can be chained)
```

Three properties fall out, and each is a requirement rather than a consequence:

**The challenge must come from the callee.** A caller that picks its own nonce
proves only that it can produce a report, not that it produced one for *this*
exchange. That is the same replay the caller's nonce already prevents in the other
direction.

**The callee must appraise before it acts, not merely before it responds.** The
task payload is sealed to the callee's key, so the callee can read it the moment
it arrives. Appraising afterwards means an unattested caller has already had its
work done. This ordering is the whole value of the change and needs a test that
fails if the calls are swapped.

**The caller's key is the vehicle, not the payoff.** Binding it into a report
under the callee's challenge is what makes the caller's measurement live rather
than replayed. The callee learns what the caller is running, and that is the
property. An earlier draft of this document claimed the key would be ceremonial
unless the response were sealed to it; see the withdrawn decision below for why
that was wrong in this protocol.

## Decisions taken 2026-08-09

1. **Stateless HMAC challenge** (option B below). Works across instances with no
   storage, and the guarantee it gives is at-most-once-per-window rather than
   exactly-once. That weaker property is stated here rather than left implied.
2. **Record the outcome, requirement configurable.** A callee does not demand
   attestation by default and can be configured to.
   - The knob is a three-rung ladder, `require_caller_attestation`:
     `"none"` (the default, demands nothing), `"any"` (an offer that appraises,
     software assurance is enough), `"hardware"` (the assurance must be
     hardware-backed). `"hardware"` without a `caller_verifier` is refused at
     construction rather than on every call, because it could never succeed.
   - The outcome is one of four values, not three: `not_offered`, `failed`,
     `software-only`, `hardware`. A peer that offered nothing and a peer whose
     offer did not appraise are different facts and neither may be readable as
     the software-only case.
   - **An offer that is present and does not appraise is refused at every rung,
     including `"none"`.** Demanding nothing means accepting a caller that proves
     nothing; it does not mean accepting a broken proof. Without this a
     misconfigured attestation path is indistinguishable from a caller that never
     had one, which is how a control ends up switched off without anyone deciding
     to switch it off.
   - The outcome is **in the hashed record body**, always, including
     `not_offered`. Omitting it when nothing was appraised would leave an auditor
     unable to tell a peer that checked and found nothing from a peer that never
     checked. The cost is real and was accepted: it changes the hash of every
     record ever emitted, and the example DAGs were regenerated for it.
3. ~~The response is sealed to the caller's attested key.~~ **Withdrawn on
   2026-08-09, before implementation.** The argument for it was that an appraised
   key which is never used is ceremony. That was wrong on both halves.

   There is no confidential response to seal. `serialize_peer_result` never
   echoes the opened payload, by design; the response carries the **provenance
   record**, which exists to be chained by the caller and handed to a verifier.
   Sealing it would produce a record only one enclave can read, which defeats the
   point of portable evidence. It would encrypt the one artifact built to be
   shareable.

   And the key was never ceremonial. It is the *vehicle*: binding it into a report
   under the callee's challenge is what makes the caller's measurement live rather
   than replayed. The callee learns what the caller is running, which is the
   property mutual attestation exists for. The key does its job at appraisal time
   whether or not anything is later encrypted to it.

   If a genuinely confidential response is ever added, sealing *that* to the
   caller's key is the right move. Encrypting the provenance record is not.

## The state problem

A challenge is worth nothing unless it is single-use and expiring, and the
reference server currently keeps no state at all.

**Option A: a challenge store.** Issue random challenges, remember them, delete on
use, expire on a timer. Straightforward, and it makes the server stateful — which
matters for anyone running more than one instance, because a challenge issued by
one is unknown to the next.

**Option B: a stateless challenge.** `HMAC(server_secret, timestamp || random)`,
verified by recomputation. No storage, works across instances, and single-use is
*not* achievable without state: the same challenge replays until it expires. The
window is a parameter rather than zero.

Neither is free and the difference is real: A gives exactly-once within one
process, B gives at-most-once-per-window across many.

## Posture when the caller will not attest

Most callers, today, cannot: cA2A is alpha and the ecosystem is two peers we run.
A callee that refuses unattested callers by default is a callee nobody can talk
to; one that accepts them silently has added a field nobody reads.

The shape used everywhere else in this stack applies here: record the outcome,
make the requirement configurable, and never let absence look like success. A
callee should be able to say "hardware or nothing" and should not say it by
default.

## What was built

```python
from ca2a_runtime.node import PeerNode
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.transport import client
from ca2a_runtime.tee.software import SoftwareProvider

# Callee: demands nothing, records everything (the default).
node = PeerNode(LocalPolicy.of(["read"]))

# Callee: opts in to strictness.
node = PeerNode(LocalPolicy.of(["read"]), require_caller_attestation="any")

# Caller: opts in to being appraised.
client.send_task(base_url, chain, "read", "r0",
                 payload=b"...", caller_provider=SoftwareProvider())
```

| Piece | Where |
|---|---|
| Stateless challenge (`v1.<expiry>.<random>.<mac>`) | `ca2a_runtime.challenge` |
| Callee-side appraisal, challenge then offer | `attestation.appraise_caller` |
| Requirement ladder and the refusal records | `peer.appraise_caller_runtime` |
| Ordering: appraise before `open_sealed` | `peer.handle_peer_request` |
| `caller_offer` on the wire | `transport.constants`, `transport.a2a_adapter` |
| Challenge on the handshake response | `transport.server`, `transport.wire` |
| Caller-side opt-in | `transport.client.send_task(caller_provider=...)` |

Two consequences worth stating plainly, because neither is free:

**Every record hash changed.** `caller_attestation` is in the hashed body of every
`DelegationRecord`, so records emitted before this change do not hash to what they
used to. The example DAGs under `examples/` were regenerated, and a record loaded
without the field is read as `not_offered` -- the only thing its emitter could
honestly have claimed.

**A challenge does not cross instances.** The secret is per-process, so a callee
behind a load balancer must pin the handshake and the task to one instance or
share a secret between them. This is the stateless scheme's cost, chosen with
open eyes over a challenge store; `test_a_challenge_from_another_instance_does_not_verify`
holds the line.

## What this still does not give you

**It is not simultaneous.** The caller appraises the callee, then the callee
appraises the caller. There is an instant where the caller has committed a sealed
payload to a peer it has verified, and the callee has not yet verified it. A truly
simultaneous exchange needs a commitment step neither side can back out of, which
is a larger protocol than this.

**It does not make either peer trustworthy.** It establishes what each side is
running. A correctly attested enclave can still be running a program that behaves
badly, and the delegation chain remains the thing that says what it is allowed to
ask for.

**It is not validated on hardware in both directions.** The cross-operator run
recorded in [hardware-validation.md](../hardware-validation.md) had the caller
appraise a real TDX quote and the callee appraise nothing. Making the protocol
mutual does not make that run mutual; it makes a mutual run possible, and both
peers in it were driven by one operator's harness.
