# A2A Profile Binding

cA2A binds to A2A v1.x as an overlay. This page states what the profile adds and where it attaches, without modifying A2A itself.

## What A2A provides

A2A moves tasks and context between agents and authenticates a peer's domain via the Signed Agent Card. cA2A treats the Agent Card as the identity anchor and adds a trust envelope around each delegated task.

## What cA2A adds

| A2A element  | cA2A addition                                                                          |
| ------------ | -------------------------------------------------------------------------------------- |
| Agent Card   | An attestation measurement expectation for the peer, checked before a task is accepted |
| Task message | A delegation credential naming issuer, subject, scope, depth, and parent link          |
| Task payload | Sealing to the peer's attested measurement                                             |
| (none)       | A TRACE record per hop linking to the parent, forming the delegation DAG               |

## Attachment points

cA2A does not change A2A wire formats. The delegation credential and the sealing metadata travel in A2A extension fields, so an A2A implementation that does not understand cA2A ignores them and a cA2A-aware peer enforces them. This is what keeps the profile an overlay rather than a fork.

## Stability

This binding targets A2A v1.x extension points. Confirming that those extension points are stable enough to bind to is a precondition on the roadmap; see [ROADMAP.md](https://ca2a.agentrust-io.com/ROADMAP/index.md).
