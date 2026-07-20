"""A2A transport binding for the cA2A peer path.

cA2A is a profile on A2A, not a transport. This package provides the wire
binding (:mod:`ca2a_runtime.transport.a2a`) that parses a cA2A-profile A2A
message into a :class:`~ca2a_runtime.peer.PeerRequest` and serializes the result
or a structured error, plus a minimal reference HTTP server and client
(:mod:`ca2a_runtime.transport.server`, :mod:`ca2a_runtime.transport.client`)
that run the full inbound pipeline over the wire. The server is a reference, not
the only transport: any A2A server can parse its wire format and call the peer
path through :mod:`ca2a_runtime.transport.a2a`.
"""
