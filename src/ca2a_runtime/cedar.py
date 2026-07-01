"""A local policy backed by a real Cedar policy engine.

`CedarPolicy` evaluates the callee's Cedar policy to decide which capabilities a
peer may exercise. It satisfies the `ca2a_runtime.policy.Policy` protocol, so it
is a drop-in for `LocalPolicy` in the peer path: the effective scope on an
inbound call is the delegated leaf scope intersected with what Cedar permits.

Each capability is evaluated as a Cedar authorization request whose action id is
the capability name; a capability is permitted iff Cedar returns Allow. This
reuses the same policy engine cMCP runs (see docs/spec/cedar-policy.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cedarpy import Decision, is_authorized


@dataclass(frozen=True)
class CedarPolicy:
    """A local policy backed by a Cedar policy set."""

    policies: str
    principal_type: str = "Agent"
    principal_id: str = "peer"
    resource_type: str = "Task"
    resource_id: str = "task"

    def _request(self, capability: str) -> dict[str, Any]:
        return {
            "principal": {"type": self.principal_type, "id": self.principal_id},
            "action": {"type": "Action", "id": capability},
            "resource": {"type": self.resource_type, "id": self.resource_id},
            "context": {},
        }

    def permits(self, capability: str) -> bool:
        """Return True iff Cedar authorizes an action of this capability's name."""
        result = is_authorized(self._request(capability), self.policies, [])
        return bool(result.decision == Decision.Allow)

    def intersect(self, delegated: frozenset[str]) -> frozenset[str]:
        """Return the effective scope: delegated capabilities Cedar permits."""
        return frozenset(cap for cap in delegated if self.permits(cap))
