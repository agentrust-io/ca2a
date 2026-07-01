"""Local peer policy for scope intersection.

A callee constrains what an inbound peer may do with a set of allowed
capabilities. The effective permission on a peer call is the delegated scope
intersected with this allow set, so a peer can never exercise more than both
its grant and the callee's local policy permit.

The intersection semantics here are policy-language-agnostic. Binding a full
Cedar policy engine (as cMCP does) is tracked separately; this allow-set model
is the enforcement primitive the peer path uses today.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@runtime_checkable
class Policy(Protocol):
    """A local policy the peer path intersects a delegated scope against.

    Implemented by ``LocalPolicy`` (a capability allow set) and by
    ``ca2a_runtime.cedar.CedarPolicy`` (a real Cedar policy engine).
    """

    def intersect(self, delegated: frozenset[str]) -> frozenset[str]:
        """Return the effective scope: the delegated capabilities this policy allows."""
        ...


@dataclass(frozen=True)
class LocalPolicy:
    """A callee's local capability allow set."""

    allow: frozenset[str]

    @classmethod
    def of(cls, caps: Iterable[str]) -> LocalPolicy:
        return cls(allow=frozenset(caps))

    def intersect(self, delegated: frozenset[str]) -> frozenset[str]:
        """Return the effective scope: delegated capabilities this policy allows."""
        return delegated & self.allow

    def permits(self, capability: str) -> bool:
        return capability in self.allow
