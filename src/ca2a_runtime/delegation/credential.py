"""Delegation credential model, canonicalization, and chain verification.

A delegation credential is a signed statement that ``issuer`` grants ``subject``
a set of capability strings (``scope``), optionally as a child of ``parent_id``.
A chain is a list of credentials ordered from root to leaf. Verification enforces
four invariants:

1. Signature: each credential verifies against its issuer's Ed25519 public key.
2. Continuity: each hop's issuer is the previous hop's subject.
3. Attenuation: each hop's scope is a subset of its parent's scope.
4. Anti-replay: parent_id links to the previous credential_id and every
   credential_id in the chain is unique.

Canonicalization uses RFC 8785 (JSON Canonicalization Scheme), so the signed
byte string is identical across conforming implementations and cA2A signatures
are cross-verifiable with agent-manifest. See ca2a_runtime.canonical.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ca2a_runtime.canonical import canonicalize
from ca2a_runtime.errors import (
    BrokenDelegationLink,
    CredentialReplay,
    DelegationDepthExceeded,
    InvalidCredential,
    ScopeEscalation,
)


def new_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Return a fresh Ed25519 private key and its public key as raw hex."""
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    return priv, pub_hex


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """RFC 8785 (JCS) canonical byte encoding of a credential body.

    This is the stable byte string signed and verified; using JCS makes cA2A
    signatures cross-verifiable with agent-manifest and any other conforming
    implementation. See ca2a_runtime.canonical.
    """
    return canonicalize(payload)


@dataclass(frozen=True)
class DelegationCredential:
    """A single signed delegation hop."""

    credential_id: str
    issuer: str  # Ed25519 public key, raw hex
    subject: str  # Ed25519 public key, raw hex
    scope: frozenset[str]
    depth: int
    parent_id: str | None = None
    signature: str = ""  # Ed25519 signature over canonical_bytes(body), hex

    def body(self) -> dict[str, Any]:
        """The signed portion of the credential (everything but the signature)."""
        return {
            "credential_id": self.credential_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "scope": sorted(self.scope),
            "depth": self.depth,
            "parent_id": self.parent_id,
        }

    def sign(self, private_key: Ed25519PrivateKey) -> DelegationCredential:
        """Return a copy signed by ``private_key`` (must match ``issuer``)."""
        expected = private_key.public_key().public_bytes_raw().hex()
        if expected != self.issuer:
            raise InvalidCredential(
                "signing key does not match credential issuer",
                detail=f"issuer={self.issuer} key={expected}",
            )
        sig = private_key.sign(canonical_bytes(self.body())).hex()
        return DelegationCredential(
            credential_id=self.credential_id,
            issuer=self.issuer,
            subject=self.subject,
            scope=self.scope,
            depth=self.depth,
            parent_id=self.parent_id,
            signature=sig,
        )

    def verify_signature(self) -> None:
        """Raise InvalidCredential if the signature does not verify."""
        if not self.signature:
            raise InvalidCredential("credential is unsigned")
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.issuer))
            pub.verify(bytes.fromhex(self.signature), canonical_bytes(self.body()))
        except (InvalidSignature, ValueError) as exc:
            raise InvalidCredential(
                "credential signature failed to verify", detail=str(exc)
            ) from exc

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DelegationCredential:
        try:
            return cls(
                credential_id=str(data["credential_id"]),
                issuer=str(data["issuer"]),
                subject=str(data["subject"]),
                scope=frozenset(str(s) for s in data["scope"]),
                depth=int(data["depth"]),
                parent_id=(None if data.get("parent_id") is None else str(data["parent_id"])),
                signature=str(data.get("signature", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidCredential("malformed credential", detail=str(exc)) from exc


def verify_chain(
    chain: list[DelegationCredential], *, max_depth: int = 8
) -> None:
    """Verify a root-to-leaf delegation chain, raising on the first violation.

    A well-formed chain of length N delegates from the root issuer down to the
    leaf subject with monotonically narrowing scope. Raises the specific
    CA2AError subtype for the invariant that failed.
    """
    if not chain:
        raise BrokenDelegationLink("empty delegation chain")

    seen_ids: set[str] = set()
    prev: DelegationCredential | None = None

    for i, cred in enumerate(chain):
        cred.verify_signature()

        if cred.credential_id in seen_ids:
            raise CredentialReplay(f"duplicate credential_id at hop {i}: {cred.credential_id}")
        seen_ids.add(cred.credential_id)

        if cred.depth > max_depth:
            raise DelegationDepthExceeded(
                f"hop {i} depth {cred.depth} exceeds max {max_depth}"
            )

        if prev is None:
            if cred.parent_id is not None:
                raise BrokenDelegationLink("root credential must not name a parent")
            if cred.depth != 0:
                raise BrokenDelegationLink("root credential must have depth 0")
        else:
            if cred.parent_id != prev.credential_id:
                raise BrokenDelegationLink(
                    f"hop {i} parent_id does not match previous credential_id"
                )
            if cred.issuer != prev.subject:
                raise BrokenDelegationLink(
                    f"hop {i} issuer is not the previous hop's subject"
                )
            if cred.depth != prev.depth + 1:
                raise BrokenDelegationLink(f"hop {i} depth is not previous + 1")
            if not cred.scope.issubset(prev.scope):
                escalated = sorted(cred.scope - prev.scope)
                raise ScopeEscalation(
                    f"hop {i} scope exceeds parent grant", detail=f"added: {escalated}"
                )

        prev = cred
