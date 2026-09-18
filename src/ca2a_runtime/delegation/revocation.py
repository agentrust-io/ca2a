"""Revocation of delegation credentials before their validity window closes.

A validity window (``not_before`` / ``not_after``) bounds how long a grant lasts,
but inside a still-valid window nothing let the delegator take it back. This
module adds that: a delegator signs a :class:`RevocationStatement` naming the
credential by digest, and a verifier handed a :class:`RevocationSnapshot`
refuses any chain that contains a revoked hop.

**Who may revoke.** A statement is effective against hop ``i`` of a chain only
when its ``revoker`` is the issuer of hop ``i`` or of an ancestor hop (``j < i``).
The delegator can withdraw what it granted, and anyone above it can withdraw a
grant made below it. A delegate cannot revoke upward, because the subject of hop
``i`` is the issuer of hop ``i + 1``, not of ``i``. A validly signed statement from
any other key has no effect on that chain. Authority is evaluated against the
presented chain at verification time, because a statement names a credential
and not the chain it will be presented in.

**Cascade.** Revoking hop ``i`` refuses every chain that contains it, so every
grant made beneath it falls with it: none of them can be presented without it.

**Monotonic.** There is no un-revoke. A statement cannot express one (the wire
object is strict and has no such field), and a revocation is decided by the
presence of any effective statement, so no later statement can reverse it.

**Integrity is fail closed.** Every statement's signature is checked when a
snapshot is built. A snapshot carrying an unsigned or forged statement is refused
as a whole with ``INVALID_REVOCATION`` rather than having the bad entry dropped:
a tampered snapshot means the revocation feed itself is untrustworthy, and
silently discarding entries would turn tampering into un-revocation.

**Offline verification is unchanged.** Revocation data is an optional input, like
the trusted root set. A verifier with no snapshot still verifies offline under
P-4, and the result says revocation was not checked, so "verified offline" cannot
be read as "not revoked". A snapshot is local data: consulting it contacts
nobody. Getting current snapshots to verifiers is the deployment's job.

Statements are signed over the RFC 8785 form of their body using the same
canonicalization helper as credentials (:func:`ca2a_runtime.canonical.canonicalize`).
The body carries a ``type`` field so a revocation signature cannot be mistaken
for a signature over any other object this key signs.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ca2a_runtime.canonical import canonicalize as canonical_bytes
from ca2a_runtime.errors import InvalidRevocation

if TYPE_CHECKING:
    from ca2a_runtime.delegation.credential import DelegationCredential

#: Domain separation tag, part of every signed revocation body.
REVOCATION_TYPE = "ca2a.delegation-revocation.v1"

_HEX_32_RE = re.compile(r"[0-9a-f]{64}")
_HEX_64_RE = re.compile(r"[0-9a-f]{128}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_STATEMENT_FIELDS = frozenset({"type", "revoked_digest", "revoker", "issued_at", "signature"})
_SNAPSHOT_FIELDS = frozenset({"as_of", "revocations"})


def credential_digest(credential: DelegationCredential) -> str:
    """Return the ``sha256:``-prefixed digest that identifies a credential.

    Taken over the canonical signed body, the same bytes the issuer signed, so it
    names exactly one grant: the issuer, subject, scope, parent link, depth and
    validity window are all inside it.
    """
    return "sha256:" + hashlib.sha256(canonical_bytes(credential.body())).hexdigest()


def _non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


@dataclass(frozen=True)
class RevocationStatement:
    """A signed statement that ``revoker`` withdraws the credential ``revoked_digest``."""

    revoked_digest: str  # sha256:<hex> of the credential's canonical body
    revoker: str  # Ed25519 public key, raw hex
    issued_at: int  # Unix epoch seconds, as claimed by the revoker
    signature: str = ""  # Ed25519 over canonical_bytes(body()), hex

    def __post_init__(self) -> None:
        if not isinstance(self.revoked_digest, str) or not _DIGEST_RE.fullmatch(
            self.revoked_digest
        ):
            raise InvalidRevocation("revoked_digest must be sha256: followed by 64 lowercase hex")
        if not isinstance(self.revoker, str) or not _HEX_32_RE.fullmatch(self.revoker):
            raise InvalidRevocation("revoker must be a lowercase 32-byte Ed25519 key in hex")
        if not _non_negative_int(self.issued_at):
            raise InvalidRevocation("issued_at must be a non-negative integer")

    def body(self) -> dict[str, Any]:
        """The signed portion of the statement (everything but the signature)."""
        return {
            "type": REVOCATION_TYPE,
            "revoked_digest": self.revoked_digest,
            "revoker": self.revoker,
            "issued_at": self.issued_at,
        }

    def sign(self, private_key: Ed25519PrivateKey) -> RevocationStatement:
        """Return a copy signed by ``private_key`` (must match ``revoker``)."""
        expected = private_key.public_key().public_bytes_raw().hex()
        if expected != self.revoker:
            raise InvalidRevocation(
                "signing key does not match revoker",
                detail=f"revoker={self.revoker} key={expected}",
            )
        return replace(self, signature=private_key.sign(canonical_bytes(self.body())).hex())

    def verify_signature(self) -> None:
        """Raise InvalidRevocation if the signature is absent or does not verify."""
        if not self.signature:
            raise InvalidRevocation("revocation statement is unsigned")
        if not isinstance(self.signature, str) or not _HEX_64_RE.fullmatch(self.signature):
            raise InvalidRevocation(
                "signature must be a lowercase 64-byte Ed25519 signature in hex"
            )
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.revoker))
            pub.verify(bytes.fromhex(self.signature), canonical_bytes(self.body()))
        except (InvalidSignature, ValueError) as exc:
            raise InvalidRevocation(
                "revocation signature failed to verify", detail=str(exc)
            ) from exc

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RevocationStatement:
        """Parse the wire form strictly: unknown or missing fields are rejected."""
        if not isinstance(data, Mapping):
            raise InvalidRevocation("revocation statement must be a JSON object")
        unknown = set(data) - _STATEMENT_FIELDS
        missing = _STATEMENT_FIELDS - set(data)
        if unknown or missing:
            raise InvalidRevocation(
                "malformed revocation fields",
                detail=f"missing={sorted(missing)} unknown={sorted(unknown)}",
            )
        if data["type"] != REVOCATION_TYPE:
            raise InvalidRevocation("unsupported revocation type", detail=f"type={data['type']!r}")
        signature = data["signature"]
        if not isinstance(signature, str):
            raise InvalidRevocation("signature must be a string")
        return cls(
            revoked_digest=data["revoked_digest"],
            revoker=data["revoker"],
            issued_at=data["issued_at"],
            signature=signature,
        )


def revoke(
    credential: DelegationCredential,
    private_key: Ed25519PrivateKey,
    *,
    issued_at: int | None = None,
) -> RevocationStatement:
    """Sign a statement withdrawing ``credential``.

    ``private_key`` should belong to the credential's issuer or to an issuer
    above it in the chain; a statement from anyone else is well formed but has
    no effect when a chain is verified.
    """
    return RevocationStatement(
        revoked_digest=credential_digest(credential),
        revoker=private_key.public_key().public_bytes_raw().hex(),
        issued_at=int(time.time()) if issued_at is None else issued_at,
    ).sign(private_key)


@dataclass(frozen=True)
class RevocationSnapshot:
    """The set of revocation statements a verifier holds, current as of ``as_of``.

    ``as_of`` is when the supplier of this snapshot last brought it up to date,
    in Unix epoch seconds. It is asserted by whoever hands the snapshot to the
    verifier and is not signed by any revoker, so a staleness bound built on it
    detects a feed that has stopped updating, not a supplier that lies about it.
    Individual statements are signed, so a supplier can withhold a statement but
    cannot forge one.
    """

    as_of: int
    statements: tuple[RevocationStatement, ...] = ()
    _by_digest: dict[str, tuple[RevocationStatement, ...]] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if not _non_negative_int(self.as_of):
            raise InvalidRevocation("as_of must be a non-negative integer")
        statements = tuple(self.statements)
        index: dict[str, list[RevocationStatement]] = {}
        for i, stmt in enumerate(statements):
            if not isinstance(stmt, RevocationStatement):
                raise InvalidRevocation(f"revocation {i} is not a RevocationStatement")
            try:
                stmt.verify_signature()
            except InvalidRevocation as exc:
                raise InvalidRevocation(
                    f"revocation {i} does not verify; the snapshot is refused as a whole",
                    detail=str(exc) if exc.detail is None else f"{exc}: {exc.detail}",
                ) from exc
            index.setdefault(stmt.revoked_digest, []).append(stmt)
        object.__setattr__(self, "statements", statements)
        object.__setattr__(self, "_by_digest", {d: tuple(s) for d, s in index.items()})

    def effective_revocation(
        self,
        digest: str,
        authorized_revokers: Iterable[str],
        *,
        at_time: int | None = None,
    ) -> RevocationStatement | None:
        """Return a statement that revokes ``digest`` under this authority, or None.

        With ``at_time`` (an audit of a past decision), only statements issued at
        or before that time count, so a revocation issued afterwards does not
        rewrite a decision that was correct when it was made. Without it (a live
        decision), every statement the verifier holds is in force whatever the
        revoker's clock said.
        """
        authorized = frozenset(authorized_revokers)
        for stmt in self._by_digest.get(digest, ()):
            if stmt.revoker not in authorized:
                continue
            if at_time is not None and stmt.issued_at > at_time:
                continue
            return stmt
        return None

    def to_dict(self) -> dict[str, Any]:
        return {"as_of": self.as_of, "revocations": [s.to_dict() for s in self.statements]}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RevocationSnapshot:
        """Parse ``{"as_of": int, "revocations": [statement, ...]}`` strictly."""
        if not isinstance(data, Mapping):
            raise InvalidRevocation("revocation snapshot must be a JSON object")
        unknown = set(data) - _SNAPSHOT_FIELDS
        missing = _SNAPSHOT_FIELDS - set(data)
        if unknown or missing:
            raise InvalidRevocation(
                "malformed revocation snapshot fields",
                detail=f"missing={sorted(missing)} unknown={sorted(unknown)}",
            )
        items = data["revocations"]
        if not isinstance(items, list):
            raise InvalidRevocation("revocations must be an array")
        return cls(
            as_of=data["as_of"],
            statements=tuple(RevocationStatement.from_dict(item) for item in items),
        )


@dataclass(frozen=True)
class RevocationStatus:
    """What a chain verification established about revocation.

    ``checked`` is False when no snapshot was supplied. The chain may then be
    revoked and the verifier would not know, which is why this is returned rather
    than left for the caller to assume. When True, no hop was revoked by any
    statement in a snapshot current as of ``as_of``.
    """

    checked: bool
    as_of: int | None = None

    @property
    def state(self) -> str:
        return "not_revoked" if self.checked else "not_checked"


REVOCATION_NOT_CHECKED = RevocationStatus(checked=False)
