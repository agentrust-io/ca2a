"""The bridge to the official ``a2a-sdk``, exercised against the real SDK.

Not against a stub of it: the whole point of this module is interoperating with
what an adopter actually runs, and a stub would agree with whatever we assumed.
The SDK is in the ``dev`` extra so these run in CI rather than skipping.

The load-bearing test here is the integer one. A2A ``metadata`` is a
``google.protobuf.Struct``, which has no integer type, so a credential's
``depth`` crosses the wire as a double. Credential signatures cover RFC 8785
canonical bytes and ``canonicalize`` refuses floats outright, so if that
round trip were not handled the bridge would break every chain it carried.
"""

from __future__ import annotations

import pytest

pytest.importorskip("a2a", reason="install 'ca2a[a2a-sdk]' to exercise the SDK bridge")

from a2a.extensions.common import HTTP_EXTENSION_HEADER  # noqa: E402
from a2a.types import Message  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from google.protobuf import json_format  # noqa: E402

from ca2a_runtime.attestation import ChannelOffer  # noqa: E402
from ca2a_runtime.delegation.credential import (  # noqa: E402
    DelegationCredential,
    canonical_bytes,
    new_keypair,
    verify_chain,
)
from ca2a_runtime.delegation.holder import build_holder_proof  # noqa: E402
from ca2a_runtime.errors import InvalidCredential, TransportError  # noqa: E402
from ca2a_runtime.node import PeerNode  # noqa: E402
from ca2a_runtime.peer import REQUIRE_ANY, PeerRequest  # noqa: E402
from ca2a_runtime.policy import LocalPolicy  # noqa: E402
from ca2a_runtime.tee.base import AttestationReport  # noqa: E402
from ca2a_runtime.transport import a2a_sdk  # noqa: E402
from ca2a_runtime.transport.constants import EXTENSION_URI  # noqa: E402


def _chain_with_keys(hops: int = 1) -> tuple[list[DelegationCredential], Ed25519PrivateKey]:
    """A verifiable chain of ``hops`` credentials, plus the leaf subject's key.

    Built for real rather than with a hand-set depth: a root must be depth 0 and
    each hop must chain to its parent, so a synthetic non-zero depth on a
    one-hop chain would fail verification for its own reasons and prove nothing
    about the Struct round trip.
    """
    root_priv, root_pub = new_keypair()
    scope = frozenset({"read", "write"})
    issuer_priv, issuer_pub = root_priv, root_pub
    chain: list[DelegationCredential] = []
    subject_priv = root_priv
    for depth in range(hops):
        subject_priv, subject_pub = new_keypair()
        chain.append(
            DelegationCredential(
                credential_id=f"c{depth}",
                issuer=issuer_pub,
                subject=subject_pub,
                scope=scope,
                depth=depth,
                parent_id=None if depth == 0 else f"c{depth - 1}",
            ).sign(issuer_priv)
        )
        issuer_priv, issuer_pub = subject_priv, subject_pub
    return chain, subject_priv


def _chain(hops: int = 1) -> list[DelegationCredential]:
    return _chain_with_keys(hops)[0]


def _request(
    *, node: PeerNode | None = None, leaf_key: Ed25519PrivateKey | None = None, **kwargs
) -> PeerRequest:
    """A request for the bridge round trip.

    Pass ``node`` when the request goes on to :meth:`PeerNode.handle`, which
    requires holder binding as it ships: the chain is then built with its leaf key
    retained so a proof can be signed against a challenge that node issued.

    Pass ``chain`` and ``leaf_key`` together when the caller needs the chain
    before the node exists, which it does whenever the node pins that chain's root
    as its trusted issuer. The generated pair cannot serve both, since the trust
    set has to be known at construction and the proof has to be signed afterwards.
    """
    chain, generated_key = _chain_with_keys()
    signing_key = leaf_key if leaf_key is not None else generated_key
    base: dict = {
        "chain": chain,
        "requested_capability": "read",
        "record_id": "r0",
        "parent_record_hash": None,
    }
    base.update(kwargs)
    if node is not None:
        base["holder_proof"] = build_holder_proof(
            signing_key,
            base["chain"][-1],
            audience=node.channel_public_key,
            challenge=node.issue_challenge(),
            requested_capability=base["requested_capability"],
            record_id=base["record_id"],
            sealed_payload=base.get("sealed_payload"),
            caller_channel_key=(
                None
                if base.get("caller_offer") is None
                else base["caller_offer"].channel_public_key
            ),
        )
    return PeerRequest(**base)


# --------------------------------------------------------------------------
# The integer problem
# --------------------------------------------------------------------------


def test_canonicalization_refuses_floats_at_all() -> None:
    """The premise of the test below: a float cannot be canonicalized, so a
    float depth cannot have been signed, and must not be silently accepted."""
    assert canonical_bytes({"depth": 0}) == b'{"depth":0}'
    with pytest.raises(TypeError, match="floats"):
        canonical_bytes({"depth": 0.0})


def test_struct_turns_depth_into_a_double() -> None:
    """Documents the hazard rather than assuming it away."""
    message = Message(message_id="m1")
    json_format.ParseDict({"depth": 3}, message.metadata)
    assert json_format.MessageToDict(message.metadata)["depth"] == 3.0
    assert isinstance(json_format.MessageToDict(message.metadata)["depth"], float)


@pytest.mark.parametrize("hops", [1, 2, 4])
def test_a_chain_still_verifies_after_the_struct_round_trip(hops: int) -> None:
    """The property the bridge depends on: the signature survives.

    Multi-hop so the non-zero depths actually cross the Struct boundary; a
    one-hop chain only ever exercises depth 0, which is the value least likely
    to expose a float problem.
    """
    request = _request(chain=_chain(hops))
    message = a2a_sdk.attach_to_sdk_message(Message(message_id="m1"), request)

    parsed = a2a_sdk.parse_sdk_message(message)
    assert parsed is not None
    assert [c.depth for c in parsed.chain] == list(range(hops))
    assert all(isinstance(c.depth, int) for c in parsed.chain)
    verify_chain(parsed.chain)


def test_a_tampered_depth_does_not_verify() -> None:
    """A float cannot be smuggled past the signature.

    The leaf of a two-hop chain is signed at depth 1. Rewriting it to ``2.5``
    coerces to ``2``, so the bytes that get canonicalized are not the bytes that
    were signed and the signature fails. Deliberately not ``1.5``, which would
    coerce back to the signed ``1`` and prove nothing.
    """
    message = a2a_sdk.attach_to_sdk_message(Message(message_id="m1"), _request(chain=_chain(2)))

    meta = a2a_sdk.metadata_from_sdk_message(message)
    key = f"{EXTENSION_URI}/delegation_chain"
    meta[key][1]["depth"] = 2.5
    message.metadata.Clear()
    json_format.ParseDict(meta, message.metadata)

    parsed = a2a_sdk.parse_sdk_message(message)
    assert parsed is not None
    assert parsed.chain[1].depth == 2  # int(2.5), not the signed 1
    with pytest.raises(InvalidCredential):
        verify_chain(parsed.chain)


# --------------------------------------------------------------------------
# Round trips
# --------------------------------------------------------------------------


def test_full_round_trip_through_a_real_sdk_message() -> None:
    request = _request(
        sealed_payload=b"\x00\x01\xfe\xff ciphertext",
        parent_record_hash="a" * 64,
    )
    parsed = a2a_sdk.parse_sdk_message(
        a2a_sdk.attach_to_sdk_message(Message(message_id="m1"), request)
    )
    assert parsed is not None
    assert parsed.requested_capability == "read"
    assert parsed.record_id == "r0"
    assert parsed.parent_record_hash == "a" * 64
    assert parsed.sealed_payload == b"\x00\x01\xfe\xff ciphertext"


def test_caller_offer_round_trips() -> None:
    offer = ChannelOffer(
        channel_public_key="k" * 43,
        report=AttestationReport(
            platform="software-only",
            measurement="m",
            public_key="k" * 43,
            nonce="v1.123.abc.def",
        ),
    )
    parsed = a2a_sdk.parse_sdk_message(
        a2a_sdk.attach_to_sdk_message(Message(message_id="m1"), _request(caller_offer=offer))
    )
    assert parsed is not None
    assert parsed.caller_offer is not None
    assert parsed.caller_offer.report.nonce == "v1.123.abc.def"


def test_attach_preserves_unrelated_metadata() -> None:
    message = Message(message_id="m1")
    json_format.ParseDict({"tenant": "acme", "trace_id": "abc"}, message.metadata)
    a2a_sdk.attach_to_sdk_message(message, _request())
    meta = a2a_sdk.metadata_from_sdk_message(message)
    assert meta["tenant"] == "acme"
    assert meta["trace_id"] == "abc"
    assert f"{EXTENSION_URI}/record_id" in meta


def test_attach_declares_the_extension_on_the_message() -> None:
    message = a2a_sdk.attach_to_sdk_message(Message(message_id="m1"), _request())
    assert EXTENSION_URI in message.extensions
    # idempotent: attaching twice must not duplicate the declaration
    a2a_sdk.attach_to_sdk_message(message, _request())
    assert list(message.extensions).count(EXTENSION_URI) == 1


# --------------------------------------------------------------------------
# Not-a-cA2A-message, and failing closed
# --------------------------------------------------------------------------


def test_a_plain_a2a_message_is_not_a_partial_trust_state() -> None:
    assert a2a_sdk.parse_sdk_message(Message(message_id="m1")) is None
    message = Message(message_id="m2")
    json_format.ParseDict({"tenant": "acme"}, message.metadata)
    assert a2a_sdk.parse_sdk_message(message) is None


def test_present_but_incomplete_ca2a_metadata_fails_closed() -> None:
    message = Message(message_id="m1")
    json_format.ParseDict({f"{EXTENSION_URI}/record_id": "r0"}, message.metadata)
    with pytest.raises(TransportError, match="delegation_chain"):
        a2a_sdk.parse_sdk_message(message)


# --------------------------------------------------------------------------
# Opt-in, and the end-to-end path a real adopter takes
# --------------------------------------------------------------------------


def test_extension_header_constant_matches_the_sdk() -> None:
    """Restated locally so the module reads without the SDK; must not drift."""
    assert a2a_sdk.EXTENSION_HEADER == HTTP_EXTENSION_HEADER


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (None, False),
        ([], False),
        ([EXTENSION_URI], True),
        ([f"other, {EXTENSION_URI}"], True),
        ([f" {EXTENSION_URI} "], True),
        (["other"], False),
        ([f"{EXTENSION_URI}x"], False),
    ],
)
def test_opted_in(values: list[str] | None, expected: bool) -> None:
    assert a2a_sdk.opted_in(values) is expected


def test_an_sdk_message_drives_the_full_inbound_pipeline() -> None:
    """What an adopter actually gets: enforcement from an SDK message."""
    chain, leaf_key = _chain_with_keys()
    node = PeerNode(LocalPolicy.of({"read"}), trusted_root_issuers={chain[0].issuer})
    request = _request(node=node, chain=chain, leaf_key=leaf_key)
    message = a2a_sdk.attach_to_sdk_message(Message(message_id="m1"), request)

    parsed = a2a_sdk.parse_sdk_message(message)
    assert parsed is not None
    result = node.handle({"metadata": a2a_sdk.metadata_from_sdk_message(message)})
    assert result.granted_capability == "read"
    assert result.record.credential_id == "c0"


def test_mutual_attestation_works_over_the_sdk_bridge() -> None:
    """The newest part of the profile must reach SDK adopters too."""
    chain, leaf_key = _chain_with_keys()
    node = PeerNode(
        LocalPolicy.of({"read"}),
        require_caller_attestation=REQUIRE_ANY,
        trusted_root_issuers={chain[0].issuer},
    )
    challenge = node.issue_challenge()
    offer = ChannelOffer(
        channel_public_key="k" * 43,
        report=AttestationReport(
            platform="software-only",
            measurement="caller",
            public_key="k" * 43,
            nonce=challenge,
        ),
    )
    message = a2a_sdk.attach_to_sdk_message(
        Message(message_id="m1"),
        _request(caller_offer=offer, node=node, chain=chain, leaf_key=leaf_key),
    )
    result = node.handle({"metadata": a2a_sdk.metadata_from_sdk_message(message)})
    assert result.caller_attestation == "software-only"
