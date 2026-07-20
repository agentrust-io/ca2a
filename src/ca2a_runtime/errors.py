"""Central error code registry - mirrors docs/spec/error-codes semantics."""

from __future__ import annotations


class CA2AError(Exception):
    """Base class for all ca2a-runtime errors."""

    code: str = "CA2A_ERROR"
    http_status: int = 500

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.detail = detail


class ConfigError(CA2AError):
    code = "CONFIG_ERROR"
    http_status = 500


class InvalidCredential(CA2AError):
    """A delegation credential is malformed or its signature does not verify."""

    code = "INVALID_CREDENTIAL"
    http_status = 400


class ScopeEscalation(CA2AError):
    """A child grant claims authority its parent did not hold."""

    code = "SCOPE_ESCALATION"
    http_status = 403


class BrokenDelegationLink(CA2AError):
    """A hop does not chain to its stated parent, or continuity is broken."""

    code = "BROKEN_DELEGATION_LINK"
    http_status = 409


class DelegationDepthExceeded(CA2AError):
    code = "DELEGATION_DEPTH_EXCEEDED"
    http_status = 403


class CredentialReplay(CA2AError):
    """A credential id appears more than once in a chain."""

    code = "CREDENTIAL_REPLAY"
    http_status = 409


class AttestationUnsupported(CA2AError):
    code = "ATTESTATION_UNSUPPORTED"
    http_status = 500


class AttestationFailed(CA2AError):
    code = "ATTESTATION_FAILED"
    http_status = 412


class SealedChannelError(CA2AError):
    code = "SEALED_CHANNEL_ERROR"
    http_status = 500


class ProvenanceLinkBroken(CA2AError):
    """A delegation record does not chain to its stated parent record, or a
    record has been tampered with so its hash no longer matches a child's link."""

    code = "PROVENANCE_LINK_BROKEN"
    http_status = 409


class ScopeNotPermitted(CA2AError):
    """A requested capability is not in the effective scope (the delegated
    scope intersected with the callee's local policy)."""

    code = "SCOPE_NOT_PERMITTED"
    http_status = 403


class TransportError(CA2AError):
    """cA2A A2A-extension metadata was present but malformed or incomplete.

    Raised by the transport adapter when a cA2A-aware peer sees namespaced
    metadata that cannot be parsed into a ``PeerRequest``. Absence of all
    cA2A keys is not an error: that message is ordinary A2A input.
    """

    code = "TRANSPORT_ERROR"
    http_status = 400


class TraceRecordInvalid(CA2AError):
    """A TRACE record is structurally invalid or its signature does not verify.

    Raised by the TRACE DAG verifier when a hop's record fails schema validation,
    is signed by a key that is not trusted, or its embedded key does not match the
    one supplied. Distinct from ProvenanceLinkBroken, which covers the parent-link
    chaining between otherwise valid records."""

    code = "TRACE_RECORD_INVALID"
    http_status = 422
