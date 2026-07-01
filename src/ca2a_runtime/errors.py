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
