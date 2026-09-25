#!/usr/bin/python3
"""Fuzz the attestation evidence parsers.

A callee reads a caller's evidence (``raw_evidence`` in a ``caller_offer``)
before deciding to trust anything about it, and an auditor feeds recorded
quotes to ``ca2a_verify`` offline. These parsers read that binary at fixed
offsets under declared lengths the blob itself supplies: a TDX quote with four
nested size fields, an SNP report, a TPM quote and a TPMT_SIGNATURE.

The property is that each fails closed: it returns, or raises
AttestationFailed, the error the verifier documents. A struct.error, IndexError
or OverflowError reaching the caller means a declared length was believed. That
is the bug this target was written against: TdxQuote.parse used to raise
struct.error on a quote whose signature section was shorter than it claimed.

The challenge verifier is included because its input, the offer nonce and the
holder proof's challenge, is caller text read before anything authenticates it.
"""

import sys

import atheris

with atheris.instrument_imports():
    from ca2a_runtime.challenge import verify_challenge
    from ca2a_runtime.errors import AttestationFailed
    from ca2a_runtime.tee.sev_snp import SevSnpReport
    from ca2a_runtime.tee.tdx import TdxQuote
    from ca2a_runtime.tee.tpm import TpmQuote
    from ca2a_verify.tpm import parse_tpmt_signature

_SECRET = b"\x00" * 32

_PARSERS = [
    TdxQuote.parse,
    SevSnpReport.parse,
    TpmQuote.parse,
    parse_tpmt_signature,
]


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, len(_PARSERS))
    try:
        if choice == len(_PARSERS):
            verify_challenge(_SECRET, fdp.ConsumeUnicode(fdp.remaining_bytes()))
        else:
            _PARSERS[choice](fdp.ConsumeBytes(fdp.remaining_bytes()))
    except AttestationFailed:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
