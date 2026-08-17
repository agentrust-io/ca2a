"""Kernel configfs-TSM access, the collection path SEV-SNP and TDX share.

Linux 6.7 added one in-kernel interface for confidential-guest attestation: a
caller creates a directory under ``/sys/kernel/config/tsm/report``, writes up to
64 bytes to ``inblob``, and reads the platform's signed report back from
``outblob``. The same interface serves AMD SEV-SNP (provider ``sev_guest``) and
Intel TDX (provider ``tdx_guest``), which is why this module is shared rather
than copied into each provider.

It supersedes the per-platform ioctls on ``/dev/sev-guest`` and
``/dev/tdx_guest``. Those device nodes still matter, as a *platform* signal
rather than a collection path: the driver that creates one is the driver that
registers the TSM provider, and the provider name is only readable from inside an
entry, which needs root. Detection therefore pairs the two signals and
:func:`collect_report` confirms the provider name before returning any bytes.

Not covered here: Azure confidential VMs. Azure runs SEV-SNP behind a Hyper-V
paravisor, so the guest never sees ``/dev/sev-guest``, registers no TSM provider,
and cannot choose ``REPORT_DATA`` at all. That path reads the report from a vTPM
NV index and is a different collector; the providers here say so rather than
reporting a generic absence.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import sys
from pathlib import Path

from ca2a_runtime.errors import AttestationFailed, AttestationUnsupported

TSM_REPORT_DIR = "/sys/kernel/config/tsm/report"

# Both platforms reserve 64 bytes for caller-chosen report data.
REPORT_DATA_LEN = 64

PROVIDER_SEV_GUEST = "sev_guest"
PROVIDER_TDX_GUEST = "tdx_guest"


def tsm_available() -> bool:
    """True when this host exposes the configfs-TSM report interface."""
    return sys.platform == "linux" and Path(TSM_REPORT_DIR).is_dir()


def require_tsm(platform: str) -> None:
    """Raise :class:`AttestationUnsupported` naming what is actually missing."""
    if sys.platform != "linux":
        raise AttestationUnsupported(
            f"{platform} report generation is only implemented on Linux",
            detail=f"running on {sys.platform}; configfs-TSM is a Linux interface",
        )
    if not Path(TSM_REPORT_DIR).is_dir():
        raise AttestationUnsupported(
            f"{platform} report generation requires the configfs-TSM interface",
            detail=(
                f"{TSM_REPORT_DIR} is not present; it needs kernel 6.7+ with a registered "
                "TSM provider, and configfs mounted"
            ),
        )


def collect_report(report_data: bytes, *, expect_provider: str) -> tuple[bytes, bytes | None]:
    """Return ``(outblob, auxblob)`` for ``report_data`` from the TSM provider.

    ``auxblob`` is the certificate material the provider supplies alongside the
    report, when it supplies any, and is ``None`` otherwise. Shipping it with the
    evidence is what lets a relying party verify offline instead of fetching a
    chain at appraisal time.

    The entry name is unique per call. A fixed name looks harmless but is a race:
    two processes collecting at once would share one entry, and the second write
    to ``inblob`` would change the report the first is about to read, so a peer
    could ship a report committing someone else's key.

    The provider is confirmed before ``outblob`` is read, because the read is
    what makes the platform generate and sign the report. Checking afterwards
    still fails closed, but only after asking the hardware to sign something over
    the caller's binding that is then discarded.
    """
    if len(report_data) > REPORT_DATA_LEN:
        raise AttestationFailed(
            "report data is larger than the field the platform reserves",
            detail=f"got {len(report_data)} bytes, the limit is {REPORT_DATA_LEN}",
        )

    entry = Path(TSM_REPORT_DIR) / f"ca2a-{os.getpid()}-{secrets.token_hex(4)}"
    try:
        entry.mkdir()
    except OSError as exc:
        raise AttestationUnsupported(
            "the kernel refused a configfs-TSM report entry",
            detail=(
                f"could not create {entry}: {exc}. Creating an entry needs root and a "
                "registered TSM provider; a guest whose driver registered none is not "
                "a supported collection host."
            ),
        ) from exc

    try:
        try:
            (entry / "inblob").write_bytes(report_data)
            provider = (entry / "provider").read_text().strip()
        except OSError as exc:
            raise AttestationFailed(
                "the configfs-TSM entry did not name its provider",
                detail=f"{type(exc).__name__}: {exc}",
            ) from exc

        # Checked before outblob is read, because reading outblob is what makes
        # the platform generate and sign a report over the caller's binding. On
        # the wrong provider that report is discarded, so asking for it at all is
        # work the hardware should never have been asked to do.
        if provider != expect_provider:
            raise AttestationFailed(
                "the configfs-TSM provider is not the expected platform",
                detail=(
                    f"the kernel reports {provider!r}, this collector expects "
                    f"{expect_provider!r}; the wrong provider was selected for this host"
                ),
            )

        try:
            outblob = (entry / "outblob").read_bytes()
        except OSError as exc:
            raise AttestationFailed(
                "the configfs-TSM provider did not return a report",
                detail=f"{type(exc).__name__}: {exc}",
            ) from exc

        if not outblob:
            raise AttestationFailed(
                "the configfs-TSM provider returned an empty report",
                detail=f"provider={provider!r} produced no bytes in outblob",
            )

        try:
            auxblob = (entry / "auxblob").read_bytes() or None
        except OSError:
            # Optional: several providers ship no certificate material at all.
            auxblob = None
        return outblob, auxblob
    finally:
        # Leaving an entry behind is untidy but not a failure of the report that
        # was already read, and each call uses a fresh name anyway.
        with contextlib.suppress(OSError):
            entry.rmdir()
