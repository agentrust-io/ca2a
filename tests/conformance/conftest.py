"""Conformance suite: ensure this branch's src/ resolves before any installed package."""

from __future__ import annotations

import sys
from pathlib import Path

_src = str(Path(__file__).parent.parent.parent / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)
