"""cA2A Runtime: confidential agent-to-agent delegation on top of A2A."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ca2a-runtime")
except PackageNotFoundError:  # source tree imported without an installation
    __version__ = "0+unknown"
