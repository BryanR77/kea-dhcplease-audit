"""Audit Kea DHCP HA peers for lease database consistency."""

try:
    from ._version import version as __version__
except ImportError:  # running from a source checkout that was never built
    __version__ = "0+unknown"
