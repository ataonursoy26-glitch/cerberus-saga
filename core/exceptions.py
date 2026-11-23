"""
core/exceptions.py
Custom exception layer for security operations (Blueprint Volume 1).
"""


class CerberusError(Exception):
    """Base class for all Cerberus errors."""


class ScanTimeout(CerberusError):
    """A scan step timed out."""


class APIQuotaExceeded(CerberusError):
    """A third-party API quota limit was exceeded."""


class OutOfScopeError(PermissionError, CerberusError):
    """
    The target is outside the authorization scope in scope.yaml.
    Per Blueprint Volume 7/8, this error halts the scan flow immediately.
    """


class BinaryNotFound(CerberusError):
    """A required system binary (nmap/nuclei/masscan) was not found."""
