"""
core/scope_guard.py
AUTHORIZATION GATE (Blueprint Volume 7, item a + Volume 8).

The most critical gap found in the blueprint's own compliance analysis:
"/api/v1/start-scan only validates payment status; there is no check that
the target actually belongs to the customer."

This module closes that gap: every active module calls assert_in_scope()
before touching a target. Out-of-scope target -> OutOfScopeError.
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from config.settings import get_authorized_scope
from core.exceptions import OutOfScopeError

log = logging.getLogger("cerberus.scope")


def _extract_host(target: str) -> str:
    """Extracts the host part from a URL or a plain host/IP input."""
    target = target.strip()
    if "://" in target:
        return urlparse(target).hostname or target
    # host:port -> host
    return target.split("/")[0].split(":")[0]


def is_in_scope(target: str, scope: list[str] | None = None) -> bool:
    scope = scope if scope is not None else get_authorized_scope()
    host = _extract_host(target)
    for allowed in scope:
        allowed = allowed.strip()
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def assert_in_scope(target: str) -> None:
    """
    Raises OutOfScopeError if the target is not authorized.
    Must be called on the first line of every active scanning module.
    """
    if not is_in_scope(target):
        host = _extract_host(target)
        log.error("OUT-OF-SCOPE target rejected: %s", host)
        raise OutOfScopeError(
            f"'{host}' is outside the authorization scope (scope.yaml). "
            "Per Blueprint Volume 7/8, scanning an unauthorized target is not allowed."
        )
    log.info("Authorization gate PASSED: %s in scope.", _extract_host(target))
