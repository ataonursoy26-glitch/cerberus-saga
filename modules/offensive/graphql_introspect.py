"""
modules/offensive/graphql_introspect.py
GraphQL introspection exposure detection (authorized, read-only).

Sends a minimal introspection query to common GraphQL endpoints; if the
server returns the schema (__schema), introspection is ENABLED — all API
types/fields/mutations leak (information disclosure, attack-surface map).
Read query only; never calls a mutation. Skips when rate-limited.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.graphql")

PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/api/v1/graphql", "/graphql/console"]
INTROSPECT = '{"query":"{__schema{types{name}}}"}'


@dataclass
class GQLReport:
    target: str
    findings: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)


class GraphQLIntrospect:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        base = target.rstrip("/")
        self.base = base if "://" in base else "https://" + base

    def run(self) -> GQLReport:
        rep = GQLReport(target=self.base)
        for p in PATHS:
            r = request(self.base + p, method="POST", body=INTROSPECT,
                        extra_headers={"Content-Type": "application/json"}, read_bytes=200_000)
            if r.status in (429, 403, 503):
                continue
            if r.status == 200 and r.body and "__schema" in r.body:
                try:
                    data = json.loads(r.body)
                    n = len(data.get("data", {}).get("__schema", {}).get("types", []))
                except Exception:  # noqa: BLE001
                    n = 0
                rep.endpoints.append(p)
                rep.findings.append({"path": p, "severity": "MEDIUM",
                    "detail": f"GraphQL introspection ENABLED ({n} types exposed) — the full API schema is visible. "
                              "Introspection should be disabled in production."})
        if not rep.findings:
            rep.findings.append({"path": "-", "severity": "INFO",
                "detail": "No open GraphQL introspection endpoint found."})
        log.info("GraphQL introspection (%s): %d endpoints.", self.base, len(rep.endpoints))
        return rep
