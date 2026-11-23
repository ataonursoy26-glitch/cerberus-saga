"""
modules/offensive/tech_fingerprint.py
Technology / CMS fingerprinting (passive-active, authorized).

Derives the target's technology stack (server, CMS, e-commerce platform, CDN,
framework) from HTTP headers, cookie names and HTML signatures, and feeds
detected versions to the CVE matcher to produce possible vulnerability hints.
Read-only; only on targets listed in scope.yaml.
"""
from __future__ import annotations

import asyncio
import logging
import re

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request
from modules.vulnerability.cve_matcher import CVEMatcher

log = logging.getLogger("cerberus.fp")

# HTML/header signatures -> technology
BODY_SIGNS = [
    (r"cdn\.shopify\.com|Shopify\.theme|x-shopify", "E-commerce", "Shopify"),
    (r"wp-content|wp-includes|/wp-json/", "CMS", "WordPress"),
    (r"Drupal\.settings|/sites/default/files", "CMS", "Drupal"),
    (r"Joomla!|/media/jui/", "CMS", "Joomla"),
    (r"__NEXT_DATA__|/_next/", "Framework", "Next.js"),
    (r"window\.__NUXT__|/_nuxt/", "Framework", "Nuxt.js"),
    (r"ng-version=|angular", "Framework", "Angular"),
    (r"data-reactroot|react", "Framework", "React"),
    (r"Magento|/static/version", "E-commerce", "Magento"),
    (r"woocommerce", "E-commerce", "WooCommerce"),
]
HEADER_SIGNS = [
    ("server", "Server"),
    ("x-powered-by", "Runtime"),
    ("x-shopify-stage", "Shopify"),
    ("x-generator", "Generator"),
    ("cf-ray", "CDN (Cloudflare)"),
    ("x-served-by", "CDN/Cache"),
    ("via", "Proxy/CDN"),
]


class TechFingerprint:
    def __init__(self, target: str) -> None:
        assert_in_scope(target)
        self.target = target if "://" in target else "https://" + target

    def run(self) -> dict:
        r = request(self.target, read_bytes=300_000, timeout=8)
        stack: dict[str, str] = {}
        if r.status == 0:
            return {"stack": {"error": r.error or "unreachable"}, "cve_hints": []}

        stack["HTTP durum"] = str(r.status)
        for hname, label in HEADER_SIGNS:
            if hname in r.headers:
                stack[label] = r.headers[hname]

        cookie_names = re.findall(r"(\w+)=", r.headers.get("set-cookie", ""))
        if any(c.startswith("_shopify") or c == "cart" for c in cookie_names):
            stack.setdefault("E-commerce", "Shopify")

        body = r.body or ""
        for pattern, label, tech in BODY_SIGNS:
            if re.search(pattern, body, re.I):
                stack.setdefault(label, tech)

        gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
        if gen:
            stack["Generator (meta)"] = gen.group(1)

        # CVE hints: feed the server header to the version matcher
        banners = [v for k, v in stack.items() if k in ("Server", "Runtime", "Generator (meta)")]
        cve_hints = asyncio.run(CVEMatcher().match(banners)) if banners else []

        log.info("Parmak izi (%s): %d teknoloji, %d CVE ipucu.",
                 self.target, len(stack), len(cve_hints))
        return {"stack": stack, "cve_hints": cve_hints}
