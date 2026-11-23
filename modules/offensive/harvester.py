"""
modules/offensive/harvester.py
Raw data harvester — PULLS data from an authorized target.

Read-only but DATA-FOCUSED: saves the target's raw HTTP responses (status + headers
+ full body) and e-commerce data endpoints (Shopify products.json/collections)
to disk as RAW files. Never MODIFIES the target; only reads and fetches.
Runs only on targets listed in scope.yaml.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from core.scope_guard import assert_in_scope
from modules.offensive._requester import request

log = logging.getLogger("cerberus.harvest")

DEFAULT_PATHS = ["/", "/robots.txt", "/sitemap.xml", "/cart.json",
                 "/collections.json", "/.well-known/security.txt"]


@dataclass
class HarvestItem:
    path: str
    status: int
    bytes: int
    saved: str
    note: str = ""


@dataclass
class HarvestReport:
    target: str
    out_dir: str
    items: list = field(default_factory=list)
    products_count: int = 0
    rate_limited: bool = False


class RawHarvester:
    def __init__(self, target: str, out_root: str = "reports/raw") -> None:
        assert_in_scope(target)
        self.base = target.rstrip("/")
        if "://" not in self.base:
            self.base = "https://" + self.base
        self.host = urlsplit(self.base).hostname or "target"
        self.out_dir = Path(out_root) / self.host
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def _save(self, name: str, content: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name.strip("/")) or "root"
        fp = self.out_dir / (safe + ".raw.txt")
        fp.write_text(content, encoding="utf-8")
        return fp

    def harvest(self, extra_paths: list[str] | None = None, product_pages: int = 5) -> HarvestReport:
        rep = HarvestReport(target=self.base, out_dir=str(self.out_dir))
        paths = DEFAULT_PATHS + (extra_paths or [])

        for p in paths:
            r = request(self.base + p, read_bytes=2_000_000, timeout=8)
            time.sleep(0.4)  # polite pace: don't overload the target
            if r.status == 429:
                rep.rate_limited = True
                rep.items.append(HarvestItem(p, 429, 0, "", "rate-limited (429) — backing off"))
                break  # WAF/CDN throttled us: stopping is the right behaviour
            if r.status == 0:
                rep.items.append(HarvestItem(p, 0, 0, "", r.error or "unreachable"))
                continue
            hdr = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            raw = f"GET {p}\nHTTP {r.status}\n\n== HEADERS ==\n{hdr}\n\n== BODY ==\n{r.body}"
            fp = self._save(p or "root", raw)
            rep.items.append(HarvestItem(p, r.status, len(r.body), str(fp)))

        # Shopify product catalogue (full paginated fetch)
        all_products = []
        for page in range(1, product_pages + 1):
            r = request(f"{self.base}/products.json?limit=250&page={page}",
                        read_bytes=4_000_000, timeout=10)
            if r.status != 200 or not r.body.lstrip().startswith("{"):
                break
            try:
                data = json.loads(r.body)
            except json.JSONDecodeError:
                break
            prods = data.get("products", [])
            if not prods:
                break
            all_products.extend(prods)
            if len(prods) < 250:
                break
        if all_products:
            fp = self._save("products_full.json", json.dumps(all_products, ensure_ascii=False, indent=2))
            rep.products_count = len(all_products)
            rep.items.append(HarvestItem("/products.json (tam)", 200,
                                          fp.stat().st_size, str(fp),
                                          f"{len(all_products)} products fetched"))
        log.info("Harvest (%s): %d files, %d products.", self.host, len(rep.items), rep.products_count)
        return rep
