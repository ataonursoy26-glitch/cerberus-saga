# 🛡️ Cerberus Saga — Authorized Defensive Security Platform

> **Part of the Cerberus series** — a line of authorization-first security tools.
> *Saga* is the first chapter: the full assessment platform documented below.

An asynchronous, modular security assessment platform built as a personal
project alongside my BSc Cyber Security & Digital Forensics studies. It turns a
19-volume design blueprint into working code: **34 CLI commands**, an async
scanning pipeline, data-loss masking, an immutable signed audit log, and HTML/PDF
reporting — all behind a strict authorization gate.

> **Scope discipline first.** Every active command refuses to run unless the
> target is listed in `scope.yaml` (or proven via the ownership-verification
> flow). Findings are masked and kept local. There is no track-covering and no
> data exfiltration — the opposite: every step is written to a tamper-evident
> audit chain.

## Quick start
```bash
python3 cerberus.py serve         # 🌐 Web dashboard (8 tabs) — easiest way to explore
python3 cerberus.py demo          # end-to-end demo on localhost, no network needed
python3 cerberus.py scope         # show the authorization scope
python3 cerberus.py scan scanme.nmap.org   # scan an in-scope target
python3 cerberus.py verify-audit  # verify the signed audit chain
pytest -q                         # unit tests
```
> Full setup (API, PDF export, crypto): `./setup.sh`

## What it does

**Platform / dashboard**
| Command | Description |
|---------|-------------|
| `serve` | Web dashboard (Scan / Network / Connections / Packets / Proxy / Store / Assessment / JWT) |
| `demo` | Full pipeline on `localhost` with a synthetic leaky sample |
| `scan <target>` | Full pipeline (ports + content + vulns + DLP + IAM) |
| `assess <target>` | Unified assessment + A–F security grade + snapshot |
| `history <target>` | Assessment history + change diff (monitoring) |
| `verify-ownership <domain>` | Prove domain ownership (unlocks active scanning) |
| `scope` / `verify-audit` | List scope / verify the audit chain |

**Offensive (authorized, non-destructive)**
| Command | Description |
|---------|-------------|
| `recon <url>` | Sensitive path/file exposure discovery (soft-404 filtered) |
| `inject-test <url>` | Reflected XSS + error-based SQLi |
| `fuzz <url>` | LFI / SSTI / command-injection detection |
| `host-header <url>` | Host header injection (password-reset poisoning) |
| `http-methods <url>` | TRACE/PUT/DELETE/XST method abuse |
| `cors-test <url>` | CORS misconfiguration |
| `redirect-test <url>` | Open redirect |
| `jwt-analyze <token>` | JWT `alg=none` + weak-secret cracking + claim analysis |
| `js-leak <url>` | Client-side (JS) hardcoded secret leaks |
| `js-libs <url>` | Client-side JS library version + CVE detection |
| `graphql <url>` | GraphQL introspection exposure |
| `subdomains <domain>` | Subdomain discovery (DNS recon) |
| `fingerprint <url>` | Technology/CMS/CDN + version-based CVE hints |
| `harvest <url>` | Raw data pull (respectful back-off on HTTP 429) |

**Audit / compliance**
| Command | Description |
|---------|-------------|
| `headers` / `csp` | Security-header + cookie audit, deep CSP + clickjacking analysis |
| `tls-scan` / `dns-audit` | TLS version scan, DNS security (AXFR/CAA/DNSSEC) |
| `trackers` | Third-party tracker / GDPR privacy audit |
| `storefront <url>` | E-commerce security & trust (TLS/headers/cookies/trust pages) |
| `domain-audit <url>` | TLS certificate + email security (SPF/DMARC/DKIM) |
| `secret-scan <dir>` | Hardcoded-secret search (gitleaks-style) |
| `crypto-scan <dir>` | Exchange API key / seed phrase / wallet key leaks |
| `crypto-phish <domain...>` | Fake-exchange (typosquat) domain detection |

## Architecture (overview)
```
cerberus.py                      CLI entry point
core/orchestrator.py             async pipeline (stages 0→4)
core/scope_guard.py              AUTHORIZATION GATE (scope.yaml)
modules/osint|network|vulnerability|iam|dlp|...   scanning modules
modules/forensics/integrity_log.py   immutable signed audit log
utils/report_engine.py           HTML/PDF reporting
web_api/                         FastAPI gateway (auth + billing gate)
```

The version-based CVE engine (`modules/vulnerability/cve_matcher.py`) maps
service banners to affected version ranges, with **branch-aware patch logic** so
split-branch products (e.g. nginx stable vs. mainline) don't produce false
positives. It only emits a finding when the version is genuinely in a vulnerable
range — no fabricated findings.

## Ethics & legal framework
- The tool runs **only** against targets you are **authorized** to test, listed
  in `scope.yaml` or proven via `verify-ownership`.
- All sensitive findings are **masked** and stay **local** (GDPR-aligned).
- **No** track-covering and **no** external exfiltration; every step is written
  to an immutable audit log.
- A real engagement requires a **written authorization agreement** with the
  target owner.

**License / intended use:** education and authorized security testing only.
