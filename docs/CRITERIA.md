# Cerberus Saga — Criteria Mapping (Blueprint → Code)

This document shows which file/class covers **each volume** and **each of the
16 vulnerability protocols** in the `Cerberus_Saga_Global_v16` blueprint.
It gives a direct answer to "where is this criterion implemented?" during a review.

> **Ethical framework note:** The project follows the blueprint's **own Volume 7
> and Volume 8** compliance analysis exactly. The offensive/pentest scanning
> capabilities (ports, vulnerabilities, OSINT, IAM, PoC) are fully kept. The 3
> points the blueprint says would "turn the tool into spyware" are kept on the
> legitimate side: (1) all findings are masked & local, (2) no external
> exfiltration, (3) no trace hiding — the opposite, an **immutable signed audit log**.

---

## 1. Volumes → files

| Volume | Topic | File / Class |
|--------|-------|--------------|
| Volume 1 | File & architecture tree | The whole `modules/` + `core/` hierarchy |
| Volume 2 | System connections & integration | `config/settings.py`, `config/database.py` |
| Volume 3 | Core code blocks | `core/orchestrator.py` (Module 1), `modules/network/port_scanner.py` (Module 2), `web_api/main.py` (Module 3) |
| Volume 4 | SaaS revenue model (3 phases) | `docs/PRESENTATION.md` (business model) + `web_api/` (Stripe gate) |
| Volume 5 | 16 vulnerability protocols | See "2. Protocol table" below |
| Volume 6 | Installation guide | `setup.sh`, `Dockerfile`, `requirements.txt` |
| Volume 7 | PII/SPII legal compliance + scope | `scope.yaml`, `core/scope_guard.py` |
| Volume 8 | Strategic profile risk analysis | `modules/evasion/waf_evasion.py`, `modules/forensics/anti_forensics.py` (legitimate redefinition) |
| Volume 9 | IAM (the IAA triad) | `modules/iam/identity_enum.py`, `auth_tester.py`, `authz_tester.py` |
| Volume 10 | Extended PII/secret engine | `modules/dlp/pii_spii_scanner.py` (EXTENDED_PATTERNS), `context_filter.py` |
| Volume 11 | Financial data classifier | `modules/dlp/financial_scanner.py` |
| Volume 13 | Semantic detection (regex + entropy + context) | `pii_spii_scanner.py` (Shannon entropy, `_shannon_entropy`) |
| Volume 14-17 | Incident response + CVE + CTI | `modules/forensics/incident_tracker.py`, `modules/intelligence/ransomware_tracker.py`, `nuclei_runner.py` (embedded CVEs) |
| Volume 18 | Architecture memorandum (raw/blackhat request) | **Deliberately not implemented** — per Volume 8; the reasoning is in the `anti_forensics.py` docstring |
| Volume 19 | User core template | `core/orchestrator.py` (async pipeline) |

---

## 2. 16 vulnerability protocols → modules

| # | Protocol (Volume 5) | Module/File |
|---|---------------------|-------------|
| 1-5 | OWASP Top 10 & network analysis | `vulnerability/owasp_top10.py`, `network/port_scanner.py`, `network/service_grab.py` |
| 6 | Prompt injection (LLM) | `vulnerability/ai_injection_check.py` |
| 7 | Excessive agency (LLM06) | `vulnerability/excessive_agency.py` |
| 8 | OpenShell sandbox isolation | `vulnerability/openshell_audit.py` |
| 9 | SBOM / supply chain | `supply_chain/sbom_analyzer.py` |
| 10 | OSINT & dark-web leaks | `osint/shodan_intel.py`, `osint/dns_recon.py`, `osint/leak_check.py` |
| 11 | PII/SPII exposure | `dlp/pii_spii_scanner.py` |
| 12 | Identification surface analysis | `iam/identity_enum.py` |
| 13 | Authentication resilience | `iam/auth_tester.py` |
| 14 | Authorization / IDOR / privilege escalation | `iam/authz_tester.py` |
| 15 | Extended secret scanning (20+) | `dlp/pii_spii_scanner.py` (EXTENDED_PATTERNS) |
| 16 | Financial instrument classification | `dlp/financial_scanner.py` |
| + | Live HTTP content scanning | `network/content_fetch.py` (downloads the real response body) |
| + | Version-based CVE detection | `vulnerability/cve_matcher.py` (real version-range matching) |
| + | Current CVEs (Nuclei) | `vulnerability/nuclei_runner.py` |
| + | CTI ransomware correlation | `intelligence/ransomware_tracker.py` |
| + | Cloud IAM privilege escalation | `cloud/cloud_iam_audit.py` |

---

## 3. Architecture/security criteria

| Criterion | Where |
|-----------|-------|
| Asynchronous (asyncio) pipeline | `core/orchestrator.py` |
| Micro-service module tree | `modules/*` |
| Event management (event bus) | `core/event_bus.py` |
| Authorization gate (domain verification) | `core/scope_guard.py` + `scope.yaml` |
| Masking (data minimization) | `dlp/*` `_mask()` |
| Immutable signed audit log (SHA-256 chain) | `forensics/integrity_log.py` |
| Encryption at rest (AES-256-GCM) | `utils/cryptography.py` |
| PDF/HTML reporting | `utils/report_engine.py` |
| Custom exception layer | `core/exceptions.py` |
| SaaS API gateway (Stripe + authorization gate) | `web_api/main.py`, `web_api/routes.py` |
| Docker deployment | `Dockerfile` |
| CI/CD | `.github/workflows/cicd.yml` |
| Unit tests | `tests/test_core.py` (39 tests) |

## 4. "Cyber machine" extensions (v2 — real-target capabilities)

| Capability | File | Note |
|------------|------|------|
| Network interface discovery/selection | `modules/network/interfaces.py` | no root needed |
| Live connection monitoring | `modules/network/connection_monitor.py` | passive, OS connection table |
| Packet capture (Wireshark style) | `modules/network/packet_capture.py` | tcpdump, own traffic only |
| Intercepting proxy (Burp-lite) | `modules/proxy/intercept_proxy.py` | own browser traffic, HTTPS tunnelled |
| Real HTTP content scanning | `modules/network/content_fetch.py` | live response body |
| Version-based CVE detection | `modules/vulnerability/cve_matcher.py` | only on genuinely vulnerable versions |
| Storefront (e-commerce) audit | `modules/web/storefront_audit.py` | TLS/headers/cookies/trust pages |
| Ad/URL & campaign analysis | `modules/web/url_analyzer.py` | UTM + gclid/gbraid parsing |
| Secret leak audit | `modules/dlp/secret_audit.py` | gitleaks style, your own files |
| Crypto exchange/wallet security | `modules/crypto/exchange_guard.py` | exchange API key + seed phrase + typosquatting |

**Ethical framework (v2):** Network monitoring and the proxy are only for the user's
OWN machine and traffic; exchanges and third parties are NOT scanned. Packet capture
is not promiscuous/MITM. All secret/crypto detection is local and findings are masked.

## 5. Offensive security toolkit (v3 — authorized pentest, non-destructive)

| Capability | File | Technique |
|------------|------|-----------|
| Active web recon | `modules/offensive/web_recon.py` | sensitive paths + soft-404 filter |
| XSS / SQLi | `modules/offensive/injection_tester.py` | reflection + DB error signature |
| LFI / SSTI / CMDi | `modules/offensive/param_fuzzer.py` | harmless probe + evidence signature |
| Host header injection | `modules/offensive/host_header.py` | fake Host reflection |
| HTTP method abuse / XST | `modules/offensive/http_methods.py` | OPTIONS/Allow + TRACE |
| CORS misconfiguration | `modules/offensive/cors_test.py` | Origin reflection + credentials |
| Open redirect | `modules/offensive/open_redirect.py` | redirect param + Location |
| JWT weaknesses | `modules/offensive/jwt_analyzer.py` | alg=none + HS256 secret cracking |
| Client-side secret leaks | `modules/offensive/js_secret_scan.py` | page + JS DLP scan |
| Subdomain discovery | `modules/offensive/subdomain_enum.py` | DNS wordlist |
| Technology fingerprinting | `modules/offensive/tech_fingerprint.py` | header/HTML signatures + CVE |
| Raw data harvesting | `modules/offensive/harvester.py` | raw dump + 429 back-off |
| Domain ownership verification | `modules/offensive/ownership.py` | /.well-known or DNS TXT token |
| Security grade + tracking | `modules/posture.py` | A–F score + snapshot/diff |

**Authorization model:** Every active module goes through `core/scope_guard` and `scope.yaml`.
A new target is only added once proven with `verify-ownership` (token via /.well-known or
DNS TXT). Third-party sites are never scanned on a verbal claim. There are no destructive
payloads (deletion/DoS/exfiltration).
