# Cerberus Saga — Presentation / Demo Guide

The flow to follow when **running the tool and showing what it does** to a reviewer.

## 0. In one line
> Cerberus is an asynchronous, modular **defensive/pentest security scanning platform**
> that runs only against **in-scope** targets: it performs port + vulnerability
> + OSINT + IAM + sensitive data (PII/SPII/financial) scanning, **masks** findings,
> keeps an **immutable signed audit log** and generates PDF/HTML reports automatically.

## 1. Setup (once)
```bash
cd cerberus-core
./setup.sh                 # venv + dependencies (not required for the demo)
```
> The demo also runs on the standard library alone; `python3 cerberus.py demo` is enough.

## 1.5. The easiest way — web panel (ideal for a presentation)
```bash
python3 cerberus.py serve
```
The panel opens in the browser: **pick a target → "Start scan" → results in a colour-coded table.**
Anyone can use it by clicking, without seeing a single command. The "inject demo data"
checkbox shows off the DLP capability; leave it unchecked and the target is scanned for real.

## 2. Live demo (no network needed)
```bash
python3 cerberus.py demo
```
The steps you will see on screen and **explain**:
1. **Stage 0 — Authorization gate:** is the target in `scope.yaml`? If not, the scan is refused.
   → *"I blocked the tool from running against unauthorized targets at the code level."*
2. **Stage 1-2 — Recon + port/service scan** (real nmap if installed, otherwise the fallback).
3. **Stage 3 — Vulnerability scan:** Nuclei / OWASP / AI injection / SBOM.
4. **Stage 3.5 — DLP:** national ID numbers, credit cards, IBANs and AWS/Stripe/GitHub keys
   are detected in a leaky sample response and shown **masked**.
   → *"Raw data never reaches the screen, the logs or the outside; it is all masked like `42***...***42`."*
5. **Stage 3.6 — IAM:** token entropy, MFA bypass, IDOR/privilege-escalation checks.
6. **Stage 3.7 — Safe PoC:** vulnerabilities are verified without harming the target.
7. **CTI:** discovered CVEs are correlated with active ransomware groups.
8. **Report:** a colour-coded HTML (and PDF if weasyprint is installed) report under `reports/`.

## 3. Show that the audit log is immutable (a strong moment)
```bash
python3 cerberus.py verify-audit        # VERIFIED ✅
# edit a line in storage/audit/*.jsonl by hand, then run again:
python3 cerberus.py verify-audit        # BROKEN ❌  (the SHA-256 chain catches it)
```
→ *"The tool does not hide its tracks; it cryptographically seals every step instead."*

## 4. Tests
```bash
pytest -q        # 39 tests pass: authorization gate, checksums, masking, audit chain, offensive modules
```

## 5. SaaS API (optional)
```bash
uvicorn web_api.main:app --reload
# POST /api/v1/start-scan  -> out-of-scope domain 403; no payment 402
```

## 6. Business model (Blueprint Volume 4 — explain on a slide)
- **Phase 1:** Boutique enterprise audit reports (£5k–10k MRR)
- **Phase 2:** Monthly MSSP subscription (£30k+ MRR)
- **Phase 3:** Global self-service SaaS (Stripe + FastAPI, $1M+ ARR target)

## 7. "Why offensive but legitimate?" (likely question)
Ports/vulnerabilities/OSINT/IAM/PoC are what standard pentest tools (nmap, nuclei, ZAP)
do. The difference: **every scan is tied to a written authorization scope**, findings are
masked and local, and instead of hiding traces there is an immutable audit log. That is
exactly the line the blueprint's own Volume 7/8 compliance section asks for.
