# nginx2root (CVE-2026-123007) — Detection Write-up

A short technical note on how Cerberus Saga detects the November 2026 nginx
HTTP/2 vulnerability set, and why getting the *detection* right is harder than it
looks.

> ⚠️ This is a **detection-only** capability for authorized assessments. Cerberus
> never runs an exploit. The goal is to tell an operator *"this nginx build is in
> a vulnerable range"* from a service banner — nothing more.

## The vulnerability

| | |
|---|---|
| **ID** | CVE-2026-123007 ("nginx2root"), with companion CVE-2026-123633 |
| **Component** | nginx HTTP/2 |
| **Class** | Integer underflow in HTTP/2 flow-control → memory corruption |
| **Impact** | Pre-authentication Remote Code Execution |
| **Severity** | Critical (CVSS 9.2) |
| **Introduced** | nginx 1.9.5 (Sep 2015) |
| **Fixed** | stable **1.30.7**, mainline **1.31.9** (Nov 2026) |

**Mechanism (conceptual):** HTTP/2 keeps a per-stream flow-control counter — a
signed integer tracking how many bytes a peer may still send. Specially crafted
frames drive this counter below zero; the value *underflows* and wraps to a very
large number. nginx then trusts that bogus window and writes past an allocated
buffer. Controlled, that memory corruption becomes code execution — hence
"…2root".

## Why detection is the interesting part

A naïve matcher says *"nginx ≤ 1.31.8 → vulnerable"*. That is **wrong**, because
nginx patches two branches independently:

- **stable** `1.30.x` → fixed in `1.30.7`
- **mainline** `1.31.x` → fixed in `1.31.9`

So `1.30.7` and `1.30.8` are **patched** even though they are numerically *below*
the last vulnerable mainline build `1.31.8`. A single closed `(low, high)` range
can't express that — it would raise a **false positive** on a patched stable
server. In a tool whose whole design promise is "no fabricated findings," that is
unacceptable.

## The branch-aware fix

`modules/vulnerability/cve_matcher.py` adds a `_is_patched()` predicate. A version
is treated as patched if either:

1. it is on the **same branch** `(major, minor)` as a fixed release **and** is
   at/after that release; or
2. it is on a **branch newer** than the newest patched branch.

```python
def _is_patched(ver, patched):
    for p in patched:
        if ver[:2] == p[:2] and ver >= p:   # same branch, at/after the fix
            return True
    if ver[:2] > max(patched)[:2]:          # a branch newer than any patched one
        return True
    return False
```

The CVE record carries the fixed releases:

```python
{"product": "nginx", "lo": (1, 9, 5), "hi": (1, 31, 8),
 "cve": "CVE-2026-123007", "severity": "CRITICAL",
 "patched": [(1, 30, 7), (1, 31, 9)],
 "detail": "nginx2root: HTTP/2 flow-control integer underflow, pre-auth RCE (CVSS 9.2)."}
```

## Verification

Run against representative banners:

| Banner | Verdict | Why |
|--------|---------|-----|
| `nginx/1.18.0` | **VULNERABLE** | old mainline, in range |
| `nginx/1.25.3` | **VULNERABLE** | in range, no branch fix |
| `nginx/1.30.6` | **VULNERABLE** | stable branch, before 1.30.7 |
| `nginx/1.30.7` | clean | stable branch, patched |
| `nginx/1.31.8` | **VULNERABLE** | mainline, before 1.31.9 |
| `nginx/1.31.9` | clean | mainline, patched |
| `nginx/1.32.0` | clean | newer branch |
| `nginx/1.9.4`  | clean | below the 1.9.5 floor |

```bash
python3 -c "import asyncio; from modules.vulnerability.cve_matcher import CVEMatcher; \
import itertools; \
print([ (b, [f['template'] for f in asyncio.run(CVEMatcher().match([b]))]) \
  for b in ['nginx/1.30.6','nginx/1.30.7','nginx/1.31.9'] ])"
```

## Honesty notes

- The affected range and fixed releases above should be **re-verified against the
  official nginx security advisory** before relying on them operationally; they
  are encoded from public disclosure summaries.
- Detection is **banner-based**. A server that hides or fakes its version string
  will not be flagged — this is a triage signal, not proof of exploitability.
- Cerberus only reports this on **in-scope** targets and never attempts the RCE.

## References

- nginx security advisories (official)
- NVD: CVE-2026-123007, CVE-2026-123633
