"""
modules/remediation.py
Turns findings into prioritized, concrete remediation actions.
Used for the executive summary and the report's "Priority Actions" section.
"""
from __future__ import annotations

# (keyword -> action). If it matches within detail/area, an action is produced.
RULES = [
    ("dmarc", "Add a DMARC record to prevent email spoofing (p=quarantine→reject)."),
    ("spf", "Add/harden an SPF record (end it with ~all or -all)."),
    ("contact", "Publish a 'contact' page on Shopify (email + address + form)."),
    ("security.txt", "Add /.well-known/security.txt (RFC 9116, a contact channel)."),
    ("content-security-policy", "Define a strict CSP; avoid 'unsafe-inline'/'unsafe-eval'."),
    ("unsafe-inline", "Remove 'unsafe-inline' from CSP; move to nonce/hash-based scripts."),
    ("clickjacking", "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."),
    ("strict-transport-security", "Add an HSTS header (max-age ≥ 31536000; includeSubDomains)."),
    ("hsts", "Add an HSTS header and apply to the preload list."),
    ("referrer-policy", "Add Referrer-Policy: strict-origin-when-cross-origin."),
    ("permissions-policy", "Use Permissions-Policy to restrict camera/microphone/location permissions."),
    ("httponly", "Add HttpOnly + Secure + SameSite flags to session cookies."),
    ("cors", "Restrict CORS to trusted origins only; never use '*' with credentials."),
    ("trace", "Disable the TRACE/TRACK method (removes the XST risk)."),
    (".env", "Remove the exposed .env/config file from the web root and rotate secrets."),
    (".git", "Block the exposed .git directory; never serve version-control files."),
    ("sql", "Use parameterized queries/ORM; add input validation (SQLi)."),
    ("xss", "Apply output encoding and enforce CSP (XSS)."),
    ("lfi", "Validate file paths with an allow-list (LFI/path traversal)."),
    ("ssti", "Do not evaluate user input in the template engine (SSTI)."),
    ("cmd_injection", "Never pass user input to system commands; use an argument array."),
    ("weak_secret", "Make the JWT signing secret strong/random (≥256-bit) and rotate it."),
    ("alg_none", "Reject alg=none in JWTs; pin the algorithm server-side."),
    ("seed", "Immediately rotate the leaked wallet/seed and move the funds."),
    ("exchange_api_key", "Revoke the leaked exchange API key; add IP restrictions."),
    ("stripe", "Revoke and reissue the leaked Stripe/payment key."),
    ("aws_access_key", "Disable the leaked AWS key; review CloudTrail."),
    ("phishing", "Report the fake-exchange/typosquat domain for takedown."),
    ("axfr", "Restrict zone transfer (AXFR) to authorized secondary nameservers only."),
    ("caa", "Add a CAA record; authorize certificates only from the CA you use."),
    ("dnssec", "Enable DNSSEC (sign the zone) — prevents DNS spoofing."),
    ("version", "Hide the server/framework version from headers (Server/X-Powered-By)."),
]

_SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def recommend(sections: list[dict]) -> list[dict]:
    """Produces a unique, prioritized action list from the findings."""
    seen = set()
    actions = []
    for sec in sections:
        for f in sec.get("findings", []):
            sev = str(f.get("severity", "INFO")).upper()
            text = (str(f.get("area", "")) + " " + str(f.get("detail", ""))).lower()
            for kw, action in RULES:
                if kw in text and action not in seen:
                    seen.add(action)
                    actions.append({"severity": sev, "action": action})
    actions.sort(key=lambda a: _SEV.get(a["severity"], 9))
    return actions
