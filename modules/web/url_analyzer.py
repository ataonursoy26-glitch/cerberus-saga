"""
modules/web/url_analyzer.py
Ad / landing URL analyzer (UTM + Google Ads click parameters).

Breaks a marketing URL into its parts: which campaign, which ad,
which keyword, which device/network, and which click-tracking IDs
(gclid, gbraid, wbraid) it carries. It also builds the "clean" (untracked) URL
and adds a privacy/tracking note. Needs no network access — it only parses the URL.
"""
from __future__ import annotations

from urllib.parse import urlsplit, parse_qs, urlunsplit

DEVICE = {"c": "Bilgisayar (desktop)", "m": "Mobil", "t": "Tablet"}
NETWORK = {"g": "Google Search", "s": "Search partner sites", "d": "Display Network",
           "u": "Bilinmeyen", "ytv": "YouTube video"}
MATCHTYPE = {"e": "Exact match", "p": "Phrase match", "b": "Broad match"}

# Click-tracking IDs (identify the person/click — privacy-sensitive)
TRACKING_IDS = {
    "gclid": "Google Ads click ID (click → conversion matching)",
    "gbraid": "Google Ads iOS web-app click ID",
    "wbraid": "Google Ads iOS click ID",
    "gad_source": "Google Ads source marker",
    "gad_campaignid": "Google Ads campaign ID",
    "fbclid": "Facebook/Meta click ID",
    "msclkid": "Microsoft Ads click ID",
    "ttclid": "TikTok click ID",
    "qwerty": "Custom/unknown tracking parameter",
}

UTM_LABELS = {
    "utm_source": "Kaynak", "utm_medium": "Ortam", "utm_campaign": "Kampanya (ID/ad)",
    "utm_content": "Ad/Content ID", "utm_term": "Keyword", "utm_adid": "Ad ID",
    "utm_targetid": "Targeting ID", "utm_placement": "Placement", "utm_device": "Device",
    "utm_network": "Network", "utm_matchtype": "Match type", "utm_position": "Position",
}


def analyze(url: str) -> dict:
    parts = urlsplit(url)
    q = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}

    utm = {}
    for key, label in UTM_LABELS.items():
        if key in q:
            raw = q[key]
            human = raw
            if key == "utm_device":
                human = DEVICE.get(raw, raw)
            elif key == "utm_network":
                human = NETWORK.get(raw, raw)
            elif key == "utm_matchtype":
                human = MATCHTYPE.get(raw, raw)
            utm[label] = human

    tracking = {TRACKING_IDS.get(k, k): (q[k][:24] + "…" if len(q[k]) > 24 else q[k])
                for k in q if k in TRACKING_IDS}

    other = {k: q[k] for k in q if k not in UTM_LABELS and k not in TRACKING_IDS}

    clean = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))

    # Summary sentence
    summary = []
    if q.get("utm_source") == "google" and q.get("utm_medium") == "cpc":
        summary.append("Google Ads PAID SEARCH (CPC) click")
    if "utm_term" in q:
        summary.append(f"anahtar kelime: '{q['utm_term']}'")
    if "utm_matchtype" in q:
        summary.append(MATCHTYPE.get(q["utm_matchtype"], q["utm_matchtype"]))
    if "utm_device" in q:
        summary.append(DEVICE.get(q["utm_device"], q["utm_device"]))
    if "utm_campaign" in q:
        summary.append(f"kampanya #{q['utm_campaign']}")

    return {
        "clean_url": clean,
        "summary": " · ".join(summary) if summary else "No tracking parameters detected.",
        "utm": utm,
        "tracking_ids": tracking,
        "other_params": other,
        "privacy_note": (
            "Click IDs like gclid/gbraid link a visitor's ad click "
            "to their conversion. YOU use these for analytics; but if you publish this URL "
            "on social media/shared posts, your campaign IDs and budget targeting "
            "leak out. Use the 'clean URL' when sharing."
            if tracking else "This URL has no click-tracking ID."),
    }
