"""
modules/dlp/context_filter.py
Contextual suppression and validation layer (Blueprint Volume 10, Module 7-C).

Two defences: (1) downgrades matches in test/example/dummy context to INFO,
(2) window search for "unstructured" fields scanned only when a trigger word is present.
Lowers the false-positive rate.
"""
from __future__ import annotations

import re

SUPPRESSION_MARKERS = [
    r"\bexample\b", r"\bdummy\b", r"\btest[_-]?data\b", r"\bplaceholder\b",
    r"\bfixture\b", r"\bXXXX+\b", r"\bsample\b", r"lorem ipsum",
]
_suppression_re = re.compile("|".join(SUPPRESSION_MARKERS), re.I)


def is_suppressed_context(text: str, match_start: int, match_end: int, window: int = 60) -> bool:
    """True if 'example/dummy/test/placeholder' appears around the match."""
    start = max(match_start - window, 0)
    end = min(match_end + window, len(text))
    return bool(_suppression_re.search(text[start:end]))


def find_contextual_matches(text: str, trigger_words, pattern: str, window: int):
    """Returns only matches that have a trigger word nearby."""
    compiled = re.compile(pattern)
    lowered = text.lower()
    results = []
    for trigger in trigger_words:
        idx = lowered.find(trigger.lower())
        while idx != -1:
            seg_start = max(idx - window, 0)
            seg_end = min(idx + len(trigger) + window, len(text))
            segment = text[seg_start:seg_end]
            for m in compiled.finditer(segment):
                results.append((seg_start + m.start(), seg_start + m.end(), m.group(0)))
            idx = lowered.find(trigger.lower(), idx + 1)
    return results
