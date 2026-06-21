"""Embedded-secret scanner.

Scans selected text-bearing entries of an APK (resources, assets, dex strings
are out of scope here — this targets text resources and config) for credential
patterns. High-signal patterns only, to keep false positives manageable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Firebase URL", re.compile(r"\bhttps://[a-z0-9\-]+\.firebaseio\.com\b")),
    ("Generic Bearer Token", re.compile(r"\b[Bb]earer\s+[A-Za-z0-9\-_.=]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b")),
]


@dataclass
class SecretHit:
    kind: str
    where: str
    sample: str


def scan_text(text: str, where: str) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for kind, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(0)
            sample = raw[:6] + "…" + raw[-4:] if len(raw) > 14 else raw
            hits.append(SecretHit(kind=kind, where=where, sample=sample))
    return hits
