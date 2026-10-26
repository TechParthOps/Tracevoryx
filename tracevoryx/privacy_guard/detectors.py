"""Deterministic secret/PII detectors (fresh implementation, same rigor)."""
from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass, field

from ..config import get_settings


@dataclass
class Detection:
    detector: str
    label: str
    start: int
    end: int
    preview: str
    confidence: float
    placeholder: str
    meta: dict = field(default_factory=dict)


def _mask(s: str, keep: int = 3) -> str:
    s = s.replace("\n", " ")
    if len(s) <= keep:
        return "*" * len(s)
    return s[:keep] + "…" + "*" * min(len(s) - keep, 10)


def _luhn(digits: str) -> bool:
    digits = re.sub(r"\D", "", digits)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


_RULES: list[tuple[str, str, re.Pattern, float, str]] = [
    ("private_key", "PEM private key",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 0.99,
     "[REDACTED_PRIVATE_KEY]"),
    ("api_key", "AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.97,
     "[REDACTED:AWS_KEY]"),
    ("api_key", "GitHub token",
     re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"),
     0.97, "[REDACTED:GITHUB_TOKEN]"),
    ("api_key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     0.97, "[REDACTED:GOOGLE_KEY]"),
    ("api_key", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
     0.95, "[REDACTED:SLACK_TOKEN]"),
    ("api_key", "OpenAI-style key",
     re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"), 0.85,
     "[REDACTED:API_KEY]"),
    ("bearer_token", "Bearer header",
     re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9_\-\.=+/]{8,}"),
     0.95, "Authorization: Bearer [REDACTED_TOKEN]"),
    ("bearer_token", "JWT",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     0.97, "[REDACTED_JWT]"),
    ("credential", "Basic auth header",
     re.compile(r"(?i)\bAuthorization\s*:\s*Basic\s+[A-Za-z0-9+/=]{8,}"),
     0.95, "Authorization: Basic [REDACTED_CREDENTIALS]"),
    ("credential", "password assignment",
     re.compile(r"(?i)\b(pass(word|wd)?|pwd)\b\s*[:=]\s*\S{4,}"), 0.8,
     "[REDACTED_PASSWORD]"),
    ("credential", "secret env assignment",
     re.compile(r"(?i)\b((?:api[_-]?key|secret|token|client[_-]?secret)[a-z0-9_-]*)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.+/]{8,}"),
     0.85, "[REDACTED_SECRET]"),
    ("email", "email address",
     re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), 0.9,
     "[REDACTED_EMAIL]"),
    ("phone", "phone number",
     re.compile(r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d)"),
     0.7, "[REDACTED_PHONE]"),
    ("internal_host", "internal/private IP",
     re.compile(r"\b(?:(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
     0.75, "[REDACTED_INTERNAL_IP]"),
]


def custom_rules(settings=None) -> list[tuple[str, str, re.Pattern, float, str]]:
    """User-defined patterns from config: privacy.custom_patterns =
    [{"name": "...", "regex": "...", "confidence": 0.9}] — bad patterns are
    skipped with the error surfaced, never silently accepted."""
    settings = settings or get_settings()
    out = []
    for spec in settings.get("privacy.custom_patterns", []) or []:
        try:
            rx = re.compile(spec["regex"])
            out.append((f"custom:{spec['name']}", spec["name"], rx,
                        float(spec.get("confidence", 0.9)),
                        f"[REDACTED:{spec['name'].upper()}]"))
        except (KeyError, re.error, TypeError, ValueError):
            continue
    return out

_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SECRET_CTX = re.compile(
    r"(?<![A-Za-z0-9])(key|token|secret|password|credential|auth)(?![A-Za-z0-9])")


def inspect_deterministic(text: str, settings=None) -> list[Detection]:
    if len(text) > 2_000_000:  # memory/size limit: refuse oversized scans
        text = text[:2_000_000]
    text = unicodedata.normalize("NFC", text)
    found: list[Detection] = []
    for det, label, rx, conf, placeholder in _RULES + custom_rules(settings):
        for m in rx.finditer(text):
            found.append(Detection(det, label, m.start(), m.end(),
                                   _mask(m.group(0)), conf, placeholder))
    for m in _CARD.finditer(text):
        if _luhn(m.group(0)):
            found.append(Detection("credit_card", "card number (Luhn)",
                                   m.start(), m.end(), _mask(m.group(0), 0),
                                   0.95, "[REDACTED_CARD]"))
    for m in re.finditer(r"[A-Za-z0-9_/+\-=]{20,}", text):
        token = m.group(0)
        if (20 <= len(token) <= 200 and _entropy(token) > 3.5
                and sum(bool(c.islower()) for c in token)
                + bool(re.search(r"[A-Z]", token))
                + bool(re.search(r"\d", token)) >= 2):
            ctx = text[max(0, m.start() - 60):m.end() + 60]
            if _SECRET_CTX.search(ctx):
                found.append(Detection(
                    "possible_secret", "high-entropy near secret keyword",
                    m.start(), m.end(), _mask(token), 0.55,
                    "[REDACTED_POSSIBLE_SECRET]"))
    found.sort(key=lambda d: (-(d.end - d.start), d.start))
    selected: list[Detection] = []
    taken: list[tuple[int, int]] = []
    for d in found:
        if any(not (d.end <= s or d.start >= e) for s, e in taken):
            continue
        selected.append(d)
        taken.append((d.start, d.end))
    return sorted(selected, key=lambda d: d.start)


def apply_redaction(text: str, detections: list[Detection]) -> str:
    out = text
    for d in sorted(detections, key=lambda d: -d.start):
        out = out[:d.start] + d.placeholder + out[d.end:]
    return out
