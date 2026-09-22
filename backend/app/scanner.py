from dataclasses import dataclass
import math
import re
from collections import Counter
from typing import Iterable


@dataclass(frozen=True)
class Finding:
    kind: str
    value: str
    start: int
    end: int
    severity: str
    confidence: float
    recommendation: str


PATTERNS: tuple[tuple[str, str, str, float, str], ...] = (
    ("email", r"\b[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b", "medium", 0.98, "Remove or redact the email address before sharing."),
    ("phone", r"(?<!\w)(?:\+?\d[\d ().-]{7,}\d)(?!\w)", "medium", 0.82, "Remove or mask the phone number."),
    ("ipv4", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", "low", 0.96, "Avoid exposing internal or personal IP addresses."),
    ("credit_card", r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)", "critical", 0.72, "Never share payment-card numbers; revoke or replace exposed data."),
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b", "critical", 0.95, "Treat government identifiers as highly sensitive and redact them."),
    ("jwt", r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b", "critical", 0.99, "Revoke the token and issue a replacement immediately."),
    ("api_key", r"\b(?:sk|pk|api|key|token)[_-][a-zA-Z0-9_-]{16,}\b", "critical", 0.86, "Revoke and rotate the exposed credential."),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical", 1.0, "Revoke the key and generate a new key pair."),
)


def _looks_like_credit_card(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _redact(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:2]}{'*' * min(12, len(value) - 4)}{value[-2:]}"


def scan_text(text: str) -> dict:
    findings: list[Finding] = []
    occupied: list[tuple[int, int]] = []

    for kind, pattern, severity, confidence, recommendation in PATTERNS:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            value = match.group(0)
            if kind == "credit_card" and not _looks_like_credit_card(value):
                continue
            if any(match.start() < end and match.end() > start for start, end in occupied):
                continue
            findings.append(Finding(kind, value, match.start(), match.end(), severity, confidence, recommendation))
            occupied.append((match.start(), match.end()))

    # Detect assignment-style secrets without retaining their values in the response.
    secret_pattern = re.compile(r"(?i)\b(password|passwd|secret)\s*[:=]\s*([^\s,;]{8,})")
    for match in secret_pattern.finditer(text):
        if any(match.start() < end and match.end() > start for start, end in occupied):
            continue
        value = match.group(2)
        if len(value) >= 12 and _entropy(value) >= 3.2:
            findings.append(Finding("password_or_secret", value, match.start(2), match.end(2), "high", 0.78, "Remove the secret and rotate it if it was shared."))
            occupied.append((match.start(), match.end()))

    findings.sort(key=lambda item: item.start)
    counts = Counter(item.severity for item in findings)
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    risk = max((item.severity for item in findings), key=lambda item: rank[item], default="none")
    return {
        "risk": risk,
        "summary": {"total": len(findings), **{level: counts.get(level, 0) for level in ("low", "medium", "high", "critical")}},
        "findings": [
            {"type": item.kind, "redacted_value": _redact(item.value), "severity": item.severity, "confidence": item.confidence, "start": item.start, "end": item.end, "recommendation": item.recommendation}
            for item in findings
        ],
    }
