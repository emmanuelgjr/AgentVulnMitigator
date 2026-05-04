"""Rule-based detector aligned to OWASP Top 10 for LLM Applications."""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from pydantic import BaseModel

from .normalize import normalize


class Vulnerability(BaseModel):
    type: str
    description: str
    severity: str
    snippet: str | None = None
    via_normalization: bool = False


@dataclass(frozen=True)
class _Rule:
    type: str
    severity: str
    description: str
    pattern: re.Pattern[str]


_RULES: tuple[_Rule, ...] = (
    _Rule(
        type="Prompt Injection",
        severity="High",
        description="Potential attempt to override or exfiltrate the system prompt.",
        pattern=re.compile(
            r"(ignore|disregard|override|forget)\b[^.\n]{0,40}\b(previous|above|system|instruction|prompt|rules?)",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        type="Prompt Injection",
        severity="High",
        description="Indirect prompt injection marker (delimiter or role-play hijack).",
        pattern=re.compile(
            r"(?:###\s*system|<\|im_start\|>|you\s+are\s+now|act\s+as\s+(?:an?\s+)?(?:admin|developer|root|dan))",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        type="Prompt Injection",
        severity="High",
        description="Jailbreak persona (DAN / unrestricted-mode prompt).",
        pattern=re.compile(
            r"\b(?:do\s+anything\s+now|developer\s+mode|jailbreak|unrestricted\s+mode)\b",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        type="Sensitive Data Exposure",
        severity="Critical",
        description="Possible payment card number (16 contiguous digits).",
        pattern=re.compile(r"\b(?:\d[ -]*?){16}\b"),
    ),
    _Rule(
        type="Sensitive Data Exposure",
        severity="High",
        description="Possible secret/API key in the input.",
        pattern=re.compile(
            r"(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})"
        ),
    ),
    _Rule(
        type="Insecure Output Handling",
        severity="High",
        description="Script tag or inline JS handler — risk of XSS when rendered.",
        pattern=re.compile(r"<\s*script\b|on\w+\s*=\s*['\"]", re.IGNORECASE),
    ),
    _Rule(
        type="Insecure Output Handling",
        severity="High",
        description="Shell metacharacters / command-injection markers.",
        pattern=re.compile(
            r"(?:;|\|\||&&|`|\$\()\s*(?:rm|curl|wget|bash|sh|powershell|cmd)\b",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        type="Excessive Agency / SSRF",
        severity="High",
        description="Agent tool-call targeting an internal/metadata endpoint.",
        pattern=re.compile(
            r"https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|metadata\.google\.internal)",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        type="Training Data Poisoning",
        severity="Medium",
        description="Instruction to permanently store or remember malicious content.",
        pattern=re.compile(
            r"(remember|store|save)\b[^.\n]{0,30}\b(forever|permanently|to\s+memory|across\s+sessions)",
            re.IGNORECASE,
        ),
    ),
)


class AnalyzerAgent:
    """Detector for OWASP-LLM-aligned vulnerabilities. Runs both raw and normalized."""

    def __init__(self, rules: Iterable[_Rule] | None = None, *, normalize_input: bool = True) -> None:
        self._rules: tuple[_Rule, ...] = tuple(rules) if rules else _RULES
        self._normalize = normalize_input

    def analyze_input(self, user_input: str) -> list[Vulnerability]:
        if not user_input:
            return []

        findings: list[Vulnerability] = []
        seen: set[tuple[str, str]] = set()

        self._scan(user_input, findings, seen, via_norm=False)

        if self._normalize:
            normalized = normalize(user_input)
            if normalized and normalized != user_input:
                self._scan(normalized, findings, seen, via_norm=True)

        return findings

    def _scan(
        self,
        text: str,
        findings: list[Vulnerability],
        seen: set[tuple[str, str]],
        *,
        via_norm: bool,
    ) -> None:
        for rule in self._rules:
            match = rule.pattern.search(text)
            if not match:
                continue
            key = (rule.type, rule.description)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Vulnerability(
                    type=rule.type,
                    description=rule.description,
                    severity=rule.severity,
                    snippet=match.group(0)[:120],
                    via_normalization=via_norm,
                )
            )


def scan_input(text: str) -> list[Vulnerability]:
    """Module-level convenience: one-shot scan with default rules."""
    return AnalyzerAgent().analyze_input(text)
