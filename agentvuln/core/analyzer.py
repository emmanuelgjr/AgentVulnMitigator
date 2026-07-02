"""Rule-based detector aligned to OWASP Top 10 for LLM Applications."""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlparse

from pydantic import BaseModel

from .netcheck import is_blocked_host
from .normalize import normalize

# Hard cap on the amount of text the detector will scan. The guard runs
# synchronously in the request path, so an unbounded input would let a single
# large payload stall the security control itself (DoS). Anything longer is
# truncated before scanning; callers that need to inspect huge blobs should
# chunk them.
MAX_SCAN_CHARS = 50_000


class Vulnerability(BaseModel):
    type: str
    description: str
    severity: str
    snippet: str | None = None
    via_normalization: bool = False


def _luhn_ok(text: str) -> bool:
    """Luhn checksum over the digits in `text` — filters random 16-digit
    numbers (order ids, hashes) that are not real payment cards."""
    digits = [int(c) for c in text if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2  # double every second digit from the right
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _ssrf_target(candidate: str) -> bool:
    """True if a matched http(s) URL points at an internal/metadata host."""
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    return is_blocked_host((parsed.hostname or "").lower())


@dataclass(frozen=True)
class _Rule:
    type: str
    severity: str
    description: str
    pattern: re.Pattern[str]
    # Optional post-match predicate; the match only counts as a finding when
    # it returns True. Lets a broad pattern stay precise (Luhn on cards,
    # internal-host check on URLs) without false positives.
    validator: Callable[[str], bool] | None = None


_RULES: tuple[_Rule, ...] = (
    _Rule(
        type="Prompt Injection",
        severity="High",
        description="Potential attempt to override or exfiltrate the system prompt.",
        pattern=re.compile(
            r"(ignore|disregard|override|forget|bypass|skip|neglect)\b[^.\n]{0,40}\b"
            r"(previous|above|earlier|prior|initial|original|system|instruction|prompt|"
            r"rules?|directives?|guidelines?|guardrails?|constraints?|polic(?:y|ies)|"
            r"configuration|filters?)",
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
        description="Attempt to exfiltrate the system prompt or hidden instructions.",
        pattern=re.compile(
            # Branch A: a verb near a system-prompt / instructions noun. Anchored
            # on specific nouns (not generic "the above") to avoid flagging
            # routine "print the above table"-style content requests.
            r"(?:reveal|print|repeat|show|output|reproduce|leak|divulge|expose|dump|display|"
            r"echo|regurgitate|summari[sz]e|translate|give\s+me|tell\s+me|what\s+(?:are|were))"
            r"\b[^.\n]{0,40}\b(?:system\s+prompt|system\s+message|"
            r"(?:initial|hidden|original)\s+instructions?|your\s+(?:instructions?|prompt|"
            r"system\s+prompt)|instructions?\s+you\s+were\s+given)"
            # Branch B: the canonical "repeat the text above ... verbatim / starting
            # with 'You are'" leak. Requires a leak qualifier so ordinary
            # "repeat the above steps" does not match.
            r"|(?:reveal|print|repeat|show|output|reproduce|echo|regurgitate|give\s+me)"
            r"\b[^.\n]{0,60}\b(?:above|before|earlier|prior)\b[^.\n]{0,40}"
            r"\b(?:verbatim|word[-\s]for[-\s]word|starting\s+with|exactly)",
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
        description="Possible payment card number (Luhn-valid 16-digit PAN).",
        # 16 digits only: matches Visa/MC/Discover PAN grouping while avoiding
        # collisions with 15-digit IMEIs and other Luhn-valid identifiers.
        # Separators exclude comma/tab to avoid flagging comma-grouped numeric
        # lists ("1111,2222,3333,4444").
        pattern=re.compile(r"\b(?:\d[ .\-_/]*?){16}\b"),
        validator=_luhn_ok,
    ),
    _Rule(
        type="Sensitive Data Exposure",
        severity="High",
        description="Possible secret/API key in the input.",
        pattern=re.compile(
            r"(?:"
            r"sk-ant-[A-Za-z0-9_-]{20,}"
            r"|sk-proj-[A-Za-z0-9_-]{20,}"
            r"|sk-[A-Za-z0-9]{20,}"
            r"|sk_(?:live|test)_[A-Za-z0-9]{16,}"
            r"|rk_(?:live|test)_[A-Za-z0-9]{16,}"
            r"|pk_(?:live|test)_[A-Za-z0-9]{16,}"
            r"|(?:AKIA|ASIA)[0-9A-Z]{16}"
            r"|ghp_[A-Za-z0-9]{36}"
            r"|gh[ousr]_[A-Za-z0-9]{36}"
            r"|github_pat_[A-Za-z0-9_]{22,}"
            r"|glpat-[A-Za-z0-9_-]{20}"
            r"|AIza[0-9A-Za-z_-]{35}"
            r"|xox[baprs]-[A-Za-z0-9-]{10,}"
            r"|-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"
            r")"
        ),
    ),
    _Rule(
        type="Insecure Output Handling",
        severity="High",
        description="Script tag or inline JS handler — risk of XSS when rendered.",
        # Event handlers only count inside a tag (`<... onerror=`) so benign
        # key=value prose like `only=true`/`online=1` is not flagged.
        pattern=re.compile(
            r"<\s*script\b|<[^>]{0,200}\son\w+\s*=|javascript:|data:text/html",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        type="Insecure Output Handling",
        severity="High",
        description="Shell metacharacters / command-injection markers.",
        # Shell-chaining operator (including newline, a real POSIX separator) +
        # optional path prefix (`/bin/rm`) + dangerous binary + a COMMAND-SHAPED
        # argument (flag / path / IP / URL / domain / quote / pipe). Gating on the
        # argument is what separates an injected "line\nrm -rf /" from benign
        # newline-delimited prose like "ruby\nnode\nphp" or "curl the latest data".
        pattern=re.compile(
            r"(?:;|\|\|?|&&?|`|\$\(|\n)[ \t]*(?:[\w.\-/]*/)?"
            r"(?:rm|curl|wget|bash|sh|zsh|powershell|pwsh|cmd|python[0-9.]*|node|deno|perl|"
            r"ruby|php|nc|ncat|socat|telnet|ssh|scp|cat|chmod|chown|tee|dd|mkfifo|kill|"
            r"eval|exec)\b"
            r"(?=[ \t]+(?:-{1,2}\w|[/~\"'$*]|\d{1,3}(?:\.\d{1,3}){1,3}|https?:|\w[\w.\-]*\.\w)"
            r"|[ \t]*[|<>&`])",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        type="Excessive Agency / SSRF",
        severity="High",
        description="Agent tool-call targeting an internal/metadata endpoint.",
        pattern=re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
        validator=_ssrf_target,
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

    def __init__(
        self,
        rules: Iterable[_Rule] | None = None,
        *,
        normalize_input: bool = True,
        max_chars: int = MAX_SCAN_CHARS,
    ) -> None:
        self._rules: tuple[_Rule, ...] = tuple(rules) if rules else _RULES
        self._normalize = normalize_input
        self._max_chars = max_chars

    def analyze_input(self, user_input: str) -> list[Vulnerability]:
        if not user_input:
            return []
        if len(user_input) > self._max_chars:
            user_input = user_input[: self._max_chars]

        findings: list[Vulnerability] = []
        seen: set[tuple[str, str]] = set()

        self._scan(user_input, findings, seen, via_norm=False)

        if self._normalize:
            normalized = normalize(user_input)
            if normalized and normalized != user_input:
                self._scan(normalized, findings, seen, via_norm=True)

        return findings

    def redact(
        self,
        text: str,
        findings: Iterable[Vulnerability],
        replacement: str = "[REDACTED]",
    ) -> str:
        """Remove every occurrence of each triggered rule's matches from `text`.

        Redaction re-runs the offending rules' regexes over the supplied text
        (not a per-finding snippet), so it removes ALL matches and full spans —
        second secrets and matches longer than the display snippet included.
        A match is only redacted when the rule's validator (if any) accepts it,
        so benign URLs / non-card numbers are left intact.

        NOTE: this can only remove content present in `text`. For findings
        surfaced via normalization the caller must fail closed — see
        `Guard._evaluate`.
        """
        keys = {(f.type, f.description) for f in findings}
        out = text
        for rule in self._rules:
            if (rule.type, rule.description) not in keys:
                continue

            def _repl(match: re.Match[str], _rule: _Rule = rule) -> str:
                if _rule.validator is not None and not _rule.validator(match.group(0)):
                    return match.group(0)
                return replacement

            out = rule.pattern.sub(_repl, out)
        return out

    def _scan(
        self,
        text: str,
        findings: list[Vulnerability],
        seen: set[tuple[str, str]],
        *,
        via_norm: bool,
    ) -> None:
        for rule in self._rules:
            key = (rule.type, rule.description)
            if key in seen:
                continue
            match = self._first_valid(rule, text)
            if match is None:
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

    @staticmethod
    def _first_valid(rule: _Rule, text: str) -> re.Match[str] | None:
        if rule.validator is None:
            return rule.pattern.search(text)
        for candidate in rule.pattern.finditer(text):
            if rule.validator(candidate.group(0)):
                return candidate
        return None


def scan_input(text: str) -> list[Vulnerability]:
    """Module-level convenience: one-shot scan with default rules."""
    return AnalyzerAgent().analyze_input(text)
