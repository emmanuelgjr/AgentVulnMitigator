"""Memory-poisoning guard for vector-store / long-term-memory writes."""
from __future__ import annotations

from ..core.analyzer import AnalyzerAgent

_analyzer = AnalyzerAgent()

_MAX_CONTENT_CHARS = 16_000


def validate_vector_write(
    content: str,
    *,
    metadata: dict[str, object] | None = None,
    trust: str = "untrusted",
) -> str | None:
    """Return None if the write is safe, else a reason string.

    `trust` is "trusted" (operator) or "untrusted" (anything reachable from
    a user prompt or tool fetch). Only "trusted" callers may write content
    that contains injection markers.
    """
    if not isinstance(content, str) or not content.strip():
        return "empty content"

    if len(content) > _MAX_CONTENT_CHARS:
        return f"content exceeds {_MAX_CONTENT_CHARS}-char cap"

    if trust == "trusted":
        return None

    findings = _analyzer.analyze_input(content)
    bad = [v for v in findings if v.severity in {"Critical", "High"}]
    if bad:
        types = ", ".join(sorted({v.type for v in bad}))
        return f"untrusted write contains {types} — refusing to persist"

    if metadata:
        for k, v in metadata.items():
            if isinstance(v, str) and _analyzer.analyze_input(v):
                return f"metadata field {k!r} contains injection markers"

    return None
