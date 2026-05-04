"""Shell tool guard. Default policy: deny."""
from __future__ import annotations

import re

_DANGEROUS = re.compile(
    r"(?:^|[\s;|&`])(?:rm\s+-rf|mkfs|dd\s+if=|:\(\)\{|wget|curl|nc\s|telnet|ssh|scp|chmod\s+[0-7]*7|chown)",
    re.IGNORECASE,
)
_SUBSTITUTION = re.compile(r"\$\(|`")


def validate_shell_command(
    command: str,
    *,
    allowed_binaries: frozenset[str] | None = None,
) -> str | None:
    """Return None if the command is allowed, else a reason string.

    Default behavior: refuse everything. Pass `allowed_binaries={'ls', 'cat'}`
    to permit a narrow set; the first whitespace-delimited token must be in
    that set, and command substitution / dangerous patterns are still denied.
    """
    if not isinstance(command, str) or not command.strip():
        return "empty command"

    if allowed_binaries is None:
        return "shell tool calls are denied by default policy"

    if _SUBSTITUTION.search(command):
        return "command substitution ($(...) or backticks) is not allowed"

    if _DANGEROUS.search(command):
        return "command contains a dangerous pattern"

    head = command.strip().split(maxsplit=1)[0]
    head = head.lstrip("./")
    if head not in allowed_binaries:
        return f"binary {head!r} is not in the allowlist"

    return None
