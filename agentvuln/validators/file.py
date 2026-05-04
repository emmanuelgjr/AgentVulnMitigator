"""Path-traversal / chroot guard for file tool calls."""
from __future__ import annotations

import os
from pathlib import Path


def validate_file_path(path: str, *, root: str | os.PathLike[str]) -> str | None:
    """Return None if `path` resolves inside `root`, else a reason string.

    Use the returned value to refuse the tool call. Symlinks are resolved
    so an attacker can't escape via `root/link-to-/etc/passwd`.
    """
    if not isinstance(path, str) or not path.strip():
        return "empty path"

    try:
        root_resolved = Path(root).resolve(strict=False)
        if os.path.isabs(path):
            target = Path(path).resolve(strict=False)
        else:
            target = (root_resolved / path).resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        return f"could not resolve path: {exc}"

    try:
        target.relative_to(root_resolved)
    except ValueError:
        return f"path {str(target)!r} escapes root {str(root_resolved)!r}"

    return None
