"""Defeat trivial obfuscation before regex/classifier detection.

The single biggest weakness of regex-based prompt-injection detectors is
that "i​gnore previous instructions" or `aWdub3JlIHByZXZpb3Vz...`
slips through. `normalize()` produces a canonical string whose detection
result is OR'd with the raw scan, so attackers pay for both layers.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

_ZERO_WIDTH = dict.fromkeys(
    [
        0x00AD,  # soft hyphen
        0x200B,  # zero-width space
        0x200C,  # zero-width non-joiner
        0x200D,  # zero-width joiner
        0x2060,  # word joiner
        0xFEFF,  # BOM / zero-width no-break space
    ],
    None,
)

# Common confusables -> ASCII. Not exhaustive (the full Unicode table is huge),
# but covers the everyday Cyrillic/Greek lookalikes used in jailbreak attempts.
_CONFUSABLES: dict[int, str] = {
    ord("а"): "a",  # Cyrillic a
    ord("е"): "e",  # Cyrillic e
    ord("о"): "o",  # Cyrillic o
    ord("р"): "p",  # Cyrillic p
    ord("с"): "c",  # Cyrillic c
    ord("х"): "x",  # Cyrillic x
    ord("ѕ"): "s",  # Cyrillic s
    ord("і"): "i",  # Cyrillic i
    ord("ԁ"): "d",  # Cyrillic komi de
    ord("ԛ"): "q",  # Cyrillic qa
    ord("ο"): "o",  # Greek omicron
    ord("α"): "a",  # Greek alpha
    ord("ρ"): "p",  # Greek rho
    ord("τ"): "t",  # Greek tau
}

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/])")
_HEX_RE = re.compile(r"\b((?:[0-9a-fA-F]{2}\s*){8,})\b")


def _strip_zero_width(text: str) -> str:
    return text.translate(_ZERO_WIDTH)


def _fold_confusables(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    return text.translate(_CONFUSABLES)


def _decode_base64_blocks(text: str) -> str:
    decoded_parts: list[str] = []
    for match in _BASE64_RE.finditer(text):
        token = match.group(1)
        try:
            raw = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if decoded.isprintable() or any(c.isspace() for c in decoded):
            decoded_parts.append(decoded)
    return text + (" " + " ".join(decoded_parts) if decoded_parts else "")


def _decode_hex_blocks(text: str) -> str:
    decoded_parts: list[str] = []
    for match in _HEX_RE.finditer(text):
        token = re.sub(r"\s+", "", match.group(1))
        if len(token) % 2:
            continue
        try:
            raw = bytes.fromhex(token)
            decoded = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            decoded_parts.append(decoded)
    return text + (" " + " ".join(decoded_parts) if decoded_parts else "")


def _try_rot13(text: str) -> str:
    rotated = codecs.decode(text, "rot_13")
    # Heuristic: only append if rotation produced common english tokens.
    triggers = ("ignore", "system", "instruction", "prompt", "password", "secret")
    if any(t in rotated.lower() for t in triggers):
        return text + " " + rotated
    return text


_SPACED_LETTERS = re.compile(r"(?:[A-Za-z][\s.\-_*]+){2,}[A-Za-z]\b")


def _collapse_spacing(text: str) -> str:
    """Turn 'i g n o r e' / 'i.g.n.o.r.e' / 'i-g-n-o-r-e' into 'ignore'.

    Only collapses runs of single-letter-plus-separator. Normal prose
    spacing between multi-character words is left untouched.
    """
    def _strip(match: re.Match[str]) -> str:
        return re.sub(r"[\s.\-_*]+", "", match.group(0))

    return _SPACED_LETTERS.sub(_strip, text)


def normalize(text: str) -> str:
    """Return a canonical-ish version of `text` for secondary detection.

    The output is intentionally lossy — it is *not* a safe sanitizer for
    forwarding to a model. It exists only to feed the detector.
    """
    if not text:
        return text
    out = _strip_zero_width(text)
    out = _fold_confusables(out)
    out = _decode_base64_blocks(out)
    out = _decode_hex_blocks(out)
    out = _try_rot13(out)
    out = _collapse_spacing(out)
    return out
