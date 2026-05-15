"""Confusable-character normalization for domain lookalike checks."""

from __future__ import annotations

# Maps visually confusable glyphs to ASCII lookalikes (lowercase).
_CONFUSABLE_MAP: dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "6": "g",
    "8": "b",
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ӏ": "l",
    "ɡ": "g",
    "ℓ": "l",
    "ⅰ": "i",
    "ⓞ": "o",
}


def ascii_fold(text: str) -> str:
    """Fold a hostname or label to an ASCII-centric representation for comparison."""
    lowered = text.lower().strip()
    out: list[str] = []
    for ch in lowered:
        if ch in _CONFUSABLE_MAP:
            out.append(_CONFUSABLE_MAP[ch])
        elif ch.isalnum() or ch in ".-":
            out.append(ch)
    return "".join(out)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def domains_lookalike(candidate: str, canonical: str, *, max_distance: int = 2) -> bool:
    """
    True when ``candidate`` is a close visual neighbor of ``canonical`` but not equal.

    Ignores exact matches and distances above ``max_distance``.
    """
    raw_left = candidate.lower().strip()
    raw_right = canonical.lower().strip()
    if not raw_left or not raw_right or raw_left == raw_right:
        return False
    left = ascii_fold(candidate)
    right = ascii_fold(canonical)
    if left == right:
        return True
    dist = levenshtein(left, right)
    return 1 <= dist <= max_distance
