"""Sigma string values as patterns, shared by the matcher and every query target.

A Sigma value is text in which ``*`` matches any run of characters and ``?``
exactly one. A backslash escapes ``*``, ``?`` or another backslash; before any
other character it is an ordinary character, so a Windows path such as
``\\Windows\\System32\\`` needs no escaping. The ``contains``, ``startswith``
and ``endswith`` modifiers add wildcards around the value, and wildcards inside
the value stay active, as in the Sigma specification.

Parsing a value once into tokens means the offline matcher and the Splunk,
KQL and ES|QL renderers all read the same thing; none of them re-interprets
the raw string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

STAR = object()  # any run of characters, including none
ONE = object()  # exactly one character


@dataclass(frozen=True)
class Pattern:
    """A parsed value: literal strings interleaved with STAR and ONE tokens."""

    tokens: tuple

    @property
    def is_literal(self) -> bool:
        return all(isinstance(t, str) for t in self.tokens)

    @property
    def text(self) -> str:
        """The literal text; only meaningful when `is_literal`."""
        return "".join(t for t in self.tokens if isinstance(t, str))

    def matches(self, text: str) -> bool:
        """Case-insensitive match of the whole text, as Sigma specifies."""
        return _compile(self.tokens).fullmatch(text) is not None


@lru_cache(maxsize=4096)
def _compile(tokens: tuple) -> re.Pattern:
    parts = []
    for token in tokens:
        if token is STAR:
            parts.append(".*")
        elif token is ONE:
            parts.append(".")
        else:
            parts.append(re.escape(token))
    return re.compile("".join(parts), re.IGNORECASE | re.DOTALL)


def _merge(tokens: list) -> tuple:
    merged: list = []
    for token in tokens:
        if isinstance(token, str) and merged and isinstance(merged[-1], str):
            merged[-1] += token
        elif token is STAR and merged and merged[-1] is STAR:
            continue
        elif token != "":
            merged.append(token)
    return tuple(merged)


@lru_cache(maxsize=4096)
def parse(value: str, modifier: str | None = None) -> Pattern:
    """Parse a Sigma value, applying a contains/startswith/endswith modifier."""
    tokens: list = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            tokens.append(value[i + 1])
            i += 2
            continue
        tokens.append(STAR if char == "*" else ONE if char == "?" else char)
        i += 1
    if modifier in ("contains", "endswith"):
        tokens.insert(0, STAR)
    if modifier in ("contains", "startswith"):
        tokens.append(STAR)
    return Pattern(_merge(tokens))
