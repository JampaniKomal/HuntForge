"""Field matching for a documented subset of the Sigma detection language.

Values are Sigma patterns (see `pattern.py`): case-insensitive, with ``*`` and
``?`` wildcards that stay active under contains/startswith/endswith.

The matcher deliberately supports a small, explicit set of field modifiers.
Anything outside that set raises `UnsupportedModifier` instead of being
silently ignored, so a rule can never look like it matched when part of its
logic was dropped.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from .pattern import parse

SUPPORTED_MODIFIERS = frozenset({"contains", "startswith", "endswith", "re", "all"})


class UnsupportedModifier(ValueError):
    """Raised when a rule uses a field modifier this engine does not implement."""


def get_field(event: dict, path: str) -> Any:
    """Look up a field, supporting dotted paths into nested objects.

    CloudTrail records nest heavily (``userIdentity.type``), Windows event
    logs are usually flat. Both are handled by the same lookup.
    """
    current: Any = event
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _compare_scalar(actual: Any, expected: Any, modifier: str | None) -> bool:
    if actual is None:
        return False

    if modifier == "re":
        return re.search(_as_text(expected), _as_text(actual), re.IGNORECASE) is not None

    # A number compares as a number, so EventID 4104 matches "4104".
    if modifier is None and isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return False

    # Everything else is a case-insensitive Sigma pattern over the text.
    return parse(_as_text(expected), modifier).matches(_as_text(actual))


def _compare(actual: Any, expected: Any, modifier: str | None) -> bool:
    """Compare one expected value against an event value.

    A list on the event side (CloudTrail resource lists, for example) matches
    if any element matches.
    """
    if isinstance(actual, list):
        return any(_compare_scalar(item, expected, modifier) for item in actual)
    return _compare_scalar(actual, expected, modifier)


def _split_key(key: str) -> tuple[str, list[str]]:
    field, *modifiers = key.split("|")
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise UnsupportedModifier(f"field '{key}' uses unsupported modifier(s): {', '.join(sorted(unknown))}")
    return field, modifiers


def match_search(search: dict, event: dict) -> bool:
    """Evaluate one Sigma search identifier (a map of field -> expected value).

    Every key must match (AND). A list of expected values is an OR, unless the
    field carries the ``|all`` modifier, in which case every value must match.
    """
    for key, expected in search.items():
        field, modifiers = _split_key(key)
        require_all = "all" in modifiers
        value_modifiers = [m for m in modifiers if m != "all"]
        modifier = value_modifiers[0] if value_modifiers else None

        actual = get_field(event, field)

        if expected is None:
            if actual is not None:
                return False
            continue

        if isinstance(expected, (list, tuple)):
            candidates: Iterable[Any] = expected
            results = (_compare(actual, item, modifier) for item in candidates)
            matched = all(results) if require_all else any(results)
        else:
            matched = _compare(actual, expected, modifier)

        if not matched:
            return False
    return True
