"""Translate rules into Splunk SPL and Elastic KQL.

The same rule text drives the offline matcher and the SIEM queries an analyst
would actually paste into Splunk or Kibana, so a hunt developed here does not
have to be rewritten by hand (and cannot drift from what CI tested).

Translation is fail-closed in both directions: a construct a target language
cannot express exactly -- a regex in KQL, for example -- raises
`UnsupportedTranslation` instead of emitting a query that quietly means
something looser than the rule.
"""

from __future__ import annotations

from .condition import fold_condition
from .matcher import SUPPORTED_MODIFIERS, UnsupportedModifier
from .rule import Rule


class UnsupportedTranslation(ValueError):
    """Raised when a rule cannot be expressed exactly in the target language."""


def _split_key(key: str) -> tuple[str, list[str]]:
    field, *modifiers = key.split("|")
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise UnsupportedModifier(f"field '{key}' uses unsupported modifier(s): {sorted(unknown)}")
    return field, modifiers


def _spl_value(field: str, value, modifier: str | None) -> str:
    if value is None:
        return f"isnull({field})"
    if modifier == "re":
        return f'match({field}, "{value}")'
    text = str(value).lower().replace('"', '\\"')
    if isinstance(value, (int, float)) and not isinstance(value, bool) and modifier is None:
        return f"{field}={value}"
    pattern = {
        "contains": f"%{text}%",
        "startswith": f"{text}%",
        "endswith": f"%{text}",
        None: text,
    }[modifier]
    return f'like(lower({field}), "{pattern}")'


def _kql_value(field: str, value, modifier: str | None) -> str:
    if value is None:
        return f"not {field}:*"
    if modifier == "re":
        raise UnsupportedTranslation(
            f"field '{field}' uses the 're' modifier, which KQL cannot express exactly"
        )
    text = str(value).replace('"', '\\"')
    rendered = {
        "contains": f"*{text}*",
        "startswith": f"{text}*",
        "endswith": f"*{text}",
        None: text,
    }[modifier]
    if isinstance(value, (int, float)) and not isinstance(value, bool) and modifier is None:
        return f"{field}: {value}"
    return f'{field}: "{rendered}"'


def _render_search(search, render_value, join_and: str, join_or: str) -> str:
    if isinstance(search, list):
        parts = [_render_search(item, render_value, join_and, join_or) for item in search]
        return "(" + f" {join_or} ".join(parts) + ")"

    clauses: list[str] = []
    for key, expected in search.items():
        field, modifiers = _split_key(key)
        require_all = "all" in modifiers
        value_modifiers = [m for m in modifiers if m != "all"]
        modifier = value_modifiers[0] if value_modifiers else None

        if isinstance(expected, (list, tuple)):
            joiner = join_and if require_all else join_or
            rendered = [render_value(field, item, modifier) for item in expected]
            clauses.append("(" + f" {joiner} ".join(rendered) + ")")
        else:
            clauses.append(render_value(field, expected, modifier))
    return "(" + f" {join_and} ".join(clauses) + ")"


def _searches(rule: Rule) -> dict:
    return {k: v for k, v in rule.raw["detection"].items() if k != "condition"}


def to_spl(rule: Rule) -> str:
    """Render a rule as a Splunk search."""
    searches = _searches(rule)
    where = fold_condition(
        rule.raw["detection"]["condition"],
        searches,
        leaf=lambda name: _render_search(searches[name], _spl_value, "AND", "OR"),
        and_=lambda a, b: f"({a} AND {b})",
        or_=lambda a, b: f"({a} OR {b})",
        not_=lambda a: f"NOT {a}",
    )
    logsource = rule.raw.get("logsource") or {}
    base = " ".join(
        f'{key}="{value}"'
        for key, value in (
            ("index", logsource.get("index", "*")),
            ("sourcetype", logsource.get("sourcetype")),
        )
        if value
    )
    return f"{base} | where {where}"


def to_kql(rule: Rule) -> str:
    """Render a rule as an Elastic KQL query."""
    searches = _searches(rule)
    return fold_condition(
        rule.raw["detection"]["condition"],
        searches,
        leaf=lambda name: _render_search(searches[name], _kql_value, "and", "or"),
        and_=lambda a, b: f"({a} and {b})",
        or_=lambda a, b: f"({a} or {b})",
        not_=lambda a: f"not {a}",
    )


TARGETS = {"splunk": to_spl, "elastic": to_kql}


def convert(rule: Rule, target: str) -> str:
    if target not in TARGETS:
        raise UnsupportedTranslation(f"unknown target '{target}', expected one of {sorted(TARGETS)}")
    return TARGETS[target](rule)
