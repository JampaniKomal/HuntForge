"""Translate rules into Splunk SPL, Kibana KQL and Elasticsearch ES|QL.

The same rule text drives the offline matcher and the queries an analyst
pastes into a SIEM, so a hunt developed here does not have to be rewritten by
hand. Every value is rendered from the same parsed Sigma pattern the matcher
uses (`pattern.py`), with each language's own quoting and escaping rules.

Translation is fail-closed: a construct a target cannot express exactly raises
`UnsupportedTranslation` instead of emitting a query that quietly means
something else. What each target cannot express:

- **regular expressions** (``|re``), in all three: Splunk's ``regex`` command
  cannot sit inside a boolean expression, KQL has no regex operator, and
  ES|QL's RLIKE is an anchored Lucene dialect, not Python's ``re``;
- **a literal ``*``** in Splunk, whose search language has no escape for it;
- **the ``?`` single-character wildcard** in Splunk and KQL, which have none.

The semantics each target is held to are those of the matcher: matching is
case-insensitive, and a search over a field the event does not have is false
(so ``not`` of it is true). Splunk's search language and the ES|QL rendering
below behave that way. KQL matches keyword fields case-sensitively unless the
field is normalised; see the README.
"""

from __future__ import annotations

import re

from .condition import fold_condition
from .matcher import SUPPORTED_MODIFIERS, UnsupportedModifier
from .pattern import ONE, STAR, Pattern, parse
from .rule import Rule


class UnsupportedTranslation(ValueError):
    """Raised when a rule cannot be expressed exactly in the target language."""


_FIELD_RE = re.compile(r"^[A-Za-z_@][A-Za-z0-9_.@-]*$")


def _split_key(key: str) -> tuple[str, str | None, bool]:
    field, *modifiers = key.split("|")
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise UnsupportedModifier(f"field '{key}' uses unsupported modifier(s): {sorted(unknown)}")
    if not _FIELD_RE.match(field):
        raise UnsupportedTranslation(f"field name '{field}' needs quoting this translator does not do")
    values = [m for m in modifiers if m != "all"]
    if len(values) > 1:
        raise UnsupportedTranslation(f"field '{key}' combines value modifiers {values}")
    return field, (values[0] if values else None), "all" in modifiers


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _value_pattern(field: str, value, modifier: str | None) -> Pattern:
    if modifier == "re":
        raise UnsupportedTranslation(
            f"field '{field}' uses the 're' modifier, which this target cannot express exactly"
        )
    text = ("true" if value else "false") if isinstance(value, bool) else str(value)
    return parse(text, modifier)


# --- Splunk SPL (search command) -------------------------------------------
# Field values in the search command compare case-insensitively, `*` is the
# only wildcard, and inside double quotes a backslash escapes `\` and `"`.
# `NOT field="x"` also matches events without the field, which is what the
# matcher does.


def _spl_value(field: str, value, modifier: str | None) -> str:
    if value is None:
        return f"NOT {field}=*"
    if _is_number(value) and modifier is None:
        return f"{field}={value}"
    out = []
    for token in _value_pattern(field, value, modifier).tokens:
        if token is STAR:
            out.append("*")
        elif token is ONE:
            raise UnsupportedTranslation(f"field '{field}': Splunk search has no single-character wildcard")
        elif "*" in token:
            raise UnsupportedTranslation(f"field '{field}': Splunk search cannot express a literal '*'")
        else:
            out.append(token.replace("\\", "\\\\").replace('"', '\\"'))
    return f'{field}="{"".join(out)}"'


# --- Kibana KQL ---------------------------------------------------------------
# Follows Kibana's KQL grammar (kbn-es-query, grammar.peggy). A quoted value is
# an exact phrase in which `*` is literal; a wildcard only works unquoted, where
# \():<>"*{} must be escaped with a backslash, `or`/`and` between spaces and
# `not` before a space must be escaped so they are not read as operators, and
# leading or trailing whitespace is trimmed away.

_KQL_SPECIAL = re.compile(r'([\\():<>"*{}])')
_KQL_KEYWORD = re.compile(r"(?i)(?<=\s)(or|and)(?=\s)|not(?=\s)")


def _kql_unquoted(field: str, text: str) -> str:
    escaped = _KQL_SPECIAL.sub(r"\\\1", text)
    return _KQL_KEYWORD.sub(lambda m: "\\" + m.group(0), escaped)


def _kql_value(field: str, value, modifier: str | None) -> str:
    if value is None:
        return f"not {field}: *"
    if (_is_number(value) or isinstance(value, bool)) and modifier is None:
        return f"{field}: {str(value).lower()}"
    pattern = _value_pattern(field, value, modifier)
    if pattern.is_literal:
        return '{}: "{}"'.format(field, pattern.text.replace("\\", "\\\\").replace('"', '\\"'))
    out = []
    for token in pattern.tokens:
        if token is STAR:
            out.append("*")
        elif token is ONE:
            raise UnsupportedTranslation(f"field '{field}': KQL has no single-character wildcard")
        else:
            out.append(_kql_unquoted(field, token))
    rendered = "".join(out)
    if rendered != rendered.strip():
        raise UnsupportedTranslation(f"field '{field}': KQL trims whitespace at the ends of an unquoted value")
    return f"{field}: {rendered}"


# --- Elasticsearch ES|QL ---------------------------------------------------------
# Strings are compared lower-cased (TO_LOWER), so matching is case-insensitive
# whatever the field mapping. LIKE uses `*` and `?` with `\` as its escape, and a
# triple-quoted string passes backslashes through untouched. A comparison on a
# missing field is null in ES|QL, so every leaf is wrapped in COALESCE(..., false)
# to keep `not` meaning what the matcher means.


def _esql_field(field: str) -> str:
    return field if re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", field) else f"`{field}`"


def _esql_string(text: str) -> str:
    if '"""' in text or text.endswith('"'):
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return f'"""{text}"""'


def _esql_value(field: str, value, modifier: str | None) -> str:
    name = _esql_field(field)
    if value is None:
        return f"{name} IS NULL"
    if (_is_number(value) or isinstance(value, bool)) and modifier is None:
        return f"COALESCE({name} == {str(value).lower()}, false)"
    pattern = _value_pattern(field, value, modifier)
    if pattern.is_literal:
        return f"COALESCE(TO_LOWER({name}) == {_esql_string(pattern.text.lower())}, false)"
    out = []
    for token in pattern.tokens:
        if token is STAR:
            out.append("*")
        elif token is ONE:
            out.append("?")
        else:
            out.append(re.sub(r"([\\*?])", r"\\\1", token.lower()))
    return f"COALESCE(TO_LOWER({name}) LIKE {_esql_string(''.join(out))}, false)"


# --- shared rendering --------------------------------------------------------


def _render_search(search, render_value, join_and: str, join_or: str) -> str:
    if isinstance(search, list):
        parts = [_render_search(item, render_value, join_and, join_or) for item in search]
        return "(" + f" {join_or} ".join(parts) + ")"

    clauses: list[str] = []
    for key, expected in search.items():
        field, modifier, require_all = _split_key(key)
        if isinstance(expected, (list, tuple)):
            joiner = join_and if require_all else join_or
            rendered = [render_value(field, item, modifier) for item in expected]
            clauses.append("(" + f" {joiner} ".join(rendered) + ")")
        else:
            clauses.append(render_value(field, expected, modifier))
    return "(" + f" {join_and} ".join(clauses) + ")"


def _searches(rule: Rule) -> dict:
    return {k: v for k, v in rule.raw["detection"].items() if k != "condition"}


def _fold(rule: Rule, render_value, and_word: str, or_word: str, not_word: str) -> str:
    searches = _searches(rule)
    return fold_condition(
        rule.raw["detection"]["condition"],
        searches,
        leaf=lambda name: _render_search(searches[name], render_value, and_word, or_word),
        and_=lambda a, b: f"({a} {and_word} {b})",
        or_=lambda a, b: f"({a} {or_word} {b})",
        not_=lambda a: f"{not_word} {a}",
    )


def to_spl(rule: Rule) -> str:
    """Render a rule as a Splunk search."""
    expression = _fold(rule, _spl_value, "AND", "OR", "NOT")
    logsource = rule.raw.get("logsource") or {}
    scope = " ".join(
        f'{key}="{value}"'
        for key, value in (("index", logsource.get("index")), ("sourcetype", logsource.get("sourcetype")))
        if value
    )
    return f"{scope} {expression}".strip()


def to_kql(rule: Rule) -> str:
    """Render a rule as a Kibana KQL query."""
    return _fold(rule, _kql_value, "and", "or", "not")


def esql_condition(rule: Rule) -> str:
    """The ES|QL boolean expression for a rule (the part after WHERE)."""
    return _fold(rule, _esql_value, "AND", "OR", "NOT")


def to_esql(rule: Rule, index: str | None = None) -> str:
    """Render a rule as an ES|QL query over ``index`` (default: logs-*)."""
    source = index or (rule.raw.get("logsource") or {}).get("index") or "logs-*"
    return f"FROM {source} | WHERE {esql_condition(rule)}"


TARGETS = {"splunk": to_spl, "kql": to_kql, "elastic": to_kql, "esql": to_esql}


def convert(rule: Rule, target: str) -> str:
    if target not in TARGETS:
        raise UnsupportedTranslation(f"unknown target '{target}', expected one of {sorted(TARGETS)}")
    return TARGETS[target](rule)
