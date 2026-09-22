"""Rule loading and schema validation.

Validation is fail-closed: a rule that is missing a required field, carries a
malformed ATT&CK tag, or uses a condition the engine cannot evaluate exactly
is rejected at load time, which is what makes CI meaningful.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .condition import ConditionError, evaluate_condition, referenced_identifiers
from .matcher import UnsupportedModifier, match_search

REQUIRED_FIELDS = ("title", "id", "status", "description", "author", "date", "logsource", "detection", "level")
VALID_LEVELS = ("informational", "low", "medium", "high", "critical")
VALID_STATUS = ("experimental", "test", "stable", "deprecated")
ATTACK_TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
ATTACK_TACTIC_RE = re.compile(r"^attack\.[a-z0-9_\-]+$")
DATE_RE = re.compile(r"^\d{4}/\d{2}/\d{2}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class RuleError(ValueError):
    """Raised when a rule file does not satisfy the schema."""


@dataclass
class Rule:
    path: Path
    raw: dict
    errors: list[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        return self.raw.get("title", self.path.stem)

    @property
    def id(self) -> str:
        return self.raw.get("id", "")

    @property
    def level(self) -> str:
        return self.raw.get("level", "")

    @property
    def product(self) -> str:
        return (self.raw.get("logsource") or {}).get("product", "")

    @property
    def techniques(self) -> list[str]:
        tags = self.raw.get("tags") or []
        return sorted({t.split(".", 1)[1].upper() for t in tags if ATTACK_TECHNIQUE_RE.match(t)})

    def matches(self, event: dict) -> bool:
        """True when ``event`` satisfies this rule's detection logic."""
        detection = self.raw["detection"]
        searches = {k: v for k, v in detection.items() if k != "condition"}
        return evaluate_condition(
            detection["condition"],
            searches,
            lambda name: _match_identifier(searches[name], event),
        )


def _match_identifier(search: Any, event: dict) -> bool:
    # A search identifier is either a map of field -> value, or a list of such
    # maps, which Sigma treats as an OR.
    if isinstance(search, list):
        return any(match_search(item, event) for item in search)
    return match_search(search, event)


def validate(raw: dict, path: Path) -> list[str]:
    """Return a list of schema problems; empty means the rule is valid."""
    problems: list[str] = []

    if not isinstance(raw, dict):
        return [f"{path.name}: rule is not a YAML mapping"]

    for key in REQUIRED_FIELDS:
        if key not in raw:
            problems.append(f"{path.name}: missing required field '{key}'")

    if "id" in raw and not UUID_RE.match(str(raw["id"])):
        problems.append(f"{path.name}: id '{raw['id']}' is not a UUID")
    if "date" in raw and not DATE_RE.match(str(raw["date"])):
        problems.append(f"{path.name}: date '{raw['date']}' is not YYYY/MM/DD")
    if "level" in raw and raw["level"] not in VALID_LEVELS:
        problems.append(f"{path.name}: level '{raw['level']}' not in {VALID_LEVELS}")
    if "status" in raw and raw["status"] not in VALID_STATUS:
        problems.append(f"{path.name}: status '{raw['status']}' not in {VALID_STATUS}")

    tags = raw.get("tags") or []
    if not any(ATTACK_TECHNIQUE_RE.match(t) for t in tags):
        problems.append(f"{path.name}: no ATT&CK technique tag (expected e.g. 'attack.t1110')")
    for tag in tags:
        if not (ATTACK_TECHNIQUE_RE.match(tag) or ATTACK_TACTIC_RE.match(tag)):
            problems.append(f"{path.name}: malformed tag '{tag}'")

    if not raw.get("falsepositives"):
        problems.append(f"{path.name}: falsepositives must be documented")

    detection = raw.get("detection")
    if not isinstance(detection, dict):
        problems.append(f"{path.name}: detection block missing or not a mapping")
        return problems

    condition = detection.get("condition")
    if not isinstance(condition, str):
        problems.append(f"{path.name}: detection.condition missing or not a string")
        return problems

    searches = {k: v for k, v in detection.items() if k != "condition"}
    if not searches:
        problems.append(f"{path.name}: detection block defines no search identifiers")
        return problems

    try:
        referenced = referenced_identifiers(condition)
    except ConditionError as exc:
        problems.append(f"{path.name}: {exc}")
        return problems

    for name in referenced - set(searches):
        problems.append(f"{path.name}: condition references undefined identifier '{name}'")
    for name in set(searches) - referenced:
        problems.append(f"{path.name}: search identifier '{name}' is never used by the condition")

    # Modifiers are checked by running the rule against an empty event: any
    # unsupported modifier raises before it can be silently ignored in production.
    try:
        Rule(path=path, raw=raw).matches({})
    except (UnsupportedModifier, ConditionError) as exc:
        problems.append(f"{path.name}: {exc}")

    return problems


def load_rule(path: Path) -> Rule:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    rule = Rule(path=path, raw=raw if isinstance(raw, dict) else {})
    rule.errors = validate(raw, path)
    return rule


def load_rules(directory: Path) -> list[Rule]:
    paths = sorted(p for p in Path(directory).rglob("*.yml"))
    if not paths:
        raise RuleError(f"no rules found under {directory}")
    return [load_rule(p) for p in paths]
