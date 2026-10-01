"""Fixture-driven tests for detection rules.

Every rule ships with a fixture file holding events it must fire on
(``true_positives``) and events it must stay quiet on (``true_negatives``).
Those negatives are where false-positive tuning lives: when a rule is
loosened, the negative that documents the benign case fails first.

On top of that, `noise_check` runs the whole pack against a benign baseline
capture. Any hit there is a false positive by definition, and CI fails.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .hunt import load_events
from .rule import Rule


@dataclass
class RuleTestResult:
    rule: Rule
    missed: list[str] = field(default_factory=list)  # true positives that did not fire
    false_alarms: list[str] = field(default_factory=list)  # true negatives that fired
    fixture_path: Path | None = None
    cases: int = 0

    @property
    def ok(self) -> bool:
        return not self.missed and not self.false_alarms and self.fixture_path is not None

    @property
    def problems(self) -> list[str]:
        if self.fixture_path is None:
            return [f"{self.rule.path.name}: no fixture file (every rule must ship tests)"]
        return [f"{self.rule.path.name}: missed true positive '{name}'" for name in self.missed] + [
            f"{self.rule.path.name}: fired on true negative '{name}'" for name in self.false_alarms
        ]


def fixture_for(rule: Rule, fixtures_dir: Path) -> Path | None:
    candidate = Path(fixtures_dir) / f"{rule.path.stem}.yml"
    return candidate if candidate.exists() else None


def run_rule_tests(rule: Rule, fixtures_dir: Path) -> RuleTestResult:
    path = fixture_for(rule, fixtures_dir)
    result = RuleTestResult(rule=rule, fixture_path=path)
    if path is None:
        return result

    fixture = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    positives = fixture.get("true_positives") or []
    negatives = fixture.get("true_negatives") or []
    result.cases = len(positives) + len(negatives)
    if not positives or not negatives:
        # A rule with no true negative has never been shown to stay quiet on anything.
        result.missed.append("(fixture needs at least one true positive and one true negative)")
    for case in positives:
        if not rule.matches(case["event"]):
            result.missed.append(case.get("name", "unnamed"))
    for case in negatives:
        if rule.matches(case["event"]):
            result.false_alarms.append(case.get("name", "unnamed"))
    return result


def run_all(rules: list[Rule], fixtures_dir: Path) -> list[RuleTestResult]:
    return [run_rule_tests(rule, fixtures_dir) for rule in rules]


def fixture_and_telemetry_events(fixtures_dir: Path, telemetry_dir: Path) -> list[tuple[str, dict]]:
    """Every fixture event and every telemetry event, named, for whole-pack comparisons."""
    events = []
    for path in sorted(Path(fixtures_dir).glob("*.yml")):
        fixture = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for kind in ("true_positives", "true_negatives"):
            for case in fixture.get(kind) or []:
                events.append((f"{path.stem} / {kind} / {case.get('name', 'unnamed')}", case["event"]))
    for path in sorted(Path(telemetry_dir).glob("*.ndjson")):
        events += [(f"{path.name} #{i}", event) for i, event in enumerate(load_events(path))]
    return events


def noise_check(rules: list[Rule], baseline_path: Path) -> list[tuple[Rule, int]]:
    """Return (rule, event index) pairs that fired on benign baseline telemetry."""
    events = load_events(Path(baseline_path))
    hits: list[tuple[Rule, int]] = []
    for index, event in enumerate(events):
        for rule in rules:
            if rule.matches(event):
                hits.append((rule, index))
    return hits
