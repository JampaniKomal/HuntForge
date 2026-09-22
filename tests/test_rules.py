"""The tests that make this repository detection-as-code rather than a rule dump.

Every rule must validate, must ship a fixture, must fire on the attack it
claims to detect, must stay quiet on the benign variants of that attack, and
must stay quiet on the benign baseline capture.
"""

from pathlib import Path

import pytest

from huntforge.rule import load_rules
from huntforge.testkit import fixture_for, noise_check, run_rule_tests

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules(ROOT / "rules")
FIXTURES = ROOT / "tests" / "fixtures"
BASELINE = ROOT / "telemetry" / "benign-baseline.ndjson"


def rule_id(rule):
    return rule.path.name


def test_rule_pack_is_not_empty():
    assert len(RULES) >= 8


@pytest.mark.parametrize("rule", RULES, ids=rule_id)
def test_rule_is_schema_valid(rule):
    assert rule.errors == [], "\n".join(rule.errors)


@pytest.mark.parametrize("rule", RULES, ids=rule_id)
def test_rule_has_fixture(rule):
    assert fixture_for(rule, FIXTURES) is not None, (
        f"{rule.path.name} has no fixture in tests/fixtures; every rule ships its own tests"
    )


@pytest.mark.parametrize("rule", RULES, ids=rule_id)
def test_rule_fires_on_true_positives_only(rule):
    result = run_rule_tests(rule, FIXTURES)
    assert result.ok, "\n".join(result.problems)


@pytest.mark.parametrize("rule", RULES, ids=rule_id)
def test_rule_declares_attack_technique(rule):
    assert rule.techniques, f"{rule.path.name} carries no ATT&CK technique tag"


def test_rule_ids_are_unique():
    ids = [rule.id for rule in RULES]
    assert len(ids) == len(set(ids))


def test_pack_is_silent_on_benign_baseline():
    hits = noise_check(RULES, BASELINE)
    assert hits == [], "\n".join(f"{rule.path.name} fired on baseline event #{i}" for rule, i in hits)
