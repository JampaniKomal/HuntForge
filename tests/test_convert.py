"""Tests for the Splunk SPL and Elastic KQL translation."""

from pathlib import Path

import pytest

from huntforge.convert import UnsupportedTranslation, to_kql, to_spl
from huntforge.rule import Rule, load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES = {rule.path.stem: rule for rule in load_rules(ROOT / "rules")}


def _rule(detection: dict, logsource: dict | None = None) -> Rule:
    return Rule(
        path=Path("x.yml"),
        raw={
            "title": "t",
            "logsource": logsource or {"index": "windows", "sourcetype": "WinEventLog:Security"},
            "detection": detection,
        },
    )


def test_spl_renders_index_sourcetype_and_where_clause():
    spl = to_spl(_rule({"selection": {"EventID": 4625}, "condition": "selection"}))
    assert spl.startswith('index="windows" sourcetype="WinEventLog:Security" | where ')
    assert "EventID=4625" in spl


def test_spl_renders_contains_as_case_insensitive_like():
    spl = to_spl(_rule({"selection": {"CommandLine|contains": "delete shadows"}, "condition": "selection"}))
    assert 'like(lower(CommandLine), "%delete shadows%")' in spl


def test_spl_negation_is_preserved():
    spl = to_spl(
        _rule(
            {
                "selection": {"EventID": 4625},
                "local": {"IpAddress": "127.0.0.1"},
                "condition": "selection and not local",
            }
        )
    )
    assert "NOT" in spl and "127.0.0.1" in spl


def test_kql_renders_field_value_pairs_and_wildcards():
    kql = to_kql(_rule({"selection": {"EventID": 4104, "Image|endswith": "\\nc.exe"}, "condition": "selection"}))
    assert "EventID: 4104" in kql
    assert 'Image: "*\\nc.exe"' in kql


def test_kql_or_list_becomes_a_disjunction():
    kql = to_kql(_rule({"selection": {"eventName": ["StopLogging", "DeleteTrail"]}, "condition": "selection"}))
    assert ' or ' in kql and "StopLogging" in kql and "DeleteTrail" in kql


def test_kql_refuses_regex_instead_of_approximating_it():
    with pytest.raises(UnsupportedTranslation):
        to_kql(_rule({"selection": {"User|re": "^CORP\\\\svc_"}, "condition": "selection"}))


def test_every_shipped_rule_translates_to_splunk():
    for name, rule in RULES.items():
        assert "| where " in to_spl(rule), name


def test_every_shipped_rule_translates_to_kql():
    # No shipped rule uses the regex modifier, so all of them must render.
    for name, rule in RULES.items():
        assert to_kql(rule).strip(), name
