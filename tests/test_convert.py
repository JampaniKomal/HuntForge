"""Tests for the Splunk SPL, Kibana KQL and ES|QL translation.

tests/test_elasticsearch.py runs the ES|QL output on a real Elasticsearch.
These tests pin the quoting and escaping rules of each language, which is
where translations go wrong without anyone noticing.
"""

from pathlib import Path

import pytest

from huntforge.convert import UnsupportedTranslation, esql_condition, to_esql, to_kql, to_spl
from huntforge.rule import Rule, load_rules

ROOT = Path(__file__).resolve().parent.parent
RULES = {rule.path.stem: rule for rule in load_rules(ROOT / "rules")}
BS = "\\"


def _rule(selection: dict, condition: str = "selection", **searches) -> Rule:
    return Rule(
        path=Path("x.yml"),
        raw={
            "title": "t",
            "logsource": {"index": "windows", "sourcetype": "WinEventLog:Security"},
            "detection": {"selection": selection, **searches, "condition": condition},
        },
    )


# --- Splunk ---------------------------------------------------------------


def test_spl_is_a_search_with_index_and_sourcetype():
    spl = to_spl(_rule({"EventID": 4625, "LogonType": 3}))
    assert spl == 'index="windows" sourcetype="WinEventLog:Security" (EventID=4625 AND LogonType=3)'


def test_spl_wildcards_and_backslashes():
    spl = to_spl(_rule({"Image|endswith": BS + "nc.exe", "CommandLine|contains": "delete shadows"}))
    assert 'Image="*' + BS + BS + 'nc.exe"' in spl  # a backslash is doubled inside quotes
    assert 'CommandLine="*delete shadows*"' in spl


def test_spl_escapes_quotes_and_renders_absent_fields():
    spl = to_spl(_rule({"CommandLine|contains": 'say "hi"', "errorCode": None}))
    assert 'CommandLine="*say ' + BS + '"hi' + BS + '"*"' in spl
    assert "NOT errorCode=*" in spl


def test_spl_negation_uses_not_so_absent_fields_still_count():
    spl = to_spl(_rule({"EventID": 4625}, "selection and not local", local={"IpAddress": "127.0.0.1"}))
    assert 'NOT (IpAddress="127.0.0.1")' in spl


@pytest.mark.parametrize("value", ["svc_?", "50" + BS + "*"])
def test_spl_refuses_what_splunk_search_cannot_express(value):
    with pytest.raises(UnsupportedTranslation):
        to_spl(_rule({"User": value}))


# --- KQL ---------------------------------------------------------------------


def test_kql_wildcards_are_unquoted_because_quoted_stars_are_literal():
    kql = to_kql(_rule({"EventID": 3, "Image|endswith": BS + "nc.exe"}))
    assert "EventID: 3" in kql
    assert "Image: *" + BS + BS + "nc.exe" in kql
    assert '"*' not in kql


def test_kql_exact_values_are_quoted_and_escaped():
    kql = to_kql(_rule({"Image": "C:" + BS + 'Tools\\"x".exe'}))
    assert kql == '(Image: "C:' + BS + BS + "Tools" + BS + BS + BS + '"x' + BS + '".exe")'


def test_kql_escapes_special_characters_and_keywords_in_unquoted_values():
    kql = to_kql(_rule({"ScriptBlockText|contains": ["IEX (", "script not found", "this or that"]}))
    assert "ScriptBlockText: *IEX " + BS + "(*" in kql
    assert "*script " + BS + "not found*" in kql
    assert "*this " + BS + "or that*" in kql


def test_kql_booleans_numbers_and_absent_fields():
    kql = to_kql(_rule({"Initiated": True, "errorCode": None}))
    assert "Initiated: true" in kql and "not errorCode: *" in kql


@pytest.mark.parametrize(
    "selection",
    [{"User|re": "^CORP" + BS + BS + "svc_"}, {"User": "svc_?"}, {"User|startswith": " leading space"}],
)
def test_kql_refuses_what_kql_cannot_express(selection):
    with pytest.raises(UnsupportedTranslation):
        to_kql(_rule(selection))


# --- ES|QL -------------------------------------------------------------------


def test_esql_lowercases_and_coalesces_so_matching_follows_the_matcher():
    esql = to_esql(_rule({"Image|endswith": BS + "NC.exe", "SubStatus": "0xC0000064", "EventID": 4625}))
    assert esql.startswith("FROM windows | WHERE ")
    assert 'COALESCE(TO_LOWER(Image) LIKE """*' + BS + BS + 'nc.exe""", false)' in esql
    assert 'COALESCE(TO_LOWER(SubStatus) == """0xc0000064""", false)' in esql
    assert "COALESCE(EventID == 4625, false)" in esql


def test_esql_escapes_literal_wildcards_and_keeps_single_character_ones():
    assert '"""50*"""' in esql_condition(_rule({"Size": "50" + BS + "*"}))  # literal: plain equality
    assert '"""*50' + BS + '**"""' in esql_condition(_rule({"Size|contains": "50" + BS + "*"}))
    assert '"""svc_?"""' in esql_condition(_rule({"User": "svc_?"}))
    assert "errorCode IS NULL" in esql_condition(_rule({"errorCode": None}))


# --- the shipped pack ------------------------------------------------------------


@pytest.mark.parametrize("target", [to_spl, to_kql, to_esql])
def test_every_shipped_rule_translates(target):
    for name, rule in RULES.items():
        assert target(rule).strip(), name
