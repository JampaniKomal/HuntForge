"""Unit tests for the matching engine and the condition parser."""

from pathlib import Path

import pytest

from huntforge.condition import ConditionError, evaluate_condition, referenced_identifiers
from huntforge.matcher import UnsupportedModifier, get_field, match_search
from huntforge.rule import Rule, validate


def test_plain_equality_is_case_insensitive():
    assert match_search({"Image": "C:\\Windows\\System32\\CMD.EXE"}, {"Image": "c:\\windows\\system32\\cmd.exe"})


def test_numeric_and_string_event_ids_compare_equal():
    assert match_search({"EventID": 4104}, {"EventID": "4104"})
    assert match_search({"EventID": "4104"}, {"EventID": 4104})


def test_list_of_values_is_an_or():
    search = {"eventName": ["StopLogging", "DeleteTrail"]}
    assert match_search(search, {"eventName": "DeleteTrail"})
    assert not match_search(search, {"eventName": "DescribeTrails"})


def test_all_modifier_requires_every_value():
    search = {"CommandLine|contains|all": ["Set-MpPreference", "DisableRealtimeMonitoring"]}
    assert match_search(search, {"CommandLine": "powershell Set-MpPreference -DisableRealtimeMonitoring $true"})
    assert not match_search(search, {"CommandLine": "powershell Set-MpPreference -ScanScheduleDay 3"})


def test_startswith_endswith_and_regex():
    assert match_search({"DestinationIp|startswith": "127."}, {"DestinationIp": "127.0.0.1"})
    assert match_search({"Image|endswith": "\\nc.exe"}, {"Image": "C:\\Tools\\nc.exe"})
    assert match_search({"User|re": "^CORP\\\\svc_"}, {"User": "CORP\\svc_deploy"})


def test_wildcards_are_anchored():
    assert match_search({"TargetUserName": "svc_*"}, {"TargetUserName": "svc_backup1"})
    assert not match_search({"TargetUserName": "svc_*"}, {"TargetUserName": "adminsvc_backup"})


def test_missing_field_never_matches_and_null_means_absent():
    assert not match_search({"Image": "cmd.exe"}, {"EventID": 1})
    assert match_search({"errorCode": None}, {"eventName": "StopLogging"})
    assert not match_search({"errorCode": None}, {"errorCode": "AccessDenied"})


def test_dotted_paths_reach_into_nested_records():
    event = {"userIdentity": {"type": "IAMUser"}, "additionalEventData": {"MFAUsed": "No"}}
    assert get_field(event, "userIdentity.type") == "IAMUser"
    assert get_field(event, "userIdentity.missing.deeper") is None
    assert match_search({"additionalEventData.MFAUsed": "No"}, event)


def test_list_valued_event_field_matches_on_any_element():
    assert match_search({"Tags|contains": "prod"}, {"Tags": ["dev", "prod-eu"]})


def test_unsupported_modifier_is_rejected_not_ignored():
    with pytest.raises(UnsupportedModifier):
        match_search({"CommandLine|base64offset": "x"}, {"CommandLine": "x"})


def test_condition_operator_precedence_and_parentheses():
    searches = {"a": {}, "b": {}, "c": {}}
    values = {"a": True, "b": False, "c": True}
    evaluate = values.__getitem__
    assert evaluate_condition("a and not b", searches, evaluate) is True
    assert evaluate_condition("a and b or c", searches, evaluate) is True
    assert evaluate_condition("a and (b or c)", searches, evaluate) is True
    assert evaluate_condition("a and (b or not c)", searches, evaluate) is False


def test_unsupported_condition_syntax_raises():
    for condition in ["1 of them", "all of selection*", "selection | count() > 5"]:
        with pytest.raises(ConditionError):
            evaluate_condition(condition, {"selection": {}}, lambda name: True)


def test_condition_referencing_unknown_identifier_raises():
    with pytest.raises(ConditionError):
        evaluate_condition("selection and not filter", {"selection": {}}, lambda name: True)


def test_referenced_identifiers_ignores_keywords():
    assert referenced_identifiers("selection and not filter_local") == {"selection", "filter_local"}


def _minimal_rule(**overrides) -> dict:
    rule = {
        "title": "t",
        "id": "7f3a1c9e-2b4d-4a61-9e08-5c7d2f1b8a34",
        "status": "experimental",
        "description": "d",
        "author": "a",
        "date": "2026/09/22",
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {"product": "windows"},
        "detection": {"selection": {"EventID": 1}, "condition": "selection"},
        "falsepositives": ["none known"],
        "level": "high",
    }
    rule.update(overrides)
    return rule


def test_validator_accepts_a_well_formed_rule():
    assert validate(_minimal_rule(), Path("x.yml")) == []


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"level": "urgent"}, "level"),
        ({"id": "not-a-uuid"}, "UUID"),
        ({"date": "22-09-2026"}, "YYYY/MM/DD"),
        ({"tags": ["attack.execution"]}, "ATT&CK technique tag"),
        ({"falsepositives": []}, "falsepositives"),
        ({"detection": {"selection": {"EventID": 1}, "condition": "selection and filter"}}, "undefined identifier"),
        ({"detection": {"selection": {"EventID": 1}, "extra": {"x": 1}, "condition": "selection"}}, "never used"),
        ({"detection": {"selection": {"a|nope": 1}, "condition": "selection"}}, "unsupported modifier"),
    ],
)
def test_validator_rejects_broken_rules(overrides, expected):
    problems = validate(_minimal_rule(**overrides), Path("x.yml"))
    assert any(expected in problem for problem in problems), problems


def test_rule_exposes_normalised_attack_techniques():
    rule = Rule(path=Path("x.yml"), raw=_minimal_rule(tags=["attack.execution", "attack.t1059.001", "attack.t1490"]))
    assert rule.techniques == ["T1059.001", "T1490"]
