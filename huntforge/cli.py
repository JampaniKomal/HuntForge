"""HuntForge command line interface.

    python -m huntforge validate                    # schema + condition + modifier checks
    python -m huntforge test                        # per-rule true positive / true negative fixtures
    python -m huntforge noise                       # fire the pack at benign telemetry, expect silence
    python -m huntforge hunt telemetry/sysmon.ndjson
    python -m huntforge convert --target splunk
    python -m huntforge coverage [--check]          # ATT&CK coverage report, --check fails if stale

Every command exits non-zero on failure so CI can gate a pull request on it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .convert import TARGETS, UnsupportedTranslation, convert
from .coverage import markdown_table, navigator_layer, write_reports
from .hunt import format_findings, hunt, load_events
from .rule import load_rules
from .testkit import noise_check, run_all

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES = ROOT / "rules"
DEFAULT_FIXTURES = ROOT / "tests" / "fixtures"
DEFAULT_BASELINE = ROOT / "telemetry" / "benign-baseline.ndjson"
COVERAGE_MD = ROOT / "ATTACK_COVERAGE.md"
COVERAGE_LAYER = ROOT / "attack-navigator-layer.json"


def _load(rules_dir: Path, require_valid: bool = True):
    rules = load_rules(rules_dir)
    invalid = [problem for rule in rules for problem in rule.errors]
    if invalid and require_valid:
        print("Rule validation failed:", file=sys.stderr)
        for problem in invalid:
            print(f"  - {problem}", file=sys.stderr)
        sys.exit(1)
    return rules


def cmd_validate(args) -> int:
    rules = load_rules(args.rules)
    problems = [problem for rule in rules for problem in rule.errors]
    for problem in problems:
        print(f"  - {problem}")
    if problems:
        print(f"\n{len(problems)} problem(s) across {len(rules)} rule(s).")
        return 1
    print(f"{len(rules)} rule(s) valid.")
    return 0


def cmd_test(args) -> int:
    rules = _load(args.rules)
    results = run_all(rules, args.fixtures)
    problems = [problem for result in results for problem in result.problems]
    cases = sum(
        len(result.missed) + len(result.false_alarms) for result in results
    )
    for problem in problems:
        print(f"  - {problem}")
    if problems:
        print(f"\n{len(problems)} failing check(s) across {len(rules)} rule(s).")
        return 1
    print(f"{len(rules)} rule(s) passed their fixtures ({cases} failure(s)).")
    return 0


def cmd_noise(args) -> int:
    rules = _load(args.rules)
    hits = noise_check(rules, args.baseline)
    if hits:
        print("False positives against benign baseline telemetry:")
        for rule, index in hits:
            print(f"  - {rule.path.name} fired on baseline event #{index}")
        return 1
    print(f"{len(rules)} rule(s) stayed silent on the benign baseline.")
    return 0


def cmd_hunt(args) -> int:
    rules = _load(args.rules)
    events = load_events(args.events)
    findings = list(hunt(rules, events))
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print(f"Ran {len(rules)} rule(s) over {len(events)} event(s) from {args.events}.\n")
        print(format_findings(findings))
    return 0


def cmd_convert(args) -> int:
    rules = _load(args.rules)
    failures = 0
    for rule in rules:
        print(f"# {rule.title}  [{rule.path.name}]")
        try:
            print(convert(rule, args.target))
        except UnsupportedTranslation as exc:
            failures += 1
            print(f"# not translatable to {args.target}: {exc}")
        print()
    return 1 if (failures and args.strict) else 0


def cmd_coverage(args) -> int:
    rules = _load(args.rules)
    if args.check:
        expected_md = COVERAGE_MD.read_text(encoding="utf-8") if COVERAGE_MD.exists() else ""
        expected_layer = COVERAGE_LAYER.read_text(encoding="utf-8") if COVERAGE_LAYER.exists() else ""
        current_md = markdown_table(rules)
        stale = current_md.strip() not in expected_md or json.dumps(
            navigator_layer(rules), indent=2
        ).strip() not in expected_layer
        if stale:
            print("ATT&CK coverage report is stale; run: python -m huntforge coverage", file=sys.stderr)
            return 1
        print("ATT&CK coverage report is up to date.")
        return 0
    write_reports(rules, COVERAGE_MD, COVERAGE_LAYER)
    print(markdown_table(rules))
    print(f"\nWrote {COVERAGE_MD.name} and {COVERAGE_LAYER.name}.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="huntforge", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"HuntForge {__version__}")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="rule directory")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="validate every rule against the schema").set_defaults(func=cmd_validate)

    test = sub.add_parser("test", help="run each rule's true positive / true negative fixtures")
    test.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    test.set_defaults(func=cmd_test)

    noise = sub.add_parser("noise", help="check the pack against benign baseline telemetry")
    noise.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    noise.set_defaults(func=cmd_noise)

    hunt_cmd = sub.add_parser("hunt", help="run the pack over a telemetry file")
    hunt_cmd.add_argument("events", type=Path)
    hunt_cmd.add_argument("--json", action="store_true", help="emit findings as JSON")
    hunt_cmd.set_defaults(func=cmd_hunt)

    convert_cmd = sub.add_parser("convert", help="translate rules to a SIEM query language")
    convert_cmd.add_argument("--target", choices=sorted(TARGETS), default="splunk")
    convert_cmd.add_argument("--strict", action="store_true", help="fail if any rule cannot be translated")
    convert_cmd.set_defaults(func=cmd_convert)

    coverage_cmd = sub.add_parser("coverage", help="regenerate the ATT&CK coverage report")
    coverage_cmd.add_argument("--check", action="store_true", help="fail if the committed report is stale")
    coverage_cmd.set_defaults(func=cmd_coverage)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
