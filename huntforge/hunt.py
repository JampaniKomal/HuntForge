"""Run a rule pack over telemetry and report findings.

Events are read from newline-delimited JSON (one event per line) or from a
JSON array, which covers both the way SIEMs export search results and the way
AWS hands back CloudTrail records.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .rule import Rule


@dataclass
class Finding:
    rule_id: str
    title: str
    level: str
    techniques: list[str]
    event_index: int
    event: dict

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "level": self.level,
            "techniques": self.techniques,
            "event_index": self.event_index,
            "event": self.event,
        }


def load_events(path: Path) -> list[dict]:
    """Read events from NDJSON or a JSON array, skipping blank lines."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text.startswith("["):
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError(f"{path}: expected a JSON array of events")
        return data
    events = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: line {number} is not valid JSON: {exc}") from exc
    return events


def hunt(rules: list[Rule], events: list[dict]) -> Iterator[Finding]:
    """Yield a finding for every (rule, event) pair that matches."""
    for index, event in enumerate(events):
        for rule in rules:
            if rule.matches(event):
                yield Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    level=rule.level,
                    techniques=rule.techniques,
                    event_index=index,
                    event=event,
                )


LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def format_findings(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    ordered = sorted(findings, key=lambda f: (LEVEL_ORDER.get(f.level, 9), f.title))
    lines = [f"{len(ordered)} finding(s):", ""]
    for finding in ordered:
        techniques = ", ".join(finding.techniques) or "-"
        lines.append(f"[{finding.level.upper():>13}] {finding.title}")
        lines.append(f"{'':16}ATT&CK: {techniques}  (event #{finding.event_index})")
    return "\n".join(lines)
