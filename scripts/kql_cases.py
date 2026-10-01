"""Write every rule's KQL, the test events and the matcher's verdicts as JSON.

Input for scripts/kql_check.mjs, which parses the KQL with Kibana's grammar.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from huntforge.convert import to_kql  # noqa: E402
from huntforge.rule import load_rules  # noqa: E402
from huntforge.testkit import fixture_and_telemetry_events  # noqa: E402

events = fixture_and_telemetry_events(ROOT / "tests" / "fixtures", ROOT / "telemetry")
rules = [
    {
        "name": rule.path.stem,
        "kql": to_kql(rule),
        "expected": [i for i, (_, event) in enumerate(events) if rule.matches(event)],
    }
    for rule in load_rules(ROOT / "rules")
]
json.dump({"rules": rules, "events": [{"name": n, "event": e} for n, e in events]}, sys.stdout, indent=1)
