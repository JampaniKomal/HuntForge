"""Run every rule's ES|QL translation on a real Elasticsearch and compare with the matcher.

Every fixture event (true positives and true negatives of every rule) and every
telemetry capture is indexed once. For each rule, the set of events ES|QL
returns must equal the set the offline matcher fires on: the same hits, and
just as important, the same misses. CI starts Elasticsearch for this; locally:

    docker run -d -p 127.0.0.1:9200:9200 -e discovery.type=single-node \\
      -e xpack.security.enabled=false docker.elastic.co/elasticsearch/elasticsearch:9.1.4
    HUNTFORGE_ES_URL=http://127.0.0.1:9200 python -m pytest tests/test_elasticsearch.py

String fields are mapped as plain `keyword` (exact, case-sensitive), so any
case-insensitivity has to come from the query itself.
"""

from __future__ import annotations

import contextlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from huntforge.convert import esql_condition
from huntforge.rule import load_rules
from huntforge.testkit import fixture_and_telemetry_events

ES = os.environ.get("HUNTFORGE_ES_URL", "").rstrip("/")
pytestmark = pytest.mark.skipif(not ES, reason="set HUNTFORGE_ES_URL to run against Elasticsearch")

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules(ROOT / "rules")
INDEX = "huntforge-differential"


def _call(method: str, path: str, body=None, ndjson: str | None = None):
    data = ndjson.encode() if ndjson is not None else (json.dumps(body).encode() if body is not None else None)
    content_type = "application/x-ndjson" if ndjson is not None else "application/json"
    request = urllib.request.Request(ES + path, data=data, method=method, headers={"Content-Type": content_type})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raise AssertionError(f"{method} {path}: {exc.code} {exc.read().decode()[:500]}") from exc


@pytest.fixture(scope="module")
def indexed():
    events = fixture_and_telemetry_events(ROOT / "tests" / "fixtures", ROOT / "telemetry")
    with contextlib.suppress(AssertionError):
        _call("DELETE", f"/{INDEX}")
    _call(
        "PUT",
        f"/{INDEX}",
        {
            "mappings": {
                "date_detection": False,
                "numeric_detection": False,
                "dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}],
            }
        },
    )
    lines = []
    for number, (_, event) in enumerate(events):
        lines.append(json.dumps({"index": {"_index": INDEX, "_id": str(number)}}))
        lines.append(json.dumps(event))
    result = _call("POST", "/_bulk?refresh=true", ndjson="\n".join(lines) + "\n")
    assert not result["errors"], [i for i in result["items"] if "error" in i["index"]][:3]
    return events


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.path.stem)
def test_esql_returns_exactly_what_the_matcher_fires_on(indexed, rule):
    query = f"FROM {INDEX} METADATA _id | WHERE {esql_condition(rule)} | KEEP _id | LIMIT 10000"
    response = _call("POST", "/_query", {"query": query})
    got = {int(row[0]) for row in response["values"]}
    expected = {number for number, (_, event) in enumerate(indexed) if rule.matches(event)}
    assert expected, f"{rule.path.name} fires on nothing; the comparison would be empty"
    names = lambda ids: sorted(indexed[i][0] for i in ids)  # noqa: E731
    assert got == expected, (
        f"\nonly the matcher: {names(expected - got)}\nonly Elasticsearch: {names(got - expected)}\nquery: {query}"
    )
