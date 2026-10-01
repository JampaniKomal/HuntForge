# HuntForge

[![detection-as-code](https://github.com/JampaniKomal/HuntForge/actions/workflows/ci.yml/badge.svg)](https://github.com/JampaniKomal/HuntForge/actions/workflows/ci.yml)

Detection-as-code for threat hunting: a rule pack that is **tested like
software**, plus the engine that makes that possible.

Detection rules usually rot quietly. Someone widens a rule to catch one more
variant, a benign process starts matching, the alert queue fills with noise,
and nobody notices until an analyst stops reading that alert. HuntForge
treats every rule the way a codebase treats a function: it has a
specification (the ATT&CK technique it claims to cover), it ships with tests
(events it must fire on, and benign events it must ignore), and CI refuses
the change if either side breaks.

```
rules/*.yml ──► validate ──► test (true positives / true negatives)
                   │             │
                   │             └─► noise check against a benign baseline
                   │
                   ├─► convert ──► Splunk SPL / Kibana KQL / ES|QL
                   │                 └─► checked against a real Elasticsearch
                   │                     and Kibana's own KQL grammar
                   └─► coverage ─► ATT&CK table + Navigator layer
```

## Why it exists

Three problems, one workflow:

1. **"Does this rule actually fire?"** Every rule ships fixtures. `huntforge
   test` runs them; CI fails if a rule misses the attack it claims to detect.
2. **"How noisy is it?"** Every rule also ships benign events that must *not*
   match, and the whole pack is fired at a benign baseline capture. A rule
   that gets loosened until it matches ordinary admin activity fails CI
   before it ever reaches an analyst.
3. **"What do we actually cover?"** `huntforge coverage` regenerates an
   ATT&CK table and a Navigator layer straight from the rule tags, so
   coverage is derived from the rules rather than maintained in a slide.

And because a hunt is useless if it cannot run where the data lives, the same
rule text translates into Splunk SPL, Kibana KQL and Elasticsearch ES|QL.
CI does not just check that a query is produced: it runs the ES|QL on a real
Elasticsearch and parses the KQL with Kibana's own grammar, and both must
select exactly the events the rule selects here. See
[Translating to a SIEM](#translating-to-a-siem).

## Quickstart

```bash
git clone https://github.com/JampaniKomal/HuntForge
cd HuntForge
pip install -e .

huntforge validate                          # schema, conditions, modifiers
huntforge test                              # per-rule fixtures
huntforge noise                             # false positives vs benign baseline
huntforge hunt telemetry/windows-endpoint.ndjson
huntforge convert --target splunk           # or kql, esql
huntforge coverage
```

(`python -m huntforge ...` works too.) Hunting the bundled endpoint capture
reconstructs the whole intrusion:

```
Ran 9 rule(s) over 11 event(s) from telemetry/windows-endpoint.ndjson.

8 finding(s):

[     CRITICAL] Volume shadow copy deletion (ransomware recovery inhibition)
                ATT&CK: T1490  (event #8)
[     CRITICAL] Volume shadow copy deletion (ransomware recovery inhibition)
                ATT&CK: T1490  (event #9)
[         HIGH] Microsoft Defender real-time protection or scanning disabled
                ATT&CK: T1562.001  (event #5)
[         HIGH] Outbound connection from a known reverse-shell binary
                ATT&CK: T1571  (event #7)
[         HIGH] PowerShell script block with in-memory execution or encoded payload
                ATT&CK: T1059.001  (event #4)
[         HIGH] Windows service installed from a user-writable path
                ATT&CK: T1543.003  (event #6)
[       MEDIUM] Failed network logon for a non-existent account
                ATT&CK: T1110  (event #0)
[       MEDIUM] Failed network logon for a non-existent account
                ATT&CK: T1110  (event #1)
```

The same pack, pointed at the CloudTrail capture, recovers the cloud chain:
console login without MFA, AdministratorAccess attached to the caller, then
CloudTrail stopped to blind the account.

## The rule pack

Nine rules across endpoint, network, identity and cloud telemetry, with 47
fixture cases. See [ATTACK_COVERAGE.md](ATTACK_COVERAGE.md) (generated) for
the live table and [attack-navigator-layer.json](attack-navigator-layer.json)
for the Navigator layer.

| Rule | Telemetry | ATT&CK |
|---|---|---|
| Failed network logon for a non-existent account | Windows Security 4625 | T1110 |
| PowerShell script block with in-memory execution or encoded payload | PowerShell 4104 | T1059.001 |
| Volume shadow copy deletion | Sysmon 1 | T1490 |
| Outbound connection from a known reverse-shell binary | Sysmon 3 | T1571 |
| Defender real-time protection or scanning disabled | Sysmon 1 | T1562.001 |
| Windows service installed from a user-writable path | System 7045 / Security 4697 | T1543.003 |
| Successful AWS console login without MFA | CloudTrail | T1078.004 |
| Administrator policy attached to an IAM principal | CloudTrail | T1098.003 |
| CloudTrail logging stopped, deleted or reconfigured | CloudTrail | T1562.008 |

Rules are written in the Sigma style, so the vocabulary is the one detection
engineers already use:

```yaml
detection:
  selection:
    EventID: 4625
    LogonType: 3
    SubStatus: '0xC0000064'      # the account does not exist -> enumeration
  local_noise:
    IpAddress: ['-', '127.0.0.1', '::1']
  condition: selection and not local_noise
```

## Translating to a SIEM

`huntforge convert --target splunk|kql|esql` renders every rule from the same
parsed values the matcher uses (`huntforge/pattern.py`), with each language's
own quoting and escaping. The reverse-shell rule, for example:

```
# Splunk SPL
index="windows" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ((EventID=3 AND Initiated="true" AND (Image="*\\nc.exe" OR Image="*\\nc64.exe" OR Image="*\\ncat.exe" OR Image="*\\powercat.ps1")) AND NOT ((DestinationIp="127.*" OR DestinationIp="::1*")))

# Kibana KQL
((EventID: 3 and Initiated: true and (Image: *\\nc.exe or Image: *\\nc64.exe or Image: *\\ncat.exe or Image: *\\powercat.ps1)) and not ((DestinationIp: 127.* or DestinationIp: \:\:1*)))

# ES|QL (abridged)
FROM windows | WHERE ((COALESCE(EventID == 3, false) AND ... COALESCE(TO_LOWER(Image) LIKE """*\\nc.exe""", false) ...
```

How each translation is checked, in CI, against all 79 fixture and telemetry
events (every rule against every event, not just its own):

| Target | Check | Result |
|---|---|---|
| ES\|QL | run on Elasticsearch 9.1 ([tests/test_elasticsearch.py](tests/test_elasticsearch.py)) | 9/9 rules select exactly what the matcher selects |
| Kibana KQL | parsed with Kibana's own grammar at a pinned commit, then evaluated ([scripts/kql_check.mjs](scripts/kql_check.mjs)) | 9/9 |
| Splunk SPL | escaping and structure unit tests | not run on Splunk (no free CI image) |

**Why this matters: version 1.0's translations were wrong for most rules,**
and its tests could not tell, because they only checked that a query
contained certain text.

- Its KQL put wildcard values in quotes (`Image: "*\nc.exe"`). In KQL a
  quoted `*` is a literal asterisk, and an unescaped backslash starts an
  escape sequence (`\n` is a newline). Run through Kibana's grammar, **6 of
  the 9 rules missed the attacks in their own fixtures**, and a seventh
  (CloudTrail logging) fired on the denied attempt it exists to ignore,
  because its exclusion could never match.
- Its SPL used `where like(lower(field), ...)`, in which `_` is a wildcard,
  backslashes were not escaped, dotted field names were not quoted, and
  `NOT` over a missing field dropped the event instead of matching it.

Version 1.1 follows each language's rules: KQL wildcards unquoted with
`\():<>"*{}` and the words `or`/`and`/`not` escaped, SPL as search-command
syntax (`field="*value*"`, case-insensitive, backslashes doubled), ES|QL with
`TO_LOWER` and `LIKE` for case-insensitive matching and `COALESCE` so that a
missing field behaves as it does in the matcher.

One more thing the testing found: **Elasticsearch's own KQL parser** (the
`kql` query, which is not what Kibana uses) reads backslashes in unquoted
wildcard values differently from Kibana: `Image: *Public\\*` finds nothing
there on a document whose `Image` is `C:\Users\Public\nc.exe`. HuntForge
targets Kibana's grammar, and checks KQL with it.

## How the engine works

| Module | Job |
|---|---|
| `huntforge/pattern.py` | Sigma values as patterns: `*` and `?` wildcards, backslash escapes, the contains/startswith/endswith modifiers. Shared by the matcher and every target |
| `huntforge/matcher.py` | Field comparison: modifiers, numbers, dotted paths into nested records (CloudTrail), list-valued fields |
| `huntforge/condition.py` | Tokenizer and recursive-descent parser for `condition`, written as a fold so evaluation and query translation share one implementation |
| `huntforge/rule.py` | Schema validation and rule objects |
| `huntforge/testkit.py` | Fixture-driven rule tests and the benign-baseline noise check |
| `huntforge/convert.py` | SPL, KQL and ES\|QL rendering |
| `huntforge/coverage.py` | ATT&CK table and Navigator layer |
| `huntforge/cli.py` | The commands above, each exiting non-zero on failure so CI can gate on them |

### Fail-closed by design

The single most important property: **the engine never silently does less
than the rule says.**

- An unknown field modifier (`|base64offset`, say) raises `UnsupportedModifier`
  rather than being dropped from the comparison.
- A condition the parser does not implement exactly (`1 of them`,
  `all of selection*`, aggregations) raises `ConditionError` instead of being
  approximated.
- A search identifier the condition never references, or one it references
  but never defines, fails validation — that mismatch is how half-edited
  rules end up matching everything.
- A fixture without at least one true positive and one true negative fails:
  a rule that has never been shown to stay quiet has not been tested.
- A value a target cannot express exactly raises `UnsupportedTranslation`
  instead of emitting a looser query: regular expressions (all three targets),
  the `?` wildcard (Splunk, KQL), a literal `*` (Splunk), whitespace at the
  ends of a KQL wildcard value (Kibana trims it).

A rule that refuses to load is an annoyance. A rule that loads and means
something other than what it says is an incident nobody sees.

### Supported Sigma subset

| Feature | Supported |
|---|---|
| Field equality, case-insensitive | yes |
| `contains`, `startswith`, `endswith`, `re` | yes (`re` only in the offline engine) |
| `all` modifier (every value must match) | yes |
| Value lists as OR, field maps as AND | yes |
| `*` / `?` wildcards, also inside modifiers; `\*`, `\?`, `\\` escapes | yes, as in the Sigma specification |
| `null` (field absent) | yes |
| Dotted paths into nested JSON | yes |
| List of maps as an OR of searches | yes |
| `and` / `or` / `not` with parentheses | yes |
| `1 of them`, `all of selection*` | no — rejected |
| Aggregations (`count() > N`), correlation | no — rejected (see Limitations) |
| `base64offset`, `utf16`, `cidr` modifiers | no — rejected |

As in Sigma, a backslash only escapes `*`, `?` or another backslash, so
Windows paths need no escaping (`'\Windows\Temp\'`), and a UNC prefix is
written `'\\\\'`.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and
pull request:

1. **Python 3.10-3.13:** ruff; `huntforge validate`; `pytest` (engine,
   pattern and translation tests plus every rule's fixtures); `huntforge
   noise`; every rule converted to SPL, KQL and ES|QL with `--strict`;
   `huntforge coverage --check`.
2. **Elasticsearch:** an Elasticsearch 9.1 service container; every rule's
   ES|QL must return exactly the matcher's events.
3. **Kibana KQL:** every rule's KQL parsed with Kibana's grammar must select
   exactly the matcher's events.

A pull request that adds a rule cannot merge unless the rule is valid,
catches its attack, ignores its benign twin, stays quiet on the baseline,
translates to all three languages with the same meaning, and updates coverage.

## Adding a rule

1. Write `rules/<platform>/<name>.yml`, tagged with its ATT&CK technique and
   with `falsepositives` filled in honestly.
2. Write `tests/fixtures/<name>.yml` with at least one true positive and,
   more importantly, the benign cases that must not fire. If you cannot think
   of a benign twin, the rule is probably too broad.
3. Run `huntforge validate && python -m pytest && huntforge noise`.
4. Run `huntforge coverage` and commit the regenerated report.

## What changed in 1.1

- Correct SPL and KQL, a new ES|QL target, and CI that runs the translations
  instead of string-matching them (above).
- Values follow Sigma's wildcard and escaping rules everywhere, including
  inside `contains`/`startswith`/`endswith`. That changed one rule: the
  service rule's UNC-path value `'\\'` meant one backslash under Sigma rules
  (matching nearly every path), so it is now `'\\\\'`, with a new fixture for
  a service binary on a network share.
- Fixtures must have both a true positive and a true negative; `huntforge
  test` reports the number of cases.
- An installable package with a `huntforge` command, and ruff in CI.

## Limitations

Stated plainly, because a detection tool that oversells itself is worse than
none:

- **No aggregation or correlation.** Every rule is single-event. "Five failed
  logons in a minute" cannot be expressed; this pack leans on high-signal
  single events (a non-existent account, shadow copies being deleted)
  instead. Stateful correlation is the natural next step.
- **The telemetry in `telemetry/` is synthetic**, hand-written to match the
  real field names of Windows Security, Sysmon and CloudTrail records. It is
  shaped like production data; it is not production data.
- **Field names are not normalised.** Rules assume the field names of the
  source (`Image`, `CommandLine`, `userIdentity.type`). A real deployment
  would map these through a schema such as ECS or OCSF first.
- **KQL is case-sensitive on keyword fields.** The rules are
  case-insensitive, and so are SPL and the ES|QL rendering (it lower-cases
  both sides). A KQL query matches a keyword field case-insensitively only if
  the field is normalised to lower case; otherwise use the ES|QL output.
- **The SPL is not run against Splunk in CI**, only checked for structure and
  escaping; there is no freely usable Splunk image for CI.
- **ES|QL compares single values.** A multi-valued field (an array) is not
  matched element by element as it is here; none of the shipped rules depend
  on one.
- **The rules are experimental** (`status: experimental`) and tuned against
  a small baseline. Production use means re-tuning against real telemetry.

## Licence

MIT. See [LICENSE](LICENSE).
