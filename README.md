# HuntForge

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
                   └─► convert ──► Splunk SPL  /  Elastic KQL
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
rule text translates into Splunk SPL and Elastic KQL — so what CI tested is
what the analyst pastes into the SIEM.

## Quickstart

```bash
git clone https://github.com/JampaniKomal/HuntForge
cd HuntForge
pip install -r requirements.txt

python -m huntforge validate                          # schema, conditions, modifiers
python -m huntforge test                              # per-rule fixtures
python -m huntforge noise                             # false positives vs benign baseline
python -m huntforge hunt telemetry/windows-endpoint.ndjson
python -m huntforge convert --target splunk
python -m huntforge coverage
```

Hunting the bundled endpoint capture reconstructs the whole intrusion:

```
Ran 9 rule(s) over 11 event(s) from telemetry/windows-endpoint.ndjson.

8 finding(s):

[     CRITICAL] Volume shadow copy deletion (ransomware recovery inhibition)
                ATT&CK: T1490  (event #8)
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
```

The same pack, pointed at the CloudTrail capture, recovers the cloud chain:
console login without MFA, AdministratorAccess attached to the caller, then
CloudTrail stopped to blind the account.

## The rule pack

Nine rules across endpoint, network, identity and cloud telemetry. See
[ATTACK_COVERAGE.md](ATTACK_COVERAGE.md) (generated) for the live table and
[attack-navigator-layer.json](attack-navigator-layer.json) for the Navigator
layer.

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

## How the engine works

| Module | Job |
|---|---|
| `huntforge/matcher.py` | Field comparison: modifiers, wildcards, dotted paths into nested records (CloudTrail), list-valued fields |
| `huntforge/condition.py` | Tokenizer and recursive-descent parser for `condition`, written as a fold so evaluation and query translation share one implementation |
| `huntforge/rule.py` | Schema validation and rule objects |
| `huntforge/testkit.py` | Fixture-driven rule tests and the benign-baseline noise check |
| `huntforge/convert.py` | SPL and KQL rendering |
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
- KQL has no regex operator, so a rule using `|re` refuses to translate to
  Elastic instead of emitting a looser query that would quietly mean
  something else.

A rule that refuses to load is an annoyance. A rule that loads and means
something other than what it says is an incident nobody sees.

### Supported Sigma subset

| Feature | Supported |
|---|---|
| Field equality, case-insensitive | yes |
| `contains`, `startswith`, `endswith`, `re` | yes |
| `all` modifier (every value must match) | yes |
| Value lists as OR, field maps as AND | yes |
| `*` / `?` wildcards (anchored) | yes |
| `null` (field absent) | yes |
| Dotted paths into nested JSON | yes |
| List of maps as an OR of searches | yes |
| `and` / `or` / `not` with parentheses | yes |
| `1 of them`, `all of selection*` | no — rejected |
| Aggregations (`count() > N`), correlation | no — rejected (see Limitations) |
| `base64offset`, `utf16`, `cidr` modifiers | no — rejected |

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and
pull request, across Python 3.10-3.13:

1. `huntforge validate` — schema, conditions, modifiers
2. `pytest` — engine unit tests plus every rule's fixtures
3. `huntforge noise` — the pack must stay silent on the benign baseline
4. `huntforge convert --target splunk --strict` and `--target elastic`
5. `huntforge coverage --check` — fails if the committed ATT&CK report is stale

That is the whole point: a pull request that adds a rule cannot merge unless
the rule is valid, catches its attack, ignores its benign twin, translates to
both SIEMs, and updates coverage.

## Adding a rule

1. Write `rules/<platform>/<name>.yml`, tagged with its ATT&CK technique and
   with `falsepositives` filled in honestly.
2. Write `tests/fixtures/<name>.yml` with at least one true positive and,
   more importantly, the benign cases that must not fire. If you cannot think
   of a benign twin, the rule is probably too broad.
3. Run `python -m huntforge validate && python -m pytest && python -m huntforge noise`.
4. Run `python -m huntforge coverage` and commit the regenerated report.

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
- **SPL and KQL translation covers the supported subset only**, and refuses
  anything it cannot express exactly.
- **The rules are experimental** (`status: experimental`) and tuned against
  a small baseline. Production use means re-tuning against real telemetry.

## Licence

MIT. See [LICENSE](LICENSE).
