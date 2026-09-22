"""HuntForge - detection-as-code for threat hunting.

A rule pack plus the machinery that keeps it honest: rules are plain YAML in
the Sigma style, every rule ships true-positive and true-negative fixtures,
CI refuses to merge a rule that does not fire on the attack or that fires on
the benign baseline, and the same rule text is translated into Splunk SPL and
Elastic KQL so what was tested is what an analyst runs.
"""

__version__ = "1.0.0"

from .condition import ConditionError
from .convert import UnsupportedTranslation, convert, to_kql, to_spl
from .hunt import Finding, hunt, load_events
from .matcher import UnsupportedModifier
from .rule import Rule, RuleError, load_rule, load_rules, validate

__all__ = [
    "ConditionError",
    "Finding",
    "Rule",
    "RuleError",
    "UnsupportedModifier",
    "UnsupportedTranslation",
    "__version__",
    "convert",
    "hunt",
    "load_events",
    "load_rule",
    "load_rules",
    "to_kql",
    "to_spl",
    "validate",
]
