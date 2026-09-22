"""Parser for the Sigma ``condition`` expressions this engine supports.

Supported grammar:

    expression := term (("and" | "or") term)*
    term       := ["not"] factor
    factor     := identifier | "(" expression ")"

Anything else -- ``1 of them``, ``all of selection*``, aggregations, near
correlation -- raises `ConditionError` rather than being approximated. A rule
that silently means something other than what it says is worse than a rule
that refuses to load.

The parser is written as a fold, so the same expression can be evaluated
against an event (`evaluate_condition`) or rendered into another query
language (`fold_condition`, used by `convert.py`) without the two
implementations drifting apart.
"""

from __future__ import annotations

import re
from typing import Callable, TypeVar

TOKEN_RE = re.compile(r"\(|\)|\b(?:and|or|not)\b|[A-Za-z_][A-Za-z0-9_]*")
KEYWORDS = ("and", "or", "not", "(", ")")

T = TypeVar("T")


class ConditionError(ValueError):
    """Raised for a condition this engine cannot handle exactly."""


def tokenize(condition: str) -> list[str]:
    tokens = TOKEN_RE.findall(condition)
    if "".join(condition.split()) != "".join("".join(tokens).split()):
        raise ConditionError(f"unsupported syntax in condition: {condition!r}")
    if not tokens:
        raise ConditionError("empty condition")
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], searches: dict) -> None:
        self.tokens = tokens
        self.pos = 0
        self.searches = searches

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> str:
        token = self.peek()
        if token is None:
            raise ConditionError("unexpected end of condition")
        self.pos += 1
        return token

    def parse(self, leaf, and_, or_, not_):
        value = self.expression(leaf, and_, or_, not_)
        if self.peek() is not None:
            raise ConditionError(f"trailing tokens in condition: {self.tokens[self.pos:]}")
        return value

    def expression(self, leaf, and_, or_, not_):
        value = self.term(leaf, and_, or_, not_)
        while self.peek() in ("and", "or"):
            operator = self.next()
            right = self.term(leaf, and_, or_, not_)
            value = and_(value, right) if operator == "and" else or_(value, right)
        return value

    def term(self, leaf, and_, or_, not_):
        if self.peek() == "not":
            self.next()
            return not_(self.term(leaf, and_, or_, not_))
        return self.factor(leaf, and_, or_, not_)

    def factor(self, leaf, and_, or_, not_):
        token = self.next()
        if token == "(":
            value = self.expression(leaf, and_, or_, not_)
            if self.next() != ")":
                raise ConditionError("unbalanced parentheses in condition")
            return value
        if token in KEYWORDS:
            raise ConditionError(f"unexpected token '{token}' in condition")
        if token not in self.searches:
            raise ConditionError(f"condition references undefined search identifier '{token}'")
        return leaf(token)


def fold_condition(
    condition: str,
    searches: dict,
    leaf: Callable[[str], T],
    and_: Callable[[T, T], T],
    or_: Callable[[T, T], T],
    not_: Callable[[T], T],
) -> T:
    """Fold a condition into any target type (bool, query string, ...)."""
    return _Parser(tokenize(condition), searches).parse(leaf, and_, or_, not_)


def evaluate_condition(condition: str, searches: dict, evaluate: Callable[[str], bool]) -> bool:
    """Evaluate ``condition`` where ``evaluate(identifier)`` returns a bool."""
    return fold_condition(
        condition,
        searches,
        leaf=evaluate,
        and_=lambda a, b: a and b,
        or_=lambda a, b: a or b,
        not_=lambda a: not a,
    )


def referenced_identifiers(condition: str) -> set[str]:
    """Identifiers a condition mentions, used to catch unused/undefined searches."""
    return {t for t in tokenize(condition) if t not in KEYWORDS}
