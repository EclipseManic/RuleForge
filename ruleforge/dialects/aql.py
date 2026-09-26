"""QRadar AQL.

AQL is SQL-shaped, so it parses more easily than the other four dialects. What
makes it interesting is not the grammar but two facts about what an AQL query IS:

1. AN AQL SEARCH IS NOT A DEPLOYABLE DETECTION RULE.
   AQL queries the Ariel database and returns rows. A production QRadar rule is
   an object in the Custom Rules Engine: a set of TESTS plus a RESPONSE, which is
   what creates an offense, and what contributes to the magnitude computed from
   relevance, credibility and severity. Pasting an AQL search into a console does
   not deploy anything.

   So this module produces two distinct artifacts and labels which is which. The
   renderer refuses to call an AQL search deployable, because doing so is the
   single easiest way to hand an analyst something that looks finished and is not.

2. OPERATOR PRECEDENCE IS A REAL SOURCE OF BUGS IN AQL RULES.
   `A OR B AND C` parses as `A OR (B AND C)`, exactly as in SQL. Written by hand
   it very often means `(A OR B) AND C`. The rule reads plausibly, runs without
   error, and matches a different set of events than its author intended.

   This parser therefore RECORDS the actual parse tree and reports a warning when
   a mixed OR/AND appears without parentheses, because a tool that silently
   accepts the literal reading is helping the author keep a bug.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from decimal import Decimal
from typing import Any, Final

from ..engine import (
    Comparison,
    FieldExpr,
    FieldRef,
    Literal,
    Refusal,
)
from ..engine.ir import BoolOp, Call

DIALECT: Final = "qradar"
LANGUAGE: Final = "AQL"

#: `QIDNAME(qid)` and friends are QRadar functions over Ariel columns, not fields
#: an analyst can filter on directly. Recorded as function calls so the rendered
#: rule is valid AQL rather than a field reference that QRadar would reject.
ARIEL_FUNCTIONS: Final = {
    "QIDNAME": ("qid", "string"),
    "LOGSOURCENAME": ("logsourceid", "string"),
    "UTF8": (None, "string"),
    "MATCHES": (None, "regex"),
    "IFMATCHES": (None, "regex"),
    "MATCH": (None, "regex"),
}

#: Aggregates AQL offers in a SELECT list, and the RuleForge measure each maps to.
AGG_MAP: Final = {
    "COUNT": "count",
    "MIN": "min",
    "MAX": "max",
    "AVG": "avg",
    "SUM": "sum",
    "STDEV": "stddev",
}

KEYWORDS: Final = {
    "SELECT", "FROM", "WHERE", "GROUP", "BY", "HAVING", "ORDER", "LIMIT",
    "AND", "OR", "NOT", "AS", "ILIKE", "LIKE", "IN", "IS", "NULL", "DISTINCT",
    "COUNT", "MIN", "MAX", "AVG", "SUM", "STDEV", "ASC", "DESC", "LAST",
    "TRUE", "FALSE",
}

_TOKEN_RE: Final = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<string>'(?:[^']|'')*')
    | (?P<number>\d+(?:\.\d+)?)
    | (?P<ident>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*)
    | (?P<op><=|>=|<>|!=|=|<|>)
    | (?P<punct>[(),*])
    """,
    re.VERBOSE,
)


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    text: str
    position: int


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """Something the analyst should know that is not a parse error.

    `severity` is `warning` or `refusal`. A warning means the query is valid and
    will run; the warning is about what it MEANS. A refusal means the tool will
    not pretend to represent it.
    """

    code: str
    message: str
    severity: str = "warning"
    line_hint: str = ""


@dataclass
class ParsedQuery:
    select: list[tuple[str, Any]] = dc_field(default_factory=list)
    source: str = "events"
    where: Any = None
    group_by: list[str] = dc_field(default_factory=list)
    having: Any = None
    order_by: list[tuple[str, str]] = dc_field(default_factory=list)
    limit: int | None = None
    diagnostics: list[Diagnostic] = dc_field(default_factory=list)


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    position = 0
    while position < len(text):
        match = _TOKEN_RE.match(text, position)
        if match is None:
            raise Refusal(
                "AQL_UNEXPECTED_CHARACTER",
                f"cannot read the character {text[position]!r} at position {position}. "
                f"AQL has no construct here that begins with it.", "AQL")
        kind = match.lastgroup or ""
        if kind != "ws":
            tokens.append(Token(kind, match.group(), position))
        position = match.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[Token], diagnostics: list[Diagnostic]) -> None:
        self.tokens = tokens
        self.index = 0
        self.diagnostics = diagnostics

    def peek(self) -> Token | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def next(self) -> Token:
        token = self.peek()
        if token is None:
            raise Refusal("AQL_UNEXPECTED_END", "the query ended early", "AQL")
        self.index += 1
        return token

    def accept_keyword(self, word: str) -> bool:
        token = self.peek()
        if token and token.kind == "ident" and token.text.upper() == word:
            self.index += 1
            return True
        return False

    def expect_keyword(self, word: str) -> None:
        if not self.accept_keyword(word):
            token = self.peek()
            seen = token.text if token else "end of query"
            raise Refusal(
                "AQL_EXPECTED_KEYWORD",
                f"expected {word} but found {seen!r}", "AQL")

    def accept_punct(self, char: str) -> bool:
        token = self.peek()
        if token and token.kind == "punct" and token.text == char:
            self.index += 1
            return True
        return False

    # -- expressions ------------------------------------------------------

    def parse_or(self) -> Any:
        operands = [self.parse_and()]
        while self.accept_keyword("OR"):
            operands.append(self.parse_and())
        if len(operands) == 1:
            return operands[0]
        # A bare OR mixed with AND is the precedence trap. Recorded, not corrected.
        if any(isinstance(o, BoolOp) and o.op == "and" for o in operands):
            self.diagnostics.append(Diagnostic(
                "AQL_MIXED_AND_OR",
                "This WHERE clause mixes AND and OR without parentheses. AQL binds AND "
                "TIGHTER than OR, so `A OR B AND C` is evaluated as `A OR (B AND C)`. "
                "If you meant `(A OR B) AND C` the rule is currently matching a "
                "different, larger set of events than intended. Add parentheses to "
                "state which you meant.",
                "warning"))
        return BoolOp("or", tuple(operands))

    def parse_and(self) -> Any:
        operands = [self.parse_not()]
        while self.accept_keyword("AND"):
            operands.append(self.parse_not())
        if len(operands) == 1:
            return operands[0]
        return BoolOp("and", tuple(operands))

    def parse_not(self) -> Any:
        if self.accept_keyword("NOT"):
            return _Negate(self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> Any:
        if self.accept_punct("("):
            inner = self.parse_or()
            if not self.accept_punct(")"):
                raise Refusal("AQL_UNCLOSED_PAREN",
                              "a parenthesis was opened and never closed", "AQL")
            return inner
        return self.parse_comparison()

    def parse_comparison(self) -> Any:
        left = self.parse_operand()
        token = self.peek()
        if token is None:
            return left

        if token.kind == "ident" and token.text.upper() in ("ILIKE", "LIKE"):
            self.next()
            pattern = self.parse_operand()
            literal = _as_literal(pattern)
            if not isinstance(literal, str):
                raise Refusal(
                    "AQL_LIKE_NEEDS_PATTERN",
                    f"{token.text} needs a string pattern on the right, "
                    f"got {literal!r}", "AQL")
            return _Like(token.text.upper() == "ILIKE", left, literal)

        if token.kind == "op":
            self.next()
            right = self.parse_operand()
            if isinstance(right, _Like):
                raise Refusal("AQL_OPERATOR_ORDER",
                              "write the comparison operator before LIKE, not after",
                              "AQL")
            op = "!=" if token.text == "<>" else token.text
            return Comparison(op, left, right)

        if token.kind == "ident" and token.text.upper() == "IN":
            self.next()
            if not self.accept_punct("("):
                raise Refusal("AQL_IN_EXPECTED_LIST",
                              "IN needs a parenthesised list", "AQL")
            options: list[Any] = []
            while not self.accept_punct(")"):
                options.append(self.parse_operand())
                self.accept_punct(",")
            return Call("in_set", (left, Literal(tuple(options))))

        if token.kind == "ident" and token.text.upper() == "IS":
            self.next()
            negated = self.accept_keyword("NOT")
            self.expect_keyword("NULL")
            op = "is_null" if not negated else "is_not_null"
            assert isinstance(left, FieldExpr)
            return Comparison(op, left, Literal(True))

        return left

    def parse_operand(self) -> Any:
        token = self.next()
        if token.kind == "string":
            return Literal(token.text[1:-1].replace("''", "'"))
        if token.kind == "number":
            return Literal(Decimal(token.text))
        if token.kind == "ident":
            upper = token.text.upper()
            if upper in ("TRUE", "FALSE"):
                return Literal(upper == "TRUE")
            if upper == "NULL":
                return Literal(None)
            nxt = self.peek()
            if nxt and nxt.kind == "punct" and nxt.text == "(" and upper in ARIEL_FUNCTIONS:
                return self.parse_function_call(upper)
            if nxt and nxt.kind == "punct" and nxt.text == "(":
                return self.parse_function_call(upper)
            return FieldExpr(FieldRef(token.text))
        if token.kind == "punct" and token.text == "*":
            return Literal("*")
        raise Refusal("AQL_UNEXPECTED_TOKEN",
                      f"unexpected {token.text!r} in an expression", "AQL")

    def parse_function_call(self, name: str) -> Any:
        self.next()                                   # the '('
        args: list[Any] = []
        while not self.accept_punct(")"):
            args.append(self.parse_operand())
            self.accept_punct(",")
        if name in ("MATCHES", "IFMATCHES", "MATCH"):
            # AQL regex operators are PCRE. Declared as such so the engine can
            # refuse them honestly rather than evaluating them with a POSIX engine.
            return Call("matches_regex", tuple(args), dialect="pcre")
        if len(args) != 1:
            raise Refusal(
                "AQL_FUNCTION_ARITY",
                f"{name}() takes exactly 1 argument, got {len(args)}", "AQL")
        return _ArielCall(name, args[0])


@dataclass(frozen=True, slots=True)
class _Negate:
    inner: Any


@dataclass(frozen=True, slots=True)
class _Like:
    case_insensitive: bool
    left: Any
    pattern: str

    @property
    def sql_operator(self) -> str:
        return "ILIKE" if self.case_insensitive else "LIKE"


@dataclass(frozen=True, slots=True)
class _ArielCall:
    name: str
    inner: Any

    def as_expression(self) -> Any:
        target = self.inner
        if isinstance(target, FieldExpr):
            return _ArielField(self.name, target.ref)
        return _ArielField(self.name, FieldRef("payload"))


@dataclass(frozen=True, slots=True)
class _ArielField:
    """A computed Ariel column such as `QIDNAME(qid)`.

    Modelled as its own node rather than a FieldRef, because rendering it back to
    AQL requires the call syntax. Collapsing it to the bare field name would emit
    `qid`, which QRadar accepts and which means something completely different.
    """

    function: str
    ref: FieldRef

    @property
    def text(self) -> str:
        return f"{self.function}({self.ref.name})"


def _as_literal(node: Any) -> Any:
    if isinstance(node, Literal):
        return node.value
    return node


def parse_aql(text: str) -> ParsedQuery:
    """Parse AQL into a structured query, collecting diagnostics."""
    diagnostics: list[Diagnostic] = []
    tokens = tokenize(text)
    if not tokens:
        raise Refusal("AQL_EMPTY", "the query is empty", "AQL")
    parser = _Parser(tokens, diagnostics)

    parser.expect_keyword("SELECT")
    query = ParsedQuery()
    query.select = _parse_select_list(parser)
    parser.expect_keyword("FROM")
    query.source = _parse_source(parser)

    if parser.accept_keyword("WHERE"):
        query.where = parser.parse_or()
    if parser.accept_keyword("GROUP"):
        parser.expect_keyword("BY")
        query.group_by = _parse_ident_list(parser)
    if parser.accept_keyword("HAVING"):
        query.having = parser.parse_or()
    if parser.accept_keyword("ORDER"):
        parser.expect_keyword("BY")
        query.order_by = _parse_order_list(parser)
    if parser.accept_keyword("LIMIT"):
        token = parser.next()
        if token.kind != "number":
            raise Refusal("AQL_LIMIT_INVALID", "LIMIT needs a number", "AQL")
        query.limit = int(token.text)
    if parser.accept_keyword("LAST"):
        parser.next()

    leftover = parser.peek()
    if leftover is not None:
        raise Refusal(
            "AQL_TRAILING_INPUT",
            f"{leftover.text!r} is not part of the query. If this is a real clause "
            f"AQL supports that this parser does not, the query will not be "
            f"reproduced faithfully.", "AQL")

    query.diagnostics = diagnostics
    return query


def _parse_select_list(parser: _Parser) -> list[tuple[str, Any]]:
    items: list[tuple[str, Any]] = []
    while True:
        token = parser.peek()
        if token is None:
            raise Refusal("AQL_UNEXPECTED_END", "the SELECT list ended early", "AQL")

        if token.kind == "ident" and token.text.upper() in AGG_MAP and \
                parser.tokens[parser.index + 1].kind == "punct" and \
                parser.tokens[parser.index + 1].text == "(":
            function = parser.next().text.upper()
            parser.next()                                    # '('
            inner = parser.next()
            if inner.kind == "punct" and inner.text == "*":
                argument = Literal("*")
            elif inner.kind == "ident":
                argument = FieldExpr(FieldRef(inner.text))
            elif inner.kind == "ident" or inner.kind == "string":
                argument = FieldExpr(FieldRef(inner.text))
            else:
                raise Refusal("AQL_AGGREGATE_ARGUMENT",
                              f"{function}() needs a column or *", "AQL")
            if not parser.accept_punct(")"):
                raise Refusal("AQL_AGGREGATE_UNCLOSED",
                              f"{function}( was not closed", "AQL")
            alias = _take_alias(parser) or (
                f"{function.lower()}_{_plain_name(argument)}")
            items.append((alias, _Aggregate(function, argument)))
        else:
            name_token = parser.next()
            if name_token.kind == "ident":
                argument = FieldExpr(FieldRef(name_token.text))
                items.append((_take_alias(parser) or name_token.text, argument))
            elif name_token.kind == "punct" and name_token.text == "*":
                items.append(("*", Literal("*")))
            else:
                raise Refusal("AQL_SELECT_ITEM",
                              f"unexpected {name_token.text!r} in the SELECT list",
                              "AQL")

        if not parser.accept_punct(","):
            return items


@dataclass(frozen=True, slots=True)
class _Aggregate:
    function: str
    argument: Any

    @property
    def measure_name(self) -> str:
        return AGG_MAP[self.function]


def _plain_name(node: Any) -> str:
    if isinstance(node, FieldExpr):
        return node.ref.name
    if isinstance(node, Literal) and node.value == "*":
        return "all"
    return "expr"


def _take_alias(parser: _Parser) -> str | None:
    if parser.accept_keyword("AS"):
        token = parser.next()
        return token.text
    token = parser.peek()
    if token and token.kind == "ident" and token.text.upper() not in KEYWORDS:
        parser.next()
        return token.text
    return None


def _parse_source(parser: _Parser) -> str:
    token = parser.next()
    if token.kind != "ident":
        raise Refusal("AQL_SOURCE_INVALID",
                      f"expected a table name, got {token.text!r}", "AQL")
    if token.text.upper() not in ("EVENTS", "FLOWS"):
        raise Refusal(
            "AQL_SOURCE_UNKNOWN",
            f"{token.text!r} is not a table this parser knows. AQL reads EVENTS or "
            f"FLOWS; anything else is a custom table whose schema I cannot see, so "
            f"guessing at its columns would be inventing them.", "AQL")
    return token.text.lower()


def _parse_ident_list(parser: _Parser) -> list[str]:
    names: list[str] = []
    while True:
        token = parser.next()
        if token.kind != "ident":
            raise Refusal("AQL_GROUP_ITEM",
                          f"expected a column name, got {token.text!r}", "AQL")
        names.append(token.text)
        if not parser.accept_punct(","):
            return names


def _parse_order_list(parser: _Parser) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    while True:
        token = parser.next()
        if token.kind != "ident":
            raise Refusal("AQL_ORDER_ITEM",
                          f"expected a column name, got {token.text!r}", "AQL")
        direction = "asc"
        nxt = parser.peek()
        if nxt and nxt.kind == "ident" and nxt.text.upper() in ("ASC", "DESC"):
            parser.next()
            direction = nxt.text.lower()
        items.append((token.text, direction))
        if not parser.accept_punct(","):
            return items
