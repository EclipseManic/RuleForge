"""Microsoft Sentinel KQL.

KQL is a PIPELINE language, not a row language. `let` binds a table to a name and
every subsequent `|` transforms it. So the lowering walks the pipes in order and
emits one node per stage, with `let` bindings becoming branches that a later
`join` splices together. That is not a convenience -- it is the shape the
language has, and flattening it into "one table with conditions" would lose the
correlation the rule is actually about.

VERIFIED SEMANTICS (Microsoft Learn, not inferred):

  * A scheduled analytics rule is a KQL query plus a schedule plus a LOOKBACK
    period. The query runs at an interval and examines the lookback window.
  * Scheduled rules run on a FIVE-MINUTE INGESTION DELAY from their scheduled
    time, to account for latency between a source generating an event and the
    event arriving. This is not a cosmetic detail: `ago(30m)` inside the query
    does not cover the window the operator thinks it does, because the run
    happens five minutes later than the schedule.
  * The rule alerts when the result count passes a configured threshold.
  * `join kind=inner ... on a, b` is an inner join on the named columns.
  * `summarize agg(...) by a, b` aggregates and groups.

THE ONE PLACE THIS FILE REFUSES TO BE CLEVER

    | where LoginTime between (LSASSTime .. LSASSTime + 10m)

After a join, `LSASSTime` and `LoginTime` are columns of the SAME merged row. So
this is a same-row comparison, NOT a join-level temporal predicate, and it is
expanded into two ordinary comparisons conjoined. Two consequences, both
deliberate:

  * It is representable without a new node. `a between (x .. y)` is exactly
    `a >= x and a <= y`.
  * The engine's `Join.temporal` must NOT also be applied. Applying both would
    constrain the window twice, and the second constraint would be invisible in
    the rendered rule -- the analyst would see one `where` and get a join that
    was also filtering. So the join carries no temporal predicate and the rule's
    own `where` does the work, exactly as written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from typing import Final

from ..dialects.aql import Diagnostic
from ..engine import Refusal

DIALECT: Final = "sentinel"
LANGUAGE: Final = "KQL"

#: Scheduled analytics rules run this late, to absorb source-to-platform latency.
INGESTION_DELAY_SECONDS: Final = 300

_TOKEN_RE: Final = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<string>"(?:[^"]|"")*")
    | (?P<number>\d+(?:\.\d+)?)
    | (?P<timespan>\d+[smhd])
    | (?P<ident>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*)
    | (?P<op><=|>=|<>|!=|==|=|<|>)
    | (?P<punct>[(),*|@])
    """,
    re.VERBOSE,
)

#: Operators that take a table as their source and produce a new table.
PIPE_OPERATORS: Final = frozenset({
    "where", "project", "extend", "summarize", "join", "sort", "top",
    "distinct", "count", "take", "limit", "order",
})

_AGGREGATE_FUNCTIONS: Final = frozenset({
    "count", "countif", "dcount", "dcountif", "sum", "avg", "min", "max",
    "make_set", "make_list", "make_bag", "stdev", "variance", "percentile",
})

_AGG_MAP: Final = {
    "count": "count", "dcount": "count_distinct", "dcountif": "count_distinct",
    "sum": "sum", "avg": "avg", "min": "min", "max": "max",
    "stdev": "stddev", "variance": "stddev",
    "make_set": "set", "make_list": "set", "make_bag": "set",
}

_JOIN_KINDS: Final = frozenset({"inner", "leftouter", "leftanti", "fullouter"})


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    text: str
    position: int


@dataclass(frozen=True, slots=True)
class KqlOp:
    """One `| operator ...` stage."""

    name: str
    args: str
    source: str | None = None


@dataclass
class ParsedKql:
    lets: dict[str, str] = dc_field(default_factory=dict)
    body: str = ""
    diagnostics: list[Diagnostic] = dc_field(default_factory=list)


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    position = 0
    while position < len(text):
        match = _TOKEN_RE.match(text, position)
        if match is None:
            raise Refusal(
                "KQL_UNEXPECTED_CHARACTER",
                f"cannot read {text[position]!r} at position {position}. KQL has "
                f"no construct here that begins with it.", "KQL")
        kind = match.lastgroup or ""
        if kind != "ws":
            tokens.append(Token(kind, match.group(), position))
        position = match.end()
    return tokens


def split_top_level(text: str, separator: str = "|") -> list[str]:
    """Split on `separator` only at nesting depth zero.

    `|` appears inside `make_set(a | b)`? It does not, but `[`/`(` nesting and
    string literals do occur, and splitting inside either would cut a function
    call in half. Depth is tracked so `summarize make_set(x)` survives intact.
    """
    parts: list[str] = []
    buffer: list[str] = []
    depth = 0
    in_string = False
    for char in text:
        if char == '"':
            in_string = not in_string
        if not in_string:
            if char in "([":
                depth += 1
            elif char in ")]":
                depth -= 1
            elif char == separator and depth == 0:
                parts.append("".join(buffer))
                buffer = []
                continue
        buffer.append(char)
    parts.append("".join(buffer))
    return [p.strip() for p in parts if p.strip()]


def parse_kql(text: str) -> ParsedKql:
    """Split a KQL script into its `let` bindings and its final expression."""
    parsed = ParsedKql()
    remainder = text.strip()

    while remainder.lower().startswith("let "):
        head, sep, rest = remainder.partition("=")
        if not sep:
            raise Refusal(
                "KQL_LET_WITHOUT_VALUE",
                "a `let` needs a name, an `=`, and an expression. Without the value "
                "there is nothing to bind.", "KQL")
        name = head.strip()[len("let"):].strip()
        if not name:
            raise Refusal("KQL_LET_UNNAMED", "a `let` binding needs a name", "KQL")
        # A `let` binding is terminated by a SEMICOLON, not by the next `let`.
        # Splitting on the next `let` instead meant the FINAL binding swallowed
        # the entire remainder of the script -- including the expression that
        # actually gets run -- so every multi-branch rule parsed as having no
        # expression at all. That is the shape of the user's rule: two lets and
        # then the join.
        value, remainder = _take_until_semicolon(rest)
        # Leading blank lines and a `;` left over from the previous binding are
        # not part of the next statement. Without this, a blank line between
        # bindings meant `remainder.startswith("let ")` was false and the SECOND
        # binding was parsed as part of the first expression -- so a two-branch
        # rule silently became a one-branch rule that then failed to parse.
        remainder = remainder.lstrip(" \t\r\n;")
        if name in parsed.lets:
            raise Refusal(
                "KQL_LET_DUPLICATE",
                f"{name!r} is bound twice. Which expression a later reference means "
                f"would depend on binding order, so this is refused rather than "
                f"resolved by position.", "KQL")
        parsed.lets[name] = value.strip()

    parsed.body = remainder.strip()
    if not parsed.body:
        raise Refusal("KQL_NO_EXPRESSION",
                      "the script has `let` bindings but no final expression to run",
                      "KQL")
    return parsed


def _take_until_semicolon(text: str) -> tuple[str, str]:
    """Split at the first top-level `;`.

    A semicolon inside a string literal or a nested call does not terminate a
    binding, so depth and quoting are tracked. The user's rule contains
    `"0x1fffff"` and parenthesised calls, and an unguarded `text.index(";")`
    would cut inside the first string it met.
    """
    depth = 0
    in_string = False
    for index, char in enumerate(text):
        if char == '"':
            in_string = not in_string
        elif in_string:
            continue
        elif char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == ";" and depth == 0:
            return text[:index], text[index + 1:]
    # No semicolon. The binding runs to the end of what is left, and there is no
    # further expression -- `parse_kql` reports that rather than inventing one.
    return text, ""
