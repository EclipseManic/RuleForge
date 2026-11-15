"""Elastic Security EQL: the dialect that needed a new IR node.

EQL is the one language here whose central construct the model could not
already express:

    sequence by host.id with maxspan=5m
      [process where process.name == "procdump.exe"]
      [process where process.name == "lsass.exe"]
    until [process where event.type == "end"]

**A sequence is ORDERED, and nothing in the IR carried order.** `ir.Join`
pairs two streams where keys match and says nothing about which came first.
`ir.Correlation` counts how often ONE condition fired. Neither can say "this,
then that, within five minutes, on the same host" -- so `ir.Sequence` and
`ir.SequenceStep` exist, and their docstrings record why. Lowering a sequence
to a join would double the matches and half of them would be the benign
direction: `procdump` then `lsass` is credential dumping, and `lsass` then
`procdump` is somebody inspecting a memory tool.

**`:` is not `==`.** EQL's `:` is a case-INSENSITIVE wildcard match and `==`
is exact and case-sensitive. They look interchangeable and are not:
`process.name : "LSASS*"` matches `lsass.exe`, and `==` with the same string
matches nothing at all. Collapsing `:` into `==` silently narrows every rule
that used it, and collapsing `==` into `:` silently widens every rule that
did not. `MATCH_OPERATORS` keeps the two apart as data.

**The event category is a predicate, not a table.** `process where ...` filters
`event.category == "process"`; it does not name an index. Modelling it as the
table loses it on the way to any dialect that reads a different stream, and
modelling `any where ...` as a table called `any` names an index that does not
exist. The category becomes an ordinary condition, which is what it is, and
`CATEGORY_FIELD` records the field it tests.

**`maxspan` bounds the whole sequence, not each gap.** A per-gap window lets
five steps stretch across five windows and still fire, which is not the bound
the rule wrote.

**`until` is a cancellation.** A chain that was abandoned -- the user logged
off, the process exited -- is not a detection, and completing it anyway
reports an attack that did not happen.

**Regex is a Java/Lucene flavour.** `regex` and `match` hand their pattern to
Elasticsearch, so `evaluate.py` refuses to execute it for the same reason it
refuses PCRE. `:` and `wildcard()` are glob tests rather than regexes and DO
execute, which is what most EQL rules use.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from decimal import Decimal
from typing import Any, Final

from ..ir import (
    Annotations,
    BoolOp,
    Call,
    Comparison,
    Emit,
    Expr,
    FieldRef,
    Filter,
    Limit,
    ListExpr,
    Literal,
    Node,
    Not,
    Read,
    Regex,
    Rule,
    Sequence,
    SequenceStep,
    Sort,
    render_expr,
)
from ..validate import validate
from ..values import Duration, Refusal
from .common import (
    plain_number,
    is_bare_identifier,
    C_LIKE_PRECEDENCE,
    DialectSpec,
    Diagnostic,
    Parser,
    parse_annotation_header,
    render_annotation_header,
    split_top_level,
    strip_comments,
    tokenize,
)

__all__ = [
    "DIALECT",
    "LANGUAGE",
    "SPEC",
    "REGEX_DIALECT",
    "DEFAULT_TABLE",
    "CATEGORY_FIELD",
    "MATCH_OPERATORS",
    "FUNCTIONS",
    "PIPES",
    "ParsedEql",
    "parse_elastic",
    "lower_elastic",
    "render_elastic",
]

DIALECT: Final = "elastic"
LANGUAGE: Final = "EQL"

#: Elasticsearch regex. Refused by `evaluate.py`, like PCRE and Java.
REGEX_DIALECT: Final = "java_regex"

#: EQL queries a data stream the caller chose; the query text names no index.
DEFAULT_TABLE: Final = "logs-*"

#: The field an event category tests. `process where ...` is a PREDICATE on
#: this, not a table name.
CATEGORY_FIELD: Final = "event.category"

#: `any` means "do not constrain the category", so it contributes no predicate
#: rather than a predicate testing for the string "any".
ANY_CATEGORY: Final = "any"

#: The two match operators, kept apart as data.
#:
#: `==` is exact and case-sensitive. `:` is a case-insensitive wildcard match.
#: Collapsing them in either direction silently changes what every rule using
#: the other one matches.
#:
#: `like~` and `regex~` are EQL's explicitly case-INSENSITIVE forms. They were
#: missing, so a rule using one was refused as unparseable -- and the trailing
#: `~` is the only thing distinguishing them from the case-sensitive spelling,
#: which makes it exactly the character a reader skips.
MATCH_OPERATORS: Final[dict[str, str]] = {
    "==": "==",
    ":": "ilike",
    "!=": "!=",
    "like": "like",
    "like~": "ilike",
    "regex": "matches",
    "regex~": "matches",
}

#: The operators whose trailing `~` means "ignore case".
_NOCASE_SPELLINGS: Final[frozenset[str]] = frozenset({"like~", "regex~"})

FUNCTIONS: Final[dict[str, str]] = {
    "wildcard": "like",
    "cidrmatch": "cidr_contains",
    "startswith": "starts_with",
    "endswith": "ends_with",
    "stringcontains": "contains",
    "length": "length",
    "concat": "to_string",
    "number": "to_int",
    "string": "to_string",
    "match": "matches_regex",
    "between": "contains",
}

#: Pipe commands and whether they are modelled.
PIPES: Final[dict[str, str]] = {
    "head": "limit",
    "tail": "limit",
    "sort": "sort",
    "unique": "distinct",
    "unique_count": "unsupported",
    "filter": "filter",
    "count": "unsupported",
}

_PRECEDENCE: Final[dict[str, int]] = dict(C_LIKE_PRECEDENCE)
#: `:` is a comparison operator in EQL. Without binding power the parser stops
#: at the field name and the rest of the condition is silently unread, which
#: produces a rule matching every event where the field merely exists.
_PRECEDENCE.update({
    ":": 30, "like": 30, "regex": 30,
    "like~": 30, "regex~": 30,
})

SPEC: Final = DialectSpec(
    key=DIALECT,
    language=LANGUAGE,
    precedence=_PRECEDENCE,
    operators={
        "==": "==", "!=": "!=", "<": "<", "<=": "<=", ">": ">", ">=": ">=",
        "and": "and", "or": "or", "in": "in", "not": "not",
        ":": "ilike", "like": "like", "regex": "matches",
        # The explicitly case-insensitive forms. Without them a rule using
        # like~ was refused as unparseable.
        "like~": "ilike", "regex~": "matches",
    },
    keywords=frozenset({
        "and", "or", "not", "in", "sequence", "by", "with", "maxspan", "until",
        "where", "runs", "any", "true", "false", "null", "like", "regex",
        "head", "tail", "sort", "unique", "filter", "join", "sample",
        "like~", "regex~",
    }),
    list_operators=frozenset({"in"}),
    functions=FUNCTIONS,
    implicit_equality=False,
    default_regex_dialect=REGEX_DIALECT,
)

_SEQUENCE_HEAD = re.compile(r"^\s*sequence\b", re.I)
_SAMPLE_HEAD = re.compile(r"^\s*sample\b", re.I)
_MAXSPAN = re.compile(r"with\s+maxspan\s*=\s*([0-9]+)\s*([a-z]+)", re.I)
_RUNS = re.compile(r"with\s+runs\s*=\s*([0-9]+)", re.I)
_DURATION_UNITS: Final[dict[str, int]] = {
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hour": 3600, "hours": 3600,
    "d": 86400, "day": 86400, "days": 86400,
}


@dataclass(frozen=True, slots=True)
class ParsedEql:
    """An EQL query split into its parts, with nothing interpreted."""

    kind: str = "event"  # event | sequence
    #: `[category where condition]` bodies, in order.
    steps: tuple[tuple[str, str, int], ...] = ()
    by: tuple[str, ...] = ()
    maxspan: str = ""
    until: tuple[str, str] | None = None
    pipes: tuple[tuple[str, str], ...] = ()


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------


def _duration(amount: str, unit: str) -> Duration:
    size = _DURATION_UNITS.get(unit.lower())
    if size is None:
        raise Refusal(
            "EQL_DURATION_UNIT_UNKNOWN",
            f"`{amount}{unit}` is not a span this parser recognises. EQL "
            f"writes them like `5m`, `30s`, `2h` or `1d`.",
            "parse",
        )
    return Duration(Decimal(int(amount) * size))


def _split_pipes(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Separate the query body from its `| command` tail.

    Split at bracket depth zero, because a `|` can appear inside a string and
    a bracketed step, and cutting there would halve the condition.
    """
    parts = split_top_level(text, "|")
    body = parts[0]
    pipes: list[tuple[str, str]] = []
    for piece in parts[1:]:
        trimmed = piece.strip()
        if not trimmed:
            continue
        name, _, argument = trimmed.partition(" ")
        pipes.append((name.strip().lower(), argument.strip()))
    return body, pipes


def _split_brackets(text: str) -> list[str]:
    """Each `[ ... ]` group, with its brackets removed."""
    out: list[str] = []
    depth = 0
    start = -1
    in_string = False
    quote = ""
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                in_string = False
            index += 1
            continue
        if char in "\"'":
            in_string = True
            quote = char
            index += 1
            continue
        if char == "[":
            if depth == 0:
                start = index + 1
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0 and start >= 0:
                out.append(text[start:index])
                start = -1
            elif depth < 0:
                raise Refusal(
                    "EQL_UNBALANCED_BRACKET",
                    f"a `]` at character {index + 1} closes a group that was "
                    f"never opened, so the query could not be read.",
                    "parse",
                )
        index += 1
    if depth != 0:
        raise Refusal(
            "EQL_UNBALANCED_BRACKET",
            "a `[` is never closed, so the rest of the query could not be "
            "read.",
            "parse",
        )
    return out


def _split_step(body: str) -> tuple[str, str]:
    """`category where condition` as its two halves."""
    match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+where\s+", body, re.I)
    if match is None:
        raise Refusal(
            "EQL_STEP_NO_WHERE",
            f"`{body.strip()[:60]}` is not `<category> where <condition>`. "
            f"Every EQL event query names a category, and inventing one would "
            f"change which events the rule reads.",
            "parse",
        )
    condition = body[match.end():].strip()
    if not condition:
        raise Refusal(
            "EQL_STEP_NO_CONDITION",
            f"the `{match.group(1)}` step has no condition after `where`. An "
            f"empty condition is not an absent one -- it passes every event in "
            f"the category.",
            "parse",
        )
    return match.group(1), condition


def parse_elastic(text: str) -> ParsedEql:
    """EQL text to its parts, with nothing interpreted."""
    cleaned = strip_comments(text).strip()
    if not cleaned:
        raise Refusal("EQL_EMPTY", "there is no query text to read.", "parse")

    if _SAMPLE_HEAD.match(cleaned):
        raise Refusal(
            "EQL_SAMPLE_UNSUPPORTED",
            "a `sample` query groups unordered events by a shared key. It is "
            "neither a sequence nor a filter, and lowering it as either would "
            "claim an ordering it does not have or drop the grouping it does.",
            "parse",
        )

    body, pipes = _split_pipes(cleaned)
    body = body.strip()

    if not _SEQUENCE_HEAD.match(body):
        category, condition = _split_step(body)
        return ParsedEql(
            kind="event",
            steps=((category, condition, 1),),
            pipes=tuple(pipes),
        )

    head_end = len(body)
    groups = _split_brackets(body)
    if not groups:
        raise Refusal(
            "EQL_SEQUENCE_NO_STEPS",
            "this `sequence` has no `[ ... ]` steps, so it describes no "
            "events.",
            "parse",
        )
    first_bracket = body.index("[")
    head = body[:first_bracket]

    maxspan = ""
    span_match = _MAXSPAN.search(head)
    if span_match:
        maxspan = f"{span_match.group(1)}{span_match.group(2)}"

    by: list[str] = []
    by_match = re.search(
        r"\bby\s+([A-Za-z_][A-Za-z0-9_.]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_.]*)*)",
        head, re.I,
    )
    if by_match:
        by = [p.strip() for p in by_match.group(1).split(",") if p.strip()]

    # `until [...]` is the LAST group when present, and it is a terminator
    # rather than a step. Counted as a step the sequence would require the
    # cancellation to happen for the rule to fire.
    until: tuple[str, str] | None = None
    until_at = re.search(r"\buntil\b", body, re.I)
    if until_at is not None:
        tail = body[until_at.end():]
        tail_groups = _split_brackets(tail)
        if not tail_groups:
            raise Refusal(
                "EQL_UNTIL_NO_STEP",
                "`until` has no `[ ... ]` after it, so there is nothing to "
                "cancel the sequence.",
                "parse",
            )
        until = _split_step(tail_groups[0])
        groups = _split_brackets(body[:until_at.start()])

    steps: list[tuple[str, str, int]] = []
    cursor = 0
    for group in groups:
        category, condition = _split_step(group)
        # `with runs=N` trails the bracket it applies to.
        position = body.find("]", body.find(group, cursor))
        cursor = position + 1 if position >= 0 else cursor
        following = body[cursor:cursor + 40]
        runs_match = _RUNS.match(following.strip())
        runs = int(runs_match.group(1)) if runs_match else 1
        steps.append((category, condition, runs))

    return ParsedEql(
        kind="sequence",
        steps=tuple(steps),
        by=tuple(by),
        maxspan=maxspan,
        until=until,
        pipes=tuple(pipes),
    )


# ---------------------------------------------------------------------------
# Lower
# ---------------------------------------------------------------------------


def _tokenise_eql(text: str) -> list[Any]:
    """Tokenize, then promote `:` from punctuation to an operator.

    The shared lexer groups `:` with `(`, `,` and `;` because in most of these
    dialects it is punctuation. In EQL it is the case-insensitive match
    operator, and `DialectSpec.precedence_of` only assigns binding power to
    `op` and `ident` tokens -- so as punctuation it had no precedence, the
    parser stopped at the field name, and `process.name : "LSASS*"` was read
    as a bare `process.name`. That is a condition matching every event where
    the field merely exists.

    Retagging every `:` is safe because EQL has no other use for it: field
    names cannot contain one, and there is no ternary or label syntax.
    """
    from .common import Token

    out: list[Any] = []
    tokens = tokenize(text)
    index = 0
    while index < len(tokens):
        token = tokens[index]
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        # `like~` and `regex~` arrive as TWO tokens, because `~` is
        # punctuation. Joined here, or the case-insensitive spelling never
        # reaches the operator map and the rule is refused as unparseable --
        # while the case-SENSITIVE spelling one character shorter parses fine.
        if (
            token.kind == "ident"
            and token.text.lower() in ("like", "regex")
            and following is not None
            and following.kind in ("punct", "op")
            and following.text == "~"
        ):
            out.append(Token("ident", token.text.lower() + "~", token.at))
            index += 2
            continue
        if token.kind == "punct" and token.text == ":":
            out.append(Token("op", ":", token.at))
            index += 1
            continue
        out.append(token)
        index += 1
    return out


def _expression(text: str, where: str) -> Expr:
    body = text.strip()
    if not body:
        raise Refusal(
            "EQL_CONDITION_EMPTY",
            f"the condition on {where} is empty, and an empty condition passes "
            f"every event.",
            "lower",
        )
    if body.lower() == "true":
        return Literal(True)
    parser = Parser(_tokenise_eql(body), SPEC)
    expr = parser.parse_expression()
    if parser.current.kind != "eof":
        raise Refusal(
            "EQL_CONDITION_TRAILING",
            f"`{parser.current.text}` on {where} was not understood, and "
            f"everything after it has not been read. A partially-read "
            f"condition matches a different set of events than the one "
            f"written.",
            "lower",
        )
    return _normalise(expr)


def _normalise(expr: Expr) -> Expr:
    """Fix the operators whose EQL meaning differs from the raw mapping.

    `wildcard(field, "a*")` is a glob test, so it becomes a `like` with the
    glob translated rather than a function call the engine cannot run. And
    `cidrMatch` takes the address first here, which already matches the
    engine's order -- stated so a future reader does not "fix" it.
    """
    if isinstance(expr, Call):
        args = tuple(_normalise(a) for a in expr.args)
        if expr.function == "like" and len(args) >= 2:
            subject = args[0]
            patterns = args[1:]
            tests = [
                Comparison("ilike", subject, Literal(_glob_to_like(p.value)))
                for p in patterns
                if isinstance(p, Literal) and isinstance(p.value, str)
            ]
            if len(tests) == len(patterns) and tests:
                # `wildcard(f, "a*", "b*")` is an OR over the patterns.
                # Keeping only the first silently narrows the rule.
                return tests[0] if len(tests) == 1 else BoolOp(
                    "or", tuple(tests)
                )
        return Call(expr.function, args, expr.flags)
    if isinstance(expr, Comparison):
        left = _normalise(expr.left)
        right = _normalise(expr.right)
        if expr.op == "ilike" and isinstance(right, Literal) \
                and isinstance(right.value, str):
            # `:` is a case-insensitive WILDCARD match, so the `*` and `?` in
            # it are globs. Left as literal text the test stops matching the
            # events the rule was written for.
            right = Literal(_glob_to_like(right.value))
        return Comparison(expr.op, left, right, expr.negate)
    if isinstance(expr, BoolOp):
        return BoolOp(expr.op, tuple(_normalise(o) for o in expr.operands))
    if isinstance(expr, Not):
        return Not(_normalise(expr.operand))
    return expr


def _glob_to_like(pattern: str) -> str:
    """An EQL glob as a LIKE pattern.

    `*` becomes `%` and `?` becomes `_`. A literal `%` or `_` in the EQL value
    is escaped, because neither is special there and an unescaped one would
    become a wildcard here and widen the test.
    """
    out: list[str] = []
    for char in pattern:
        if char == "*":
            out.append("%")
        elif char == "?":
            out.append("_")
        elif char in "%_\\":
            out.append("\\" + char)
        else:
            out.append(char)
    return "".join(out)


def _like_to_glob(pattern: str) -> str:
    """The inverse of `_glob_to_like`."""
    out: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            out.append(pattern[index + 1])
            index += 2
            continue
        if char == "%":
            out.append("*")
        elif char == "_":
            out.append("?")
        else:
            out.append(char)
        index += 1
    return "".join(out)


def _category_predicate(category: str) -> Expr | None:
    """The event category as the PREDICATE it is.

    `any` constrains nothing, so it contributes no predicate. Modelled as a
    comparison against the string "any" it would match no event at all.
    """
    if category.lower() == ANY_CATEGORY:
        return None
    return Comparison(
        "==", FieldRef.parse(CATEGORY_FIELD), Literal(category)
    )


def _step_condition(category: str, condition: str, where: str) -> Expr:
    predicate = _expression(condition, where)
    category_test = _category_predicate(category)
    if category_test is None:
        return predicate
    if isinstance(predicate, Literal) and predicate.value is True:
        # `any where true` is "every event", and `process where true` is
        # "every process event". The category alone is the condition.
        return category_test
    return BoolOp("and", (category_test, predicate))


def _field(text: str, where: str) -> FieldRef:
    name = text.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", name):
        raise Refusal(
            "EQL_NOT_A_FIELD",
            f"`{name}` in {where} is not a field name.",
            "lower",
        )
    return FieldRef.parse(name)


def _lower_pipes(
    pipes: tuple[tuple[str, str], ...], diagnostics: list[Diagnostic]
) -> list[Node]:
    nodes: list[Node] = []
    for index, (name, argument) in enumerate(pipes, start=1):
        handling = PIPES.get(name)
        if handling is None:
            raise Refusal(
                "EQL_PIPE_UNKNOWN",
                f"`| {name}` is not an EQL pipe this tool models. Dropping it "
                f"would return a different set of rows than the query asks "
                f"for.",
                "lower",
            )
        if handling == "unsupported":
            raise Refusal(
                f"EQL_PIPE_{name.upper()}_UNSUPPORTED",
                f"`| {name}` aggregates the result, and the model keeps an "
                f"aggregation as named measures rather than as a pipe. "
                f"Lowering it silently would report a number the query did "
                f"not ask for.",
                "lower",
            )
        if handling == "limit":
            try:
                count = int(argument)
            except ValueError:
                raise Refusal(
                    "EQL_PIPE_LIMIT_NOT_A_NUMBER",
                    f"`| {name} {argument}` needs a whole number of rows.",
                    "lower",
                ) from None
            if name == "tail":
                diagnostics.append(Diagnostic(
                    code="EQL_TAIL_IS_A_HEAD",
                    message=(
                        f"`| tail {count}` keeps the LAST {count} rows. The "
                        f"model's Limit keeps the first, so the ordering this "
                        f"depends on is recorded as `keep_last` rather than "
                        f"being quietly turned into a head."
                    ),
                    severity="caution",
                    verified=True,
                ))
            nodes.append(Limit(
                id=f"pipe_{index}_{name}", count=count,
                keep_last=name == "tail",
            ))
        elif handling == "sort":
            keys = [
                (_field(part, "| sort"), False)
                for part in split_top_level(argument, ",") if part.strip()
            ]
            nodes.append(Sort(id=f"pipe_{index}_sort", keys=tuple(keys)))
        elif handling == "distinct":
            from ..ir import Distinct
            keys = [
                _field(part, "| unique")
                for part in split_top_level(argument, ",") if part.strip()
            ]
            nodes.append(Distinct(
                id=f"pipe_{index}_unique", keys=tuple(keys)
            ))
        elif handling == "filter":
            nodes.append(Filter(
                id=f"pipe_{index}_filter",
                condition=_expression(argument, "| filter"),
            ))
    return nodes


def lower_elastic(
    text: str, rule_id: str = "rule"
) -> tuple[Rule, list[Diagnostic]]:
    """EQL text to a Rule, plus what could not be represented.

    A `//` annotation header at the top is read back into `ir.Annotations`.
    Elastic's own detection rules carry a name, severity and ATT&CK mapping
    alongside the query, so dropping them makes the output unroutable.
    """
    header, body = parse_annotation_header(text, "//")
    parsed = parse_elastic(body if header else text)
    diagnostics: list[Diagnostic] = []

    nodes: list[Node] = [
        Read(id="source", table=DEFAULT_TABLE, time_field="@timestamp")
    ]

    if parsed.kind == "event":
        category, condition, _runs = parsed.steps[0]
        nodes.append(Filter(
            id="where",
            condition=_step_condition(
                category, condition, f"`{category} where`"
            ),
        ))
    else:
        if len(parsed.steps) < 2:
            raise Refusal(
                "EQL_SEQUENCE_TOO_SHORT",
                f"this sequence has {len(parsed.steps)} step, and one step is "
                f"an ordinary filter. Writing it as a sequence implies an "
                f"ordering the rule does not require.",
                "lower",
            )
        if not parsed.by:
            raise Refusal(
                "EQL_SEQUENCE_NO_BY",
                "this sequence has no `by`, so any first event would pair "
                "with any later one anywhere in the estate. EQL allows it; it "
                "is refused here because the result is almost never the "
                "intent and never says so.",
                "lower",
            )
        if not parsed.maxspan:
            diagnostics.append(Diagnostic(
                code="EQL_SEQUENCE_NO_MAXSPAN",
                message=(
                    "this sequence has no `with maxspan=`, so it spans all of "
                    "recorded history: an attack chain and two unrelated "
                    "events a year apart are the same finding."
                ),
                severity="caution",
                verified=True,
            ))

        steps = tuple(
            SequenceStep(
                condition=_step_condition(
                    category, condition, f"step {index} (`{category} where`)"
                ),
                runs=runs,
            )
            for index, (category, condition, runs) in
            enumerate(parsed.steps, start=1)
        )
        span_match = re.fullmatch(r"([0-9]+)([a-z]+)", parsed.maxspan, re.I)
        maxspan = (
            _duration(span_match.group(1), span_match.group(2))
            if span_match else None
        )
        until = None
        if parsed.until is not None:
            until = _step_condition(
                parsed.until[0], parsed.until[1], "`until`"
            )
        nodes.append(Sequence(
            id="sequence",
            steps=steps,
            by=tuple(_field(name, "`by`") for name in parsed.by),
            maxspan=maxspan,
            until=until,
        ))

    nodes.extend(_lower_pipes(parsed.pipes, diagnostics))
    nodes.append(Emit(id="out"))

    rule = Rule(
        rule_id=rule_id,
        pipeline=tuple(nodes),
        bindings=(),
        annotations=Annotations(**header) if header else Annotations(title=""),
        metadata={
            "dialect": DIALECT,
            "language": LANGUAGE,
            "artifact": "query",
            "elastic.kind": parsed.kind,
        },
    )
    validate(rule)
    return rule, diagnostics


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def _literal(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Decimal):
        return plain_number(value)
    if isinstance(value, (int, float)):
        return str(value)
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


_RENDER_OPS: Final[dict[str, str]] = {
    "==": "==", "!=": "!=", "<": "<", "<=": "<=", ">": ">", ">=": ">=",
}


def _render_expression(expr: Expr) -> str:
    """One expression as EQL.

    Every branch ends in a refusal. A silent `else` drops part of a condition,
    and a query with a clause missing matches events the author excluded.
    """
    if isinstance(expr, Literal):
        return _literal(expr.value)
    if isinstance(expr, FieldRef):
        # EQL's bare field name is ASCII; an irregular one needs backticks,
        # which this dialect's tokenizer does not read -- so emitting it bare
        # produced a query its OWN parser refused.
        if not is_bare_identifier(expr.full):
            raise Refusal(
                "EQL_RENDER_FIELD_NOT_AN_IDENTIFIER",
                f"`{expr.full}` is not a bare EQL field name: those are ASCII "
                f"letters, digits and underscores. Elastic writes an "
                f"irregular name in backticks, which this tool does not yet "
                f"read back -- so it is refused rather than written into a "
                f"query that cannot be re-imported. Map the field to an ASCII "
                f"name first.",
                "render",
            )
        return expr.full
    if isinstance(expr, BoolOp):
        joiner = " and " if expr.op == "and" else " or "
        return "(" + joiner.join(
            _render_expression(o) for o in expr.operands
        ) + ")"
    if isinstance(expr, Not):
        return f"not {_render_expression(expr.operand)}"
    if isinstance(expr, Comparison):
        return _render_comparison(expr)
    if isinstance(expr, Call):
        return _render_call(expr)
    raise Refusal(
        "EQL_RENDER_EXPRESSION",
        f"`{render_expr(expr)}` has no EQL spelling, so writing this query out "
        f"would drop part of the condition.",
        "render",
    )


def _render_comparison(expr: Comparison) -> str:
    left = _render_expression(expr.left)

    if isinstance(expr.right, Regex):
        if expr.right.dialect != REGEX_DIALECT:
            raise Refusal(
                "EQL_RENDER_REGEX_DIALECT",
                f"this pattern is {expr.right.dialect}, and EQL hands its "
                f"patterns to Elasticsearch. Writing it out unchanged would "
                f"hand Elastic a pattern in a syntax it reads differently.",
                "render",
            )
        text = f'{left} regex "{expr.right.pattern}"'
        return f"not {text}" if expr.negate else text

    if expr.op == "in":
        if not isinstance(expr.right, ListExpr):
            raise Refusal(
                "EQL_RENDER_IN_NOT_A_LIST",
                "a membership test needs a list of values.",
                "render",
            )
        items = ", ".join(
            _render_expression(item) for item in expr.right.items
        )
        text = f"{left} in ({items})"
        return f"not ({text})" if expr.negate else text

    if expr.op in ("ilike", "like"):
        if not isinstance(expr.right, Literal) \
                or not isinstance(expr.right.value, str):
            raise Refusal(
                "EQL_RENDER_MATCH_NOT_LITERAL",
                "a wildcard match needs a constant pattern.",
                "render",
            )
        glob = _like_to_glob(expr.right.value)
        # `:` is the case-INSENSITIVE operator and `like` is not, so the two
        # must not be rendered with the same spelling.
        operator = ":" if expr.op == "ilike" else "like"
        text = f'{left} {operator} "{glob}"'
        return f"not {text}" if expr.negate else text

    if expr.op in ("contains", "startswith", "endswith"):
        spelled = {
            "contains": "stringContains",
            "startswith": "startsWith",
            "endswith": "endsWith",
        }[expr.op]
        text = f"{spelled}({left}, {_render_expression(expr.right)})"
        return f"not {text}" if expr.negate else text

    spelled = _RENDER_OPS.get(expr.op)
    if spelled is None:
        raise Refusal(
            "EQL_RENDER_OPERATOR",
            f"`{expr.op}` has no EQL spelling. Rendering it as equality would "
            f"change what the query matches.",
            "render",
        )
    text = f"{left} {spelled} {_render_expression(expr.right)}"
    return f"not ({text})" if expr.negate else text


def _render_call(call: Call) -> str:
    inverse = {
        "cidr_contains": "cidrMatch",
        "starts_with": "startsWith",
        "ends_with": "endsWith",
        "contains": "stringContains",
        "length": "length",
        "to_string": "string",
        "to_int": "number",
        "matches_regex": "match",
    }
    spelled = inverse.get(call.function)
    if spelled is None:
        raise Refusal(
            "EQL_RENDER_FUNCTION",
            f"`{call.function}()` has no EQL equivalent. Dropping it would "
            f"change what the expression computes.",
            "render",
        )
    arguments = ", ".join(_render_expression(a) for a in call.args)
    return f"{spelled}({arguments})"


def _split_category(condition: Expr) -> tuple[str, Expr | None]:
    """Pull the category predicate back out of a step condition.

    The category is modelled as an ordinary predicate, so rendering has to
    recognise it again. A category left in the condition would be written as
    `any where event.category == "process" and ...`, which runs and means the
    same thing but is not the query the analyst pasted in.
    """
    if isinstance(condition, Comparison) and _is_category(condition):
        return str(condition.right.value), None
    if isinstance(condition, BoolOp) and condition.op == "and":
        head = condition.operands[0]
        if isinstance(head, Comparison) and _is_category(head):
            rest = condition.operands[1:]
            if not rest:
                return str(head.right.value), None
            return (
                str(head.right.value),
                rest[0] if len(rest) == 1 else BoolOp("and", rest),
            )
    return ANY_CATEGORY, condition


def _is_category(expr: Comparison) -> bool:
    return (
        expr.op == "=="
        and not expr.negate
        and isinstance(expr.left, FieldRef)
        and expr.left.full == CATEGORY_FIELD
        and isinstance(expr.right, Literal)
        and isinstance(expr.right.value, str)
    )


def _render_step(condition: Expr, runs: int = 1) -> str:
    category, rest = _split_category(condition)
    body = "true" if rest is None else _render_expression(rest)
    text = f"[{category} where {body}]"
    return f"{text} with runs={runs}" if runs > 1 else text


def _render_duration(duration: Duration) -> str:
    seconds = int(duration.seconds)
    for suffix, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0 and seconds >= size:
            return f"{seconds // size}{suffix}"
    return f"{seconds}s"


def render_elastic(rule: Rule) -> str:
    """Write a Rule back out as EQL.

    A stage that cannot be placed is refused rather than skipped. An EQL query
    missing its `maxspan` or a pipe still runs and returns a different set of
    events than the rule it came from.
    """
    from ..ir import Distinct

    head: str | None = None
    pipes: list[str] = []
    seen_body = False

    for node in rule.pipeline:
        if isinstance(node, Read):
            continue
        if isinstance(node, Emit):
            continue
        if isinstance(node, Sequence):
            if seen_body:
                raise Refusal(
                    "EQL_RENDER_TWO_BODIES",
                    "this rule holds more than one matching stage, and EQL has "
                    "one query body. Writing only the first would drop the "
                    "rest of the detection.",
                    "render",
                )
            head = _render_sequence(node)
            seen_body = True
            continue
        if isinstance(node, Filter):
            if not seen_body:
                head = _render_step(node.condition)
                # A bare event query is written without its brackets.
                head = head[1:-1]
                seen_body = True
            else:
                pipes.append(f"| filter {_render_expression(node.condition)}")
            continue
        if isinstance(node, Limit):
            pipes.append(
                f"| {'tail' if node.keep_last else 'head'} {node.count}"
            )
            continue
        if isinstance(node, Sort):
            pipes.append("| sort " + ", ".join(
                ref.full for ref, _descending in node.keys
            ))
            continue
        if isinstance(node, Distinct):
            pipes.append("| unique " + ", ".join(
                ref.full for ref in node.keys
            ))
            continue
        raise Refusal(
            "EQL_RENDER_STAGE",
            f"a `{type(node).__name__}` stage has no EQL form. Writing the "
            f"query without it would produce one that runs and returns a "
            f"different set of events.",
            "render",
        )

    if rule.bindings:
        raise Refusal(
            "EQL_RENDER_BINDINGS",
            "EQL has no named sub-queries. Writing only the main query would "
            "drop whatever the bindings constrained.",
            "render",
        )

    if head is None:
        raise Refusal(
            "EQL_RENDER_NO_BODY",
            "this rule has no matching stage, so its query body would be "
            "empty -- and an EQL query with no condition matches every event.",
            "render",
        )

    header = render_annotation_header(rule.annotations, "//")
    return "\n".join(header + [head] + pipes)


def _render_sequence(node: Sequence) -> str:
    parts = ["sequence"]
    if node.by:
        parts.append("by " + ", ".join(ref.full for ref in node.by))
    if node.maxspan is not None:
        parts.append(f"with maxspan={_render_duration(node.maxspan)}")
    lines = [" ".join(parts)]
    lines.extend(
        "  " + _render_step(step.condition, step.runs) for step in node.steps
    )
    if node.until is not None:
        lines.append("until " + _render_step(node.until))
    return "\n".join(lines)
