"""CrowdStrike Falcon FQL: the dialect where a comma widens the rule.

FQL is the filter language the Falcon API takes. It is not a pipeline and not
SQL -- it is one compact boolean expression over event fields:

    event_simpleName:'ProcessRollup2'+FileName:['lsass.exe','procdump.exe']

**`+` is AND and `,` is OR.** This is the defect this module exists to
prevent. Every other list syntax a reader has met -- SQL `IN (a, b)`, a Python
list, a CSV header -- uses the comma as a separator inside a conjunction, so
`a:'1',b:'2'` reads like "a is 1 AND b is 2" and means "a is 1 OR b is 2". A
three-clause rule misread that way matches the union instead of the
intersection, which is not a near miss: an alert meant to fire on one specific
process on one specific host fires on every host, and it reports success
while doing it. `_BOOLEAN_WORDS` keeps the mapping as data and
`CommaIsOrNotAnd` is the test class that holds it down.

**`:` is not always equality.** `field:'v'` is equality, `field:!'v'` is
inequality, `field:*'v*'` is a wildcard match, `field:>5` is an ordering, and
`field:['a','b']` is membership. Reading the prefix as decoration and treating
all five as equality produces a rule that compares against the literal text
`!'v'`, which matches nothing and errors nowhere.

**`*` is a glob, not a regex.** `FileName:*'*lsass*'` uses `*` for "any run of
characters". Lowering it to a regex makes `.` a metacharacter, so
`*'1.2.3.4'` would match `1x2y3z4`. It becomes the engine's `like` operator,
whose `%` has exactly the glob meaning, with the wildcards translated rather
than reinterpreted.

**FQL has no pipeline.** There is no aggregation, no sort, no limit and no
join: the API applies the filter and returns matching records. A rule that
counts, groups or correlates therefore cannot be written as FQL at all, and
`render_crowdstrike` REFUSES rather than emitting the filter half alone.
Emitting the filter and dropping the threshold is the specific failure that
turns "five failed logons from one host" into "any failed logon", which is the
same silent widening the comma causes, reached by a different route.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Final

from ..ir import (
    Aggregate,
    Annotations,
    BoolOp,
    Comparison,
    Correlation,
    Distinct,
    Emit,
    Expr,
    FieldRef,
    Filter,
    Join,
    Limit,
    ListExpr,
    Literal,
    Node,
    Not,
    Project,
    Read,
    Rule,
    Sort,
    render_expr,
)
from ..validate import validate
from ..values import Refusal
from .common import (
    Diagnostic,
    is_bare_identifier,
    plain_number,
    strip_comments,
)

__all__ = [
    "DIALECT",
    "LANGUAGE",
    "DEFAULT_TABLE",
    "ParsedFql",
    "MATCHERS",
    "BOOLEAN_OPERATORS",
    "UNSUPPORTED_STAGES",
    "parse_crowdstrike",
    "lower_crowdstrike",
    "render_crowdstrike",
]

DIALECT: Final = "crowdstrike"
LANGUAGE: Final = "FQL"

#: FQL filters a stream the API already chose, so the rule text names no
#: table. `event_simpleName` is the conventional discriminator and is left as
#: an ordinary predicate; this is the stream it filters.
DEFAULT_TABLE: Final = "falcon_events"

#: The two boolean operators, as data.
#:
#: `,` is OR. Written down rather than inlined because the whole module exists
#: to stop it being read as AND -- see the module docstring.
BOOLEAN_OPERATORS: Final[dict[str, str]] = {
    "+": "and",
    ",": "or",
}

#: Matcher prefix -> (engine operator, negated).
#:
#: Ordered longest-first by the scanner, because `!*` and `>=` would otherwise
#: be read as `!` and `>` with the second character left as part of the value.
MATCHERS: Final[tuple[tuple[str, str, bool], ...]] = (
    ("!*", "like", True),
    (">=", ">=", False),
    ("<=", "<=", False),
    ("!", "==", True),
    ("*", "like", False),
    (">", ">", False),
    ("<", "<", False),
    ("", "==", False),
)

#: Stages FQL cannot express at all, and why.
#:
#: Each one is REFUSED on render rather than dropped. Dropping any of them
#: leaves a filter that runs and matches more than the rule said.
UNSUPPORTED_STAGES: Final[dict[str, str]] = {
    "Aggregate": (
        "FQL has no aggregation. Writing the filter without the count turns "
        "`five failed logons from one host` into `any failed logon`, which "
        "fires on the first attempt and reports success"
    ),
    "Correlation": (
        "FQL has no threshold or timeframe. Writing the filter without them "
        "drops the part of the rule that distinguished an attack from a typo"
    ),
    "Join": (
        "FQL filters one stream and cannot combine two. Writing one side "
        "alone matches every record that side would have contributed, "
        "including the ones the join would have excluded"
    ),
    "Sort": (
        "FQL has no ordering. A rule whose meaning depends on order -- "
        "`the most recent`, `the top ten` -- cannot be expressed as a filter"
    ),
    "Limit": (
        "FQL has no row limit. Dropping it widens the result set, and the "
        "limit is usually what kept an alert actionable"
    ),
    "Distinct": (
        "FQL cannot de-duplicate. Without it the same finding is reported "
        "once per record rather than once"
    ),
}


@dataclass(frozen=True, slots=True)
class ParsedFql:
    """An FQL filter with nothing interpreted yet."""

    text: str
    #: Top-level operators in the order they appeared, for showing an analyst
    #: how their filter was read.
    operators: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Scanner:
    """A cursor over FQL text.

    Hand-written rather than driven by `common.tokenize`, because FQL's
    lexical rules genuinely differ: `+` and `,` are boolean operators rather
    than arithmetic and punctuation, `:` introduces a matcher whose prefix is
    part of the operator, and a bare word is a value rather than a field. Bending
    the shared tokenizer to all three would make it harder to read, not easier.
    """

    text: str
    index: int = 0

    def skip_space(self) -> None:
        while self.index < len(self.text) and self.text[self.index].isspace():
            self.index += 1

    @property
    def done(self) -> bool:
        self.skip_space()
        return self.index >= len(self.text)

    def peek(self) -> str:
        self.skip_space()
        return self.text[self.index] if self.index < len(self.text) else ""

    def take(self) -> str:
        char = self.peek()
        if char:
            self.index += 1
        return char

    def accept(self, char: str) -> bool:
        if self.peek() == char:
            self.index += 1
            return True
        return False

    def refuse(self, wanted: str, code: str = "FQL_UNEXPECTED") -> Refusal:
        found = self.text[self.index:self.index + 12] or "the end of the filter"
        return Refusal(
            code,
            f"needed {wanted} at character {self.index + 1} but found "
            f"{found!r}. Everything from here on was not read, so nothing "
            f"after this point has been checked.",
            "parse",
        )


def _parse_field(scanner: _Scanner) -> str:
    """A field name: letters, digits, dot, underscore."""
    scanner.skip_space()
    start = scanner.index
    text = scanner.text
    while scanner.index < len(text) and (
        text[scanner.index].isalnum() or text[scanner.index] in "._"
    ):
        scanner.index += 1
    name = text[start:scanner.index]
    if not name:
        raise scanner.refuse("a field name", "FQL_NO_FIELD")
    return name


def _parse_string(scanner: _Scanner) -> str:
    """A single-quoted value, with `\\'` for an embedded quote."""
    if not scanner.accept("'"):
        raise scanner.refuse("a quoted value", "FQL_VALUE_NOT_QUOTED")
    out: list[str] = []
    text = scanner.text
    while scanner.index < len(text):
        char = text[scanner.index]
        if char == "\\" and scanner.index + 1 < len(text):
            out.append(text[scanner.index + 1])
            scanner.index += 2
            continue
        if char == "'":
            scanner.index += 1
            return "".join(out)
        out.append(char)
        scanner.index += 1
    raise Refusal(
        "FQL_STRING_UNTERMINATED",
        "a quoted value is never closed, so the rest of the filter could not "
        "be read.",
        "parse",
    )


#: Characters an UNQUOTED value may contain.
#:
#: Deliberately excludes the structural ones. `+`, `,` and `:` used to be
#: allowed, so `A:1+B:2+C:3` was read as a single comparison against the
#: string `"1+B:2+C:3"` -- three conditions collapsed into one that matches
#: nothing, with no error at all. That is worse than a refusal: the rule looks
#: like it loaded.
#:
#: A value needing any of them must be quoted, which is FQL's own rule and
#: what the documented examples do.
_BARE_VALUE_EXTRA: Final = ".-_"


def _parse_bare_value(scanner: _Scanner) -> Any:
    """An unquoted value: a number, a boolean, or `null`."""
    scanner.skip_space()
    start = scanner.index
    text = scanner.text
    while scanner.index < len(text) and (
        text[scanner.index].isalnum()
        or text[scanner.index] in _BARE_VALUE_EXTRA
    ):
        scanner.index += 1
    body = text[start:scanner.index]
    if not body:
        raise scanner.refuse("a value", "FQL_NO_VALUE")
    lowered = body.lower()
    if lowered == "null":
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        return Decimal(body)
    except Exception:
        # A bare word that is not a number is still a value in FQL. It is kept
        # as text rather than refused, because `platform_name:Windows` is
        # idiomatic and refusing it would reject working rules.
        return body


def _parse_value(scanner: _Scanner) -> Any:
    if scanner.peek() == "'":
        return _parse_string(scanner)
    return _parse_bare_value(scanner)


def _glob_to_like(pattern: str) -> str:
    """An FQL wildcard as a LIKE pattern.

    `*` becomes `%` and `?` becomes `_`. A literal `%` or `_` in the FQL value
    is escaped, because it has no special meaning there and would otherwise
    become a wildcard here and widen the test.

    Lowering the glob to a REGEX instead is the mistake this avoids: in a
    regex `.` matches any character, so `*'1.2.3.4'` would match `1x2y3z4`.
    """
    out: list[str] = []
    for char in pattern:
        if char == "*":
            out.append("%")
        elif char == "?":
            out.append("_")
        elif char in "%_":
            out.append("\\" + char)
        else:
            out.append(char)
    return "".join(out)


def _parse_matcher(scanner: _Scanner, field: str) -> Expr:
    """Everything after the `:` in one predicate."""
    scanner.skip_space()
    operator = "=="
    negate = False
    for prefix, mapped, flip in MATCHERS:
        if not prefix:
            break
        if scanner.text.startswith(prefix, scanner.index):
            scanner.index += len(prefix)
            operator, negate = mapped, flip
            break

    reference = FieldRef(name=field.split(".")[0],
                         path=tuple(field.split(".")[1:]))

    if scanner.peek() == "[":
        scanner.take()
        items: list[Expr] = []
        while True:
            items.append(Literal(_parse_value(scanner)))
            if scanner.accept(","):
                continue
            if scanner.accept("]"):
                break
            raise scanner.refuse("`,` or `]` in a value list")
        if operator not in ("==",):
            raise Refusal(
                "FQL_LIST_OPERATOR",
                f"a value list is a membership test, so `{operator}` has no "
                f"meaning against it. Reading it as equality would compare the "
                f"field with the whole list and match nothing.",
                "parse",
            )
        return Comparison("in", reference, ListExpr(tuple(items)), negate)

    value = _parse_value(scanner)

    if operator == "like":
        if not isinstance(value, str):
            raise Refusal(
                "FQL_WILDCARD_NOT_TEXT",
                f"`{field}:*{value}` applies a wildcard to a non-text value, "
                f"which has no wildcard to apply.",
                "parse",
            )
        return Comparison("like", reference, Literal(_glob_to_like(value)),
                          negate)

    if value is None:
        # `field:null` asks whether the field is absent, which is not the same
        # question as `field == null`. The engine has a predicate for it.
        from ..ir import Call
        test: Expr = Call("is_null", (reference,))
        return Not(test) if negate else test

    return Comparison(operator, reference, Literal(value), negate)


def _parse_predicate(scanner: _Scanner) -> Expr:
    scanner.skip_space()
    remainder = scanner.text[scanner.index:]
    for word in _FOREIGN_BOOLEANS:
        if remainder[:len(word) + 1].lower() in (word + " ", word + "("):
            # A leading `NOT` would otherwise be read as a field name and
            # refused as "has no `:` after it", which says nothing useful.
            raise _refuse_foreign_boolean(scanner, word)
    if scanner.accept("("):
        inner = _parse_expression(scanner)
        if not scanner.accept(")"):
            raise scanner.refuse("`)`", "FQL_UNBALANCED")
        return inner
    if scanner.accept("!"):
        # A leading `!` before a GROUP negates the group. Before a field it is
        # part of the matcher and is handled there.
        return Not(_parse_predicate(scanner))
    field = _parse_field(scanner)
    if not scanner.accept(":"):
        raise Refusal(
            "FQL_NO_MATCHER",
            f"`{field}` has no `:` after it, so it is a bare field name "
            f"rather than a test. FQL has no bare-word search, and reading it "
            f"as one would pass every record where the field merely exists.",
            "parse",
        )
    return _parse_matcher(scanner, field)


#: Spellings from OTHER query languages, and FQL's own.
#:
#: FQL joins with `+` and `,` and negates with `:!`. Someone arriving from SPL
#: or KQL writes `AND`, `OR` and `NOT`, and the scanner refused those with
#: `FQL_TRAILING` ("needed the end of the filter") -- which says where it
#: stopped and not what to write instead. Naming the FQL spelling turns a
#: dead end into a one-line fix.
_FOREIGN_BOOLEANS: Final[dict[str, str]] = {
    "and": "`+`",
    "or": "`,`",
    "not": "a `!` before the value, as in `field:!'value'`",
}


def _refuse_foreign_boolean(scanner: _Scanner, word: str) -> Refusal:
    return Refusal(
        "FQL_FOREIGN_BOOLEAN",
        f"`{word.upper()}` is not FQL. FQL spells that operator "
        f"{_FOREIGN_BOOLEANS[word.lower()]}, so this filter reads as "
        f"`{word.upper()}` being part of a value. Nothing after it has been "
        f"interpreted.",
        "parse",
    )


def _parse_expression(scanner: _Scanner, minimum: int = 0) -> Expr:
    """Precedence climbing over `+` (AND, tighter) and `,` (OR, looser)."""
    left = _parse_predicate(scanner)
    while True:
        scanner.skip_space()
        # A foreign boolean keyword is named rather than reported as trailing
        # junk. See `_FOREIGN_BOOLEANS`.
        remainder = scanner.text[scanner.index:]
        for word in _FOREIGN_BOOLEANS:
            if remainder[:len(word) + 1].lower() in (word + " ", word + "("):
                raise _refuse_foreign_boolean(scanner, word)
        char = scanner.peek()
        if char not in BOOLEAN_OPERATORS:
            break
        operator = BOOLEAN_OPERATORS[char]
        binding = 20 if operator == "and" else 10
        if binding < minimum:
            break
        scanner.take()
        right = _parse_expression(scanner, binding + 1)
        left = _flatten(operator, left, right)
    return left


def _flatten(operator: str, left: Expr, right: Expr) -> Expr:
    """`a+b+c` as one BoolOp rather than a left-leaning nest.

    Flat because a nest renders as `((a+b)+c)`, and an analyst comparing the
    rendered filter with the one they pasted should see the same text.
    """
    operands: list[Expr] = []
    for side in (left, right):
        if isinstance(side, BoolOp) and side.op == operator:
            operands.extend(side.operands)
        else:
            operands.append(side)
    return BoolOp(operator, tuple(operands))


def parse_crowdstrike(text: str) -> ParsedFql:
    """FQL text to a parsed filter, with nothing lowered.

    Rarely what a caller wants; `lower_crowdstrike` is the useful entry point.
    """
    body = strip_comments(text).strip()
    if not body:
        raise Refusal(
            "FQL_EMPTY",
            "there is no filter text to read. An empty filter is not a filter "
            "that matches nothing -- the API would return every record.",
            "parse",
        )
    scanner = _Scanner(body)
    _parse_expression(scanner)
    if not scanner.done:
        raise scanner.refuse("the end of the filter", "FQL_TRAILING")
    operators = tuple(
        BOOLEAN_OPERATORS[c] for c in body if c in BOOLEAN_OPERATORS
    )
    return ParsedFql(text=body, operators=operators)


# ---------------------------------------------------------------------------
# Lower
# ---------------------------------------------------------------------------


def lower_crowdstrike(
    text: str, rule_id: str = "rule"
) -> tuple[Rule, list[Diagnostic]]:
    """FQL text to a Rule, plus what could not be represented."""
    parsed = parse_crowdstrike(text)
    diagnostics: list[Diagnostic] = []

    scanner = _Scanner(parsed.text)
    condition = _parse_expression(scanner)

    if "or" in parsed.operators:
        # Stated out loud because the comma is the thing this dialect gets
        # misread on, and an analyst who meant AND should see that the tool
        # read OR while the rule is still in front of them.
        diagnostics.append(Diagnostic(
            code="FQL_COMMA_IS_OR",
            message=(
                "a `,` in this filter has been read as OR, which is what FQL "
                "means by it. If it was meant as AND the rule matches the "
                "union rather than the intersection, which is a far wider set "
                "of records -- `+` is AND."
            ),
            severity="caution",
            verified=True,
        ))

    nodes: list[Node] = [
        Read(id="source", table=DEFAULT_TABLE),
        Filter(id="filter", condition=condition),
        Emit(id="out"),
    ]

    rule = Rule(
        rule_id=rule_id,
        pipeline=tuple(nodes),
        bindings=(),
        annotations=Annotations(title=""),
        metadata={
            "dialect": DIALECT,
            "language": LANGUAGE,
            "artifact": "filter",
        },
    )
    validate(rule)
    return rule, diagnostics


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def _number(value: Decimal) -> str:
    """A Decimal in PLAIN notation, never scientific.

    `Decimal("1e10")` formats as `1E+10`, and `+` is no longer a bare-value
    character -- so the scanner read `1E`, then a `+` it took for an AND, and
    refused the rest. Writing `10000000000` keeps it readable.

    `format(..., "f")` rather than `str()` because that is what suppresses the
    exponent for both very large and very small values.
    """
    text = format(value, "f")
    # `format` keeps a trailing `.0` for an integral Decimal with an exponent,
    # and FQL has no reason to see one.
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Decimal):
        return _number(value)
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _escape_glob_literal(text: str) -> str:
    """Characters that must stay LITERAL inside an FQL wildcard value.

    `*` and `?` are the wildcards, `\\` is the escape, and `'` closes the
    value. Everything here is being written out as itself, so each one is
    escaped.
    """
    return (
        text.replace("\\", "\\\\")
        .replace("*", "\\*")
        .replace("?", "\\?")
        .replace("'", "\\'")
    )


def _quote_glob(glob: str) -> str:
    """Wrap an already-escaped wildcard value in quotes.

    Deliberately NOT `_value`. `_value` escapes backslashes, and a glob has
    already placed its own: running it through both turned the `\\*` that
    means "a literal star" into `\\\\*`, which means "a literal backslash
    followed by a wildcard" -- a pattern matching something the rule never
    described.
    """
    return "'" + glob + "'"


def _like_to_glob(pattern: str) -> str:
    """A LIKE pattern back to an FQL wildcard value.

    The inverse of `_glob_to_like`, and it has to track which characters were
    wildcards and which were escaped literals. An escaped `\\%` came from a
    literal percent, and `%` has no meaning in FQL, so it is written plainly.
    A `%` that was a wildcard becomes `*`. A literal `*` in the LIKE pattern
    has to be escaped on the way out or the rendered filter is wider than the
    rule.
    """
    out: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            following = pattern[index + 1]
            if following in "%_":
                # A literal percent or underscore. Neither is special in FQL.
                out.append(following)
            else:
                out.append(_escape_glob_literal(following))
            index += 2
            continue
        if char == "%":
            out.append("*")
        elif char == "_":
            out.append("?")
        else:
            out.append(_escape_glob_literal(char))
        index += 1
    return "".join(out)



def _render_field(ref: FieldRef) -> str:
    """A field path.

    FQL field names are API paths and have NO quoting syntax, so an irregular
    one cannot be written at all: emitted bare, `_parse_field` stopped at the
    first space and the filter came back as `FQL_NO_MATCHER` -- the renderer's
    own parser refusing the renderer's own output.
    """
    path = ".".join((ref.name,) + tuple(ref.path))
    if not is_bare_identifier(path):
        raise Refusal(
            "FQL_RENDER_FIELD_NOT_AN_IDENTIFIER",
            f"`{path}` is not an FQL field path: those are ASCII letters, "
            f"digits and underscores separated by dots. FQL has no way to "
            f"quote an irregular name -- the API field would simply not be "
            f"found -- so there is nothing to write. Map the field onto a "
            f"Falcon field name first.",
            "render",
        )
    return path


def _render_expression(expr: Expr) -> str:
    """One expression as FQL.

    Every branch ends in a refusal. A silent `else` drops a clause, and a
    filter with a clause missing passes records the author excluded.
    """
    if isinstance(expr, BoolOp):
        joiner = "+" if expr.op == "and" else ","
        rendered = [_render_expression(o) for o in expr.operands]
        # An OR nested inside an AND must keep its brackets: `+` binds tighter,
        # so `a+(b,c)` without them becomes `a+b,c`, which is `(a+b) OR c` --
        # a wider rule than the one being written out.
        if expr.op == "and":
            rendered = [
                f"({part})" if isinstance(child, BoolOp) and child.op == "or"
                else part
                for part, child in zip(rendered, expr.operands)
            ]
        return joiner.join(rendered)

    if isinstance(expr, Not):
        inner = expr.operand
        if isinstance(inner, Comparison):
            return _render_comparison(inner, extra_negate=True)
        from ..ir import Call
        if isinstance(inner, Call) and inner.function == "is_null":
            return f"{_render_field(inner.args[0])}:!null"
        return f"!({_render_expression(inner)})"

    if isinstance(expr, Comparison):
        return _render_comparison(expr)

    from ..ir import Call
    if isinstance(expr, Call) and expr.function == "is_null":
        if len(expr.args) == 1 and isinstance(expr.args[0], FieldRef):
            return f"{_render_field(expr.args[0])}:null"

    raise Refusal(
        "FQL_RENDER_EXPRESSION",
        f"`{render_expr(expr)}` has no FQL spelling. FQL is a filter language "
        f"with no functions or arithmetic, so writing this out would drop part "
        f"of the condition.",
        "render",
    )


_RENDER_OPS: Final[dict[str, str]] = {
    "==": "",
    ">": ">",
    ">=": ">=",
    "<": "<",
    "<=": "<=",
}


def _render_comparison(expr: Comparison, extra_negate: bool = False) -> str:
    negate = expr.negate != extra_negate

    if not isinstance(expr.left, FieldRef):
        raise Refusal(
            "FQL_RENDER_LEFT_NOT_FIELD",
            f"`{render_expr(expr.left)}` is not a field. An FQL predicate is "
            f"always `field:matcher`, so there is nowhere to put this.",
            "render",
        )
    field = _render_field(expr.left)

    if expr.op == "in":
        if not isinstance(expr.right, ListExpr):
            raise Refusal(
                "FQL_RENDER_IN_NOT_A_LIST",
                "a membership test needs a list of values.",
                "render",
            )
        items = ",".join(
            _value(item.value) if isinstance(item, Literal)
            else _render_expression(item)
            for item in expr.right.items
        )
        prefix = "!" if negate else ""
        return f"{field}:{prefix}[{items}]"

    if expr.op in ("like", "ilike"):
        if not isinstance(expr.right, Literal) \
                or not isinstance(expr.right.value, str):
            raise Refusal(
                "FQL_RENDER_WILDCARD_NOT_LITERAL",
                "a wildcard match needs a constant pattern.",
                "render",
            )
        if expr.op == "ilike":
            raise Refusal(
                "FQL_RENDER_CASE_INSENSITIVE",
                "FQL's wildcard match is case-SENSITIVE. Writing a "
                "case-insensitive test as `:*` would silently narrow the rule, "
                "so it is refused rather than downgraded.",
                "render",
            )
        glob = _like_to_glob(expr.right.value)
        return f"{field}:{'!*' if negate else '*'}{_quote_glob(glob)}"

    if expr.op in ("contains", "startswith", "endswith"):
        # FQL has no substring operator, and the wildcard one is the faithful
        # translation. The value is escaped so a literal `*` in the data does
        # not become a wildcard and widen the test.
        if not isinstance(expr.right, Literal) \
                or not isinstance(expr.right.value, str):
            raise Refusal(
                "FQL_RENDER_SUBSTRING_NOT_LITERAL",
                f"a `{expr.op}` test needs a constant to place the wildcards "
                f"around.",
                "render",
            )
        body = _escape_glob_literal(expr.right.value)
        glob = {
            "contains": f"*{body}*",
            "startswith": f"{body}*",
            "endswith": f"*{body}",
        }[expr.op]
        return f"{field}:{'!*' if negate else '*'}{_quote_glob(glob)}"

    if expr.op == "!=":
        negate = not negate
        operator = ""
    else:
        operator = _RENDER_OPS.get(expr.op, None)  # type: ignore[arg-type]
        if operator is None:
            raise Refusal(
                "FQL_RENDER_OPERATOR",
                f"`{expr.op}` has no FQL spelling. Rendering it as equality "
                f"would change what the filter matches.",
                "render",
            )

    if negate and operator:
        raise Refusal(
            "FQL_RENDER_NEGATED_ORDERING",
            f"FQL cannot negate an ordering: there is no `:!>`. Rewrite "
            f"`NOT ({field} {expr.op} ...)` as the opposite comparison.",
            "render",
        )

    if not isinstance(expr.right, Literal):
        raise Refusal(
            "FQL_RENDER_RIGHT_NOT_LITERAL",
            f"`{render_expr(expr.right)}` is not a constant. FQL compares a "
            f"field with a value, not with another field.",
            "render",
        )
    prefix = "!" if negate else operator
    return f"{field}:{prefix}{_value(expr.right.value)}"


def render_crowdstrike(rule: Rule) -> str:
    """Write a Rule back out as an FQL filter.

    A stage FQL cannot express is REFUSED, never dropped. FQL is a filter and
    nothing else, so a rule that counts or correlates has no FQL form -- and
    emitting the filter half alone produces a filter that runs, returns
    records, and matches far more than the rule it came from.
    """
    condition: Expr | None = None

    for node in rule.pipeline:
        kind = type(node).__name__
        if isinstance(node, Read):
            continue
        if isinstance(node, Filter):
            condition = (
                node.condition if condition is None
                else _flatten("and", condition, node.condition)
            )
            continue
        if isinstance(node, Emit):
            continue
        if isinstance(node, Project):
            # A projection has no FQL form: the API returns whole records.
            # Dropping it never widens what MATCHES, which is why this was
            # written as a `continue` with a comment claiming it was "still
            # reported" -- and it never was, because a dialect renderer has no
            # diagnostics channel. Refused instead, so the claim and the
            # behaviour agree.
            raise Refusal(
                "FQL_RENDER_NO_PROJECT",
                f"`{node.id}` chooses which columns to keep, and an FQL "
                f"filter cannot: the API returns whole records. This does not "
                f"change which records MATCH, so the detection is intact -- "
                f"but the column choice is not expressible and is refused "
                f"rather than dropped without a word.",
                "render",
            )
        reason = UNSUPPORTED_STAGES.get(kind)
        if reason is None:
            raise Refusal(
                "FQL_RENDER_STAGE",
                f"a `{kind}` stage has no FQL form, and writing the filter "
                f"without it would produce a filter that matches a different "
                f"set of records.",
                "render",
            )
        raise Refusal(
            f"FQL_RENDER_NO_{kind.upper()}",
            f"{reason}. This rule cannot be expressed as an FQL filter.",
            "render",
        )

    if rule.bindings:
        raise Refusal(
            "FQL_RENDER_BINDINGS",
            "FQL has no named sub-queries, so a rule with bindings cannot be "
            "written as one filter. Writing only the main stream would drop "
            "whatever the bindings constrained.",
            "render",
        )

    if condition is None:
        raise Refusal(
            "FQL_RENDER_NO_CONDITION",
            "this rule has no filter stage, so there is no FQL to write. An "
            "empty filter returns every record, which is the opposite of a "
            "detection.",
            "render",
        )

    return _render_expression(condition)
