"""IBM QRadar AQL: the dialect where written order is not execution order.

Every other dialect in this package reads in the order it runs. SPL pipes
left to right, KQL pipes top to bottom, Sigma's `detection` is a set of
selections. AQL is SQL, and SQL is written in an order that has almost nothing
to do with the order it executes:

    SELECT   sourceip, COUNT(*)   <- written FIRST, runs LAST
    FROM     events
    WHERE    qid = 28250080       <- runs SECOND
    GROUP BY sourceip             <- runs THIRD
    HAVING   COUNT(*) > 5         <- runs FOURTH
    ORDER BY COUNT(*) DESC
    LIMIT    10
    LAST 24 HOURS                 <- runs FIRST, before any row exists

**This is the defect this module exists to avoid.** `ir.Rule.pipeline` is an
ordered stream: stage N sees what stage N-1 produced. Lowering AQL clauses in
the order they are WRITTEN puts the `SELECT` projection at the front, which
drops every column the `WHERE` has not read yet. The filter then compares
ABSENT against its literal, the comparison goes UNDECIDED, and the rule
reports a clean `no_match` on events it was written to catch. So
`_lower_clauses` reorders deliberately, and `CLAUSE_EXECUTION_ORDER` states
the order as data so it can be asserted about rather than inferred from the
shape of a function.

**`'x'` is a string, `"x"` is a column.** AQL follows SQL here, and it is the
exact opposite of the convention in most of the other dialects. QRadar needs
it because its property names contain spaces -- `"Event Name"`,
`"Log Source"`, `"Account Name"` -- so a quoted identifier is the normal case
rather than an exotic one. Reading `"admin"` as a string makes
`WHERE username = "admin"` a comparison between the `username` column and a
column called `admin`, which does not exist: every row is then ABSENT = ABSENT,
and the rule either matches nothing or matches everything depending on which
way the engine resolves two absences. The shared tokenizer collapses both
quote styles into one `string` token, so `_tokenise_aql` re-reads the original
character at each token's offset to recover the distinction.

**`LAST 24 HOURS` is not a row filter.** It is the Ariel time range, resolved
against the index before any record is read. It is kept on `Read.selector`
verbatim and never evaluated locally, for the same reason a Sigma `logsource`
and an SPL `index=` are: treating it as a predicate would let a local run
claim a match it cannot actually produce.

**`MATCHES` is Java regex.** `evaluate.py` refuses to execute it, as it
refuses PCRE, because no Java regex engine is implemented here and running the
pattern with Python's `re` while calling the result Java would be a false
claim about a security control. `LIKE` and `ILIKE` are SQL wildcard tests, not
regexes, and those DO execute -- which is what most AQL rules use, so most of
them stay testable.

**`WHERE` and `HAVING` are not interchangeable.** `WHERE` filters rows before
grouping; `HAVING` filters groups after it. Lowering `HAVING COUNT(*) > 5` as
a `WHERE` asks each individual row whether its own count exceeds five, which
is never true, and the rule silently stops firing.

**`COUNT(*)` and `COUNT(field)` are different counts.** SQL's `COUNT(field)`
skips NULLs; `COUNT(*)` counts rows. A threshold rule written against
`COUNT(authfail)` and lowered as `COUNT(*)` fires on rows where the field is
absent, which is the wrong population.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from decimal import Decimal
from typing import Any, Final

from ..ir import (
    Aggregate,
    Annotations,
    Arith,
    Binding,
    BoolOp,
    Call,
    Comparison,
    Distinct,
    Emit,
    Expr,
    FieldRef,
    Filter,
    Limit,
    ListExpr,
    Literal,
    Measure,
    Node,
    Not,
    Project,
    Read,
    Regex,
    Rule,
    Sort,
    Span,
    render_expr,
)
from ..validate import validate
from ..values import Duration, Refusal
from .common import (
    plain_number,
    C_LIKE_PRECEDENCE,
    DialectSpec,
    Diagnostic,
    Parser,
    Token,
    is_bare_identifier,
    parse_annotation_header,
    render_annotation_header,
    split_top_level,
    strip_comments,
    tokenize,
    escape_for_string_literal,
)

__all__ = [
    "DIALECT",
    "LANGUAGE",
    "SPEC",
    "ParsedAql",
    "CLAUSE_EXECUTION_ORDER",
    "CLAUSE_WORDS",
    "AGGREGATES",
    "TIME_UNITS",
    "parse_qradar",
    "lower_qradar",
    "render_qradar",
]

DIALECT: Final = "qradar"
LANGUAGE: Final = "AQL"

#: The Ariel regex flavour. Refused by `evaluate.py`, like PCRE.
REGEX_DIALECT: Final = "java_regex"


# ---------------------------------------------------------------------------
# Spec
# ---------------------------------------------------------------------------

_PRECEDENCE: Final[dict[str, int]] = dict(C_LIKE_PRECEDENCE)
#: `=` is equality in SQL, not assignment, and `<>` is the SQL spelling of
#: `!=`. Without binding power of their own the parser stops at the field name
#: and the rest of the condition goes unread -- a `WHERE` that matches every
#: row where the column merely exists.
_PRECEDENCE.update({"=": 30, "<>": 30, "imatches": 30, "ilike": 30})

_OPERATORS: Final[dict[str, str]] = {
    "=": "==",
    "==": "==",
    "<>": "!=",
    "!=": "!=",
    "<": "<",
    "<=": "<=",
    ">": ">",
    ">=": ">=",
    "and": "and",
    "or": "or",
    "in": "in",
    "like": "like",
    "not like": "like",
    "not ilike": "ilike",
    # ILIKE is LIKE with case folding. Mapped to the engine's own `ilike` so
    # the case-insensitivity survives a round trip instead of being quietly
    # upgraded to a case-SENSITIVE test on the way back out.
    "ilike": "ilike",
    "matches": "matches",
    "imatches": "matches",
}

#: Words that are grammar, not property names. A property genuinely called
#: `order` exists in some QRadar deployments and AQL allows it double-quoted;
#: an UNQUOTED one here is a missing operand.
_KEYWORDS: Final[frozenset[str]] = frozenset({
    "select", "from", "where", "group", "by", "having", "order", "limit",
    "last", "start", "stop", "asc", "desc", "and", "or", "not", "in", "like",
    "ilike", "matches", "imatches", "between", "as", "distinct", "is", "null",
    "text", "search", "parsedtime", "into",
})

_FUNCTIONS: Final[dict[str, str]] = {
    # Local: these run here.
    "lower": "lower",
    "upper": "upper",
    "strlen": "length",
    "incidr": "cidr_contains",
    "now": "now",
    "isnull": "is_null",
    "isnotnull": "is_not_null",
    "coalesce": "coalesce",
    "dateformat": "strftime",
    "long": "to_int",
    "str": "to_string",
    # Appliance-only: these need QRadar's own tables and cannot resolve here.
    # Modelled rather than refused so a rule that uses them still round-trips;
    # `pipeline.py` reports them as not locally evaluable.
    "qidname": "qidname",
    "qiddescription": "qidname",
    "logsourcename": "logsource_name",
    "categoryname": "qidname",
    "utf8": "utf8",
    "payload": "utf8",
    "rulename": "qidname",
    "assetname": "lookup",
    "networkname": "lookup",
}

SPEC: Final = DialectSpec(
    key=DIALECT,
    language=LANGUAGE,
    precedence=_PRECEDENCE,
    operators=_OPERATORS,
    keywords=_KEYWORDS,
    list_operators=frozenset({"in"}),
    functions=_FUNCTIONS,
    # AQL has no bare-word search syntax: `WHERE sourceip` is not a predicate.
    # Declaring implicit equality here would turn a typo into a filter that
    # passes every row where the column is present.
    implicit_equality=False,
    default_regex_dialect=REGEX_DIALECT,
)


# ---------------------------------------------------------------------------
# Clause model
# ---------------------------------------------------------------------------

#: The order AQL clauses RUN in, which is not the order they are written.
#:
#: Data rather than control flow so `tests/test_qradar.py` can assert the
#: reordering directly. `select` is last because its projection must not run
#: before the clauses whose predicates read the columns it would drop.
CLAUSE_EXECUTION_ORDER: Final[tuple[str, ...]] = (
    "from", "where", "group", "having", "order", "limit", "select",
)

#: Clause-introducing words, longest first so `GROUP BY` is matched before
#: `GROUP` and `ORDER BY` before `ORDER`.
CLAUSE_WORDS: Final[tuple[tuple[str, ...], ...]] = (
    ("select",),
    ("from",),
    ("where",),
    ("group", "by"),
    ("having",),
    ("order", "by"),
    ("limit",),
    ("last",),
    ("start",),
    ("stop",),
    ("into",),
)

#: AQL aggregate -> (engine measure function, needs an argument).
#:
#: `uniquecount` is a DISTINCT count. Mapping it to `count` reports the number
#: of rows rather than the number of distinct values, which fires a
#: password-spray rule on one account retrying.
AGGREGATES: Final[dict[str, tuple[str, bool]]] = {
    "count": ("count", False),
    "uniquecount": ("dcount", True),
    "sum": ("sum", True),
    "avg": ("avg", True),
    "average": ("avg", True),
    "min": ("min", True),
    "max": ("max", True),
    "first": ("earliest", True),
    "last": ("latest", True),
}

#: `LAST n <unit>`. Plural and singular both appear in real rules.
TIME_UNITS: Final[dict[str, int]] = {
    "second": 1, "seconds": 1,
    "minute": 60, "minutes": 60,
    "hour": 3600, "hours": 3600,
    "day": 86400, "days": 86400,
}


@dataclass(frozen=True, slots=True)
class ParsedAql:
    """An AQL statement split into clauses, with nothing interpreted yet.

    Kept as raw text per clause so `parse` can show an analyst how their query
    was divided before any meaning is attached to it.
    """

    select: str = ""
    source: str = ""
    where: str = ""
    group_by: str = ""
    having: str = ""
    order_by: str = ""
    limit: str = ""
    time_range: str = ""
    into: str = ""
    clause_order: tuple[str, ...] = ()
    extra: dict[str, str] = dc_field(default_factory=dict)


# ---------------------------------------------------------------------------
# Tokenize
# ---------------------------------------------------------------------------


def _tokenise_aql(text: str) -> list[Token]:
    """Tokenize, then restore AQL's quoting convention.

    The shared lexer produces one `string` token for both `'...'` and `"..."`,
    because in most of these dialects both are strings. In SQL they are not:
    double quotes delimit an IDENTIFIER. The original character at the token's
    offset is the only place that distinction still exists by this point, so it
    is read back from the source here.

    Without this, `WHERE "Event Name" = 'Logon'` parses as a comparison between
    two string literals -- a constant expression, true or false for every row
    at once, which is a rule that matches all events or none of them.
    """
    tokens = _retag_identifiers(text, tokenize(text))
    out: list[Token] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if (
            token.kind == "ident"
            and token.text.lower() == "not"
            and following is not None
            and following.kind == "ident"
            and following.text.lower() in ("like", "ilike")
        ):
            out.append(Token("ident", f"not {following.text.lower()}", token.at))
            index += 2
            continue
        out.append(token)
        index += 1
    return out


def _retag_identifiers(text: str, tokens: list[Token]) -> list[Token]:
    out: list[Token] = []
    for token in tokens:
        if token.kind == "string" and token.at < len(text) \
                and text[token.at] == '"':
            # A quoted property name. `ident` is what the parser expects for a
            # field, and the spaces inside it are part of the name.
            out.append(Token("ident", token.text, token.at))
            continue
        out.append(token)
    return out


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------


def _match_clause(words: list[str], index: int) -> tuple[str, int] | None:
    """Longest clause keyword starting at `index`, or None."""
    for phrase in CLAUSE_WORDS:
        if words[index:index + len(phrase)] == list(phrase):
            return phrase[0], len(phrase)
    return None


def _starts_a_call(tokens: list[Token], index: int) -> bool:
    """True when the token at `index` is immediately followed by `(`.

    `LAST` is both an Ariel time-range keyword and an aggregate function:
    `LAST 24 HOURS` is a clause and `LAST(username)` is a column. Treating the
    second as the first swallowed the SELECT list into a time range, so
    `SELECT LAST(username) FROM events` lowered to a rule with no measures at
    all. A following `(` is what separates them, and it is the same rule
    QRadar itself applies.
    """
    following = tokens[index + 1] if index + 1 < len(tokens) else None
    return following is not None and following.kind == "punct" \
        and following.text == "("


def _split_clauses(text: str) -> tuple[dict[str, str], tuple[str, ...]]:
    """Split a statement on clause keywords that are not inside brackets.

    Bracket depth is tracked because `WHERE sourceip IN (SELECT ...)` contains
    the word `select`, and splitting on it would cut the predicate in half and
    leave the remainder unparsed.
    """
    tokens = _tokenise_aql(text)
    # Lowered words, aligned with `tokens`, for phrase matching. Only `ident`
    # tokens can introduce a clause; a quoted identifier cannot, which is what
    # keeps a property called "Last" from being read as `LAST n HOURS`.
    words: list[str] = []
    for token in tokens:
        if token.kind == "ident" and _is_bare_word(text, token):
            words.append(token.text.lower())
        else:
            words.append("")

    found: list[tuple[str, int, int]] = []
    depth = 0
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.kind == "punct" and token.text in "([{":
            depth += 1
        elif token.kind == "punct" and token.text in ")]}":
            depth -= 1
        elif depth == 0 and words[index]:
            # An aggregate call is not a clause, even when it is spelled with a
            # clause word. See `_starts_a_call`.
            if words[index] in AGGREGATES and _starts_a_call(tokens, index):
                index += 1
                continue
            hit = _match_clause(words, index)
            if hit is not None:
                name, length = hit
                found.append((name, token.at, index + length))
                index += length
                continue
        index += 1

    if not found:
        raise Refusal(
            "AQL_NO_CLAUSES",
            "this does not look like an AQL statement: no SELECT, FROM or "
            "WHERE was found. Nothing has been interpreted.",
            "parse",
        )

    clauses: dict[str, str] = {}
    order: list[str] = []
    for position, (name, _at, after) in enumerate(found):
        start = tokens[after].at if after < len(tokens) else len(text)
        if position + 1 < len(found):
            end = found[position + 1][1]
        else:
            end = len(text)
        body = text[start:end].strip().rstrip(";").strip()
        if not body:
            # A clause that is WRITTEN but empty is refused rather than
            # treated as absent. `SELECT * FROM events WHERE` with nothing
            # after it was silently lowered to a rule with no filter at all,
            # which passes every row: the analyst wrote a restriction, the
            # tool dropped it, and the result reported success.
            raise Refusal(
                "AQL_CLAUSE_EMPTY",
                f"`{name.upper()}` is written here but has nothing after it. "
                f"An empty clause is not an absent one -- an empty WHERE "
                f"passes every row, so this is refused rather than ignored.",
                "parse",
            )
        if name in clauses:
            raise Refusal(
                "AQL_CLAUSE_REPEATED",
                f"`{name.upper()}` appears more than once. Which one applies "
                f"is a guess, and guessing changes what the rule matches.",
                "parse",
            )
        clauses[name] = body
        order.append(name)
    return clauses, tuple(order)


def _is_bare_word(text: str, token: Token) -> bool:
    """True when this identifier was written UNQUOTED.

    A double-quoted `"Last"` is a property name, not the `LAST` clause.
    """
    return not (token.at < len(text) and text[token.at] == '"')


def parse_qradar(text: str) -> ParsedAql:
    """AQL text to its clauses, with nothing interpreted.

    Rarely what a caller wants; `lower_qradar` is the useful entry point. This
    exists to show an analyst how their statement was divided.
    """
    stripped = strip_comments(text).strip()
    if not stripped:
        raise Refusal(
            "AQL_EMPTY", "there is no query text to read.", "parse"
        )

    statements = [s for s in split_top_level(stripped, ";") if s.strip()]
    if len(statements) > 1:
        raise Refusal(
            "AQL_MULTIPLE_STATEMENTS",
            f"this text holds {len(statements)} statements. Lowering only the "
            f"first would silently discard the rest, so name the one you mean "
            f"and pass it alone.",
            "parse",
        )
    if not statements:
        # Text that is NOT empty but holds no statement -- `;` on its own, or
        # `;;`. The emptiness check above passes because there is a character,
        # and `statements[0]` then raised IndexError: an uncaught crash where
        # every other unreadable input gets a named refusal.
        raise Refusal(
            "AQL_NO_STATEMENT",
            "this text holds only statement separators, so there is no query "
            "to read.",
            "parse",
        )

    clauses, order = _split_clauses(statements[0])
    time_range = clauses.get("last", "")
    if "start" in clauses or "stop" in clauses:
        # START/STOP is an absolute Ariel window. Kept with the relative one so
        # both land on the source stage rather than one being dropped.
        window = " ".join(
            f"{word.upper()} {clauses[word]}"
            for word in ("start", "stop") if word in clauses
        )
        time_range = f"{time_range} {window}".strip()

    return ParsedAql(
        select=clauses.get("select", ""),
        source=clauses.get("from", ""),
        where=clauses.get("where", ""),
        group_by=clauses.get("group", ""),
        having=clauses.get("having", ""),
        order_by=clauses.get("order", ""),
        limit=clauses.get("limit", ""),
        time_range=time_range,
        into=clauses.get("into", ""),
        clause_order=order,
        extra={k: v for k, v in clauses.items() if k in ("start", "stop")},
    )


# ---------------------------------------------------------------------------
# Lower: expressions
# ---------------------------------------------------------------------------


def _expression(text: str, source: str) -> Expr:
    """One AQL predicate or scalar expression."""
    body = text.strip()
    if not body:
        raise Refusal(
            "AQL_EXPRESSION_EMPTY",
            f"the `{source}` clause is empty. An empty predicate is not an "
            f"absent one: it would pass every row.",
            "lower",
        )
    parser = Parser(_tokenise_aql(body), SPEC)
    expr = parser.parse_expression()
    if parser.current.kind != "eof":
        raise Refusal(
            "AQL_EXPRESSION_TRAILING",
            f"`{parser.current.text}` in the `{source}` clause was not "
            f"understood, and everything after it has not been read. A "
            f"partially-read predicate matches a different set of events than "
            f"the one written.",
            "lower",
        )
    return _fix_argument_orders(expr)


def _fix_argument_orders(expr: Expr) -> Expr:
    """Normalise functions whose AQL argument order differs from the model's.

    `INCIDR('10.0.0.0/8', sourceip)` takes the network FIRST. The engine's
    `cidr_contains` takes the address first, like every other dialect here.
    Passing them straight through makes the network the subject and the address
    the pattern, which never matches and never errors.
    """
    if isinstance(expr, Call):
        args = tuple(_fix_argument_orders(a) for a in expr.args)
        if expr.function == "cidr_contains" and len(args) == 2:
            return Call(expr.function, (args[1], args[0]), expr.flags)
        return Call(expr.function, args, expr.flags)
    if isinstance(expr, Comparison):
        return Comparison(
            expr.op,
            _fix_argument_orders(expr.left),
            _fix_argument_orders(expr.right),
            expr.negate,
        )
    if isinstance(expr, BoolOp):
        return BoolOp(
            expr.op, tuple(_fix_argument_orders(o) for o in expr.operands)
        )
    if isinstance(expr, Not):
        return Not(_fix_argument_orders(expr.operand))
    return expr


# ---------------------------------------------------------------------------
# Lower: SELECT list
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _SelectItem:
    """One entry in the SELECT list, already classified."""

    text: str
    alias: str = ""
    measure: Measure | None = None
    field: FieldRef | None = None
    star: bool = False


def _parse_alias(piece: str) -> tuple[str, str]:
    """Split `expr AS alias`, honouring quotes and brackets."""
    tokens = _tokenise_aql(piece)
    depth = 0
    for index, token in enumerate(tokens):
        if token.kind == "punct" and token.text in "([{":
            depth += 1
        elif token.kind == "punct" and token.text in ")]}":
            depth -= 1
        elif depth == 0 and token.kind == "ident" \
                and token.text.lower() == "as" and _is_bare_word(piece, token):
            if index + 1 >= len(tokens) - 1:
                raise Refusal(
                    "AQL_ALIAS_MISSING",
                    f"`{piece.strip()}` ends with AS and no name.",
                    "lower",
                )
            alias = tokens[index + 1].text
            return piece[:token.at].strip(), alias
    return piece.strip(), ""


def _measure_from(piece: str, alias: str) -> Measure | None:
    """An aggregate call, or None when this item is not one."""
    body = piece.strip()
    open_paren = body.find("(")
    if open_paren < 0 or not body.endswith(")"):
        return None
    name = body[:open_paren].strip().lower()
    spec = AGGREGATES.get(name)
    if spec is None:
        return None

    function, needs_argument = spec
    argument = body[open_paren + 1:-1].strip()
    distinct = False
    if argument.lower().startswith("distinct "):
        # `COUNT(DISTINCT x)` is a distinct count, not a count. Reading past
        # the keyword and counting rows reports attempts where the rule asked
        # for actors.
        distinct = True
        argument = argument[len("distinct "):].strip()
        function = "dcount" if function == "count" else function

    if argument == "*":
        if needs_argument:
            raise Refusal(
                "AQL_AGGREGATE_NEEDS_FIELD",
                f"`{name.upper()}(*)` has no column to work on. Only COUNT "
                f"can count rows.",
                "lower",
            )
        return Measure(
            function=function, name=alias or "count", field=None,
            distinct=distinct,
        )

    if not argument:
        if needs_argument:
            raise Refusal(
                "AQL_AGGREGATE_NEEDS_FIELD",
                f"`{name.upper()}()` has no column to work on.",
                "lower",
            )
        return Measure(
            function=function, name=alias or "count", field=None,
            distinct=distinct,
        )

    field = _field_of(argument, f"{name.upper()}()")
    default = alias or f"{function}_{field.name}"
    return Measure(
        function=function, name=default, field=field, distinct=distinct
    )


def _field_of(text: str, where: str) -> FieldRef:
    """A bare column reference, or a refusal naming where it was needed."""
    expr = _expression(text, where)
    if isinstance(expr, FieldRef):
        return expr
    raise Refusal(
        "AQL_NOT_A_FIELD",
        f"`{text.strip()}` in {where} is an expression, not a column. The "
        f"model groups and sorts by columns, so lowering this would mean "
        f"inventing a derived column the query never declared.",
        "lower",
    )


def _lower_select(body: str) -> tuple[list[_SelectItem], bool]:
    """The SELECT list, and whether it was marked DISTINCT.

    `SELECT DISTINCT sourceip` used to fail with AQL_EXPRESSION_TRAILING: the
    keyword was handed to the expression parser as part of the first column,
    which read `DISTINCT` as a field name and then found `sourceip` with no
    operator between them. `DISTINCT` is one of the first words in SQL, so
    this rejected a shape an analyst writes without thinking about it.

    Returned rather than applied here, because de-duplication is a STAGE and
    this function only reads the column list.
    """
    text = body.strip()
    distinct = False
    if text[:9].lower() == "distinct " or text.lower() == "distinct":
        distinct = True
        text = text[9:].strip()
    if text[:4].lower() == "all ":
        # The explicit opposite of DISTINCT, and the default. Consumed so it
        # does not become a column called `ALL`.
        text = text[4:].strip()

    items: list[_SelectItem] = []
    for piece in split_top_level(text, ","):
        text_piece = piece.strip()
        if not text_piece:
            continue
        if text_piece == "*":
            items.append(_SelectItem(text=text_piece, star=True))
            continue
        expression, alias = _parse_alias(text_piece)
        measure = _measure_from(expression, alias)
        if measure is not None:
            items.append(
                _SelectItem(text=text_piece, alias=alias, measure=measure)
            )
            continue
        parsed = _expression(expression, "SELECT")
        if isinstance(parsed, FieldRef):
            items.append(
                _SelectItem(text=text_piece, alias=alias, field=parsed)
            )
            continue
        raise Refusal(
            "AQL_SELECT_EXPRESSION",
            f"`{text_piece}` in the SELECT list is a computed expression. The "
            f"model keeps a projection as a list of columns, so this would "
            f"have to become a derived column -- and silently naming it would "
            f"hide that the query never did.",
            "lower",
        )
    if not items:
        raise Refusal(
            "AQL_SELECT_EMPTY",
            "the SELECT list is empty, so the query names no output.",
            "lower",
        )
    return items, distinct


# ---------------------------------------------------------------------------
# Lower: clauses
# ---------------------------------------------------------------------------


def _lower_source(parsed: ParsedAql) -> Read:
    """`FROM` plus the Ariel time range as the source stage."""
    table = parsed.source.strip()
    if not table:
        raise Refusal(
            "AQL_NO_FROM",
            "this query has no FROM clause, so it does not say what it reads. "
            "AQL defaults to `events` interactively; defaulting here would "
            "mean a rule whose source depends on where it was run.",
            "lower",
        )
    if len(split_top_level(table, ",")) > 1:
        raise Refusal(
            "AQL_FROM_MULTIPLE",
            f"`FROM {table}` names more than one source. The model reads one "
            f"stream and joins explicitly, so collapsing these would invent a "
            f"join condition the query never stated.",
            "lower",
        )
    selector = parsed.time_range.strip()
    if selector:
        selector = f"LAST {selector}" if not selector.upper().startswith(
            ("START", "LAST")
        ) else selector
    return Read(
        id="source",
        table=table,
        selector=selector,
        time_field="starttime" if table.lower() in ("events", "flows") else "",
    )


def _lower_group_keys(body: str) -> list[FieldRef]:
    keys: list[FieldRef] = []
    for piece in split_top_level(body, ","):
        text = piece.strip()
        if text:
            keys.append(_field_of(text, "GROUP BY"))
    return keys


def _lower_order(body: str) -> list[tuple[FieldRef, bool]]:
    keys: list[tuple[FieldRef, bool]] = []
    for piece in split_top_level(body, ","):
        text = piece.strip()
        if not text:
            continue
        descending = False
        lowered = text.lower()
        for suffix, flag in (("desc", True), ("asc", False)):
            if lowered.endswith(" " + suffix):
                descending = flag
                text = text[: -(len(suffix) + 1)].strip()
                break
        keys.append((_field_of(text, "ORDER BY"), descending))
    return keys


def _lower_limit(body: str) -> int:
    text = body.strip()
    try:
        count = int(text)
    except ValueError:
        raise Refusal(
            "AQL_LIMIT_NOT_A_NUMBER",
            f"`LIMIT {text}` is not a whole number.",
            "lower",
        ) from None
    if count <= 0:
        raise Refusal(
            "AQL_LIMIT_NOT_POSITIVE",
            f"`LIMIT {count}` keeps no rows, so the rule can never fire.",
            "lower",
        )
    return count


def _measure_key(measure: Measure) -> tuple[str, bool, str]:
    """Identity of an aggregate, for matching a HAVING call to a SELECT one."""
    return (
        measure.function.lower(),
        measure.distinct,
        measure.field.name if measure.field else "",
    )


def _find_aggregate_calls(text: str) -> list[tuple[int, int, str, str]]:
    """Every top-level aggregate call in a clause.

    Returns `(start, end, name, argument)` spans. Parentheses are balanced by
    counting rather than by regex, because `COUNT(DISTINCT LOWER(user))` nests
    and a non-greedy match would close at the inner bracket and leave the rest
    of the clause as stray text.
    """
    found: list[tuple[int, int, str, str]] = []
    tokens = _tokenise_aql(text)
    for index, token in enumerate(tokens):
        if token.kind != "ident" or not _is_bare_word(text, token):
            continue
        if token.text.lower() not in AGGREGATES:
            continue
        after = tokens[index + 1] if index + 1 < len(tokens) else None
        if after is None or not (after.kind == "punct" and after.text == "("):
            continue
        depth = 0
        cursor = after.at
        while cursor < len(text):
            if text[cursor] == "(":
                depth += 1
            elif text[cursor] == ")":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1
        if depth != 0:
            raise Refusal(
                "AQL_UNBALANCED_PARENTHESES",
                f"`{token.text.upper()}(` in this clause is never closed, so "
                f"the rest of the clause could not be read.",
                "lower",
            )
        found.append((
            token.at, cursor + 1, token.text.lower(),
            text[after.at + 1:cursor].strip(),
        ))
    return found


def _resolve_aggregates(
    text: str,
    items: list[_SelectItem],
    extra: list[Measure],
    clause: str,
    diagnostics: list[Diagnostic],
) -> str:
    """Rewrite aggregate calls in HAVING or ORDER BY into column references.

    After grouping, an aggregate is a COLUMN -- that is what `ir.Aggregate`
    produces and what the stage after it can read. `HAVING COUNT(*) > 5` has to
    become `hits > 5`, naming the measure the SELECT already computes.

    Re-expressing the aggregate as a row predicate instead is the failure this
    function prevents: it asks each individual row whether its own count
    exceeds five, which is never true, and the rule stops firing without any
    error. Lowering it as a plain `WHERE` has the same effect.

    An aggregate that appears in HAVING but not in SELECT is ADDED to the
    aggregate stage rather than refused. QRadar computes it either way, and the
    group count exists whether or not the analyst chose to display it.
    """
    spans = _find_aggregate_calls(text)
    if not spans:
        return text

    known = {
        _measure_key(item.measure): item.measure
        for item in items if item.measure is not None
    }
    known.update({_measure_key(m): m for m in extra})

    out: list[str] = []
    cursor = 0
    for start, end, name, argument in spans:
        out.append(text[cursor:start])
        candidate = _measure_from(f"{name}({argument})", "")
        if candidate is None:  # pragma: no cover - name came from AGGREGATES
            raise Refusal(
                "AQL_AGGREGATE_UNREADABLE",
                f"`{name.upper()}({argument})` in {clause} could not be read.",
                "lower",
            )
        key = _measure_key(candidate)
        existing = known.get(key)
        if existing is None:
            existing = candidate
            known[key] = existing
            extra.append(existing)
            diagnostics.append(Diagnostic(
                code="AQL_AGGREGATE_ADDED",
                message=(
                    f"`{name.upper()}({argument})` is filtered on in {clause} "
                    f"but not listed in SELECT, so it has been added to the "
                    f"aggregation as `{existing.name}`. The value is the same "
                    f"one QRadar computes; naming it is what lets the rule be "
                    f"read and tested."
                ),
                severity="note",
                verified=True,
            ))
        out.append(f'"{existing.name}"')
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def _lower_clauses(
    parsed: ParsedAql, diagnostics: list[Diagnostic]
) -> list[Node]:
    """Clauses to stages, in EXECUTION order rather than written order.

    This function is the whole point of the module. See the module docstring:
    emitting `SELECT` first, where it is written, puts a projection ahead of
    every predicate that reads a column it does not keep.
    """
    if parsed.select.strip():
        items, select_distinct = _lower_select(parsed.select)
    else:
        items, select_distinct = [_SelectItem(text="*", star=True)], False
    if not parsed.select.strip():
        diagnostics.append(Diagnostic(
            code="AQL_SELECT_ASSUMED",
            message=(
                "this query has no SELECT clause, so every column is kept. "
                "That is what QRadar does, and it is stated here because a "
                "rule that keeps everything is a rule whose output changes "
                "when the log source adds a field."
            ),
            severity="note",
            verified=True,
        ))

    nodes: list[Node] = [_lower_source(parsed)]

    if parsed.where.strip():
        if _find_aggregate_calls(parsed.where):
            raise Refusal(
                "AQL_AGGREGATE_IN_WHERE",
                "WHERE filters rows BEFORE grouping, so an aggregate there has "
                "nothing to aggregate over. QRadar rejects this too; it is "
                "named here rather than silently moved to HAVING, because "
                "moving it would change which rows reach the grouping.",
                "lower",
            )
        nodes.append(Filter(
            id="where", condition=_expression(parsed.where, "WHERE")
        ))

    keys = _lower_group_keys(parsed.group_by) if parsed.group_by.strip() else []

    # HAVING and ORDER BY are resolved BEFORE the aggregate stage is built,
    # because either can name an aggregate the SELECT list omitted and the
    # stage has to carry every measure the later stages read.
    extra: list[Measure] = []
    having_text = parsed.having
    if having_text.strip():
        having_text = _resolve_aggregates(
            having_text, items, extra, "HAVING", diagnostics
        )
    order_text = parsed.order_by
    if order_text.strip():
        order_text = _resolve_aggregates(
            order_text, items, extra, "ORDER BY", diagnostics
        )

    measures = [i.measure for i in items if i.measure is not None] + extra
    aggregate = (
        Aggregate(id="group_by", measures=tuple(measures), keys=tuple(keys))
        if measures else None
    )
    if aggregate is not None:
        nodes.append(aggregate)
    elif keys:
        # `GROUP BY` with no aggregate is a de-duplication, and `Distinct` is
        # what the model calls that. Dropping the grouping instead would widen
        # the result set.
        nodes.append(Distinct(id="group_by", keys=tuple(keys)))

    if having_text.strip():
        if aggregate is None:
            raise Refusal(
                "AQL_HAVING_WITHOUT_AGGREGATE",
                "HAVING filters GROUPS, and this query aggregates nothing, so "
                "there are no groups to filter. Lowering it as a WHERE would "
                "ask each row whether its own aggregate passed, which is never "
                "true.",
                "lower",
            )
        nodes.append(Filter(
            id="having", condition=_expression(having_text, "HAVING")
        ))

    if order_text.strip():
        nodes.append(Sort(id="order_by", keys=tuple(_lower_order(order_text))))

    if parsed.limit.strip():
        nodes.append(Limit(id="limit", count=_lower_limit(parsed.limit)))

    # SELECT runs LAST. Renames and keeps are both projections, so they are one
    # stage, and a `SELECT *` adds none at all.
    renames = tuple(
        (item.field, item.alias)
        for item in items
        if item.field is not None and item.alias
    )
    keeps = tuple(
        item.field for item in items if item.field is not None
    )

    if aggregate is not None:
        # After grouping, the row IS the group keys plus the measures -- that
        # is what `ir.Aggregate` produces, and it is exactly the SELECT list.
        # Projecting only the non-aggregate items here dropped the counts:
        # `SELECT sourceip, COUNT(*) AS hits` came back with `sourceip` alone,
        # so a threshold rule reported which host fired without reporting how
        # many times, and the number the analyst set the threshold on was gone
        # from the output.
        if renames:
            nodes.append(Project(
                id="select",
                renames=renames,
                keeps=tuple(keys) + tuple(
                    FieldRef(name=m.name) for m in measures
                ),
            ))
    elif renames or (keeps and not any(i.star for i in items)):
        nodes.append(Project(id="select", renames=renames, keeps=keeps))

    if select_distinct:
        # `SELECT DISTINCT` de-duplicates the OUTPUT, so it runs after the
        # projection -- de-duplicating before it would compare columns the
        # query does not return and keep rows the analyst asked to collapse.
        #
        # Keyed on the projected columns when there are any, and on nothing
        # when the query is `SELECT DISTINCT *` -- which `ir.Distinct` refuses,
        # correctly: de-duplicating on no key is not a defined operation.
        distinct_keys = keeps or tuple(
            FieldRef(name=m.name) for m in measures
        )
        if not distinct_keys:
            raise Refusal(
                "AQL_DISTINCT_NEEDS_COLUMNS",
                "`SELECT DISTINCT *` de-duplicates on every column the event "
                "happens to have, which differs per log source -- so the same "
                "query would collapse different rows on different days. Name "
                "the columns the rows should be distinct on.",
                "lower",
            )
        nodes.append(Distinct(id="distinct", keys=tuple(distinct_keys)))

    nodes.append(Emit(id="out"))
    return nodes


def lower_qradar(text: str, rule_id: str = "rule") -> tuple[Rule, list[Diagnostic]]:
    """AQL text to a Rule, plus what could not be represented.

    A `--` annotation header at the top is read back into `ir.Annotations`, so
    a rule that round-trips through AQL keeps its title and severity rather
    than arriving as an unnamed query.
    """
    header, body = parse_annotation_header(text, "--")
    parsed = parse_qradar(body if header else text)
    diagnostics: list[Diagnostic] = []

    if parsed.into.strip():
        diagnostics.append(Diagnostic(
            code="AQL_INTO_DROPPED",
            message=(
                f"`INTO {parsed.into.strip()}` writes the result to a named "
                f"Ariel table. That is a side effect on the appliance, not "
                f"part of what the rule matches, so it is not modelled -- the "
                f"detection logic is kept and the write is not."
            ),
            severity="caution",
            verified=True,
        ))

    if parsed.time_range.strip():
        diagnostics.append(Diagnostic(
            code="INDEX_TIME_FILTER",
            message=(
                f"`{parsed.time_range.strip()}` is the Ariel time range. It is "
                f"resolved against the index before any record is read, so it "
                f"is kept verbatim on the source stage and is NOT applied when "
                f"this rule is tested locally."
            ),
            severity="note",
            verified=True,
        ))

    nodes = _lower_clauses(parsed, diagnostics)

    rule = Rule(
        rule_id=rule_id,
        pipeline=tuple(nodes),
        bindings=(),
        annotations=Annotations(**header) if header else Annotations(title=""),
        metadata={
            "dialect": DIALECT,
            "language": LANGUAGE,
            "artifact": "search",
            "qradar.clause_order": ",".join(parsed.clause_order),
        },
    )
    validate(rule)
    return rule, diagnostics


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def _literal(value: Any) -> str:
    """A constant as AQL.

    Strings get SINGLE quotes. Double quotes would make the value an
    identifier, so `username = "admin"` compares two columns -- see the module
    docstring.
    """
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, Decimal):
        return plain_number(value)
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def _identifier(name: str) -> str:
    """A column name, quoted only when it has to be.

    QRadar property names contain spaces, and an unquoted `Event Name` is two
    tokens that fail to parse rather than one column.

    The safety check is `is_bare_identifier`, which is ASCII-only. It used to
    be `str.isalnum()`, which is UNICODE-aware -- so a Cyrillic field name
    passed as "safe to write bare" and the AQL tokenizer, whose identifier
    pattern is ASCII, then refused the renderer's own output.
    """
    if is_bare_identifier(name) and name.lower() not in _KEYWORDS:
        return name
    return '"' + name.replace('"', '""') + '"'


def _field(ref: FieldRef) -> str:
    # `path` is a nested accessor, which Ariel properties do not have: QRadar
    # flattens everything to a custom property. Rendering `a.b` as a column
    # called `a.b` would name a property that does not exist, so it is refused
    # rather than guessed at.
    if ref.path:
        raise Refusal(
            "AQL_RENDER_NESTED_FIELD",
            f"`{ref.full}` is a nested field. Ariel properties are flat, so "
            f"this needs a custom property defined in QRadar before the rule "
            f"can reference it.",
            "render",
        )
    return _identifier(ref.name)


_RENDER_OPS: Final[dict[str, str]] = {
    "==": "=",
    "!=": "<>",
    "<": "<",
    "<=": "<=",
    ">": ">",
    ">=": ">=",
    "like": "LIKE",
    "ilike": "ILIKE",
}

#: Engine function -> AQL spelling. The inverse of `_FUNCTIONS`, written out
#: rather than inverted at import time because the mapping is many-to-one:
#: `qidname` is reachable from four AQL names and must render back as one.
_RENDER_FUNCTIONS: Final[dict[str, str]] = {
    "lower": "LOWER",
    "upper": "UPPER",
    "length": "STRLEN",
    "now": "NOW",
    "is_null": "ISNULL",
    "is_not_null": "ISNOTNULL",
    "coalesce": "COALESCE",
    "strftime": "DATEFORMAT",
    "to_int": "LONG",
    "to_string": "STR",
    "qidname": "QIDNAME",
    "logsource_name": "LOGSOURCENAME",
    "utf8": "UTF8",
}


def _render_expression(expr: Expr) -> str:
    """One expression as AQL.

    Every branch ends in a refusal. A silent `else` here renders a predicate as
    nothing, and a `WHERE` with a clause missing passes rows the author
    excluded.
    """
    if isinstance(expr, Literal):
        return _literal(expr.value)
    if isinstance(expr, FieldRef):
        return _field(expr)
    if isinstance(expr, Regex):
        if expr.dialect != REGEX_DIALECT:
            # POSIX ERE and Java regex agree on the portable subset, so a
            # pattern that passes the portable screen means the same thing in
            # both. Refusing on the DIALECT TAG alone rejected `-enc`, `^power`
            # and `\.exe$`, which are identical in every flavour.
            from ..evaluate import _screen_portable

            try:
                _screen_portable(expr.pattern)
            except Refusal:
                raise Refusal(
                    "AQL_RENDER_REGEX_DIALECT",
                    f"this pattern is {expr.dialect}, and AQL's MATCHES is Java "
                    f"regex. Writing it out unchanged would hand QRadar a "
                    f"pattern in a syntax it reads differently.",
                    "render",
                ) from None
        # Java regex has the inline flag, and AQL MATCHES is case-sensitive:
        # dropping the fold would narrow every rule that carried one.
        prefix = "(?i)" if expr.nocase else ""
        return _literal(prefix + expr.pattern)
    if isinstance(expr, Not):
        return f"NOT ({_render_expression(expr.operand)})"
    if isinstance(expr, Span):
        # AQL has BETWEEN, and the parser already reads it -- so refusing it
        # here meant this dialect could not write back a query it had just
        # read. `destinationport BETWEEN 1 AND 1024` lowered cleanly and then
        # refused with AQL_RENDER_EXPRESSION on the way out.
        #
        # AQL's BETWEEN is inclusive on both ends. An exclusive bound has no
        # BETWEEN spelling, so it is written as the pair of comparisons it
        # means rather than silently widened to include the endpoint.
        value = _render_expression(expr.value)
        low = _render_expression(expr.low)
        high = _render_expression(expr.high)
        if expr.low_inclusive and expr.high_inclusive:
            return f"{value} BETWEEN {low} AND {high}"
        low_op = ">=" if expr.low_inclusive else ">"
        high_op = "<=" if expr.high_inclusive else "<"
        return f"({value} {low_op} {low} AND {value} {high_op} {high})"
    if isinstance(expr, ListExpr):
        return "(" + ", ".join(_render_expression(i) for i in expr.items) + ")"
    if isinstance(expr, Arith):
        return (
            f"({_render_expression(expr.left)} {expr.op} "
            f"{_render_expression(expr.right)})"
        )
    if isinstance(expr, BoolOp):
        joiner = f" {expr.op.upper()} "
        return "(" + joiner.join(
            _render_expression(o) for o in expr.operands
        ) + ")"
    if isinstance(expr, Comparison):
        return _render_comparison(expr)
    if isinstance(expr, Call):
        return _render_call(expr)
    raise Refusal(
        "AQL_RENDER_EXPRESSION",
        f"`{render_expr(expr)}` has no AQL spelling, so writing this query out "
        f"would drop part of the condition.",
        "render",
    )


def _render_comparison(expr: Comparison) -> str:
    left = _render_expression(expr.left)
    operator = expr.op

    if operator == "in":
        items = expr.right
        if isinstance(items, ListExpr):
            rendered = ", ".join(_render_expression(i) for i in items.items)
        else:
            rendered = _render_expression(items)
        text = f"{left} IN ({rendered})"
        return f"NOT ({text})" if expr.negate else text

    if operator in ("contains", "startswith", "endswith"):
        # AQL has no substring operator. LIKE with the wildcards placed to
        # match is the faithful translation, and the value has to be escaped
        # because a literal `%` in the data would otherwise become a wildcard
        # and widen the test.
        #
        # AQL spells the case-insensitive form `ILIKE`, and `expr.nocase` is
        # what says to use it. Emitting plain LIKE lost the fold, so a rule
        # that matched `ADMIN` locally stopped matching it in QRadar.
        pattern = _like_pattern(expr.right, operator)
        word = "ILIKE" if expr.nocase else "LIKE"
        text = f"{left} {word} {pattern}"
        return f"{left} NOT {word} {pattern}" if expr.negate else text

    if operator == "matches":
        right = _render_expression(expr.right)
        text = f"{left} MATCHES {right}"
        return f"NOT ({text})" if expr.negate else text

    spelled = _RENDER_OPS.get(operator)
    if spelled is None:
        raise Refusal(
            "AQL_RENDER_OPERATOR",
            f"`{operator}` has no AQL spelling. Rendering it as equality would "
            f"change what the rule matches.",
            "render",
        )
    right = _render_expression(expr.right)
    if expr.nocase and operator in ("==", "!="):
        # AQL's `=` is exact-case. `UPPER()` on both sides is the portable way
        # to say "ignore case" for equality: `ILIKE` without wildcards also
        # works, but reads as a pattern test and some Ariel builds treat `_` in
        # the value as a wildcard. The operator carries the negation, so a
        # negated test stays folded rather than becoming `NOT (a = b)`.
        folded = "=" if operator == "==" else "<>"
        if expr.negate:
            folded = "<>" if folded == "=" else "="
        return f"UPPER({left}) {folded} UPPER({right})"
    if expr.negate:
        # Negation is folded into the operator where one exists, because
        # `NOT (a <> b)` is harder to read than `a = b` and some Ariel versions
        # optimise the two differently.
        flipped = {"=": "<>", "<>": "=", "<": ">=", ">=": "<", ">": "<=",
                   "<=": ">"}.get(spelled)
        if flipped:
            return f"{left} {flipped} {right}"
        return f"NOT ({left} {spelled} {right})"
    return f"{left} {spelled} {right}"


def _like_pattern(right: Expr, operator: str) -> str:
    if not isinstance(right, Literal):
        raise Refusal(
            "AQL_RENDER_LIKE_NOT_LITERAL",
            f"a `{operator}` test against a non-constant cannot become a LIKE "
            f"pattern, because the wildcards have to be placed around a known "
            f"value.",
            "render",
        )
    # `%` and `_` are LIKE wildcards. An unescaped one from the data widens the
    # match: `contains "100%"` would otherwise match "100" followed by
    # anything.
    body = str(right.value).replace("\\", "\\\\")
    body = body.replace("%", "\\%").replace("_", "\\_")
    wrapped = {
        "contains": f"%{body}%",
        "startswith": f"{body}%",
        "endswith": f"%{body}",
    }[operator]
    # The glob layer's backslashes have to survive the STRING layer too. See
    # `escape_for_string_literal`: without this a trailing `\` in the value
    # became an escaped `%`, so `User|startswith: 'NT AUTHORITY\'` stopped
    # matching and its negation alerted on every SYSTEM event.
    quoted = escape_for_string_literal(wrapped).replace("'", "''")
    return "'" + quoted + "'"


def _render_call(call: Call) -> str:
    if call.function == "cidr_contains":
        # Back to AQL's order: network first. See `_fix_argument_orders`.
        if len(call.args) != 2:
            raise Refusal(
                "AQL_RENDER_INCIDR_ARITY",
                "INCIDR takes a network and an address.",
                "render",
            )
        network = _render_expression(call.args[1])
        address = _render_expression(call.args[0])
        return f"INCIDR({network}, {address})"
    spelled = _RENDER_FUNCTIONS.get(call.function)
    if spelled is None:
        raise Refusal(
            "AQL_RENDER_FUNCTION",
            f"`{call.function}()` has no AQL equivalent. Dropping it would "
            f"change what the expression computes.",
            "render",
        )
    arguments = ", ".join(_render_expression(a) for a in call.args)
    return f"{spelled}({arguments})"


def _render_measure(measure: Measure) -> str:
    name = measure.function.lower()
    if name == "count":
        inner = "*" if measure.field is None else _field(measure.field)
        body = f"COUNT({inner})"
    elif name in ("dcount", "distinct_count", "dc"):
        if measure.field is None:
            raise Refusal(
                "AQL_RENDER_UNIQUECOUNT_NO_FIELD",
                "a distinct count needs a column to be distinct over.",
                "render",
            )
        body = f"UNIQUECOUNT({_field(measure.field)})"
    elif name in ("sum", "avg", "min", "max"):
        if measure.field is None:
            raise Refusal(
                "AQL_RENDER_AGGREGATE_NO_FIELD",
                f"`{name.upper()}` needs a column.",
                "render",
            )
        body = f"{name.upper()}({_field(measure.field)})"
    elif name in ("earliest", "latest"):
        if measure.field is None:
            raise Refusal(
                "AQL_RENDER_AGGREGATE_NO_FIELD",
                f"`{name}` needs a column.",
                "render",
            )
        body = f"{'FIRST' if name == 'earliest' else 'LAST'}" \
               f"({_field(measure.field)})"
    else:
        raise Refusal(
            "AQL_RENDER_MEASURE",
            f"`{measure.function}` is not an Ariel aggregate. Rendering it as "
            f"COUNT would report a different number than the rule asked for.",
            "render",
        )
    if measure.name and measure.name != body:
        return f"{body} AS {_identifier(measure.name)}"
    return body


def render_qradar(rule: Rule) -> str:
    """Write a Rule back out as AQL.

    The stages arrive in EXECUTION order and have to be emitted in CLAUSE
    order, which is the inverse of the reordering `_lower_clauses` performs. A
    stage that cannot be placed is refused rather than skipped: an AQL
    statement missing a clause still parses, runs, and returns the wrong rows.
    """
    select: list[str] = []
    group_keys: list[FieldRef] = []
    source: Read | None = None
    where: list[Expr] = []
    having: list[Expr] = []
    order: list[tuple[FieldRef, bool]] = []
    limit: int | None = None
    seen_aggregate = False
    select_distinct = False

    for node in rule.pipeline:
        if isinstance(node, Read):
            source = node
        elif isinstance(node, Filter):
            # Which clause a filter belongs to depends on whether it runs
            # before or after the aggregate, which is exactly the distinction
            # the pipeline order carries and AQL's syntax loses.
            (having if seen_aggregate else where).append(node.condition)
        elif isinstance(node, Aggregate):
            seen_aggregate = True
            group_keys = list(node.keys)
            select.extend(_render_measure(m) for m in node.measures)
        elif isinstance(node, Distinct):
            if node.id == "distinct":
                # `SELECT DISTINCT` is a projection modifier, not a GROUP BY.
                # Treating its keys as group keys caused the renderer to emit
                # both DISTINCT and GROUP BY, so re-lowering inserted a second
                # Distinct stage and changed the pipeline on every round trip.
                select_distinct = True
            else:
                group_keys = list(node.keys)
        elif isinstance(node, Sort):
            order = list(node.keys)
            if node.limit is not None:
                limit = node.limit
        elif isinstance(node, Limit):
            limit = node.count
        elif isinstance(node, Project):
            renamed = {ref.name: alias for ref, alias in node.renames}
            for ref in node.keeps:
                rendered = _field(ref)
                alias = renamed.pop(ref.name, "")
                select.append(
                    f"{rendered} AS {_identifier(alias)}" if alias else rendered
                )
            for name, alias in renamed.items():
                select.append(
                    f"{_identifier(name)} AS {_identifier(alias)}"
                )
            if node.drops:
                raise Refusal(
                    "AQL_RENDER_DROPS",
                    "AQL has no way to say 'every column except these'. A "
                    "SELECT names what it keeps, so a drop list would have to "
                    "be inverted against a schema this rule does not carry.",
                    "render",
                )
        elif isinstance(node, Emit):
            if node.keeps:
                select.extend(_field(ref) for ref in node.keeps)
        else:
            raise Refusal(
                "AQL_RENDER_STAGE",
                f"a `{type(node).__name__}` stage has no AQL clause. Writing "
                f"the query out without it would produce a statement that runs "
                f"and returns a different set of rows.",
                "render",
            )

    if source is None:
        raise Refusal(
            "AQL_RENDER_NO_SOURCE",
            "this rule has no source stage, so there is no FROM clause to "
            "write and the query would read an unspecified table.",
            "render",
        )

    # Group keys belong in the SELECT list as well as the GROUP BY: Ariel
    # returns only what is selected, so grouping by a column without selecting
    # it produces counts with nothing to attribute them to.
    for ref in group_keys:
        rendered = _field(ref)
        if rendered not in select:
            select.insert(0, rendered)

    distinct_prefix = "DISTINCT " if select_distinct else ""
    lines = [f"SELECT {distinct_prefix}{', '.join(select) if select else '*'}"]
    lines[:0] = render_annotation_header(rule.annotations, "--")
    lines.append(f"FROM {source.table or 'events'}")
    if where:
        lines.append(f"WHERE {_join_conditions(where)}")
    if group_keys:
        lines.append(f"GROUP BY {', '.join(_field(r) for r in group_keys)}")
    if having:
        lines.append(f"HAVING {_join_conditions(having)}")
    if order:
        lines.append("ORDER BY " + ", ".join(
            f"{_field(r)} DESC" if descending else _field(r)
            for r, descending in order
        ))
    if limit is not None:
        lines.append(f"LIMIT {limit}")

    selector = (source.selector or "").strip()
    if selector:
        # The Ariel time range is raw dialect text and is written back
        # verbatim. It is only AQL's when the rule came from AQL; the registry
        # reports the loss when it did not.
        if rule.metadata.get("dialect") == DIALECT:
            lines.append(selector)

    return "\n".join(lines)


def _join_conditions(conditions: list[Expr]) -> str:
    """Several filter stages as one clause.

    ANDed, because consecutive pipeline stages are a conjunction. Rendering
    only the first would produce a query that passes rows the later stages
    rejected.
    """
    if len(conditions) == 1:
        return _render_expression(conditions[0])
    return " AND ".join(_render_expression(c) for c in conditions)
