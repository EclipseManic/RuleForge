"""Lower CQL: a filter onto one `Filter`, the pipes onto the SPL-shaped nodes.

The filter language here is comparisons, `AND`/`OR`/`NOT` with NOT > AND > OR
precedence, parentheses, quoted strings, numbers, dotted fields, `#tag` and
`@meta` prefixes, and `true`. `in()` lowers EXACTLY, as a disjunction of
equalities. Everything else -- wildcards, regex, functions, `field = *`, `now()`,
`| join`, the aggregate functions, a computed `:=` RHS -- is refused BY NAME,
because each changes which rows match or needs a node not yet wired.

THE PIPES ARE AN ORDERED LIST, not a set of slots, and the lowerer walks it in
the order written. See `CqlQuery` for why that is a correctness property and not
a convenience.

A LEADING `#` IS A PERFORMANCE HINT, NOT PART OF THE NAME, and is stripped at
every field site -- sort, rename source, `:=` RHS, and membership alike. (The
`|`-pipe form of `in()` is a filter-position test, where a bare token and a
quoted string already mean the same thing; the `:=` RHS is not, which is why
that one path quotes its literals.) A leading `@` IS part of the name
(`@timestamp` is the field), so it is kept verbatim.
"""

from __future__ import annotations

from typing import Any

from dialects.cql import CqlAssign, CqlQuery, CqlRename, CqlSort, CqlTable, DIALECT
from engine.ir import (
    Arrange,
    BoolOp,
    Comparison,
    Derive,
    Emit,
    FieldExpr,
    FieldRef,
    Filter,
    Literal,
    Not,
    Read,
    RuleIR,
    SourceSelector,
)
from engine.values import Refusal


def lower(query: CqlQuery, rule_id: str = "rule") -> tuple[RuleIR, list[dict]]:
    """A CQL filter -> `Read` -> `Filter` (+ pipes in order) -> `Emit`.

    Pipes lower in PIPELINE ORDER, because each transforms its input: `| sort`
    then `| table` sorts the full rows and projects the sorted ones, while the
    reverse would sort one-column rows. Reordering stages returns different
    events, so the order the analyst wrote is the order lowered.
    """
    condition = _condition(query.filt)
    nodes: list[Any] = [
        Read(id="read", selector=SourceSelector(name="any")),
        Filter(id="filter", input="read", condition=condition),
    ]
    current = "filter"
    # ONE PASS, IN WRITTEN ORDER. The previous version had one optional slot
    # per pipe kind and emitted them in a fixed order, which turned
    # `| table a,b | sort(x)` into `| sort(x) | table a,b` -- a different rule
    # that can order by a column the projection had already dropped. Each
    # stage consumes the previous one's output, so the only faithful emission
    # order is the one the analyst wrote.
    for index, stage in enumerate(query.stages):
        if isinstance(stage, CqlSort):
            # `| sort(field[, limit=N])` is ascending with an optional cap --
            # the only form this parser accepts, so there is no direction to
            # lose.
            field = stage.field
            if field.startswith("#"):
                field = field[1:]
            node_id = _stage_id("arrange", index)
            nodes.append(Arrange(id=node_id, input=current,
                                 order_by=((FieldRef(field), "asc"),),
                                 limit=stage.limit))
        elif isinstance(stage, CqlRename):
            # `| rename old as new`: the original column is GONE afterwards, so
            # a later term reading the old name finds nothing. That is what
            # `rename` means (unlike `eval`, which keeps both), and the
            # renderer must say `rename`, not `eval`, for the same reason.
            # The TARGET keeps a leading `#` stripped too: `rename a as #b` was
            # minting a column named `#b`, which nothing would ever read.
            node_id = _stage_id("rename", index)
            nodes.append(Derive(id=node_id, input=current,
                                assignments=((_field_name(stage.new),
                                              FieldExpr(FieldRef(_field_name(
                                                  stage.old)))),),
                                projects=False, kind="rename"))
        elif isinstance(stage, CqlAssign):
            # `| name := operand`: the new column is ADDED and everything else
            # is KEPT, which is `eval` semantics, not `rename`. Getting these
            # two backwards is the exact bug the SPL renderer once shipped
            # (`eval` rendered as `rename`, dropping the original column), so
            # the kind here is asserted by test, not left to memory.
            node_id = _stage_id("assign", index)
            nodes.append(Derive(id=node_id, input=current,
                                assignments=((stage.name,
                                              _assign_value(stage.expr)),),
                                projects=False, kind="eval"))
        elif isinstance(stage, CqlTable):
            node_id = _stage_id("derive", index)
            # A LEADING `#` IS STRIPPED HERE TOO, like every other field site in
            # this file. `| table #foo` keeping the `#` produced a column
            # literally NAMED `#foo`, which is always ABSENT, and the query then
            # rendered back identically while evaluating to a column the analyst
            # never asked for. The `#` is an indexing hint, not part of the name.
            nodes.append(Derive(id=node_id, input=current,
                                assignments=tuple(
                                    (_field_name(column),
                                     FieldExpr(FieldRef(_field_name(column))))
                                    for column in stage.columns),
                                projects=True, kind="fields"))
        else:  # pragma: no cover -- a new stage type must be lowered, not skipped
            raise Refusal(
                "CQL_STAGE_NOT_LOWERED",
                f"a {type(stage).__name__} stage has no lowering. Refused "
                f"rather than dropped -- a dropped pipe stage silently changes "
                f"which rows come back.", DIALECT)
        current = nodes[-1].id
    nodes.append(Emit(id="out", input=current))
    return (RuleIR(rule_id=rule_id, nodes=tuple(nodes), output="out",
                   title="CQL filter", metadata={"dialect": DIALECT}), [])


def _field_name(name: str) -> str:
    """A field reference with a leading `#` stripped.

    `#foo` and `foo` name the same field; the `#` is an indexing hint. Stripped
    at EVERY field site, because keeping it in one position and not another
    means a query that names the same field three different ways in three
    positions -- and a column literally named `#foo` is always absent.
    """
    return name[1:] if name.startswith("#") else name


def _stage_id(base: str, index: int) -> str:
    """A unique node id per stage.

    Index-suffixed rather than the bare `base`, because two stages of the same
    kind are refused at parse time -- but the id has to stay unique for a
    DIFFERENT reason too: node ids address the graph, and a duplicate id would
    make `| table` after `| table`-shaped stages ambiguous. A reviewer reading
    `arrange2` also knows instantly that stage order is now load-bearing.
    """
    return f"{base}{index + 1}"


def _assign_value(expr: str) -> Any:
    """An assign RHS back into an IR expression.

    Mirrors the parser's contract exactly: one quoted string, one number, or
    one bare field. Anything else was refused at parse time, so reaching here
    with anything else means the parser and lowerer disagree -- which is
    refused rather than papered over, because silently computing a different
    value is the failure this whole file exists to prevent.
    """
    text = expr.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return Literal(value=text[1:-1])
    try:
        return Literal(value=int(text))
    except ValueError:
        pass
    try:
        return Literal(value=float(text))
    except ValueError:
        pass
    if text and " " not in text:
        bare = text[1:] if text.startswith("#") else text
        return FieldExpr(FieldRef(bare))
    raise Refusal("CQL_ASSIGN_EXPRESSION_NOT_LOWERED",
                  f":= {text} is not a single field, string, or number.",
                  DIALECT)


def _condition(text: str) -> Any:
    """A CQL boolean condition with NOT > AND > OR precedence."""
    or_parts = _split_top_level(text, "OR")
    if len(or_parts) > 1:
        return BoolOp("or", tuple(_condition(p) for p in or_parts))
    and_parts = _split_top_level(text, "AND")
    if len(and_parts) > 1:
        return BoolOp("and", tuple(_condition(p) for p in and_parts))
    body = text.strip()
    negated = False
    while body[:4].upper() == "NOT ":
        negated = not negated
        body = body[4:].strip()
    if body.startswith("!") and not body.startswith("!="):
        negated = not negated
        body = body[1:].strip()
    node = _comparison(body)
    return Not(node) if negated else node


def _split_top_level(text: str, keyword: str) -> list[str]:
    """Split on `keyword` only at paren depth 0, outside strings, whole words.

    `UserName = "and"` is one comparison whose value contains the word, and
    `ORANGE = 1` contains `OR`. Both are asserted, because both have happened
    in this codebase before -- in SPL and EQL, where the same splitter shape
    was built for the same reasons. Third copy of the shape; if a fourth
    appears, that is the moment to share one.
    """
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    start = 0
    index = 0
    upper_keyword = keyword.upper()
    while index < len(text):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and text[index:index + len(keyword)].upper() \
                == upper_keyword:
            before = text[index - 1] if index else " "
            after = text[index + len(keyword):index + len(keyword) + 1] or " "
            if not before.isalnum() and before not in (".", "_") \
                    and not after.isalnum() and after not in (".", "_"):
                parts.append(text[start:index])
                index += len(keyword)
                start = index
                continue
        index += 1
    parts.append(text[start:])
    return [p for p in (part.strip() for part in parts) if p]


def _comparison(text: str) -> Any:
    """One `field op value`, or `true`, or a parenthesised condition."""
    body = text.strip()
    if not body:
        raise Refusal("CQL_EMPTY_CONDITION", "an empty filter matches "
                      "everything, which is a no-op.", DIALECT)
    if body.lower() == "true":
        return Literal(value=True)
    if body.startswith("(") and body.endswith(")"):
        return _condition(body[1:-1])
    if body.lower().startswith("in(") and body.endswith(")"):
        return _membership(body)
    bare = _without_strings(body)
    # Refused by name, because each changes which rows match:
    if "/" in bare and _looks_like_regex(body):
        raise Refusal("CQL_REGEX_NOT_LOWERED",
                      "regex (`/pattern/` and `regex()`) is not in the lowered "
                      "subset. Refused rather than approximated.", DIALECT)
    # A LEADING `in(` lowers above; what remains here is `in(` buried
    # mid-expression where the AND/OR splitter did not separate it -- which
    # means the surrounding syntax is malformed, not a membership test.
    if " in(" in bare.lower():
        raise Refusal("CQL_IN_NOT_LOWERED",
                      "`in(field, [...])` outside a boolean position is not a "
                      "membership test this lowering can place. Refused rather "
                      "than approximated.", DIALECT)
    if ":=" in bare:
        raise Refusal("CQL_ASSIGN_NOT_LOWERED",
                      "`:=` creates a new field, which needs a `Derive` the "
                      "filter lowering does not build. Refused rather than "
                      "dropped.", DIALECT)
    for op in ("!=", ">=", "<=", "=", ">", "<"):
        left, sep, right = body.partition(op)
        # `!=` must win over `=`; partition finds the FIRST occurrence, so try
        # two-char operators before one-char ones. `==` is not CQL -- a double
        # equals here means the value starts with `=`, which is refused below
        # as not-a-value rather than misread.
        if sep:
            return _comparison_op(left.strip(), op, right.strip(), body)
    raise Refusal(
        "CQL_NOT_A_COMPARISON",
        f"{body[:60]!r} is not a comparison this lowering handles.",
        DIALECT)


def _looks_like_regex(body: str) -> bool:
    """A `/` outside strings that opens a `/pattern/` or `regex(` call."""
    bare = _without_strings(body)
    return "/" in bare


def _membership(body: str) -> Any:
    """`in(field, values=[v1, v2])` or `in(field, [v1, v2])` as an OR of
    equalities.

    Membership IS a disjunction -- `field` equal to any one of the values --
    so this lowers exactly onto `BoolOp("or", ...)` with no new node and no
    approximation. An empty value list matches nothing, so the rule could never
    fire; refused rather than rendered, the way `head 0` is.
    """
    inner = body[len("in("):-1].strip()
    field, sep, rest = inner.partition(",")
    field = field.strip()
    if not sep or not field:
        raise Refusal("CQL_IN_MALFORMED",
                      f"`{body[:50]!r}` is not `in(field, [...])`. Refused "
                      f"rather than guessed.", DIALECT)
    values_text = rest.strip()
    if values_text.lower().startswith("values="):
        values_text = values_text[len("values="):].strip()
    if not (values_text.startswith("[") and values_text.endswith("]")):
        raise Refusal("CQL_IN_MALFORMED",
                      f"`{body[:50]!r}` needs a `[...]` value list. Refused "
                      f"rather than guessed.", DIALECT)
    raw_values = [v.strip() for v in values_text[1:-1].split(",")
                  if v.strip()]
    if not raw_values:
        raise Refusal("CQL_IN_EMPTY",
                      f"`in({field}, [])` matches nothing, so the rule could "
                      f"never fire. Refused rather than rendered.", DIALECT)
    if not all(part.isidentifier() or part.replace("_", "").isalnum()
               for part in field.replace("#", "").replace("@", "").split(".")):
        raise Refusal("CQL_FIELD_NOT_A_NAME",
                      f"`{field}` is not a plain field name.", DIALECT)
    bare = field[1:] if field.startswith("#") else field
    terms = tuple(Comparison("=", FieldExpr(FieldRef(bare)),
                             _literal(v)) for v in raw_values)
    if len(terms) == 1:
        return terms[0]
    return BoolOp("or", terms)


def _without_strings(body: str) -> str:
    """`body` with quoted regions blanked."""
    out: list[str] = []
    quote: str | None = None
    for char in body:
        if quote is not None:
            if char == quote:
                quote = None
            out.append(" ")
        elif char in ("'", '"'):
            quote = char
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)


def _comparison_op(field: str, op: str, value: str, body: str) -> Any:
    """Build the comparison, or refuse what is not in the subset."""
    if not field:
        raise Refusal("CQL_FIELD_MISSING",
                      f"{body[:50]!r} has an operator with no field.",
                      DIALECT)
    # Strip the `#` tag marker: performance hint, not part of the name. `@`
    # stays -- it IS part of names like `@timestamp`.
    bare_field = field[1:] if field.startswith("#") else field
    if not bare_field or not all(
            part.isidentifier() or part.replace("_", "").isalnum()
            for part in bare_field.replace("@", "").split(".")):
        raise Refusal(
            "CQL_FIELD_NOT_A_NAME",
            f"`{field}` is not a plain field name. Refused rather than "
            f"guessed.", DIALECT)
    if not value:
        raise Refusal("CQL_VALUE_MISSING",
                      f"`{field} {op}` with no value matches nothing "
                      f"testable.", DIALECT)
    # `field = *` is an existence check, which the engine has -- but wiring it
    # here would need a presence node this lowering does not build. Refused by
    # name rather than read as equality against a literal star.
    if value == "*":
        raise Refusal(
            "CQL_EXISTS_NOT_LOWERED",
            f"`{field} = *` tests existence, not equality against `*`. There "
            f"is no presence node in this lowering yet. Refused rather than "
            f"read as a literal star that would match almost nothing.",
            DIALECT)
    if "*" in value.strip("'\""):
        raise Refusal(
            "CQL_WILDCARD_NOT_LOWERED",
            f"`{field} {op} {value}` contains a `*` wildcard, which matches "
            f"one or more characters. There is no wildcard node yet. Refused "
            f"rather than read as a literal.", DIALECT)
    if op == "=" and value.startswith("="):
        raise Refusal(
            "CQL_DOUBLE_EQUALS",
            f"`{body[:50]!r}` uses `==`, which is not CQL -- CQL equality is "
            f"a single `=`. Refused rather than read as equality against a "
            f"value starting with `=`.", DIALECT)
    return Comparison("=" if op == "=" else op,
                      FieldExpr(FieldRef(bare_field)),
                      _literal(value))


def _literal(text: str) -> Any:
    """A quoted string, a number, `true`, or a bare word.

    CQL values are very often unquoted (`#event_simpleName=ProcessRollup2`),
    so a bare word is a string value, not a syntax error. It must still be a
    single token -- anything with spaces in it that is not quoted is refused,
    because an unquoted multi-word value is two things the analyst may have
    meant as one.
    """
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return Literal(value=text[1:-1])
    if text.lower() == "true":
        return Literal(value=True)
    try:
        return Literal(value=int(text))
    except ValueError:
        pass
    try:
        return Literal(value=float(text))
    except ValueError:
        pass
    if text and " " not in text:
        return Literal(value=text)
    raise Refusal("CQL_LITERAL_NOT_A_VALUE",
                  f"{text[:40]!r} is not a quoted string, a number, or a bare "
                  f"word. Refused rather than guessed.", DIALECT)
