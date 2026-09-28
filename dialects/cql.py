"""CrowdStrike CQL (LogScale), slice 1: a filter plus `| table`, honestly.

CQL is a PIPELINE language: `filter | table a, b`. The filter uses `=`/`!=`
comparisons with `AND`/`OR`/`NOT`, `#tag` fields (indexed), `@meta` fields
(`@timestamp`), and bare event fields. This slice lowers the filter onto one
`Filter` and `| table a, b` onto `Derive(kind="fields")` -- both existing
nodes, no approximations.

THIS IS NOT FQL, and the two must never share a parser. FQL is
`property:[operator]value` with `+`/`,`; CQL is `field = "value"` with pipes
and word operators. Each refuses the other's shape by name: a combined grammar
would accept strings valid in neither language.

Refused by name in this slice: wildcards in values, regex (`/re/` and
`regex()`), functions, `in()`, `:=` assignment, `field = *` exists-checks, and
every pipe except `table`. Each changes which rows match or needs a node not
yet wired, so each is named rather than approximated.
"""

from __future__ import annotations

from dataclasses import dataclass

from engine.values import Refusal

DIALECT = "cql"
LANGUAGE = "CrowdStrike CQL"


@dataclass(frozen=True, slots=True)
class CqlSort:
    """`| sort(field[, limit=N])` -- ascending by default. CQL's sort takes an
    optional row limit; direction, if the query spells one this parser does not
    know, is refused rather than defaulted."""
    field: str
    limit: int | None = None


@dataclass(frozen=True, slots=True)
class CqlRename:
    """`| rename old as new`, one pair. Each pair is its own pipe in CQL."""
    old: str
    new: str


@dataclass(frozen=True, slots=True)
class CqlAssign:
    """`| name := expr` where expr is a field, a quoted string, or a number.

    Arithmetic (`a+b`), concatenation (`f+"x"`), and function calls are real
    CQL but need expression shapes this lowering does not build -- so the RHS
    is one operand and anything else is refused by name, not approximated.
    """
    name: str
    expr: str


@dataclass(frozen=True, slots=True)
class CqlQuery:
    """A CQL filter with pipes. `table`, `sort` and `rename` lower; `:=`
    assigns one field, string, or number. Each pipe appears at most once and
    in pipeline order -- the parser preserves the order the analyst wrote."""
    filt: str
    table: tuple[str, ...] = ()
    sort: CqlSort | None = None
    rename: CqlRename | None = None
    assign: CqlAssign | None = None


def parse_cql(text: str) -> CqlQuery:
    """Split a CQL query into its filter and its pipes."""
    stripped = text.strip()
    if not stripped:
        raise Refusal("CQL_EMPTY", "nothing to parse", DIALECT)
    # FQL SHAPES ARE REFUSED AS FQL, NOT AS BROKEN CQL. `a:'b'` with a colon
    # and no `=` is FQL's `property:value`, and `a+b` is FQL's AND. Reading
    # either as CQL would misparse a valid rule from the other language.
    bare = _without_quotes(stripped)
    if ":" in bare and "=" not in bare.replace("==", "").replace("!=", "") \
            .replace("<=", "").replace(">=", ""):
        raise Refusal(
            "CQL_NOT_FQL",
            "this looks like FQL (`property:value`), not CQL (`field = "
            "\"value\"`). The two languages share a name and nothing else; "
            "this is refused rather than read as either.", DIALECT)
    segments = _split_pipes(stripped)
    filt = segments[0].strip()
    if not filt:
        raise Refusal("CQL_EMPTY_FILTER",
                      "a query starting with `|` has no filter, which matches "
                      "everything -- a no-op disguised as a rule.", DIALECT)
    table: tuple[str, ...] = ()
    sort: CqlSort | None = None
    rename: CqlRename | None = None
    assign: CqlAssign | None = None
    for pipe in segments[1:]:
        text = pipe.strip()
        # `:=` FIRST, BEFORE THE PAREN CHECK. An assignment RHS may contain a
        # paren inside a string (`x := "a(b"`), and the `(` branch below is not
        # quote-aware -- it would misread the string's paren as a function
        # call. `_find_assign` only matches `:=` outside strings and parens,
        # so a `:=` inside a value cannot misroute the other way either.
        at = _find_assign(text)
        if at >= 0:
            if assign is not None:
                raise Refusal("CQL_ASSIGN_TWICE",
                              "two `| :=` stages; the second overwrites what "
                              "the first assigned. Refused rather than "
                              "silently kept.", DIALECT)
            assign = _parse_assign(text[:at], text[at + 3:])
            continue
        # Function-call pipes (`sort(...)`) vs space-separated pipes (`table`,
        # `rename`). Split on `(` first: a pipe whose name contains `(` is a
        # call, and anything after the closing paren is refused rather than
        # silently ignored.
        if "(" in text:
            name, _, rest = text.partition("(")
            name = name.strip().lower()
            if not rest.endswith(")"):
                raise Refusal(
                    "CQL_PIPE_MALFORMED",
                    f"`| {text[:40]}` has an opening paren with no close. "
                    f"Refused rather than guessed.", DIALECT)
            args = rest[:-1].strip()
            if name == "sort":
                if sort is not None:
                    raise Refusal("CQL_SORT_TWICE",
                                  "two `| sort` stages; the second reorders "
                                  "what the first ordered. Refused rather "
                                  "than silently kept.", DIALECT)
                sort = _parse_sort_args(args)
                continue
            raise Refusal(
                "CQL_PIPE_NOT_LOWERED",
                f"`| {name}(...)` is a real CQL command, but only `| table`, "
                f"`| sort`, and `| rename` lower today. Refused by name rather "
                f"than dropped.", DIALECT)
        name, _, args = text.partition(" ")
        name, args = name.lower(), args.strip()
        if name == "table":
            if table:
                raise Refusal("CQL_TABLE_TWICE",
                              "two `| table` stages join nothing new; the "
                              "second is refused rather than silently kept.",
                              DIALECT)
            table = tuple(f.strip() for f in args.split(",") if f.strip())
            if not table:
                raise Refusal("CQL_TABLE_EMPTY",
                              "`| table` with no columns projects nothing.",
                              DIALECT)
            for column in table:
                _check_field_name(column, "column")
        elif name == "rename":
            if rename is not None:
                raise Refusal("CQL_RENAME_TWICE",
                              "two `| rename` stages; the second renames what "
                              "the first renamed. Refused rather than silently "
                              "kept.", DIALECT)
            old, sep, new = args.partition(" as ")
            old, new = old.strip(), new.strip()
            if not sep or not old or not new:
                raise Refusal(
                    "CQL_RENAME_NOT_A_PAIR",
                    f"`| rename {args}` is not `old as new`. A rename needs "
                    f"both sides, and guessing either is a different rule.",
                    DIALECT)
            _check_field_name(old, "rename source")
            _check_field_name(new, "rename target")
            rename = CqlRename(old=old, new=new)
        else:
            raise Refusal(
                "CQL_PIPE_NOT_LOWERED",
                f"`| {name}` is a real CQL command, but only `| table`, "
                f"`| sort`, `| rename`, and `| :=` lower today. Refused by "
                f"name rather than dropped -- dropping a pipe stage silently "
                f"changes which rows come back.", DIALECT)
    return CqlQuery(filt=filt, table=table, sort=sort, rename=rename,
                    assign=assign)


def _find_assign(text: str) -> int:
    """Index of a top-level `:=`, or -1.

    Top-level means outside strings AND outside parens: a `:=` inside
    `sort(a:=b)` would be a different construct, and one inside `"a:=b"` is
    data. Either misroute silently changes the rule, so both are excluded.
    """
    depth = 0
    quote: str | None = None
    index = 0
    while index < len(text) - 1:
        char = text[index]
        if quote is not None:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and char == ":" and text[index + 1] == "=":
            return index
        index += 1
    return -1


def _parse_assign(name: str, expr: str) -> CqlAssign:

    """`| name := expr` where expr is one field, string, or number.

    Arithmetic, concatenation, and function calls are real CQL on the right
    side, and each needs expression shapes this lowering does not build. So
    the RHS must be a single operand -- anything with an operator, a paren, or
    a second token is refused with what it is, not approximated as the first
    piece of it.
    """
    name, expr = name.strip(), expr.strip()
    if not name or not expr:
        raise Refusal("CQL_ASSIGN_MALFORMED",
                      f"`| {name} := {expr}` is not `name := expr`. An "
                      f"assignment needs both sides.", DIALECT)
    _check_field_name(name, "assign target")
    # One operand: a quoted string, a number, or a bare field. Anything else
    # -- `a+b`, `f("x")`, `a+"x"` -- is a bigger expression wearing the shape
    # of a value, and taking its first token would silently compute something
    # the analyst did not write.
    if len(expr) >= 2 and expr[0] == expr[-1] and expr[0] in ("'", '"'):
        return CqlAssign(name=name, expr=expr)
    try:
        float(expr)
        return CqlAssign(name=name, expr=expr)
    except ValueError:
        pass
    if expr and " " not in expr and all(
            part.isidentifier() or part.replace("_", "").isalnum()
            for part in expr.replace("#", "").replace("@", "").split(".")):
        return CqlAssign(name=name, expr=expr)
    raise Refusal(
        "CQL_ASSIGN_EXPRESSION_NOT_LOWERED",
        f"`| {name} := {expr}` computes something -- arithmetic, concatenation, "
        f"or a function call -- and this lowering builds single operands, not "
        f"expressions. Refused rather than approximated as its first piece.",
        DIALECT)


def _check_field_name(column: str, what: str) -> None:
    """A plain dotted field name, with `#`/`@` prefixes allowed."""
    if not column or not all(part.isidentifier()
                             for part in column.replace("#", "").replace(
                                 "@", "").split(".")):
        raise Refusal(
            "CQL_COLUMN_NOT_A_NAME",
            f"`{column}` is not a plain field name. Refused rather than "
            f"guessed.", DIALECT)


def _parse_sort_args(args: str) -> CqlSort:
    """`field` or `field, limit=N`. Anything else is refused by name.

    Direction is deliberately absent: CQL's `sort()` takes a field and an
    optional row limit, and any direction keyword this parser does not know
    would be silently defaulted -- so an unknown argument is a refusal, not an
    ascending sort the analyst did not ask for.
    """
    parts = [p.strip() for p in args.split(",") if p.strip()]
    if not parts:
        raise Refusal("CQL_SORT_EMPTY",
                      "`| sort()` with no field orders by nothing.", DIALECT)
    field = parts[0]
    _check_field_name(field, "sort field")
    limit: int | None = None
    for extra in parts[1:]:
        key, sep, value = extra.partition("=")
        if not sep or key.strip().lower() != "limit" or not value.strip():
            raise Refusal(
                "CQL_SORT_ARG_UNKNOWN",
                f"`| sort({args})` takes a field and `limit=N` -- nothing "
                f"else is known here, and defaulting an unknown argument "
                f"would silently change the sort. Refused by name.", DIALECT)
        if not value.strip().isdigit() or int(value.strip()) <= 0:
            raise Refusal(
                "CQL_SORT_LIMIT_NOT_POSITIVE",
                f"`limit={value.strip()}` is not a positive integer, so it "
                f"cannot cap rows. Refused rather than guessed.", DIALECT)
        limit = int(value.strip())
    return CqlSort(field=field, limit=limit)


def _split_pipes(text: str) -> list[str]:
    """Split on `|` at bracket depth 0 outside strings.

    A `|` inside a quoted value (`name == "a|b"`) or inside parens is data,
    not a pipe. Splitting there would break the value and then refuse on the
    pieces.
    """
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    start = 0
    for index, char in enumerate(text):
        if quote is not None:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def _without_quotes(text: str) -> str:
    """`text` with quoted regions blanked, so shape checks cannot fire inside
    a value."""
    out: list[str] = []
    quote: str | None = None
    for char in text:
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
