"""CrowdStrike CQL (LogScale): a filter plus its pipe stages, honestly.

CQL is a PIPELINE language: `filter | table a, b | sort(x)`. The filter uses
`=`/`!=` comparisons with `AND`/`OR`/`NOT`, `#tag` fields (indexed), `@meta`
fields (`@timestamp`), and bare event fields. The filter lowers onto one
`Filter`; the pipes lower onto `Derive`/`Arrange` -- all existing nodes, no
approximations.

SHIPPED: the filter, plus `| table`, `| sort`, `| rename`, `| name :=` (a single
operand: a field, quoted string, or number), and `in()`. Pipes lower IN THE
ORDER WRITTEN, and each kind appears at most once.

THIS IS NOT FQL, and the two must never share a parser. FQL is
`property:[operator]value` with `+`/`,`; CQL is `field = "value"` with pipes
and word operators. Each refuses the other's shape by name: a combined grammar
would accept strings valid in neither language.

Refused by name in this slice: wildcards in values, regex (`/re/` and
`regex()`), functions, `field = *` exists-checks, `now()`, `join()`, the
aggregates other than the nullary `count()` and a counted `groupBy`, an
arithmetic or function RHS to `:=`, and a repeated pipe. Each changes which
rows match, fabricates a value, or needs a node not yet wired, so each is named
rather than approximated.
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
class CqlCount:
    """`| count()` -- nullary: counts ROWS, reading no field.

    `count(field=x)` is a DIFFERENT aggregate (it counts rows where x is
    present) and is refused by name. `count` is the only nullary aggregate the
    IR's `AGGREGATES` set contains, and it is the one an analyst reaches for
    first -- "how many of these events" is the question most CQL asks.
    """
    #: `count()` has no argument at all, so this is always empty. It is here so
    #: a future `by` variant has a home rather than growing a parallel field.
    by: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CqlGroupBy:
    """`| groupBy([a, b])` -- one row per distinct COMBINATION of the keys.

    LogScale's own reference: `groupBy(field, [function], [limit])`, and the
    `function` parameter DEFAULTS to `count(as=_count)`. So the default output
    column is named `_count`, not `count` -- which is why this carries the
    measure name as data rather than assuming the nullary `count()` shape.

    `function=[]` is a DIFFERENT result: unique values with nothing aggregated,
    one row per value and no measure column at all. That is not a count with a
    zero in it, so it is refused by name rather than folded into one.
    """
    keys: tuple[str, ...]
    #: The measure's OUTPUT column, from `count(as=...)`. Defaults to `_count`,
    #: which is LogScale's spelling and NOT a cosmetic choice -- rendering it as
    #: `count` would rename a column the analyst's own queries read.
    measure_name: str = "_count"


@dataclass(frozen=True, slots=True)
class CqlTable:
    """`| table c1, c2` -- PROJECT: the result keeps only these columns, in
    this order. A `CqlTable` is a stage, not a property of the query, because
    where it sits in the pipe chain changes what the later stages can see."""
    columns: tuple[str, ...]


#: Every pipe stage this lowering understands. A stage is a `|` in the analyst's
#: query, and stages lower IN WRITTEN ORDER -- so this is a union of shapes, not
#: a list of features the query optionally has.
CqlStage = (CqlTable | CqlSort | CqlRename | CqlAssign | CqlCount
            | CqlGroupBy)


@dataclass(frozen=True, slots=True)
class CqlQuery:
    """A CQL filter plus its pipe stages, IN THE ORDER THEY WERE WRITTEN.

    WHY AN ORDERED LIST AND NOT ONE SLOT PER PIPE. This was four separate
    optional fields (`table`, `sort`, `rename`, `assign`) and the lowerer
    emitted them in a fixed order. That is a silent correctness bug, not a
    style one: `| table a,b | sort(x)` -- project, then order by a column that
    SURVIVED the projection -- was lowered to sort FIRST, so the sort could
    order by a column the analyst's own query had already dropped, and the
    rendered rule no longer said what they wrote. The stages are a sequence
    because each one transforms its input; a fixed order cannot express that.
    """
    filt: str
    stages: tuple[CqlStage, ...] = ()


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
    # ONE LIST, IN WRITTEN ORDER. See `CqlQuery` for why the order is the
    # whole point rather than a convenience. `seen` still refuses a repeated
    # pipe, because a second `| sort` or `| rename` is a rewrite of the first
    # and this slice does not model the rewrite -- but the refusal is about
    # REPETITION, not position.
    stages: list[CqlStage] = []
    seen: set[str] = set()
    for pipe in segments[1:]:
        text = pipe.strip()
        # `:=` FIRST, BEFORE THE PAREN CHECK. An assignment RHS may contain a
        # paren inside a string (`x := "a(b"`), and the `(` branch below is not
        # quote-aware -- it would misread the string's paren as a function
        # call. `_find_assign` only matches `:=` outside strings and parens,
        # so a `:=` inside a value cannot misroute the other way either.
        at = _find_assign(text)
        if at >= 0:
            _claim(stages, seen, "assign", "CQL_ASSIGN_TWICE",
                   "two `| :=` stages. Two assignments are perfectly ordinary "
                   "CQL -- `| a := 1 | b := 2` writes two different fields and "
                   "overwrites nothing -- so this is refused as an unsupported "
                   "shape, NOT as a hazard. Nothing here can corrupt the rule; "
                   "it just is not lowered yet.")
            stages.append(_parse_assign(text[:at], text[at + 3:]))
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
                _claim(stages, seen, "sort", "CQL_SORT_TWICE",
                       "two `| sort` stages. A second sort replaces the first "
                       "ordering, which is legal CQL, so this is refused as an "
                       "unsupported shape rather than as a hazard.")
                stages.append(_parse_sort_args(args))
                continue
            if name == "count":
                stages.append(_parse_count(text, args))
                continue
            if name in ("groupby", "group_by"):
                _claim(stages, seen, "groupby", "CQL_GROUPBY_TWICE",
                       "two `| groupBy` stages. A second grouping re-groups the "
                       "first one's output, which is a different shape and not "
                       "lowered yet; refused as an unsupported shape, not as a "
                       "hazard.")
                stages.append(_parse_groupby(text, args))
                continue
            if name == "join":
                raise Refusal(*_join_refusal(args), DIALECT)
            raise Refusal(
                "CQL_PIPE_NOT_LOWERED",
                f"`| {name}(...)` is a real CQL command, but only `| table`, "
                f"`| sort`, `| rename`, `| count()`, `| groupBy(...)`, and "
                f"`| :=` lower today. Refused by name rather than dropped -- "
                f"dropping a pipe stage silently changes which rows come back.",
                DIALECT)
        name, _, args = text.partition(" ")
        name, args = name.lower(), args.strip()
        if name == "table":
            _claim(stages, seen, "table", "CQL_TABLE_TWICE",
                   "two `| table` stages. A second projection is a re-projection "
                   "and has nothing to do with joining; this is refused as an "
                   "unsupported shape, not as a hazard.")
            columns = tuple(f.strip() for f in args.split(",") if f.strip())
            if not columns:
                raise Refusal("CQL_TABLE_EMPTY",
                              "`| table` with no columns projects nothing.",
                              DIALECT)
            for column in columns:
                _check_field_name(column, "column")
            stages.append(CqlTable(columns=columns))
        elif name == "rename":
            _claim(stages, seen, "rename", "CQL_RENAME_TWICE",
                   "two `| rename` stages. Renaming two different fields in one "
                   "query is ordinary CQL, so this is an unsupported shape, not "
                   "a hazard: nothing about it is unsafe, it is just not "
                   "lowered yet.")
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
            stages.append(CqlRename(old=old, new=new))
        else:
            raise Refusal(
                "CQL_PIPE_NOT_LOWERED",
                f"`| {name}` is a real CQL command, but only `| table`, "
                f"`| sort`, `| rename`, `| count()`, `| groupBy(...)`, and "
                f"`| :=` lower today. Refused by name rather than dropped -- "
                f"dropping a pipe stage silently changes which rows come back.",
                DIALECT)
    return CqlQuery(filt=filt, stages=tuple(stages))


def _claim(stages: list[CqlStage], seen: set[str], kind: str, code: str,
           why: str) -> None:
    """Refuse a REPEATED pipe of the same kind, once, by name.

    A set rather than four `is not None` checks, because the stages are now a
    list and "have I already seen one" is the only question the refusal asks.
    """
    if kind in seen:
        raise Refusal(code, why, DIALECT)
    seen.add(kind)


def _join_refusal(args: str) -> tuple[str, str]:
    """`join()` is refused, and the reason is SPECIFIC rather than "not yet".

    Measured against LogScale's own `join()` reference, this is not a pipeline
    stage that happens to resemble the IR's `Join` node. It is a FILTER function
    with eleven named parameters, and the defaults are load-bearing:

      - `mode=inner` (default) keeps only events matching in both queries;
        `mode=left` keeps every left event. Different rows survive.
      - `max=1` (default) takes ONE subquery row per key. Two subquery rows
        sharing a key produce ONE output row, not two. This is a fan-in limit,
        and the IR's `Join` has no field for it -- there is nowhere to record a
        number that changes how many rows come back.
      - `include=[...]` adds the named subquery fields to matching events, and
        the documentation is explicit that a subquery event missing one of them
        outputs THE EMPTY STRING. This project treats NULL and "" as DISTINCT
        values throughout, because a detection that cannot tell "field absent"
        from "field empty" is a detection that cannot be trusted. Fabricating ""
        here would put a lie into the output row.
      - `limit=100000` caps the subquery, and `repo=`/`view=`/`start=`/`end=`
        let it read a different repository or time range than the main query.
        A subquery over different data is not a join over this data.

    So the refusal names these rather than saying "unsupported", because "not
    implemented yet" invites the reader to think a `Join` node is one commit
    away when the node does not have the fields the construct needs. The KQL
    `Join` producer is the reference for what this IR CAN express: same-named
    key equality, inner or left, nothing else.
    """
    mode = "inner"
    lowered = args.lower()
    if "mode=" in lowered:
        at = lowered.index("mode=")
        mode = args[at + 5:].split(",")[0].split("}")[0].strip() or "?"
    detail = f"`mode={mode}`" if mode else "`mode`"
    return (
        "CQL_JOIN_NOT_LOWERED",
        f"`join()` is a LogScale FILTER function, not a pipeline stage, and this "
        f"tool does not lower it. {detail} decides which rows survive; `max=1` "
        f"by default takes one subquery row per key, so two subquery rows "
        f"sharing a key yield one output row; and per LogScale's own reference, "
        f"`include=[...]` fills a missing subquery field with THE EMPTY STRING, "
        f"which this engine refuses to fabricate because it keeps absent and "
        f"empty distinct. The IR's `Join` node has fields for same-named key "
        f"equality and inner/left, and no field for a per-key fan-in limit, an "
        f"`include` list, or a subquery over a different repo or time range. "
        f"Refused rather than lowered as a plain join, which would be a "
        f"different rule returning different rows.")


def _parse_groupby(text: str, args: str) -> CqlGroupBy:
    """`groupBy([a, b])`, `groupBy([a], function=count())`, `function=[count(as=n)]`.

    MEASURED AGAINST LOGSCALE'S REFERENCE, which states the shape plainly:
    `groupBy(field, [function], [limit])`, `field` required, `function` an array
    of aggregate functions defaulting to `count(as=_count)`, and `limit`
    defaulting to 20,000 with top-N series selection semantics.

    THE OUTPUT COLUMN NAME IS DATA, NOT A FORMATTING CHOICE. The default is
    literally `_count`, and `count(as=total)` names it `total`. A renderer that
    assumed the nullary `count()` shape would emit `| groupBy([a])` for a rule
    whose columns are `a` and `total`, renaming a column downstream queries
    read. So the name is parsed and carried, and the render arm emits it back.

    WHAT IS REFUSED, AND WHY EACH IS A DIFFERENT RULE RATHER THAN A MISSING
    FEATURE:

      `function=[]`      unique values, NOTHING aggregated. One row per value
                         and no measure column. Not a count of zero per group.
      `limit=N`          top-N SERIES SELECTION: it keeps the N groups with the
                         highest aggregate, dropping the rest. A cap, not a
                         filter, and the rows that disappear are the whole point.
      nested `groupBy`   a groupBy inside a groupBy, which changes the shape of
                         the output to a nested structure.
      embedded `{...}`   a sub-PIPELINE inside the function list, e.g.
                         `function=[{count() | esp:=_count/300}]`. That is a
                         whole pipeline where this expects one function.
    """
    if "{" in args:
        raise Refusal(
            "CQL_GROUPBY_EMBEDDED_PIPELINE",
            f"`groupBy({args})` embeds a sub-pipeline inside its function list. "
            f"That is a nested pipeline where this expects a single function, "
            f"and it computes per-group expressions this lowering does not "
            f"build. Refused rather than read as a plain count.", DIALECT)
    if "groupby(" in args.lower().replace(" ", ""):
        raise Refusal(
            "CQL_GROUPBY_NESTED",
            f"`groupBy({args})` nests one groupBy inside another, which produces "
            f"a nested output structure rather than one row per key. Refused "
            f"rather than flattened into a single grouping.", DIALECT)

    keys_raw, tail = _split_groupby_params(args)
    keys = _parse_groupby_keys(keys_raw, text)
    measure_name = "_count"
    tail = tail.strip()
    if not tail:
        return CqlGroupBy(keys=keys, measure_name=measure_name)
    lowered = tail.lower()
    if not lowered.startswith("function"):
        raise Refusal(
            "CQL_GROUPBY_PARAMETER_UNKNOWN",
            f"`groupBy({args})` has a parameter this lowering does not read "
            f"(`{tail.split('=')[0].strip()}`). An accepted-and-ignored parameter "
            f"is worse than a refusal, because the rule runs and returns "
            f"something other than what was written.", DIALECT)
    body = tail.partition("=")[2].strip()
    if not lowered.startswith("function="):
        raise Refusal(
            "CQL_GROUPBY_PARAMETER_UNKNOWN",
            f"`groupBy({args})` needs `function=` before its function list. "
            f"Refused rather than guessed at which half was meant.", DIALECT)
    if body in ("[]", ""):
        raise Refusal(
            "CQL_GROUPBY_NO_AGGREGATE",
            f"`groupBy({args}, function=[])` asks for the DISTINCT VALUES with "
            f"nothing aggregated: one row per value and no measure column. That "
            f"is not a count of zero per group, so it is a different result "
            f"shape and is refused rather than folded into a count.", DIALECT)
    named = _parse_groupby_function(body, args)
    return CqlGroupBy(keys=keys, measure_name=named)


def _split_groupby_params(args: str) -> tuple[str, str]:
    """Split on the first COMMA THAT IS NOT INSIDE BRACKETS.

    `groupBy([a, b], function=count())` has a comma inside `[a, b]` and another
    after it. Splitting on the first one regardless took `[a` as the key list,
    saw an unclosed `[`, and refused a perfectly valid query -- and the message
    named `groupBy(groupBy([a, b]))`, quoting the pipe twice, because the
    caller passes the whole `groupBy(...)` text. Both are the "misleading refusal
    on valid input" defect, reached through a missing depth check rather than
    through a wrong decision.
    """
    depth = 0
    quote: str | None = None
    for index, char in enumerate(args):
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        elif char == "," and depth == 0:
            return args[:index], args[index + 1:].strip()
    return args, ""


def _parse_groupby_keys(raw: str, text: str) -> tuple[str, ...]:
    """The `field` parameter: `a`, `[a]`, `[a, b]`, or any of those with a
    `field=` prefix. LogScale allows all four; the brackets are optional and
    the parameter name may be omitted."""
    body = raw.strip()
    # `field=` is peeled FIRST, and the brackets after -- the other order read
    # `field=[a]` as the single key `field=[a]` and refused it as a malformed
    # column name, which is a refusal on input LogScale documents.
    prefix, sep, rest = body.partition("=")
    if sep:
        if prefix.strip().lower() != "field":
            raise Refusal(
                "CQL_GROUPBY_KEYS_MALFORMED",
                f"`groupBy({text.strip()})` has an unrecognised first "
                f"parameter `{prefix.strip()}`. `field` is the only one that "
                f"names the keys, and reading any other as a column would "
                f"group by a field the analyst never named.", DIALECT)
        body = rest.strip()
    if body.startswith("["):
        if not body.endswith("]"):
            raise Refusal("CQL_GROUPBY_KEYS_MALFORMED",
                          f"`groupBy({text.strip()})` has an unclosed `[`. "
                          f"Refused rather than guessed.", DIALECT)
        body = body[1:-1]
    keys = tuple(part.strip() for part in body.split(",") if part.strip())
    if not keys:
        raise Refusal(
            "CQL_GROUPBY_NO_KEYS",
            f"`groupBy({text.strip()})` groups by nothing, which would collapse "
            f"every event into a single group. Refused rather than treated as a "
            f"count, which is a different query.", DIALECT)
    for key in keys:
        _check_field_name(key, "groupBy key")
    return keys


def _parse_groupby_function(body: str, whole: str) -> str:
    """`count()` or `[count(as=name)]` -> the measure's output column name."""
    inner = body.strip()
    if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1].strip()
    if not inner.startswith("count"):
        raise Refusal(
            "CQL_GROUPBY_FUNCTION_NOT_LOWERED",
            f"`groupBy(..., function={body})` is not a count. This slice lowers "
            f"the grouped count only -- every other aggregate is a different set "
            f"of rows, and a count here would answer a different question.",
            DIALECT)
    rest = inner[len("count"):].strip()
    if not rest:
        return "_count"
    if rest == "()":
        return "_count"
    if rest.startswith("(as=") and rest.endswith(")"):
        name = rest[4:-1].strip()
        if not name:
            raise Refusal(
                "CQL_GROUPBY_MEASURE_NAME_EMPTY",
                f"`groupBy(..., function={body})` names no output column, so the "
                f"count would land in a column with no name. Refused rather "
                f"than invented.", DIALECT)
        _check_field_name(name, "count output column")
        return name
    raise Refusal(
        "CQL_GROUPBY_FUNCTION_NOT_LOWERED",
        f"`groupBy(..., function={body})` is not a plain count. Only "
        f"`count()` and `count(as=name)` lower; anything else is a different "
        f"aggregate and is refused rather than approximated.", DIALECT)


def _parse_count(text: str, args: str) -> CqlCount:
    """`| count()` and nothing else.

    An aggregate is NOT a projection or a filter -- it collapses many rows into
    one, so every stage after it sees a different rowset. That is why this is a
    stage in the ordered list rather than a detail of the query.

    `count(field=x)` is refused separately, not folded in: it counts rows where
    `x` is PRESENT, which is a different question from "how many rows". Reading
    it as a field count would turn "how many of these events" into "how many of
    these events have an x", which is a rule that returns a different number.
    """
    if not args:
        return CqlCount()
    if args.lower().startswith("field="):
        raise Refusal(
            "CQL_COUNT_FIELD_NOT_LOWERED",
            f"`count({args})` counts the rows where a field is PRESENT, which is "
            f"a different question from `count()`'s \"how many rows\". Taking the "
            f"field and ignoring it would return a number the analyst did not "
            f"ask for, so it is refused rather than approximated.", DIALECT)
    if args.lower().startswith("by ") or args.lower().startswith("by="):
        raise Refusal(
            "CQL_COUNT_BY_NOT_LOWERED",
            f"`count({args})` groups the count, which is a different aggregate "
            f"shape (grouped keys, not one number) and is not lowered yet. "
            f"Refused rather than counted ungrouped.", DIALECT)
    raise Refusal(
        "CQL_COUNT_NOT_NULLARY",
        f"`| {text.strip()}` is not `count()`. CQL aggregates take a field or a "
        f"`by` grouping, both of which change which rows the count describes; "
        f"only the nullary `count()` lowers.", DIALECT)


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
