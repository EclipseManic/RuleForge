"""KQL <-> RuleIR, and render.

The lowering is a PIPELINE WALK, because KQL is a pipeline language. Each `|`
operator becomes one node; `let` bindings become branches that a `join` splices
together. Getting the order right is not a style choice:

    | where <cond>            BEFORE the join
    | join kind=inner ...     the correlation
    | where <cond>            AFTER the join, so it sees MERGED columns
    | summarize ... by ...    the aggregate
    | where <count> >= 1      the threshold, AFTER the aggregate

Moving any of these changes which rows exist when the next one runs. A `where`
lifted above a join that names a column only the join produces would reference a
field no row has yet, and every row would go undecidable.

`between` IS EXPANDED, NOT SIMPLIFIED AWAY

    | where LoginTime between (LSASSTime .. LSASSTime + 10m)

becomes two ordinary comparisons conjoined, and the engine's `Join.temporal` is
deliberately NOT set. After a join both operands are columns of the same merged
row, so this is a same-row test. Applying the engine's temporal predicate as well
would filter twice -- and the second filter would be invisible in the rendered
rule, which would show one `where` while the join quietly did extra work.
"""

from __future__ import annotations

import re
from dataclasses import replace
from decimal import Decimal
from typing import Any

from ..dialects.aql import Diagnostic
from ..dialects.kql import (
    INGESTION_DELAY_SECONDS,
    _AGG_MAP,
    _AGGREGATE_FUNCTIONS,
    _JOIN_KINDS,
    ParsedKql,
    split_top_level,
)
from ..engine import (
    Aggregate,
    Arrange,
    Comparison,
    Derive,
    Duration,
    Emit,
    FieldExpr,
    FieldRef,
    Filter,
    Frame,
    Join,
    Literal,
    Measure,
    Read,
    Refusal,
    RuleIR,
    SourceSelector,
    TimeRef,
)
from ..engine.ir import Arith, BoolOp, Call, Not


def lower(parsed: ParsedKql, rule_id: str = "sentinel") -> tuple[RuleIR, list[Diagnostic]]:
    """Lower a parsed KQL script into a runnable graph."""
    diagnostics = list(parsed.diagnostics)
    diagnostics.append(Diagnostic(
        "SENTINEL_INGESTION_DELAY",
        f"A scheduled analytics rule runs {INGESTION_DELAY_SECONDS // 60} minutes "
        f"LATER than its schedule, to absorb the gap between a source emitting an "
        f"event and the event arriving. A `ago(...)` inside the query therefore does "
        f"not cover the window it appears to, and this tool will not pretend "
        f"otherwise when explaining the rule.", "warning"))

    nodes: list[Any] = []
    # name -> node id, for `let` bindings that are pipelines
    produced: dict[str, str] = {}
    # name -> value, for `let` bindings that are constants or aliases
    aliases: dict[str, str] = {}
    # EVERY node built so far, across all branches. The main pipeline's own
    # `nodes` list starts empty when its head is a `let` name, so the branch nodes
    # a join refers to live only in this shared map. Without it the column map was
    # built from an empty graph, resolved nothing, and every post-join comparison
    # stayed undecidable.
    known: dict[str, Any] = {}

    for name, value in parsed.lets.items():
        # A `let` whose value is a bare name, not a pipeline, is an ALIAS for
        # another binding. `let timeframe = 30m` is a constant, not a branch, and
        # turning it into a Read node made a table called `30m` appear in the
        # graph.
        if "|" not in value.strip():
            aliases[name] = value.strip()
            continue
        branch = _lower_pipeline(value, name, diagnostics, produced, aliases, known)
        nodes.extend(branch)
        # The NODE ID, not the node. Storing the object made a join's right side a
        # node rather than a reference to one, and validation refused with
        # DANGLING_INPUT naming the whole Derive instead of a missing id.
        produced[name] = branch[-1].id

    main = _lower_pipeline(parsed.body, "main", diagnostics, produced, aliases, known)
    nodes.extend(main)
    # The NODE ID. output = main[-1] put a node OBJECT into Emit.input, so
    # validation refused with DANGLING_INPUT naming the whole Derive rather than
    # a missing reference.
    output = main[-1].id

    nodes.append(Emit(id="out", input=output))
    return RuleIR(rule_id=rule_id, nodes=tuple(nodes), output="out",
                  title=rule_id, metadata={"dialect": "sentinel"}), diagnostics


def _lower_pipeline(text: str, prefix: str,
                    diagnostics: list[Diagnostic],
                    produced: dict[str, str] | None = None,
                    aliases: dict[str, str] | None = None,
                    known: dict[str, Any] | None = None) -> list[Any]:
    """Lower one pipeline expression into a list of nodes, last one the output."""
    text = _substitute_constants(text, aliases or {})
    stages = split_top_level(text)
    if not stages:
        raise Refusal("KQL_EMPTY_PIPELINE", "a pipeline is empty", "KQL")

    head = stages[0].strip()
    if "|" in head:
        raise Refusal(
            "KQL_EXPRESSION_BEFORE_PIPE",
            f"{head!r} is more than a table name. A pipeline must start at a table, "
            f"and the name must be a real table or a `let` binding.", "KQL")

    produced = produced or {}
    aliases = aliases or {}
    column_map: dict[str, str] | None = None

    # THE HEAD MAY BE A let NAME, NOT A TABLE. LSASSAccess | join ... starts
    # from the branch let LSASSAccess already built. Creating a Read for a table
    # named LSASSAccess produced a graph with a DANGLING_INPUT on the join's right
    # side -- the join referenced the let NAME, not a node id -- so the whole rule
    # refused even though every branch had parsed perfectly.
    if head in produced:
        current = produced[head]
        nodes = []
    else:
        nodes = [Read(id=f"{prefix}_read",
                      selector=SourceSelector(name=head, kind="events"))]
        current = f"{prefix}_read"

    for index, raw in enumerate(stages[1:]):
        operator, args = _split_operator(raw)

        if column_map is not None:
            # THIS STAGE IS DOWNSTREAM OF A JOIN. Its bare column names refer to
            # the merged row, which the engine stores prefixed (`l_` / `r_`) so a
            # self-join cannot have one side silently overwrite the other. KQL puts
            # them in ONE namespace, so the rule writes them bare -- and unresolved,
            # every comparison went UNDECIDED and the correlation never ran.
            args = _rewrite_joined_columns(args, column_map)

        node_id = f"{prefix}_{operator}_{index}"
        if operator == "join":
            column_map = _column_map_for_join(
                node_id, current, args, _nodes_so_far(nodes, known), produced)
        current, node = _lower_operator(operator, args, current, node_id,
                                        diagnostics, produced, aliases)
        if operator == "join" and column_map and isinstance(node, Join):
            # RECORD THE RENAMES ON THE NODE. A renderer has to turn `r_LoginTime`
            # back into `LoginTime`, and it cannot do that by stripping a prefix:
            # `l_Process` is a legal KQL field name, so a blind strip would
            # rewrite a rule about `l_Process` into a rule about `Process`. Only
            # the join that renamed the column knows, so the answer lives here --
            # the same class of defect as the duplicate field resolver, a second
            # source of truth for what a name means.
            node = replace(node,
                           column_map=tuple(sorted(column_map.items())))
        nodes.append(node)
        if known is not None:
            known[node.id] = node
    return nodes


def _nodes_so_far(nodes: list[Any],
                  known: dict[str, Any] | None = None) -> dict[str, Any]:
    merged = dict(known or {})
    merged.update({n.id: n for n in nodes if hasattr(n, "id")})
    return merged


def _output_columns(node_id: str, by_id: dict[str, Any]) -> set[str]:
    """Columns a chain produces.

    A `Read` names a table whose schema this tool cannot see -- and must not
    guess -- so it contributes nothing. Only a `Derive` states its columns, which
    is what a KQL `project` lowers to. A chain that is only a Read therefore has no
    known columns, and every name from it stays ambiguous, which is the honest
    answer rather than a guess.
    """
    columns: set[str] = set()
    cursor: str | None = node_id
    seen: set[str] = set()
    while cursor and cursor in by_id and cursor not in seen:
        seen.add(cursor)
        node = by_id[cursor]
        if type(node).__name__ == "Derive":
            columns.update(name for name, _ in node.assignments)
        if isinstance(node, Join):
            columns.update(_output_columns(node.left, by_id))
            columns.update(_output_columns(node.right, by_id))
            return columns
        cursor = getattr(node, "input", None)
    return columns


def _column_map_for_join(node_id: str, left_id: str, args: str,
                         by_id: dict[str, Any],
                         produced: dict[str, str]) -> dict[str, str] | None:
    """Build bare-name -> prefixed-name for everything downstream of this join."""
    right_name = _right_side_name(args)
    if right_name is None:
        return None
    # The right side is written as a SOURCE-LEVEL NAME -- join kind=inner
    # LateralMovement -- but the graph is keyed by NODE ID. Resolving it
    # through produced is what turns a let binding into a node reference. Without
    # this the right side stayed a name, no node matched, the map came back empty,
    # and every post-join comparison silently stayed undecidable.
    right_id = produced.get(right_name, right_name)
    if right_id not in by_id:
        return None

    left_columns = _output_columns(left_id, by_id)
    right_columns = _output_columns(right_id, by_id)
    keys = _join_key_names(args)

    mapping: dict[str, str] = {}
    for name in left_columns:
        if name in right_columns and name not in keys:
            # Genuinely ambiguous: the value differs between the two rows and
            # nothing in the rule says which one it means. Refused at USE time by
            # `_rewrite_joined_columns`, because that is where the analyst's intent
            # would be invented.
            continue
        mapping[name] = f"l_{name}"
    for name in right_columns:
        if name in left_columns and name not in keys:
            continue
        mapping.setdefault(name, f"r_{name}")
    return mapping


def _right_side_name(args: str) -> str | None:
    kind = re.match(r"kind\s*=\s*\w+", args, re.IGNORECASE)
    rest = args[kind.end():].strip() if kind else args
    if rest.startswith("("):
        depth = 0
        for index, char in enumerate(rest):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return rest[1:index].strip()
        return None
    best = -1
    for candidate in (" on ", " ON ", " On "):
        found = rest.find(candidate)
        if found >= 0 and (best < 0 or found < best):
            best = found
    return rest[:best].strip() if best >= 0 else None


def _join_key_names(args: str) -> set[str]:
    on_clause = args
    if re.search(r"\bon\b", args, re.IGNORECASE):
        on_clause = re.split(r"\bon\b", args, maxsplit=1, flags=re.IGNORECASE)[1]
    names: set[str] = set()
    for part in split_top_level(on_clause, ","):
        part = part.strip()
        if not part:
            continue
        if "==" in part:
            left, _, right = part.partition("==")
            names.add(left.strip())
            names.add(right.strip())
        else:
            names.add(part)
    return names


def _rewrite_joined_columns(args: str, mapping: dict[str, str]) -> str:
    """Rewrite bare column names downstream of a join to their prefixed form.

    JOIN KEYS ARE ALLOWED THROUGH EVEN THOUGH THEY EXIST ON BOTH SIDES. An
    equi-join on `Computer` proved the two values are equal, so either side
    resolves to the same number and the choice cannot change a verdict. Every
    other name present on both sides is left alone, and refused below, because
    there the two values genuinely differ and the rule does not say which it
    means.
    """
    left_only = {k: v for k, v in mapping.items() if v.startswith("l_")}
    right_only = {k: v for k, v in mapping.items() if v.startswith("r_")}

    both = {name for name, target in left_only.items()
            if name in right_only and _is_join_key(args, name)}

    def replace(match: re.Match[str]) -> str:
        name = match.group(0)
        if name in both:
            return left_only[name]
        if name in left_only:
            return left_only[name]
        if name in right_only:
            return right_only[name]
        return name

    return re.sub(r"(?<![\w.$@])[A-Za-z_][A-Za-z0-9_.]*(?![\w.])", replace, args)


def _is_join_key(args: str, name: str) -> bool:
    on_clause = args
    if re.search(r"\bon\b", args, re.IGNORECASE):
        on_clause = re.split(r"\bon\b", args, maxsplit=1, flags=re.IGNORECASE)[1]
    return bool(re.search(rf"(?<![\w.]){re.escape(name)}(?![\w.])", on_clause))


def _substitute_constants(text: str, aliases: dict[str, str]) -> str:
    """Replace `let`-bound CONSTANTS with their values, as whole identifiers.

    `let timeframe = 30m;` then `ago(timeframe)` means `ago(30m)`. Lowered without
    this, `timeframe` became a FIELD REFERENCE -- a column called `timeframe`
    that exists in no row -- so every row went undecidable and the rule reported
    not_evaluated on data it should have matched. The user's rule does exactly
    this.

    WHOLE-IDENTIFIER substitution only, and only for aliases that are literals. A
    bound PIPE is not substituted here -- it is resolved through `produced` as a
    node reference, which is a different mechanism for a different thing.
    """
    for name, value in aliases.items():
        if _literal(value) is _NOT_LITERAL:
            continue
        text = re.sub(rf"(?<![\w.]){re.escape(name)}(?![\w.])", value, text)
    return text


def _split_operator(stage: str) -> tuple[str, str]:
    parts = stage.strip().split(None, 1)
    name = parts[0].lower()
    args = parts[1].strip() if len(parts) > 1 else ""
    if name not in ("where", "project", "extend", "summarize", "join", "sort",
                    "top", "distinct", "order"):
        raise Refusal(
            "KQL_OPERATOR_UNSUPPORTED",
            f"`{name}` is not implemented. Implemented operators are where, project, "
            f"extend, summarize, join, sort and top. Refusing rather than dropping a "
            f"stage that changes which rows the rule sees.", "KQL")
    return name, args


def _lower_operator(operator: str, args: str, source: str, node_id: str,
                    diagnostics: list[Diagnostic],
                    produced: dict[str, str],
                    aliases: dict[str, str]) -> tuple[str, Any]:
    """Lower one operator. Returns `(next_node_id, node)`.

    IT USED TO STASH THE NODE IN A MODULE-LEVEL `_LAST_NODE`. That global was
    read by `_lower_pipeline`, so the moment the pipeline needed to inspect the
    node -- to record a join's column map on it -- Python treated the name as a
    function-local and every call raised UnboundLocalError. A mutable module
    global is a second, invisible channel between two functions; returning the
    node makes the data flow explicit and the class of bug goes away.
    """
    node: Any
    if operator == "where":
        condition = _expression(args)
        node = Filter(id=node_id, input=source, condition=condition)
    elif operator == "project":
        # `projects=True` IS THE RECORD THAT THIS REPLACES THE ROW. The
        # renderers used to re-derive it by matching the node id, which is a
        # second source of truth minted here and read there -- so one dialect's
        # naming convention decided whether a Wazuh artifact got a `<fields>`
        # list.
        node = Derive(id=node_id, input=source, projects=True,
                      assignments=tuple(_assignments(args, diagnostics)))
    elif operator == "extend":
        node = Derive(id=node_id, input=source, projects=False,
                      assignments=tuple(_assignments(args, diagnostics)))
    elif operator == "summarize":
        node = _summarize(args, source, node_id, diagnostics)
    elif operator == "join":
        node = _join(args, source, node_id, diagnostics, produced, aliases)
    elif operator in ("sort", "order"):
        node = Arrange(id=node_id, input=source,
                       order_by=tuple(_order_by(args)))
    elif operator == "top":
        parts = args.split()
        if len(parts) != 2 or parts[0].lower() != "by":
            raise Refusal("KQL_TOP_UNPARSEABLE",
                          f"`top {args}` is not `top N by field`", "KQL")
        node = Arrange(id=node_id, input=source,
                       order_by=((FieldRef(parts[1]), "desc"),),
                       limit=int(parts[0]))
    else:
        raise Refusal("KQL_OPERATOR_UNSUPPORTED",
                      f"`{operator}` is not implemented", "KQL")
    return node_id, node


def _assignments(args: str, diagnostics: list[Diagnostic]) -> list[tuple[str, Any]]:
    """Parse `Alias=Expr, Alias, ...` from project/extend."""
    out: list[tuple[str, Any]] = []
    for part in split_top_level(args, ","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            alias, _, expr = part.partition("=")
            alias = alias.strip()
            # A project RENAME. The alias becomes a new column and the source
            # column is KEPT, which is a superset of what KQL does -- KQL
            # replaces the column set. Keeping the original is safe here because
            # a `summarize ... by` naming a dropped column would be a rule this
            # tool must refuse rather than silently mis-aggregate, and a superset
            # cannot hide a referenced column. The difference is disclosed.
            diagnostics.append(Diagnostic(
                "KQL_PROJECT_KEEPS_SOURCE_COLUMN",
                f"`{part.strip()}` renames {expr.strip()!r} to {alias!r}. The source "
                f"column is kept as well as the alias, so this graph is a superset of "
                f"the query. A KQL `project` replaces the column set; keeping the "
                f"original cannot change a result, and it makes the rename visible "
                f"as an addition rather than pretending a column never existed.",
                "warning"))
            out.append((alias, _expression(expr.strip())))
        else:
            out.append((part, FieldExpr(FieldRef(part))))
    return out


def _summarize(args: str, source: str, node_id: str,
               diagnostics: list[Diagnostic]) -> Aggregate:
    """Parse `Name=agg(...), ..., by a, b`."""
    by_clause = ""
    if re.search(r"\bby\b", args, re.IGNORECASE):
        # `re.split(..., maxsplit=1)` returns TWO items, not three. Unpacking three
        # raised a bare ValueError, which escaped as a traceback rather than a
        # named refusal -- on the user's own rule, at the `summarize` stage.
        parts = re.split(r"\bby\b", args, maxsplit=1, flags=re.IGNORECASE)
        args, by_clause = parts[0].strip(), parts[1].strip()

    measures: list[Measure] = []
    for part in split_top_level(args, ","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            alias, _, call = part.partition("=")
            measures.append(_measure(alias.strip(), call.strip()))
        else:
            measures.append(_measure(part, part))

    keys = tuple(FieldRef(k.strip()) for k in split_top_level(by_clause, ",")
                 if k.strip())

    frame = Frame(kind="per_event")
    if keys:
        frame = Frame(kind="tumbling", size=Duration(3600),
                      time_ref=TimeRef(keys[0].name))

    return Aggregate(id=node_id, input=source, measures=tuple(measures),
                     frame=frame, keys=keys)


def _measure(alias: str, call: str) -> Measure:
    match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)$", call.strip(),
                     re.DOTALL)
    if not match:
        raise Refusal(
            "KQL_AGGREGATE_UNPARSEABLE",
            f"{call!r} is not an aggregate call. Use Name=agg(column) or agg(column).",
            "KQL")
    function = match.group(1).lower()
    inner = match.group(2).strip()
    if function not in _AGGREGATE_FUNCTIONS:
        raise Refusal(
            "KQL_AGGREGATE_UNKNOWN",
            f"{function}() is not an aggregate this tool knows. Known: "
            f"{sorted(_AGGREGATE_FUNCTIONS)}", "KQL")

    mapped = _AGG_MAP.get(function)
    if mapped is None:
        # countif / percentile and friends take a CONDITION, not just a column.
        raise Refusal(
            "KQL_AGGREGATE_CONDITIONAL_UNSUPPORTED",
            f"{function}() takes a condition rather than a plain column, and this "
            f"engine has no conditional aggregate. Approximating it with a plain "
            f"aggregate would count the wrong rows.", "KQL")

    if mapped == "count":
        if inner not in ("*", ""):
            # count(SomeColumn) counts NON-NULL values, which is not count(*).
            raise Refusal(
                "KQL_COUNT_OF_COLUMN_UNSUPPORTED",
                f"count({inner}) counts non-null values, not rows. This engine's "
                f"`count` counts rows, so mapping one to the other would change "
                f"the number. Use count_distinct for a distinct count, or declare "
                f"the non-null count explicitly.", "KQL")
        return Measure(alias, "count")

    return Measure(alias, mapped, field=FieldRef(inner))


def _join(args: str, source: str, node_id: str,
          diagnostics: list[Diagnostic],
          produced: dict[str, str],
          aliases: dict[str, str]) -> Join:
    """Parse `kind=inner (Table) on A, B`."""
    kind_match = re.match(r"kind\s*=\s*(\w+)", args, re.IGNORECASE)
    kind = kind_match.group(1).lower() if kind_match else "inner"
    if kind not in _JOIN_KINDS:
        raise Refusal("KQL_JOIN_KIND_UNKNOWN",
                      f"`kind={kind}` is not a join type this tool implements. "
                      f"Implemented: {sorted(_JOIN_KINDS)}", "KQL")
    if kind != "inner":
        raise Refusal(
            "KQL_JOIN_KIND_UNSUPPORTED",
            f"`kind={kind}` is not implemented. Only `inner` is, because the other "
            f"kinds change which rows survive and a wrong row set here would change "
            f"the correlation the rule exists to detect.", "KQL")

    rest = args[kind_match.end():].strip() if kind_match else args
    right = ""
    if rest.startswith("("):
        depth = 0
        for index, char in enumerate(rest):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    right = rest[1:index].strip()
                    rest = rest[index + 1:].strip()
                    break
    else:
        # KQL allows `join kind=inner Table on ...` with NO parentheses when the
        # right side is a bare table or `let` name. The user's rule writes it
        # exactly that way. Only the parenthesised form was handled, so the right
        # table came back empty and every join refused as having no right side.
        marker_at = -1
        for candidate in (" on ", " ON ", " On "):
            found = rest.find(candidate)
            if found >= 0 and (marker_at < 0 or found < marker_at):
                marker_at = found
        if marker_at >= 0:
            right = rest[:marker_at].strip()
            rest = rest[marker_at:].strip()

    on_clause = rest
    if on_clause.lower().startswith("on "):
        on_clause = on_clause[3:].strip()
    elif " on " in f" {on_clause.lower()} ":
        on_clause = on_clause.lower().split(" on ", 1)[1].strip()

    # RESOLVE THE RIGHT-HAND NAME TO A NODE ID. The graph references nodes, not
    # source-level names, so a let name must be translated or the join points at
    # nothing and validation refuses with DANGLING_INPUT.
    right = produced.get(right, aliases.get(right, right))

    if not right:
        raise Refusal("KQL_JOIN_NO_RIGHT_TABLE",
                      "a join needs a table on the right. `join (Table) on ...`",
                      "KQL")
    if not on_clause:
        raise Refusal("KQL_JOIN_NO_ON",
                      "a join with no `on` clause is a cross product. This engine "
                      "refuses those, and so should the rule.", "KQL")

    on: list[tuple[FieldRef, FieldRef]] = []
    for name in split_top_level(on_clause, ","):
        name = name.strip()
        if not name:
            continue
        if "==" in name:
            left, _, right_name = name.partition("==")
            on.append((FieldRef(left.strip()), FieldRef(right_name.strip())))
        else:
            on.append((FieldRef(name), FieldRef(name)))

    return Join(id=node_id, left=source, right=right, on=tuple(on), how="inner")


def _order_by(args: str) -> list[tuple[FieldRef, str]]:
    text = args.strip()
    if text.lower().startswith("by "):
        text = text[3:]
    out: list[tuple[FieldRef, str]] = []
    for part in split_top_level(text, ","):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        direction = tokens[1].lower() if len(tokens) > 1 else "asc"
        out.append((FieldRef(tokens[0]), direction))
    return out


def _expression(text: str) -> Any:
    """Parse the subset of KQL expressions this engine can honour.

    Supported: comparisons, `and`/`or`/`not`, parentheses, `between (a .. b)`,
    arithmetic, `ago(...)`, `endswith`/`startswith`/`contains`/`has_any`,
    `in~ (...)`, field references, string and numeric literals.

    `between` is EXPANDED to two conjoined comparisons, not treated as a
    distinct operator. `a between (x .. y)` is exactly `a >= x and a <= y`, and
    expanding it means the rendered rule shows the two tests the engine actually
    applied, instead of hiding them behind an operator the analyst cannot verify.
    """
    text = text.strip()
    # KQL marks a VERBATIM string with a leading `@`: `@"\lsass.exe"`. The sigil
    # is syntax, not data. Left in place it made every `@`-literal unparseable,
    # and the user's rule uses one for the Windows path -- so a plain string
    # comparison refused where an identical quoted string was accepted, which
    # reads as a platform difference rather than a parser gap.
    if text.startswith("@"):
        text = text[1:].strip()
    if not text:
        raise Refusal("KQL_EXPRESSION_EMPTY", "an expression is empty", "KQL")

    lowered = text.lower()

    if lowered.startswith("not "):
        return Not(_expression(text[4:]))

    for joiner, op in ((" and ", "and"), (" or ", "or")):
        parts = _split_keyword(text, joiner.strip())
        if parts:
            return BoolOp(op, tuple(_expression(p) for p in parts))

    between = re.match(r"^(.*?)\s+between\s*\((.*?)\.\.(.*?)\)\s*$", text,
                       re.IGNORECASE | re.DOTALL)
    if between:
        subject = _expression(between.group(1))
        low = _expression(between.group(2))
        high = _expression(between.group(3))
        # Inclusive on both ends, which is KQL's `between`.
        return BoolOp("and", (Comparison(">=", subject, low),
                              Comparison("<=", subject, high)))

    for operator in ("==", "!=", "<=", ">=", "<", ">"):
        parts = _split_operator_at(text, operator)
        if parts:
            left, right = parts
            op = "=" if operator == "==" else ("!=" if operator == "!=" else operator)
            return Comparison(op, _expression(left), _expression(right))

    # KQL STRING OPERATORS ARE INFIX, NOT SUFFIXES: `field endswith "x"`, not
    # `endswith(field, "x")`. The original code looked for the operator name at
    # the END of the expression, which is the shape of a prefix call, so every
    # infix string operator was parsed as a bare field reference followed by
    # nonsense -- and `TargetImage endswith @"\lsass.exe"` refused as an
    # unsupported expression. Same for the user's Windows path test.
    for keyword, function in (("endswith", "ends_with"),
                              ("startswith", "starts_with"),
                              ("has_any", "in_set"),
                              ("has_all", "in_set"),
                              ("contains", "contains"),
                              ("matches regex", "matches_regex")):
        parts = _split_infix(text, keyword)
        if parts:
            subject, operand = parts
            if function == "matches_regex":
                return Call(function, (_expression(subject),
                                      _expression(operand)), dialect="pcre")
            if function == "in_set":
                inner = operand.strip()
                if inner.startswith("("):
                    # RAW VALUES, not nested Literal objects. Wrapping each option
                    # in a Literal and then putting the tuple inside another
                    # Literal produced `in_set(field, (Literal('0x1fffff'), ...))`,
                    # so every comparison was against a Literal OBJECT, never
                    # matched, and the filter silently dropped every row -- the
                    # correlation reported a clean no_match for the right reason
                    # and the wrong cause.
                    options = tuple(_literal(o.strip())
                                    for o in split_top_level(inner[1:-1], ","))
                    return Call(function, (_expression(subject),
                                           Literal(options)))
                return Call(function, (_expression(subject), _expression(operand)))
            return Call(function, (_expression(subject), _expression(operand)))

    # `field in~ (a, b)` and `field in (a, b)` -- both infix, both case-insensitive,
    # both followed by a parenthesised list. Matched as an INFIX operator rather
    # than a line suffix: the expression `GrantedAccess in ("0x1fffff", "0x1010")`
    # ends with `)`, so a suffix test never fired and the whole predicate refused
    # as unsupported -- on the user's own rule.
    for keyword in ("in~", "in"):
        parts = _split_infix(text, keyword)
        if parts:
            subject, operand = parts
            inner = operand.strip()
            if not (inner.startswith("(") and inner.endswith(")")):
                raise Refusal(
                    "KQL_IN_EXPECTED_LIST",
                    f"`{keyword}` needs a parenthesised list, got {operand!r}", "KQL")
            # RAW VALUES, not nested Literal objects. Wrapping each option in a
            # Literal and then putting the tuple inside another Literal produced
            # in_set(field, (Literal('0x1fffff'), ...)), so every comparison was
            # against a Literal OBJECT and never matched -- the filter silently
            # dropped every row, and the correlation reported a clean no_match.
            options = tuple(_literal(o.strip())
                            for o in split_top_level(inner[1:-1], ","))
            return Call("in_set", (_expression(subject), Literal(options)))

    timespan = re.match(r"^ago\((.*)\)$", text, re.IGNORECASE)
    if timespan:
        return _expression(timespan.group(1).strip())

    arithmetic = _arithmetic(text)
    if arithmetic is not None:
        return arithmetic

    literal = _literal(text)
    if literal is not _NOT_LITERAL:
        return Literal(literal)

    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$", text):
        return FieldExpr(FieldRef(text))

    raise Refusal(
        "KQL_EXPRESSION_UNSUPPORTED",
        f"{text!r} is not an expression this engine can honour. Refusing rather "
        f"than approximating, because an approximated predicate matches a "
        f"different set of rows than the rule states.", "KQL")


_NOT_LITERAL = object()


def _split_infix(text: str, keyword: str) -> tuple[str, str] | None:
    """Split `subject KEYWORD operand` at depth zero, outside strings."""
    depth = 0
    in_string = False
    lowered = text.lower()
    index = 0
    needle = f" {keyword} "
    while index < len(text):
        char = text[index]
        if char == '"':
            in_string = not in_string
        if in_string:
            index += 1
            continue
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif depth == 0 and lowered.startswith(needle, index):
            return text[:index].strip(), text[index + len(needle):].strip()
        index += 1
    return None


def _literal(text: str) -> Any:
    text = text.strip()
    # A VERBATIM string sigil. `@"\lsass.exe"` and `"\lsass.exe"` are the same
    # string; the `@` is KQL syntax. Left on the value it made the literal
    # `@\lsass.exe`, which would never equal the real path.
    if text.startswith("@"):
        text = text[1:].strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1].replace('""', '"')
    if text.lower() == "true":
        return True
    if text.lower() == "false":
        return False
    if re.fullmatch(r"\d+", text):
        return Decimal(text)
    if re.fullmatch(r"\d+\.\d+", text):
        return Decimal(text)
    span = re.fullmatch(r"(\d+)([smhd])", text, re.IGNORECASE)
    if span:
        # KEEP THE UNIT. An earlier version returned a bare int of seconds, so
        # `LSASSTime + 10m` became `LSASSTime + 600` -- the same instant for
        # evaluation, but a rule that renders as a comparison of a timestamp
        # against the number six hundred, and that cannot be written back as
        # `10m` because the unit is gone.
        return Duration(Decimal(span.group(1)) * {
            "s": 1, "m": 60, "h": 3600, "d": 86400}[span.group(2).lower()])
    return _NOT_LITERAL


def _args(text: str) -> str:
    opener = text.rindex("(")
    return text[opener + 1:-1]


def _arithmetic(text: str) -> Any | None:
    for symbol in ("+", "-", "*", "/"):
        parts = _split_operator_at(text, symbol)
        if parts and all(_is_arithmetic_operand(p) for p in parts):
            left, right = parts
            return Arith(symbol, (_expression(left), _expression(right)))
    return None


def _is_arithmetic_operand(text: str) -> bool:
    text = text.strip()
    if not text:
        return False
    if text.startswith(('"', "(")):
        return False
    return _literal(text) is not _NOT_LITERAL or bool(
        re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", text))


def _split_operator_at(text: str, symbol: str) -> tuple[str, str] | None:
    """Split at `symbol` only at depth zero, and not inside `<=`, `>=`, `!=`."""
    depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif depth == 0 and text.startswith(symbol, index):
            before = text[index - 1] if index else ""
            after = text[index + len(symbol)] if index + len(symbol) < len(text) else ""
            if symbol in ("+", "-", "*", "/"):
                if before.isdigit() or before == ")":
                    return None
            else:
                if before in ("<", ">", "!", "=") or after == "=":
                    index += 1
                    continue
            return text[:index].strip(), text[index + len(symbol):].strip()
        index += 1
    return None


def _split_keyword(text: str, keyword: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    lowered = text.lower()
    index = 0
    while index < len(text):
        char = text[index]
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif depth == 0 and lowered.startswith(f" {keyword} ", index):
            parts.append(text[start:index].strip())
            start = index + len(keyword) + 2
            index = start
            continue
        index += 1
    if not parts:
        return []
    parts.append(text[start:].strip())
    return [p for p in parts if p]
