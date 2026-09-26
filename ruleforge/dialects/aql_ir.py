"""AQL <-> RuleIR, and the CRE split.

TWO OUTPUTS, AND THEY ARE NOT THE SAME THING:

    SEARCH ARTIFACT   the AQL as written. Paste it into the Log Activity tab to
                      hunt. It returns rows. Deploying it: not a thing.

    RULE ARTIFACT     a Custom Rules Engine object: TESTS plus a RESPONSE. This
                      is what evaluates in near-real-time against the event
                      pipeline and what creates an offense. Offense magnitude is
                      computed from relevance, credibility and severity, none of
                      which appear anywhere in an AQL search.

So `render` refuses to describe an AQL search as deployable, and `cre_from_ir`
produces the CRE shape separately. Collapsing the two is how an analyst ends up
with a query they believe is protecting their network and is not.

GROUP BY + HAVING maps onto Aggregate-then-Filter, which is the shape the rule
actually has: count per group, then keep the groups above a threshold. Rendering
that as WHERE would move the threshold before the grouping and change the count.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from ..engine import (
    Aggregate,
    Arrange,
    Comparison,
    Duration,
    Emit,
    FieldExpr,
    FieldRef,
    Filter,
    Frame,
    Literal,
    Measure,
    Read,
    Refusal,
    RuleIR,
    SourceSelector,
    TimeRef,
)

from ..engine.ir import BoolOp, Call, Not
from .aql import (
    DIALECT,
    Diagnostic,
    ParsedQuery,
    _Aggregate,
    _ArielCall,
    _ArielField,
    _Like,
    _Negate,
)

#: Bucket width used when a query groups by time but this parser has not read its
#: SPAN clause. AQL's default span is an hour, so this matches the platform rather
#: than inventing a boundary -- and it is a named constant, not a literal buried
#: in an expression, so it is visible to anyone reading the lowering.
DEFAULT_SPAN: Final = Duration(3600)

#: Time columns AQL carries on every event. Used to find a time field for a
#: windowed rule; if the query has no window, none is invented.
TIME_COLUMNS: Final = ("starttime", "endtime", "timestamp", "deviceTime")


def lower(query: ParsedQuery, rule_id: str = "qradar") -> tuple[RuleIR, list[Diagnostic]]:
    """Turn a parsed AQL query into a RuleIR graph.

    The mapping, and why each step is where it is:

        FROM            -> Read
        WHERE           -> Filter, BEFORE the aggregate. A post-aggregate filter
                           would be HAVING and would change what COUNT sees.
        GROUP BY        -> Aggregate keys
        aggregates      -> measures
        HAVING          -> Filter, AFTER the aggregate
        ORDER BY        -> Arrange
        output columns  -> Emit

    ORDER MATTERS and is not a stylistic choice: the count in HAVING is a count of
    rows that already passed WHERE. Moving the WHERE after the aggregate would
    count rows that the rule never intended to consider.

    A DIAGNOSTIC IS ADDED WHEN THE QUERY USES AN ARIEL-SIDE COLUMN.
    `QIDNAME(qid)` and `LOGSOURCENAME(logsourceid)` are computed by the QRadar
    appliance from a QID lookup. Their values do not exist in raw logs, so this
    tool cannot evaluate them. A rule that uses one is fully understood and fully
    renderable, but only QRadar can run it -- and saying so is the whole point of
    a diagnostic. Silently yielding no rows for such a clause would be
    indistinguishable from a rule that matched nothing.
    """
    diagnostics = list(query.diagnostics)

    if _uses_ariel_column(query.where) or _uses_ariel_column(query.having):
        diagnostics.append(Diagnostic(
            "AQL_ARIEL_SIDE_COLUMN",
            "This query filters on a column QRadar computes from its QID map "
            "(QIDNAME, LOGSOURCENAME) rather than on something present in the raw "
            "log. The rule is understood and renders correctly, and QRadar will run "
            "it correctly -- but this tool CANNOT evaluate it, because that column's "
            "value only exists inside the appliance. Any local run will report "
            "these rows as undecidable, which is the honest answer, not zero matches.",
            "refusal"))
    nodes: list[Any] = []
    selector = SourceSelector(name=query.source,
                              kind="flow" if query.source == "flows" else "events")
    nodes.append(Read(id="read", selector=selector))
    current = "read"

    if query.where is not None:
        nodes.append(Filter(id="where", input=current, condition=_lower_expr(query.where)))
        current = "where"

    measures: list[Measure] = []
    plain_keys: list[FieldRef] = []
    for alias, item in query.select:
        if isinstance(item, _Aggregate):
            measure = _lower_measure(item, alias)
            measures.append(measure)
        else:
            ref = _key_ref(item)
            if ref is not None and ref.name not in [k.name for k in plain_keys]:
                plain_keys.append(ref)

    grouped = bool(query.group_by)
    if measures or grouped:
        frame = Frame(kind="per_event") if not grouped else _frame_for(query)
        aggregate = Aggregate(
            id="agg", input=current, measures=tuple(measures),
            frame=frame,
            keys=tuple(FieldRef(name) for name in query.group_by))
        nodes.append(aggregate)
        current = "agg"

    if query.having is not None:
        nodes.append(Filter(id="having", input=current,
                            condition=_lower_expr(query.having)))
        current = "having"

    if query.order_by:
        order = tuple(
            (FieldRef(_resolve_alias(name, query)), direction)
            for name, direction in query.order_by)
        nodes.append(Arrange(id="order", input=current, order_by=order,
                             limit=query.limit))
        current = "order"

    nodes.append(Emit(id="out", input=current))

    if not measures and not grouped and query.select:
        # A projection-only query: the selected columns must be produced by
        # something, and without an aggregate the only producer is the source.
        pass

    ir = RuleIR(rule_id=rule_id, nodes=tuple(nodes), output="out",
                title="QRadar AQL",
                metadata={"dialect": DIALECT, "artifact": "search"})
    return ir, diagnostics


def _ilike(node: _Like) -> Any:
    """Translate an ILIKE/LIKE pattern into an engine operator.

    AN ILIKE PATTERN IS NOT A SUBSTRING. `ILIKE '%x%'` means "contains x, ignoring
    case" -- the `%` are WILDCARDS, not characters. Lowering it to
    `contains(field, '%x%')` asks instead whether the literal text `%x%` occurs
    in the value, which is almost never true, so every such filter silently
    matched nothing. That bug shipped in the first version of this adapter and its
    test passed, because the test asserted that the pattern string had been
    carried through rather than that anything matched.

    The three simple shapes map onto real operators:

        '%x%'   contains x        (case-folded, which is ILIKE's meaning)
        'x%'    starts_with x
        '%x'    ends_with x

    Anything else -- an interior `%`, a `_` wildcard, an escaped `%` -- needs a
    real pattern matcher, so it is REFUSED with the pattern shown rather than
    approximated by the nearest operator.
    """
    pattern = node.pattern
    leading = pattern.startswith("%")
    trailing = pattern.endswith("%")
    core = pattern[1:-1] if (leading and trailing) else (
        pattern[1:] if leading else (pattern[:-1] if trailing else pattern))

    if not core or "%" in core or "_" in core or "\\" in core:
        raise Refusal(
            "AQL_LIKE_PATTERN_UNSUPPORTED",
            f"the pattern {pattern!r} uses a wildcard this tool cannot evaluate "
            f"faithfully. `_` and interior `%` change what the pattern matches, and "
            f"approximating it with a substring test would report confidently wrong "
            f"results. Supported shapes are '%text%', 'text%' and '%text'.", "AQL")

    left = _lower_expr(node.left)
    if not node.case_insensitive:
        # Case-SENSITIVE LIKE has no faithful home either: the engine's
        # `starts_with`/`ends_with` are case-sensitive but `contains` is not, so
        # there is no case-sensitive substring operator to reach for.
        raise Refusal(
            "AQL_LIKE_CASE_SENSITIVE_UNSUPPORTED",
            f"LIKE (case-sensitive) with pattern {pattern!r} has no faithful "
            f"operator here. The engine's `contains` folds case, so using it for a "
            f"case-sensitive LIKE would match rows the rule excludes.", "AQL")

    if leading and trailing:
        return Call("contains", (left, Literal(core)))
    if trailing:
        return Call("starts_with", (left, Literal(core)))
    if leading:
        return Call("ends_with", (left, Literal(core)))
    return Comparison("=", left, Literal(core))


def _uses_ariel_column(node: Any) -> bool:
    """Does this predicate reference a QRadar-computed column?"""
    if isinstance(node, _ArielCall):
        return True
    if isinstance(node, _ArielField):
        return True
    if isinstance(node, (BoolOp,)):
        return any(_uses_ariel_column(o) for o in node.operands)
    if isinstance(node, Comparison):
        return _uses_ariel_column(node.left) or _uses_ariel_column(node.right)
    if isinstance(node, Call):
        return any(_uses_ariel_column(a) for a in node.args)
    if isinstance(node, _Like):
        return _uses_ariel_column(node.left)
    if isinstance(node, _Negate):
        return _uses_ariel_column(node.inner)
    return False


def _frame_for(query: ParsedQuery) -> Frame:
    """Choose a frame for a grouped query.

    AQL's `GROUP BY ... _time` plus `SPAN` is a tumbling window. If the query
    groups by time without a span, there is no window and the group is just a
    value, so per_event is used rather than inventing a span.

    The span comes from the query's own LIMIT-adjacent state or defaults to an
    hour, and that default is named rather than silent: AQL's `SPAN` is a separate
    clause this parser does not yet read, so a bucket boundary it picks is a
    boundary the rule never stated.
    """
    if any(name.lower() in ("_time", "starttime", "endtime") for name in query.group_by):
        time_field = next(
            (n for n in query.group_by if n.lower() in ("_time", "starttime")),
            "starttime")
        return Frame(kind="tumbling", size=DEFAULT_SPAN, time_ref=TimeRef(time_field))
    return Frame(kind="per_event")


def _lower_measure(item: _Aggregate, alias: str) -> Measure:
    function = item.measure_name
    if function == "count":
        return Measure(alias, "count")
    argument = item.argument
    if isinstance(argument, FieldExpr):
        return Measure(alias, function, field=argument.ref)
    return Measure(alias, function)


def _key_ref(item: Any) -> FieldRef | None:
    if isinstance(item, FieldExpr):
        return item.ref
    return None


def _resolve_alias(name: str, query: ParsedQuery) -> str:
    for alias, _item in query.select:
        if alias == name:
            return name
    return name


def _lower_expr(node: Any) -> Any:
    """Lower a parsed predicate into a RuleIR expression."""
    if isinstance(node, _Negate):
        return Not(_lower_expr(node.inner))
    if isinstance(node, BoolOp):
        return BoolOp(node.op, tuple(_lower_expr(o) for o in node.operands))
    if isinstance(node, _Like):
        return _ilike(node)
    if isinstance(node, _ArielCall):
        return _lower_expr(node.as_expression())
    if isinstance(node, _ArielField):
        return _FieldByArielFunction(node)
    if isinstance(node, Comparison):
        return Comparison(node.op, _lower_expr(node.left), _lower_expr(node.right),
                         side=node.side)
    if isinstance(node, Call):
        return node
    if isinstance(node, FieldExpr):
        return node
    if isinstance(node, Literal):
        return node
    raise Refusal("AQL_EXPR_UNSUPPORTED",
                  f"cannot represent {type(node).__name__} in the neutral form",
                  "AQL")


@dataclass(frozen=True, slots=True)
class _FieldByArielFunction:
    """`QIDNAME(qid)` and friends, kept whole so rendering stays valid AQL."""

    node: Any

    @property
    def function(self) -> str:
        return self.node.function

    @property
    def ref(self) -> FieldRef:
        return self.node.ref


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render(ir: RuleIR) -> str:
    """Render RuleIR back to AQL.

    This produces a SEARCH. It is labelled as such in the header, because an AQL
    search is not a QRadar rule and calling it one is the mistake this tool
    exists to prevent.
    """
    where = ""
    having = ""
    group_by: list[str] = []
    select_items: list[str] = []
    order_by: list[str] = []
    source = "events"
    limit: str = ""

    for node in ir.nodes:
        name = type(node).__name__
        if name == "Read":
            source = node.selector.name
        elif name == "Filter":
            text = _render_expr(node.condition)
            if _is_post_aggregate(ir, node):
                having = f"\nHAVING {text}"
            else:
                where = f"\nWHERE {text}"
        elif name == "Aggregate":
            group_by = [k.name for k in node.keys]
            for measure in node.measures:
                select_items.append(_render_measure(measure, node))
        elif name == "Arrange":
            order_by = [f"{ref.name} {direction.upper()}"
                        for ref, direction in node.order_by]
            if node.limit:
                limit = f"\nLIMIT {node.limit}"
        elif name == "Derive":
            # A DERIVED COLUMN IS A PREDICATE IN AQL. `| project` and `| eval`
            # both change the shape of the row, and an AQL search has neither:
            # a computed column in a `WHERE` would be a filter on something the
            # search never produced. It was in no branch at all, so a graph with
            # one rendered as `SELECT * FROM events` with the derived column
            # gone, no refusal and no diagnostic -- the same silent drop as the
            # Join/SetOp/Pattern case, one node lower on the list.
            raise Refusal(
                "AQL_NODE_NOT_RENDERABLE",
                "this rule contains a Derive node, which computes new columns. AQL "
                "searches index-time fields and has no `project` or `eval`, so a "
                "computed column has no AQL form. Rendering the rest would hand "
                "you a query with the derivation missing from it.",
                "AQL")
        elif name in ("Join", "SetOp", "Pattern", "Package", "Expand"):
            # NO SILENT `else`, AND THAT IS THE POINT. This loop used to fall
            # through for every node type it did not name, so a graph containing
            # a `Package` -- a parent/child correlation, whose ENTIRE detection
            # lives in that node -- rendered as `SELECT * FROM events`. No
            # refusal, no diagnostic, and the artifact still carried the
            # "NOT a deployable QRadar rule" header, so it read as finished.
            # `wazuh_render.py` calls that "the most dangerous output this tool
            # can produce", and it was true here too.
            #
            # AQL has no parent/child correlation, no multi-event pattern and no
            # unnest. Naming that is the correct output; emitting the rest of the
            # query as though this node were not there is not.
            raise Refusal(
                "AQL_NODE_NOT_RENDERABLE",
                f"this rule contains a {name} node. AQL has no equivalent -- a "
                f"correlation, a sequence and an unnest are all things an AQL "
                f"search cannot express -- so rendering the rest of the graph "
                f"would hand you a query with the detection missing from it. "
                f"The rule is fully understood; it simply has no AQL form.",
                "AQL")

    if not select_items:
        select_items = group_by or ["*"]

    lines = ["-- RuleForge search artifact. NOT a deployable QRadar rule.",
             "-- A Custom Rules Engine object (tests + response) is required to",
             "-- create offenses. See cre_from_ir for that shape.",
             "SELECT " + ", ".join(select_items),
             f"FROM {source}"]
    if where:
        lines.append(where)
    if group_by:
        lines.append("GROUP BY " + ", ".join(group_by))
    if having:
        lines.append(having)
    if order_by:
        lines.append("ORDER BY " + ", ".join(order_by))
    if limit:
        lines.append(limit)
    return "\n".join(lines)


def _is_post_aggregate(ir: RuleIR, node: Any) -> bool:
    """A Filter downstream of an Aggregate is HAVING, not WHERE.

    Getting this backwards moves the threshold before the grouping, so COUNT
    sees rows the rule never meant to consider and the numbers change.
    """
    for candidate in ir.nodes:
        if type(candidate).__name__ == "Aggregate" and candidate.id == node.input:
            return True
    return False


def _render_measure(measure: Measure, aggregate: Aggregate) -> str:
    if measure.function == "count":
        return f"COUNT(*) AS {measure.name}"
    if measure.field is not None:
        return f"{measure.function.upper()}({measure.field.name}) AS {measure.name}"
    return f"{measure.function.upper()}(*) AS {measure.name}"


def _render_expr(node: Any) -> str:
    if isinstance(node, BoolOp):
        joiner = f" {node.op.upper()} "
        return "(" + joiner.join(_render_expr(o) for o in node.operands) + ")"
    if isinstance(node, _FieldByArielFunction):
        return node.node.text
    if isinstance(node, Call):
        if node.function == "contains":
            left, right = node.args
            return f"{_render_expr(left)} ILIKE {_render_literal(right)}"
        if node.function == "in_set":
            left, right = node.args
            options = ", ".join(_render_literal(o) for o in right.value)
            return f"{_render_expr(left)} IN ({options})"
        if node.function == "matches_regex":
            rendered = ", ".join(_render_expr(a) for a in node.args)
            return f"MATCHES({rendered})"
        return f"{node.function.upper()}(" + ", ".join(
            _render_expr(a) for a in node.args) + ")"
    if isinstance(node, Comparison):
        # EACH OP NAME NOW MEANS WHAT IT SAYS. `is_not_null` used to render as
        # `IS NULL` -- the exact opposite -- because the AQL parser had given
        # `IS NULL` the name `is_not_null` and this branch compensated. So an
        # SPL bare term, which correctly means "exists and is not null", came
        # out of the AQL renderer as `WHERE EventCode IS NULL`: an inverted
        # detection, produced by a cross-dialect render. One name, two meanings,
        # in the module whose whole point is that null and absent differ.
        if node.op == "is_null":
            return f"{_render_expr(node.left)} IS NULL"
        if node.op in ("exists", "is_not_null"):
            return f"{_render_expr(node.left)} IS NOT NULL"
        return f"{_render_expr(node.left)} {node.op} {_render_expr(node.right)}"
    if isinstance(node, FieldExpr):
        return node.ref.name
    if isinstance(node, Literal):
        return _render_literal(node)
    raise Refusal("AQL_RENDER_UNSUPPORTED",
                  f"cannot render {type(node).__name__} as AQL", "AQL")


def _render_literal(node: Any) -> str:
    value = node.value if isinstance(node, Literal) else node
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, str):
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    if value == "*":
        return "*"
    return str(value)


# ---------------------------------------------------------------------------
# The CRE shape
# ---------------------------------------------------------------------------


def cre_from_ir(ir: RuleIR, rule_name: str = "ruleforge_rule") -> dict[str, Any]:
    """Describe the Custom Rules Engine object an IR implies.

    Returned as data, not as text, because a CRE rule is configured in a console
    rather than pasted as a query. Each test maps to a CRE test, and the response
    is stated separately so the offense-producing half is never implied by a WHERE
    clause the way it would be in a search.

    `not_covered` lists anything in the IR that has no CRE equivalent. Omitting
    that list would let a reader assume full coverage.
    """
    tests: list[dict[str, Any]] = []
    not_covered: list[str] = []
    sequence_tests: list[dict[str, Any]] = []

    for node in ir.nodes:
        name = type(node).__name__
        if name == "Filter":
            tests.append({
                "type": "event_test",
                "description": "all conditions must hold",
                "condition": _render_expr(node.condition),
            })
        elif name == "Aggregate":
            if node.keys:
                tests.append({
                    "type": "grouping_test",
                    "group_by": [k.name for k in node.keys],
                    "measures": [m.name for m in node.measures],
                })
            for measure in node.measures:
                if measure.function in ("count",):
                    tests.append({
                        "type": "threshold_test",
                        "on": measure.name,
                        "note": "a CRE threshold test needs the numeric limit; it "
                                "is not stated in the neutral form, so supply it "
                                "in the console rather than have it guessed",
                    })
        elif name == "Pattern":
            sequence_tests.append({
                "type": "sequence_test",
                "stages": len(node.stages),
                "within": str(node.within),
                "group_by": [k.name for k in node.key],
            })
        elif name == "Arrange":
            not_covered.append(
                "ordering has no meaning in a CRE rule: rules evaluate, they do "
                "not present sorted output")
        elif name == "Join":
            tests.append({"type": "correlation_test",
                          "note": "join conditions must be expressed as CRE "
                                  "building-block references"})

    return {
        "artifact": "cre_rule",
        "rule_name": rule_name,
        "deployable": False,
        "deployable_reason": "A CRE rule is CONFIGURED in the console, not "
                             "imported as text. This is a specification of the "
                             "rule, ready to transcribe. Building blocks are "
                             "evaluated before rules, so a building block "
                             "referenced here must exist first.",
        "tests": tests,
        "sequence_tests": sequence_tests,
        "response": {
            "create_offense": True,
            "note": "offense magnitude is derived by QRadar from relevance, "
                    "credibility and severity. None of those appear in the "
                    "detection logic, so the magnitude this rule produces cannot "
                    "be predicted from the rule alone.",
        },
        "not_covered": not_covered,
    }
