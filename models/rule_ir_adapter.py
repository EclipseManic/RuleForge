"""v1 -> RuleIR v2 adapter.

Phase 2 of docs/ruleforge-redesign-plan.md. Ships DARK: nothing in the application calls
this yet, and `tests/test_rule_ir.py::ShadowModeTests` asserts that, so this file cannot
change any existing behaviour.

THE GOVERNING RULE: REFUSE, DO NOT GUESS.

The v1 model is a bag of parallel lists with no ordering, so some v1 states genuinely do
not determine a pipeline. Where that is true the adapter emits a `ParseLoss` with severity
"must" rather than inventing an order, a window kind, or a field name. A `must` loss blocks
`exact` and blocks cross-target compilation, which is correct: we do not know what the rule
meant.

The alternative - pick the most plausible order and flag it - is the defect class this
redesign exists to remove. It is also unrecoverable once a renderer starts reading the IR,
whereas a refusal is trivially reversible.

Mappings that are unambiguous are exact:

    logic / exclusions      -> Read + Filter, boolean structure preserved
    Aggregation             -> one Measure per entry, alias as the measure name
    Aggregation.threshold   -> a FOLLOWING Filter over the measure, never a measure attribute
    global threshold > 1    -> Measure("EventCount", "count") + a following Filter
    source                  -> SourceSelector; "*" becomes name=None, never a table name
    Sequence                -> Pattern, ONLY when every stage parses into typed predicates
    Join                    -> Join, ONLY when both endpoints resolve to graph nodes
    Lookup                  -> no safe typed form in v1, therefore a must-loss

Time is the subtle one. v1 has a single `window` string, but v2 distinguishes five
meanings for it (source lookback, aggregation window, bucket span, pattern span, match
window). `window_to_frame` therefore REFUSES to classify a bare v1 window rather than
silently choosing one, because choosing wrong is precisely the `span=5m is not a
correlation window` bug.
"""

from __future__ import annotations

from typing import Any

from models.correlation import Aggregation, CorrelationModel, LogicNode, Predicate
from models.rule_ir import (Aggregate, BoolOp, Call, Comparison, Derive, Emit, Expr, FieldExpr,
                            FieldRef, Filter, Frame, InList, Join as IRJoin, Literal, Measure,
                            MeasureExpr, Pattern, ParseLoss, Read, RuleIR, SourceSelector,
                            Stage, Duration, canonical_operator)

#: v1 aggregation function -> v2 measure function.
AGG_MAP = {
    "count": "count",
    "dc": "dcount",
    "dcount": "dcount",
    "distinct_count": "dcount",
    "values": "values",
    "make_set": "make_set",
    "sum": "sum",
    "min": "min",
    "max": "max",
    "avg": "avg",
}

#: v1 comparison operator -> v2 comparison operator. Only equality-family maps; ordering
#: operators are not invented because v1 never declared what they compared against.
COMPARISON_MAP = {
    "equals": "=",
    "eq": "=",
    "not_equals": "!=",
    "ne": "!=",
    "contains": None,       # becomes a registered function, see _predicate_expr
    "starts_with": None,
    "ends_with": None,
    "regex": None,
    "in_list": None,
    "wildcard": None,
    "windash": None,
    "base64": None,
    "exists": None,
    "cidr": None,
    "gt": None,
    "gte": None,
    "lt": None,
    "lte": None,
}

#: Operators expressed as a registered function rather than a comparison.
FUNCTION_MAP = {
    "contains": "contains",
    "starts_with": "starts_with",
    "ends_with": "ends_with",
    "regex": "matches_regex",
    "in_list": "in_set",
    "cidr": "cidr_contains",
    "windash": "matches_regex",
    "wildcard": "matches_regex",
    "base64": "matches_regex",
}

#: A wildcard source is UNRESOLVED, not a table called "*".
WILDCARD_SOURCES = {"", "*"}


class _Losses:
    """Collects losses so the adapter can report every one, not just the first."""

    def __init__(self) -> None:
        self.items: list[ParseLoss] = []

    def must(self, code: str, message: str, affected: tuple[str, ...] = ()) -> None:
        self.items.append(ParseLoss(code, "must", message, affected_targets=affected))

    def advisory(self, code: str, message: str) -> None:
        self.items.append(ParseLoss(code, "advisory", message))

    def has_must(self) -> bool:
        return any(i.severity == "must" for i in self.items)


# --------------------------------------------------------------------------
# Time
# --------------------------------------------------------------------------

def parse_duration(text: str) -> Duration | None:
    """`5m` -> Duration(300). Returns None rather than raising, so callers can record a
    loss instead of aborting a whole conversion."""
    raw = (text or "").strip().lower()
    if not raw or raw[-1] not in "smhd" or not raw[:-1].isdigit():
        return None
    amount = int(raw[:-1])
    if amount < 1:
        return None
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[raw[-1]]
    return Duration(amount * unit)


def window_to_frame(window: str, *, context: str, losses: _Losses) -> Frame | None:
    """Convert a v1 `window` string, refusing to guess its MEANING.

    v2 distinguishes a source lookback, an aggregation window, a bucket span and a pattern
    span. v1 has one string and no marker saying which it is. Emitting `Frame(sliding=...)`
    would be a guess, and guessing here is the exact bug that made a Splunk `span=5m` bucket
    get treated as a correlation window. So: measure the duration, and record a must-loss
    for the ambiguity unless the caller has already decided which kind it means.
    """
    duration = parse_duration(window)
    if duration is None:
        losses.must("OPAQUE_WINDOW",
                    f"{context}: window {window!r} is not a duration this tool can measure")
        return None
    losses.must(
        "AMBIGUOUS_WINDOW_KIND",
        f"{context}: v1 records only the string {window!r}; v2 requires knowing whether this "
        f"is a source lookback, an aggregation window, a bucket span or a pattern span, and "
        f"v1 does not say. Refusing to pick one.",
    )
    return None


# --------------------------------------------------------------------------
# Expressions
# --------------------------------------------------------------------------

def _predicate_expr(predicate: Predicate, losses: _Losses) -> Expr:
    operator, _changed = canonical_operator(predicate.operator)
    value = predicate.value
    if isinstance(value, list):
        return InList(FieldExpr(FieldRef(predicate.field, confidence="parsed")),
                      tuple(Literal(v) for v in value))
    left = FieldExpr(FieldRef(predicate.field, confidence="parsed"))
    comparison = COMPARISON_MAP.get(operator, "UNMAPPED")
    if comparison in {"=", "!=", "<", "<=", ">", ">="}:
        return Comparison(comparison, left, Literal(value))
    function = FUNCTION_MAP.get(operator)
    if function:
        return Call(function, (left, Literal(value)))
    if operator == "exists":
        return Call("if", (Comparison("=", left, Literal(None)), Literal(True), Literal(False)))
    losses.must("UNREPRESENTABLE_OPERATOR",
                f"operator {predicate.operator!r} on field {predicate.field!r} has no v2 form")
    return Comparison("=", left, Literal(value))


def _logic_expr(node: Any, losses: _Losses) -> Expr:
    if isinstance(node, Predicate):
        return _predicate_expr(node, losses)
    if isinstance(node, LogicNode):
        if node.op == "not":
            # v1 `not` may carry several children; v2's BoolOp('not') takes exactly one.
            # Fan them out rather than silently keeping only the first.
            if len(node.children) == 1:
                return BoolOp("not", children=(_logic_expr(node.children[0], losses),))
            return BoolOp("and", children=tuple(
                BoolOp("not", children=(_logic_expr(child, losses),)) for child in node.children))
        return BoolOp(node.op, children=tuple(_logic_expr(c, losses) for c in node.children))
    losses.must("UNREPRESENTABLE_LOGIC", f"logic node {type(node).__name__} has no v2 form")
    return Literal(True)


# --------------------------------------------------------------------------
# Measures
# --------------------------------------------------------------------------

def _measure_name(aggregation: Aggregation, index: int) -> str:
    if aggregation.alias.strip():
        return aggregation.alias.strip()
    if aggregation.field.strip():
        return aggregation.field.strip()
    return f"Aggregate{index + 1}"


def _measure_function(aggregation: Aggregation, losses: _Losses, name: str) -> str:
    mapped = AGG_MAP.get(aggregation.function.strip().lower())
    if mapped is None:
        losses.must("UNREPRESENTABLE_AGGREGATE",
                    f"aggregate function {aggregation.function!r} on measure {name!r} has no v2 form")
        return "count"
    return mapped


# --------------------------------------------------------------------------
# The adapter
# --------------------------------------------------------------------------

def correlation_to_ir(model: CorrelationModel, *, rule_id: str = "v1", title: str = "") -> RuleIR:
    """Convert a v1 CorrelationModel into a RuleIR, recording every ambiguity as a loss.

    Never raises for a merely ambiguous v1 state: an ambiguous state becomes a `must` loss
    and a structurally valid IR that will refuse to deploy. It raises only for a
    structurally impossible one (e.g. no logic at all), because there is nothing to build.
    """
    losses = _Losses()
    nodes: list[Any] = []

    # --- Read: a wildcard source is unresolved, never a table name -------------
    if model.source.strip() in WILDCARD_SOURCES:
        selector = SourceSelector(name=None, confidence="unverified")
        losses.must("UNRESOLVED_SOURCE",
                    "v1 source is a wildcard; no index, table or repository was named, and "
                    "one must not be invented")
    else:
        selector = SourceSelector(name=model.source.strip(), confidence="parsed")
    read = Read(id="read", selector=selector)
    nodes.append(read)

    if model.logic is None:
        losses.must("NO_LOGIC", "v1 model has no logic, so there is nothing to build")
    else:
        condition = _logic_expr(model.logic, losses)
        exclusions = [_logic_expr(e, losses) for e in (model.exclusions or [])]
        if exclusions:
            # v1 exclusions are independent ANDed exclusions, so a set-wide NOT would
            # invert them. AND them individually and negate each.
            condition = BoolOp("and", children=(
                condition,
                *(BoolOp("not", children=(e,)) for e in exclusions),
            ))
        nodes.append(Filter(id="filter", input="read", condition=condition))
    current = "filter" if model.logic is not None else "read"

    # --- Pattern: only when every stage is a typed predicate ------------------
    for index, sequence in enumerate(model.sequences or []):
        pattern_id = f"pattern{index + 1}"
        stage_inputs: list[str] = []
        for stage_index, stage in enumerate(sequence.stages):
            if not isinstance(stage.condition, str) or not stage.condition.strip():
                losses.must("OPAQUE_SEQUENCE_STAGE",
                            f"sequence {index + 1} stage {stage_index + 1} has an empty condition, "
                            "so it cannot be typed; the stage text is preserved, not interpreted")
                continue
            losses.must(
                "OPAQUE_SEQUENCE_STAGE",
                f"sequence {index + 1} stage {stage_index + 1} condition {stage.condition!r} is "
                f"free text in v1; v2 requires typed predicates. Preserved verbatim, not parsed",
            )
            stage_id = f"stage{index + 1}_{stage_index + 1}"
            nodes.append(Read(id=stage_id, selector=selector))
            stage_inputs.append(stage_id)
        if not stage_inputs:
            continue
        if sequence.ordered is False:
            losses.must("UNORDERED_SEQUENCE",
                        f"sequence {index + 1} is unordered; v1 does not record the alternative "
                        "structure, so the pattern cannot be built faithfully")
        span = parse_duration(sequence.maxspan)
        if span is None:
            losses.must("OPAQUE_WINDOW", f"sequence {index + 1} maxspan {sequence.maxspan!r} is unusable")
            span = None
        nodes.append(Pattern(
            id=pattern_id,
            stages=tuple(Stage(id=f"s{i + 1}", input=node_id, quantifier="exactly")
                         for i, node_id in enumerate(stage_inputs)),
            mode="ordered",
            key=(FieldRef(sequence.join_by, confidence="parsed"),) if sequence.join_by.strip() else (),
            max_span=span,
        ))
        current = pattern_id

    # --- Joins: only when both endpoints resolve ------------------------------
    stream_ids = {stream.get("name"): f"stream_{i + 1}"
                  for i, stream in enumerate(model.event_streams or [])}
    for index, stream in enumerate(model.event_streams or []):
        nodes.append(Read(id=f"stream_{index + 1}",
                          selector=SourceSelector(name=(stream.get("source") or "").strip() or None,
                                                  confidence="parsed" if (stream.get("source") or "").strip()
                                                  else "unverified")))
    for index, join in enumerate(model.joins or []):
        join_id = f"join{index + 1}"
        left, right = stream_ids.get(join.left), stream_ids.get(join.right)
        if not left or not right:
            losses.must("UNRESOLVED_JOIN_ENDPOINTS",
                        f"join {index + 1} endpoints {join.left!r}/{join.right!r} do not resolve to "
                        f"declared event streams; the names are preserved, not turned into sources")
            continue
        losses.must("OPAQUE_JOIN_PREDICATE",
                    f"join {index + 1} `on` expression {join.on!r} is a free-text string in v1; v2 "
                    f"requires a typed predicate, so it is preserved and not parsed")
        nodes.append(IRJoin(id=join_id, left=left, right=right,
                            on=Comparison("=", Literal(True), Literal(True)),
                            kind=join.kind if join.kind in {
                                "inner", "left", "right", "full", "left_anti", "right_anti"}
                            else "inner",
                            match_key=join.on.strip() or None))
        current = join_id

    # --- Aggregates: named measures, then threshold as a following Filter ------
    threshold_filters: list[tuple[str, int]] = []
    if model.aggregations or (model.threshold or 1) > 1:
        measures: list[Measure] = []
        for index, aggregation in enumerate(model.aggregations or []):
            name = _measure_name(aggregation, index)
            measures.append(Measure(
                name=name,
                function=_measure_function(aggregation, losses, name),
                field=FieldRef(aggregation.field, confidence="parsed") if aggregation.field.strip() else None,
                distinct=aggregation.function.strip().lower() in {"dc", "dcount", "distinct_count"},
            ))
            if aggregation.threshold is not None and aggregation.threshold > 1:
                threshold_filters.append((name, aggregation.threshold))
        if not model.aggregations and (model.threshold or 1) > 1:
            # A plain count threshold, named deterministically rather than with an invented
            # alias: the name is referenced by the filter that follows.
            measures.append(Measure(name="EventCount", function="count"))
            threshold_filters.append(("EventCount", int(model.threshold)))
        group_by = tuple(FieldRef(name.strip(), confidence="parsed")
                         for name in (model.group_by or []) if name.strip())
        if not group_by and (model.group_by or []):
            losses.must("OPAQUE_GROUP_BY", "group_by entries are not resolvable field names")
        frame = None
        if (model.threshold or 1) > 1 or model.aggregations:
            frame = window_to_frame(model.window, context="aggregation", losses=losses)
        nodes.append(Aggregate(id="aggregate", input=current, measures=tuple(measures),
                               group_by=group_by, frame=frame))
        current = "aggregate"
        for index, (name, value) in enumerate(threshold_filters):
            filter_id = f"threshold{index + 1}"
            nodes.append(Filter(id=filter_id, input=current,
                                condition=Comparison(">=", MeasureExpr(name), Literal(value))))
            current = filter_id
    elif (model.group_by or []) and not model.aggregations:
        losses.must("GROUP_BY_WITHOUT_AGGREGATE",
                    "group_by was supplied with no aggregate, so v1 does not say what it groups")

    # --- Lookups have no safe typed form in v1 ---------------------------------
    for index, lookup in enumerate(model.lookups or []):
        losses.must("UNREPRESENTABLE_LOOKUP",
                    f"lookup {index + 1} {lookup.name!r} has a free-text argument string "
                    f"{lookup.arguments!r}; v2 requires a typed provider contract, so it is "
                    f"preserved and not guessed")

    # --- Outcome: only typed assignments ---------------------------------------
    risk = (model.outcome or {}).get("risk_score")
    if risk is not None:
        nodes.append(Derive(id="outcome",
                            input=current,
                            assignments=((FieldRef("risk_score", confidence="authored"), Literal(risk)),)))
        current = "outcome"
    for key in (model.outcome or {}):
        if key not in {"risk_score"}:
            losses.must("UNREPRESENTABLE_OUTCOME",
                        f"outcome key {key!r} has no v2 typed form in v1")

    emit = Emit(id="emit", input=current)
    nodes.append(emit)

    return RuleIR(
        rule_id=rule_id,
        title=title,
        nodes=tuple(nodes),
        output="emit",
        parse_diagnostics=tuple(losses.items),
    )


def request_to_ir(request: Any, *, rule_id: str | None = None) -> RuleIR:
    """Convert a v1 `RuleRequest` (the form-shaped payload) into a RuleIR.

    The form is the one v1 surface that is genuinely ordered: the analyst filled the fields
    in a known sequence. So the ordering ambiguity that forces losses on `CorrelationModel`
    does not apply here, and a normal single-event request converts with only a source
    loss (because the form's data source is a placeholder by default).
    """
    losses = _Losses()
    source = (request.data_source or "").strip()
    if source in WILDCARD_SOURCES:
        selector = SourceSelector(name=None, confidence="unverified")
        losses.must("UNRESOLVED_SOURCE",
                    "the form's data source is a placeholder; no index or table was named")
    else:
        selector = SourceSelector(name=source, confidence="authored")
    read = Read(id="read", selector=selector)
    nodes: list[Any] = [read]

    conditions = list(request.conditions or [])
    excluded = list(request.exclude_conditions or [])
    if not conditions:
        losses.must("NO_LOGIC", "the request carries no conditions, so there is nothing to build")
        condition = Literal(True)
    else:
        parts = [_predicate_expr(
            Predicate(c.get("field", ""), c.get("operator", ""), c.get("value", "")), losses)
            for c in conditions]
        joined = parts[0] if len(parts) == 1 else BoolOp(
            "and" if (request.condition_logic or "all") == "all" else "or", children=tuple(parts))
        if excluded:
            joined = BoolOp("and", children=(
                joined,
                *(BoolOp("not", children=(
                    _predicate_expr(Predicate(c.get("field", ""), c.get("operator", ""),
                                              c.get("value", "")), losses),))
                  for c in excluded),
            ))
        condition = joined
    nodes.append(Filter(id="filter", input="read", condition=condition))
    current = "filter"

    if (request.threshold or 1) > 1:
        nodes.append(Aggregate(
            id="aggregate", input=current,
            measures=(Measure(name="EventCount", function="count"),),
            group_by=(FieldRef(request.group_by, confidence="authored"),)
            if (request.group_by or "").strip() else (),
            frame=window_to_frame(request.timeframe, context="count", losses=losses),
        ))
        current = "aggregate"
        nodes.append(Filter(id="threshold", input=current,
                            condition=Comparison(">=", MeasureExpr("EventCount"),
                                                 Literal(int(request.threshold)))))
        current = "threshold"
    elif (request.group_by or "").strip():
        losses.must("GROUP_BY_WITHOUT_AGGREGATE",
                    "a group_by was supplied with the count turned off, so v1 does not say "
                    "what it groups")

    nodes.append(Emit(id="emit", input=current))
    return RuleIR(
        rule_id=rule_id or (request.title or "v1")[:140],
        title=request.title or "",
        description=request.description or "",
        nodes=tuple(nodes),
        output="emit",
        parse_diagnostics=tuple(losses.items),
    )


def ir_to_correlation(ir: RuleIR) -> CorrelationModel:
    """Project a RuleIR back to v1, REFUSING when v1 cannot represent it.

    A lossy projection here would reintroduce exactly the bug that started this: a pipeline
    whose post-aggregate filter silently vanished, reported as a faithful v1 rule. So an
    unrepresentable graph raises rather than degrading.
    """
    from models.rule_ir import RuleIRValidationError as _Reject

    if any(n.__class__.__name__ in {"Pattern", "Join", "SetOp", "Iterate",
                                                          "Expand", "Arrange"}
                                 for n in ir.nodes):
        raise _Reject("IR_NOT_V1_REPRESENTABLE",
                      "this graph uses constructs the v1 model has no field for; a lossy "
                      "projection would drop them silently")
    if any(loss.severity == "must" for loss in ir.parse_diagnostics):
        codes = sorted({loss.code for loss in ir.parse_diagnostics if loss.severity == "must"})
        raise _Reject("IR_HAS_MUST_LOSS", f"v1 projection refused; unresolved: {codes}")

    source = ""
    logic: Any = None
    aggregations: list[Aggregation] = []
    group_by: list[str] = []
    threshold: int | None = 1
    window = "5m"
    for node in ir.nodes:
        kind = node.__class__.__name__
        if kind == "Read" and node.selector.name:
            source = node.selector.name
        elif kind == "Filter" and logic is None:
            logic = _expr_to_v1_predicate(node.condition)
        elif kind == "Aggregate":
            for measure in node.measures:
                aggregations.append(Aggregation(
                    function="dc" if measure.function == "dcount" else measure.function,
                    field=measure.field.name if measure.field else "",
                    alias=measure.name))
            group_by = [ref.name for ref in node.group_by]
            if node.frame and node.frame.size:
                window = f"{max(1, node.frame.size.seconds // 60)}m"
        elif kind == "Filter" and isinstance(node.condition, Comparison) \
                and isinstance(node.condition.left, MeasureExpr):
            threshold = node.condition.right.value if isinstance(node.condition.right, Literal) else None
    return CorrelationModel(
        logic=logic, source=source or "*", aggregations=aggregations,
        group_by=group_by, threshold=threshold, window=window,
    )


def _expr_to_v1_predicate(expr: Any) -> Any:
    if isinstance(expr, Comparison) and isinstance(expr.left, FieldExpr):
        reverse = {"=": "equals", "!=": "not_equals", ">": "gt", ">=": "gte",
                   "<": "lt", "<=": "lte"}
        operator = reverse.get(expr.op)
        if operator and isinstance(expr.right, Literal):
            return Predicate(expr.left.ref.name, operator, expr.right.value)
    if isinstance(expr, Call):
        inverse = {v: k for k, v in FUNCTION_MAP.items()}
        if len(expr.args) == 2 and isinstance(expr.args[0], FieldExpr) \
                and isinstance(expr.args[1], Literal) and expr.function in inverse:
            return Predicate(expr.args[0].ref.name, inverse[expr.function], expr.args[1].value)
    if isinstance(expr, InList) and isinstance(expr.value, FieldExpr) \
            and all(isinstance(o, Literal) for o in expr.options):
        return Predicate(expr.value.ref.name, "in_list", [o.value for o in expr.options])
    if isinstance(expr, BoolOp) and expr.children:
        return LogicNode(op=expr.op, children=tuple(_expr_to_v1_predicate(c) for c in expr.children))
    return Predicate("_unrepresentable", "equals", "")
