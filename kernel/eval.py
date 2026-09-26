"""The evaluation driver: pre-flight, graph walk, and result assembly.

Phase 3A. Ships DARK. Nothing in app.py, rule_engine.py, compiler/ or the front end imports
`kernel/` yet, and a test asserts that.

EXECUTION ORDER IS DERIVED, NEVER ASSUMED
------------------------------------------
Nodes are walked in dependency order computed from the input edges, never in tuple order. A
tuple is not an execution order, and evaluating in tuple order would silently use a stale or
uncomputed result. A `SetOp` reads two inputs, so it joins them.

FAIL-CLOSED BY CONSTRUCTION
---------------------------
A refusal anywhere produces a `not_evaluated` result with NO rows and NO columns, and every
downstream node is recorded as `skipped` rather than `evaluated` with zero rows. That
distinction is what makes "deleting a required node changes the verdict" observable, instead
of a coincidentally-empty result looking identical to a genuine no-match.
"""

from __future__ import annotations

from typing import Any

from kernel.eval_errors import KERNEL_EVAL_CODES, EvaluationRefusal, not_evaluated
from kernel.eval_expr import EvalContext, evaluate
from kernel.eval_nodes import (DEFERRED_NODES, Sample, _aggregate_group, _check_frame,
                               _resolve_time_field, _stamp, _windows)
from kernel.eval_types import (ABSENT, MAX_CAVEATS, MAX_INPUT_ROWS, MAX_TRACE_SAMPLES, NODE_TYPES,
                               Caveat, EvalCounts, EvalState, EvaluationResult, NodeTrace, Row,
                               canonical, columns_of, primitive_of, row_key)
from models.rule_ir import (Aggregate, Arrange, Derive, Emit, Filter, Pattern, Read, RuleIR,
                            RuleIRValidationError, SetOp, SourceSelector, validate_ir)

_SET_OPS = frozenset({"union", "intersect", "except", "append", "except_both"})
_UNVERIFIED = frozenset({"unverified", "inferred"})

_primitive_of = primitive_of


# --------------------------------------------------------------------------
# Pre-flight: everything that refuses, checked before a single row is touched
# --------------------------------------------------------------------------


def _preflight(ir: RuleIR, sample: Sample) -> EvaluationRefusal | None:
    for node in ir.nodes:
        primitive = _primitive_of(node)
        if primitive in DEFERRED_NODES:
            return EvaluationRefusal(
                "EVAL_PHASE_NOT_IMPLEMENTED",
                f"a {primitive} node is expressible in the IR but phase 3A is single-stream "
                f"and does not execute it; it is deferred to "
                f"{DEFERRED_NODES[primitive]}", node.id,
                deferred_to=DEFERRED_NODES[primitive])
        if primitive not in NODE_TYPES:
            return EvaluationRefusal(
                "NOT_A_KERNEL_NODE",
                f"{type(node).__name__} is not a RuleIR primitive", node.id)

        if isinstance(node, Read):
            selector: SourceSelector = node.selector
            if selector.name is None:
                return EvaluationRefusal(
                    "UNRESOLVED_SOURCE",
                    f"the source of {node.id!r} is unresolved; the kernel will not invent a "
                    f"table or index to read from", node.id)
            if selector.confidence in _UNVERIFIED:
                return EvaluationRefusal(
                    "UNVERIFIED_SOURCE_REFERENCE",
                    f"source {node.id!r} is named {selector.name!r} at confidence "
                    f"{selector.confidence!r}, so a match on it would be a coincidence rather "
                    f"than evidence", node.id)
            if selector.strategy == "accelerated" and not (selector.schema_id or "").strip():
                return EvaluationRefusal(
                    "ACCELERATED_SOURCE_WITHOUT_SCHEMA",
                    f"source {node.id!r} is accelerated with no schema contract", node.id)
            if selector.strategy == "prior_emission" and not (
                    ir.package is not None and ir.package.dependencies):
                return EvaluationRefusal(
                    "PRIOR_EMISSION_WITHOUT_PACKAGE",
                    f"source {node.id!r} reads a prior emission but no package declares a "
                    f"dependency edge to supply it", node.id)
            if sample.rows(node.id) is None:
                return EvaluationRefusal(
                    "EVAL_INPUT_SOURCE_NOT_PROVIDED",
                    f"no sample rows were supplied for Read node {node.id!r}; a rule with two "
                    f"Reads cannot be evaluated against one shared row set", node.id)

        if isinstance(node, Aggregate):
            if node.frame is not None:
                refusal = _frame_refusal(node.frame)
                if refusal is not None:
                    return refusal
            for measure in node.measures:
                if measure.function in ("arg_max", "arg_min"):
                    return EvaluationRefusal(
                        "MEASURE_ARG_EXTREME_UNDER_SPECIFIED",
                        f"measure {measure.name!r} uses {measure.function!r}, which needs a "
                        f"value field and an ordering field; Measure declares only one",
                        f"{node.id}.{measure.name}")
        if isinstance(node, SetOp) and node.op not in _SET_OPS:
            return EvaluationRefusal(
                "UNKNOWN_SET_OPERATION",
                f"unknown set operation {node.op!r}; the model permits {sorted(_SET_OPS)}",
                node.id)
        if isinstance(node, Arrange) and (node.offset or 0) < 0:
            return EvaluationRefusal(
                "ARRANGE_NEGATIVE_OFFSET",
                f"Arrange offset {node.offset} is negative; clamping it would hide a mistake",
                node.id)
        if isinstance(node, Emit) and node.cooldown:
            return EvaluationRefusal(
                "EVAL_PHASE_NOT_IMPLEMENTED",
                f"Emit.cooldown is a stateful counter ({node.cooldown!r}); pretending it does "
                f"nothing would be a silent lie about alerting volume", node.id,
                deferred_to="3C")

    return _unverified_field_refusal(ir)


def _frame_refusal(frame: Any) -> EvaluationRefusal | None:
    from kernel.eval_nodes import _check_frame
    try:
        _check_frame(frame)
    except EvaluationRefusal as refusal:
        return refusal
    return None


def _unverified_field_refusal(ir: RuleIR) -> EvaluationRefusal | None:
    """A load-bearing field at low confidence means we do not know which column this is.

    This is the construct-level counterpart to a per-row UNKNOWN: a row missing a value is
    data-level and counted, but a field we cannot locate is undecidable for every row, so the
    graph refuses. It matches what the capability layer already refuses, and the two layers
    must not disagree in the direction that matters.
    """
    from models.rule_ir import FieldRef

    def walk(value: Any, node_id: str) -> EvaluationRefusal | None:
        if isinstance(value, FieldRef):
            if value.confidence in _UNVERIFIED:
                return EvaluationRefusal(
                    "UNVERIFIED_FIELD_REFERENCE",
                    f"field {value.name!r} at confidence {value.confidence!r} is not "
                    f"documented, so evaluating against it would be guesswork", node_id)
            return None
        if isinstance(value, (tuple, list)):
            for item in value:
                found = walk(item, node_id)
                if found is not None:
                    return found
            return None
        import dataclasses
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            for f in dataclasses.fields(value):
                found = walk(getattr(value, f.name, None), node_id)
                if found is not None:
                    return found
        return None

    for node in ir.nodes:
        for f in ("condition", "assignments", "order_by", "group_by", "partition_by", "field",
                  "on", "key", "columns", "measures", "until", "step"):
            found = walk(getattr(node, f, None), node.id)
            if found is not None:
                return found
    return None


# --------------------------------------------------------------------------
# Per-node execution
# --------------------------------------------------------------------------


def _exec_derive(node: Derive, rows: list[Row], ctx: EvalContext) -> list[Row]:
    out = []
    for row in rows:
        values = dict(row.values)
        for target, expression in node.assignments:
            value = evaluate(expression, row, ctx, None)
            name = target.name
            if name in values and node.collision == "error":
                raise EvaluationRefusal(
                    "EVAL_DERIVE_FIELD_COLLISION",
                    f"Derive {node.id!r} assigns {name!r}, which the row already carries; the "
                    f"collision policy is 'error', so this is refused rather than silently "
                    f"overwritten", node.id)
            values[name] = None if value is ABSENT else value
        for name in node.drop:
            values.pop(name, None)
        out.append(Row(values=values, index=row.index, time=row.time,
                       time_source=row.time_source))
    return out


def _exec_filter(node: Filter, rows: list[Row], ctx: EvalContext) -> list[Row]:
    out = []
    for row in rows:
        verdict = evaluate(node.condition, row, ctx, None)
        if verdict is True:
            ctx.counts.rows_predicate_true += 1
            out.append(row)
        elif verdict is False:
            ctx.counts.rows_predicate_false += 1
        else:
            # UNKNOWN also drops the row - the rule being kept is "no row in this output is a
            # row we have not affirmatively shown matches". Counted separately from FALSE so
            # absence of evidence is distinguishable from evidence of absence.
            ctx.counts.rows_predicate_unknown += 1
    return out


def _exec_aggregate(node: Aggregate, rows: list[Row], ctx: EvalContext,
                    caveats: list[Caveat]) -> list[Row]:
    if node.frame is not None:
        windows = _windows(rows, node.frame)
        caveats.extend(_check_frame(node.frame))
    else:
        windows = [rows]
    ctx.counts.windows += len(windows)

    out: list[Row] = []
    for window in windows:
        if not window:
            continue
        groups: dict[tuple, list[Row]] = {}
        if node.group_by:
            for row in window:
                key = tuple(canonical(row.get(f.name)) for f in node.group_by)
                groups.setdefault(key, []).append(row)
        else:
            groups = {(): window}

        for key, members in groups.items():
            scope: dict[str, Any] = {}
            _aggregate_group(members, node, ctx, scope)
            values: dict[str, Any] = {}
            for field in node.group_by:
                present = [m for m in members if m.get(field.name) is not ABSENT]
                if not present:
                    ctx.counts.groups_with_absent_key += 1
                raw = members[0].get(field.name)
                values[field.name] = None if raw is ABSENT else raw
            values.update(scope)
            out.append(Row(values=values, index=members[0].index, time=members[0].time))
            ctx.counts.groups += 1
    return out


def _exec_arrange(node: Arrange, rows: list[Row], ctx: EvalContext,
                  caveats: list[Caveat]) -> list[Row]:
    """Sort -> distinct_on -> offset -> limit, in that fixed order.

    That order is the only one in which `distinct_on` plus `order_by` plus `limit` expresses
    top-N-per-group, which is the reason the node exists.
    """
    if not node.order_by:
        caveats.append(Caveat("ARRANGE_WITHOUT_ORDER_IS_INPUT_ORDER", nodes=(node.id,)))

    unknown_keys = 0

    def key_of(row: Row, expr: Any) -> tuple[int, Any]:
        """(is_unknown, value). An unknown key sorts after every known one."""
        nonlocal unknown_keys
        value = evaluate(expr, row, ctx, None)
        if value is ABSENT or value is None:
            unknown_keys += 1
            return (1, ())
        return (0, canonical(value))

    for key_expr, ascending in node.order_by:
        keyed = [(key_of(row, key_expr), row) for row in rows]
        known = sorted([t for t in keyed if t[0][0] == 0],
                       key=lambda t: t[0][1], reverse=not ascending)
        unknown = [t[1] for t in keyed if t[0][0] == 1]
        # Unknown keys go LAST in both directions. Nulls-first was rejected: it silently
        # promotes unmeasurable rows to the top of a `limit N`, which is the most damaging
        # possible ordering error and the hardest to notice.
        rows = [row for _key, row in known] + unknown

    if node.distinct_on:
        caveats.append(Caveat("DISTINCT_ON_APPLIED_AFTER_ORDER", nodes=(node.id,)))
        seen: set = set()
        deduped = []
        for row in rows:
            key = tuple(canonical(row.get(f.name)) for f in node.distinct_on)
            if key in seen:
                ctx.counts.setop_rows_dropped += 1
                continue
            seen.add(key)
            deduped.append(row)
        rows = deduped

    offset = node.offset or 0
    if offset:
        rows = rows[offset:]
    if node.limit is not None:
        rows = rows[:node.limit]
    ctx.counts.rows_with_unknown_order_key += unknown_keys
    return rows


def _exec_setop(node: SetOp, left: list[Row], right: list[Row], ctx: EvalContext,
                caveats: list[Caveat]) -> list[Row]:
    if node.all and node.op != "append":
        caveats.append(Caveat(f"SETOP_ALL_SEMANTICS_ASSUMED_{node.op.upper()}", nodes=(node.id,)))

    if node.op == "append":
        return list(left) + list(right)

    right_keys = {row_key(r) for r in right}
    left_keys = {row_key(r) for r in left}

    if node.op == "union":
        if node.all:
            return list(left) + list(right)
        return _dedupe(left + right, ctx)
    if node.op == "intersect":
        if node.all:
            caveats.append(Caveat("SETOP_MULTISET_INTERSECT_ASSUMED", nodes=(node.id,)))
            return [r for r in left if row_key(r) in right_keys]
        return _dedupe([r for r in left if row_key(r) in right_keys], ctx)
    if node.op == "except":
        return _dedupe([r for r in left if row_key(r) not in right_keys], ctx) \
            if not node.all else [r for r in left if row_key(r) not in right_keys]
    if node.op == "except_both":
        return _dedupe([r for r in left if row_key(r) not in right_keys]
                       + [r for r in right if row_key(r) not in left_keys], ctx)
    raise EvaluationRefusal("UNKNOWN_SET_OPERATION",
                            f"unknown set operation {node.op!r}", node.id)


def _dedupe(rows: list[Row], ctx: EvalContext) -> list[Row]:
    seen: set = set()
    out = []
    for row in rows:
        key = row_key(row)
        if key in seen:
            ctx.counts.setop_rows_dropped += 1
            continue
        seen.add(key)
        out.append(row)
    return out


def _exec_emit(node: Emit, rows: list[Row], ctx: EvalContext,
               caveats: list[Caveat]) -> list[Row]:
    if node.columns:
        present = {c for c in node.columns}
        out = []
        for row in rows:
            values = {}
            for column in node.columns:
                if column not in present or column not in row.values:
                    # A projection naming a column the input does not have yields ABSENT and
                    # is counted - never a silent None, which reads as "the value was null".
                    ctx.counts.emit_column_absent += 1
                raw = row.get(column)
                values[column] = None if raw is ABSENT else raw
            out.append(Row(values=values, index=row.index, time=row.time))
        rows = out
    if node.dedupe_by:
        seen: set = set()
        out = []
        for row in rows:
            key = tuple(canonical(row.get(f.name)) for f in node.dedupe_by)
            if key in seen:
                ctx.counts.emit_dedupe_dropped += 1
                continue
            seen.add(key)
            out.append(row)
        rows = out
    return rows


# --------------------------------------------------------------------------
# The driver
# --------------------------------------------------------------------------


def _order(ir: RuleIR) -> list[Any]:
    """Topological order from the input edges. Never tuple order.

    A tuple is not an execution order, and `validate_ir` allows a node to precede its own
    input in the tuple, so walking in tuple order would read an uncomputed result.
    """
    by_id = {node.id: node for node in ir.nodes}
    dependencies: dict[str, set[str]] = {}
    for node in ir.nodes:
        deps: set[str] = set()
        for f in ("input", "left", "right"):
            value = getattr(node, f, None)
            if isinstance(value, str) and value in by_id:
                deps.add(value)
        if isinstance(node, SetOp):
            for f in ("left", "right"):
                value = getattr(node, f, None)
                if isinstance(value, str):
                    deps.add(value)
        if isinstance(node, Pattern):
            for stage in getattr(node, "stages", ()):
                value = getattr(stage, "input", None)
                if isinstance(value, str) and value in by_id:
                    deps.add(value)
        dependencies[node.id] = deps

    ordered: list[Any] = []
    placed: set[str] = set()
    remaining = [n for n in ir.nodes]
    while remaining:
        progressed = False
        for node in list(remaining):
            if dependencies[node.id] <= placed:
                ordered.append(node)
                placed.add(node.id)
                remaining.remove(node)
                progressed = True
        if not progressed:
            # validate_ir rejects cycles, so this only fires for a hand-built graph.
            raise EvaluationRefusal(
                "IR_UNSUPPORTED_CONSTRUCT",
                "the graph could not be ordered; its edges are not a DAG", None)
    return ordered


def evaluate_ir(ir: RuleIR, sample: Sample) -> EvaluationResult:
    """Evaluate `ir` against `sample`. Never raises for a refusal - it returns one.

    A refusal is a RESULT, not an exception, because "we could not decide this" is something
    a UI has to display, and an exception invites a caller to swallow it into a success path.
    The exception type exists for the internal helpers; this boundary converts it.
    """
    counts = EvalCounts()
    caveats: list[Caveat] = []
    unmodelled: list[str] = []
    ctx = EvalContext(counts=counts, unmodelled=unmodelled)

    try:
        validate_ir(ir)
    except RuleIRValidationError as exc:
        # Preserve the specific diagnosis when the kernel validator already has one. Collapsing
        # "unknown measure" into a generic "did not validate" would throw away the one thing
        # the analyst needs, which is the same defect as a refusal naming the wrong operator.
        code = exc.code if exc.code in KERNEL_EVAL_CODES else "IR_UNSUPPORTED_CONSTRUCT"
        return not_evaluated(EvaluationRefusal(
            code,
            f"the rule did not validate, so there is nothing to evaluate: {exc.message}",
            exc.path), counts)

    if sum(len(v) for v in sample.rows_by_read.values()) > MAX_INPUT_ROWS:
        # Refuse, never truncate: dropping rows changes window contents, therefore changes the
        # verdict, which is precisely the false tuning confidence the plan lists as risk 5.
        return not_evaluated(EvaluationRefusal(
            "EVAL_INPUT_TOO_LARGE",
            f"the sample exceeds {MAX_INPUT_ROWS} rows; refusing rather than truncating, "
            f"because dropping rows would silently change the verdict"), counts)

    refusal = _preflight(ir, sample)
    if refusal is not None:
        return not_evaluated(refusal, counts, unmodelled=tuple(unmodelled))

    policy = ir.execution
    for name in ("late_arrival", "state_retention"):
        if getattr(policy, name, None):
            unmodelled.append(f"ExecutionPolicy.{name} was declared and is NOT honoured by 3A")

    trace: list[NodeTrace] = []
    try:
        values: dict[str, list[Row]] = {}
        for read_id, rows in sample.rows_by_read.items():
            values[read_id] = [Row(values=dict(r), index=i) for i, r in enumerate(rows)]
        counts.rows_in = sum(len(v) for v in values.values())

        node_by_id = {n.id: n for n in ir.nodes}
        order = _order(ir)
        skipped_from: str | None = None

        for node in order:
            primitive = _primitive_of(node)
            node_id = node.id

            if skipped_from is not None:
                # A downstream node of a refused node is `skipped`, never `evaluated` with
                # zero rows. That distinction is what makes a missing node observable.
                trace.append(NodeTrace(node_id, primitive, "skipped"))
                continue

            try:
                if isinstance(node, Read):
                    produced = values.get(node_id, [])
                    detail: dict[str, Any] = {"strategy": node.selector.strategy}
                    if node.bound is not None:
                        detail["declared_source_bound"] = True
                        caveats.append(Caveat("READ_BOUND_NOT_ENFORCED", nodes=(node_id,)))
                    if node.selector.strategy != "raw":
                        caveats.append(Caveat("READ_STRATEGY_SIMULATED", nodes=(node_id,)))
                elif isinstance(node, SetOp):
                    produced = _exec_setop(node, values[node.left], values[node.right],
                                           ctx, caveats)
                    detail = {"op": node.op, "all": node.all}
                else:
                    produced, detail = _exec_scalar(node, values, node_by_id, ctx, caveats, sample)
                values[node_id] = produced
            except EvaluationRefusal as exc:
                if exc.deferred_to:
                    # Already caught at pre-flight; a repeat here would be a pre-flight gap.
                    skipped_from = node_id
                trace.append(NodeTrace(node_id, primitive, "refused",
                                       refusal_code=exc.code))
                return not_evaluated(
                    EvaluationRefusal(exc.code, exc.message, exc.path or node_id,
                                      exc.deferred_to),
                    counts, tuple(trace), tuple(caveats[:MAX_CAVEATS]),
                    tuple(unmodelled))

            incoming = len(produced)
            trace.append(NodeTrace(node_id, primitive, "evaluated",
                                   rows_in=counts.rows_in, rows_out=incoming,
                                   detail=detail,
                                   samples=tuple(r.index for r in produced[:MAX_TRACE_SAMPLES]),
                                   samples_truncated=incoming > MAX_TRACE_SAMPLES))

        output = values.get(ir.output, [])
        if isinstance(ir.output, str) and ir.output not in values:
            return not_evaluated(EvaluationRefusal(
                "IR_UNSUPPORTED_CONSTRUCT",
                f"the declared output node {ir.output!r} was never produced", ir.output),
                counts, tuple(trace), tuple(caveats[:MAX_CAVEATS]), tuple(unmodelled))

        counts.rows_out = len(output)
        columns = columns_of(output) if output else ()
        if output:
            caveats.append(Caveat("SCHEMA_INFERRED_FROM_SAMPLE",
                                  count=len(columns), nodes=(ir.output,)))
        # True only when no aggregation, join, pattern or set operation contributed rows, i.e.
        # every output row is exactly one input event. The plan requires a single-event result
        # to announce itself, and a UI cannot render what the type does not carry.
        relational = {"Aggregate", "Join", "SetOp", "Pattern", "Expand", "Iterate"}
        single = not any(_primitive_of(n) in relational for n in order)

        return EvaluationResult(
            state=EvalState.EVALUATED,
            rows=tuple(output),
            columns=columns,
            trace=tuple(trace),
            counts=counts,
            caveats=tuple(caveats[:MAX_CAVEATS]),
            single_event_projection=single,
            unmodelled=tuple(unmodelled),
        )
    except EvaluationRefusal as exc:
        return not_evaluated(exc, counts, tuple(trace), tuple(caveats[:MAX_CAVEATS]),
                             tuple(unmodelled))


def _upstream_read(node: Any, node_by_id: dict[str, Any]) -> str:
    """The Read node an Aggregate reads through, for looking up a time binding.

    Walks the single-input chain back to a Read. 3A is single-stream, so that chain is linear;
    a multi-stream walk belongs to 3B.
    """
    current = node
    for _ in range(64):
        if isinstance(current, Read):
            return current.id
        parent = node_by_id.get(getattr(current, "input", None))
        if parent is None:
            break
        current = parent
    return ""


def _exec_scalar(node: Any, values: dict[str, list[Row]], node_by_id: dict[str, Any],
                 ctx: EvalContext,
                 caveats: list[Caveat], sample: Sample) -> tuple[list[Row], dict[str, Any]]:
    """Execute a single-input node. Returns the rows and a small detail map for the trace."""
    source = values[node.input]

    if isinstance(node, Derive):
        return _exec_derive(node, source, ctx), {"assignments": len(node.assignments),
                                                "drop": len(node.drop)}
    if isinstance(node, Filter):
        return _exec_filter(node, source, ctx), {}

    if isinstance(node, Aggregate):
        if node.frame is not None:
            read_id = _upstream_read(node, node_by_id)
            field = _resolve_time_field(node.frame, read_id, sample)
            source, usable = _stamp(source, field, ctx)
            if usable == 0 and source:
                raise EvaluationRefusal(
                    "TIME_UNRESOLVED_ON_ALL_ROWS",
                    f"a temporal frame is in play but no row carries a usable value in "
                    f"{field!r}; reporting 'matched nothing' here would be a false verdict",
                    node.id)
        produced = _exec_aggregate(node, source, ctx, caveats)
        return produced, {"groups": ctx.counts.groups, "windows": ctx.counts.windows,
                          "measures": [m.name for m in node.measures]}

    if isinstance(node, Arrange):
        produced = _exec_arrange(node, source, ctx, caveats)
        return produced, {"limit": node.limit, "offset": node.offset,
                          "distinct_on": len(node.distinct_on)}

    if isinstance(node, Emit):
        return _exec_emit(node, source, ctx, caveats), {
            "columns": list(node.columns) if node.columns else None,
            "dedupe_by": len(node.dedupe_by)}

    raise EvaluationRefusal(
        "EVAL_PHASE_NOT_IMPLEMENTED",
        f"phase 3A does not execute a {_primitive_of(node)} node", node.id,
        deferred_to=DEFERRED_NODES.get(_primitive_of(node), "3C"))


