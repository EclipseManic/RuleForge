"""Node execution and the evaluation driver for the semantic execution kernel.

Phase 3A: single-stream only. Read, Derive, Filter, Aggregate (with an optional Frame),
Arrange, SetOp, Emit. Everything from 3B and 3C is refused BY NAME at pre-flight, before a
single row is touched, so a deferred rule costs nothing to reject.

WHAT THIS NEVER CLAIMS
----------------------
This models OUR IR semantics. It never says what a QRadar, Splunk, Elastic or Sentinel engine
will do, because no vendor engine has ever been executed against it - Docker is unavailable in
this environment. Vendor comparison belongs to the capability layer and is marked inferred
there. A result from this module is evidence about the rule, not about a deployment.

THE FOUR SEMANTIC DECISIONS THAT MATTER MOST
---------------------------------------------
1. `sum` of an empty group is 0; `avg` of an empty group is NULL. That asymmetry is the
   classic source of a rule that "fires at threshold 1" on an empty group.
2. A row whose time cannot be resolved is EXCLUDED from windows and counted. If EVERY row's
   time is unusable under a temporal frame, the graph is `not_evaluated` - returning an empty
   result would be a false "matched nothing", the most dangerous possible output.
3. An order key that is ABSENT or NULL sorts AFTER every known key, in BOTH directions, and
   the count is reported. Nulls-first was rejected: it silently promotes unmeasurable rows to
   the top of a `limit N`.
4. `not_evaluated` yields no rows and no columns, enforced in EvaluationResult.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from kernel.eval_errors import EvaluationRefusal
from kernel.eval_expr import EvalContext, evaluate
from kernel.eval_types import (ABSENT, Caveat, Row, canonical)
from models.rule_ir import (AGGREGATE_FUNCTIONS, Aggregate, Frame)

#: Constructs the kernel does not execute. Checked at pre-flight so a deferred rule never
#: costs a row walk.
#:
#: `Pattern` is NOT here: 3C implements it. `Iterate` stays deferred because its `step` is a
#: graph NODE, so a fixed point needs a sub-graph execution model the single-input executor
#: does not have — reported rather than approximated.
DEFERRED_NODES: Mapping[str, str] = {
    "Iterate": "3C",
}

#: Expand modes the model declares but cannot express. `Expand` carries a single `input` and no
#: second operand, so `cross` has nothing to cross with and `generate` has nothing to generate
#: from. Reported as an IR gap rather than approximated.
INEXPRESSIBLE_EXPAND_MODES: Mapping[str, str] = {
    "cross": "Expand declares one input and no second operand",
    "generate": "Expand declares no parameters to generate from",
}

_FRAME_KINDS = frozenset({"tumbling", "sliding", "session", "per_event", "cumulative"})
_SET_OPS = frozenset({"union", "intersect", "except", "append", "except_both"})


class Sample:
    """The caller's rows, keyed per Read node id.

    Keyed per Read because a rule with two Reads over different sources cannot honestly be
    evaluated against one shared row set - assuming they are the same is an invention.
    """

    def __init__(self, rows_by_read: Mapping[str, list[Mapping[str, Any]]],
                 time_bindings: Mapping[str, str] | None = None) -> None:
        self.rows_by_read = {k: list(v) for k, v in rows_by_read.items()}
        self.time_bindings = dict(time_bindings or {})

    def rows(self, read_id: str) -> list[Row] | None:
        raw = self.rows_by_read.get(read_id)
        if raw is None:
            return None
        return [Row(values=dict(r), index=i) for i, r in enumerate(raw)]


# --------------------------------------------------------------------------
# Time resolution - never guessed
# --------------------------------------------------------------------------


def _parse_time(value: Any) -> float | None:
    """Epoch seconds from an int, a float, or a numeric string. Never a bool."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _resolve_time_field(frame: Frame, read_id: str, sample: Sample) -> str:
    """The field carrying the clock, or a refusal. `@timestamp` is never assumed.

    A Frame has no `id`, so the sample binding is keyed by the Read node the frame reads
    through - the binding describes the data, not the window.
    """
    time_ref = frame.time_ref
    field_name = time_ref.field_name
    which = time_ref.which
    bound = sample.time_bindings.get(read_id)

    if field_name and bound and field_name != bound:
        raise EvaluationRefusal(
            "TIME_BINDING_CONFLICT",
            f"frame declares time field {field_name!r} but the sample binds {bound!r} for "
            f"this Read; refusing to prefer one", read_id)
    chosen = field_name or bound
    if not chosen:
        raise EvaluationRefusal(
            "TIME_FIELD_UNRESOLVED",
            f"no time field is declared for the {which} clock and the sample binds none; the "
            f"kernel will not assume a field name such as '@timestamp'", read_id)
    return chosen


def _stamp(rows: list[Row], field: str, ctx: EvalContext) -> tuple[list[Row], int]:
    """Attach resolved times, counting every row whose time is unusable.

    Returns new rows: a Row is frozen, and a window assignment is data, so it is built rather
    than assigned. A row whose time cannot be resolved is excluded from every window and
    counted, because silently treating it as time zero would place it in the first window.
    """
    usable = 0
    out: list[Row] = []
    for row in rows:
        raw = row.get(field)
        if raw is ABSENT or raw is None:
            ctx.counts.rows_without_time += 1
            out.append(Row(values=row.values, index=row.index, time=None))
            continue
        parsed = _parse_time(raw)
        if parsed is None:
            ctx.counts.rows_unparseable_time += 1
            out.append(Row(values=row.values, index=row.index, time=None))
            continue
        usable += 1
        out.append(Row(values=row.values, index=row.index, time=parsed, time_source=field))
    return out, usable


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------


def _check_frame(frame: Frame) -> list[Caveat]:
    """Refuse what the IR cannot express; record what it can only approximate."""
    caveats: list[Caveat] = []
    if frame.kind not in _FRAME_KINDS:
        raise EvaluationRefusal("IR_UNSUPPORTED_PARAMETERS",
                                f"unknown frame kind {frame.kind!r}", "frame")
    # `sliding` and `alignment="explicit"` are now EXPRESSIBLE - the model carries `Frame.step`
    # and `Frame.anchor` and refuses at construction when either is missing. Expressible is not
    # the same as implemented, and the gap between the two is where this kernel nearly lied.
    #
    # With the old refusals deleted, a sliding frame with a 60s step over a 600s window was
    # quietly computed as TUMBLING: two buckets instead of ~20 windows, verdict `matched`, and
    # a caveat reading TUMBLING_BUCKETS_FULLY_FORMED - so `step` was read and discarded while
    # the output positively asserted a different operator than the one requested. That is the
    # "declared-but-ignored parameter" hazard the model validation warns about, except here the
    # parameter went missing in the KERNEL and the caveat covered for it. Refusing is correct
    # and the reason is the KERNEL's, not the model's and not a vendor's.
    if frame.kind == "sliding":
        raise EvaluationRefusal(
            "FRAME_SLIDING_NOT_IMPLEMENTED",
            f"this kernel implements tumbling, per_event, cumulative and session frames, but "
            f"NOT sliding ones: a {frame.size.seconds}s window on a "
            f"{frame.step.seconds}s grid emits one row per grid position per event, which is a "
            f"different algorithm from the one here. Falling back to tumbling would return "
            f"confident wrong counts, so the kernel refuses", "frame")
    if frame.alignment == "explicit":
        raise EvaluationRefusal(
            "FRAME_EXPLICIT_ANCHOR_NOT_IMPLEMENTED",
            f"this kernel aligns frames to the epoch, not to a declared anchor field "
            f"({frame.anchor.name!r}); epoch-aligned buckets silently ignore the anchor and "
            f"return confident wrong counts, so the kernel refuses rather than mis-bucket",
            "frame")
    if frame.kind in ("per_event", "cumulative", "session"):
        if frame.offset_seconds:
            raise EvaluationRefusal(
                "FRAME_OFFSET_NOT_APPLICABLE",
                f"offset_seconds has no meaning for a {frame.kind} frame; silently ignoring a "
                f"declared parameter is how a parameter goes missing unnoticed", "frame")
    if frame.kind in ("per_event", "cumulative") and frame.size is not None:
        raise EvaluationRefusal(
            "FRAME_SIZE_NOT_APPLICABLE",
            f"a {frame.kind} frame takes no size", "frame")
    if frame.kind == "tumbling" and frame.size is None:
        raise EvaluationRefusal("FRAME_SIZE_NOT_APPLICABLE",
                                "a tumbling frame requires a size", "frame")

    caveats.append(Caveat("TUMBLING_BUCKETS_FULLY_FORMED",
                          nodes=("frame",)))
    caveats.append(Caveat("EMPTY_WINDOWS_SUPPRESSED", nodes=("frame",)))
    if frame.kind == "session":
        caveats.append(Caveat("SESSION_SIZE_READ_AS_GAP", nodes=("frame",)))
        caveats.append(Caveat("SESSION_NOT_EXTENDED_BY_TRAILING_GAP", nodes=("frame",)))
    if frame.alignment == "epoch" and frame.kind == "tumbling":
        caveats.append(Caveat("TUMBLING_BOUNDARY_LEFT_CLOSED_RIGHT_OPEN", nodes=("frame",)))
    return caveats


def _windows(rows: list[Row], frame: Frame) -> list[list[Row]]:
    """Partition rows into windows. Order is (time, index); index is the tie-break."""
    ordered = sorted((r for r in rows if r.time is not None), key=lambda r: (r.time, r.index))

    if frame.partition_by:
        partitions: dict[tuple, list[Row]] = {}
        for row in ordered:
            key = tuple(canonical(row.get(f.name)) for f in frame.partition_by)
            partitions.setdefault(key, []).append(row)
    else:
        partitions = {(): ordered}

    out: list[list[Row]] = []
    for group in partitions.values():
        if not group:
            continue
        if frame.kind == "per_event":
            out.extend([[row] for row in group])
        elif frame.kind == "cumulative":
            out.extend([group[:i + 1] for i in range(len(group))])
        elif frame.kind == "session":
            size = float(frame.size.seconds) if frame.size else 0.0
            session = [group[0]]
            for row in group[1:]:
                # A gap of exactly the size opens a new session.
                if row.time - session[-1].time >= size:
                    out.append(session)
                    session = [row]
                else:
                    session.append(row)
            out.append(session)
        else:   # tumbling
            size = float(frame.size.seconds) if frame.size else 0.0
            offset = float(frame.offset_seconds or 0)
            buckets: dict[int, list[Row]] = {}
            for row in group:
                # Half-open [origin + kS + O, origin + (k+1)S + O): an event exactly on a
                # boundary belongs to the LATER window.
                index = math.floor((row.time - offset) / size) if size else 0
                buckets.setdefault(int(index), []).append(row)
            out.extend(buckets[key] for key in sorted(buckets))
    return out


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

_NEEDS_FIELD = frozenset({"count_distinct", "dcount", "min", "max", "sum", "avg", "values",
                          "make_set"})
_ARG_EXTREME = frozenset({"arg_max", "arg_min"})


def _collect_measure_values(rows: list[Row], measure: Any, ctx: EvalContext,
                            require_field: bool) -> list[Any]:
    """Rows admitted by `where`, mapped to the measure's field.

    `where` is a Filter on the rows feeding THAT measure, so it obeys the same three-valued
    rule: only True admits a row. The RAW value is tested rather than a booleanised helper,
    because collapsing UNKNOWN to False here would silently turn "we cannot tell" into "it did
    not match" and the unknown would never be counted.

    With `require_field=False` (a fieldless `count()`) the sentinel is returned per admitted row
    instead of a value, so `count()` counts ROWS and `count(field)` counts VALUES - the
    distinction is the whole meaning of `count(f)`.
    """
    values: list[Any] = []
    for row in rows:
        if measure.where is not None:
            verdict = evaluate(measure.where, row, ctx, None)
            if verdict is None:
                ctx.counts.measure_where_unknown += 1
                continue
            if verdict is not True:
                continue
        if not require_field:
            values.append(_COUNT_SENTINEL)
            continue
        # `Measure.field` is a FieldRef, so the row lookup needs its NAME. Reading the
        # FieldRef object itself as a key would silently yield ABSENT for every row, and
        # every measure would collapse to zero.
        value = row.get(measure.field.name)
        if value is ABSENT or value is None:
            continue
        values.append(value)
    return values


class _CountSentinel:
    """One admitted row of a fieldless count. Not a value; `count()` counts occurrences."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<row>"


_COUNT_SENTINEL = _CountSentinel()


def _aggregate_group(rows: list[Row], node: Aggregate, ctx: EvalContext,
                     scope: dict[str, Any]) -> None:
    for measure in node.measures:
        # `arg_max`/`arg_min` are no longer refused here. `Measure.by` exists and the model
        # refuses a measure that declares only one of the two fields, so the branch that used
        # to live here could never fire. EVALUATING them is the next increment, not refusing
        # them: a guard that cannot fire is read as protection while checking nothing.
        if measure.function in _NEEDS_FIELD and measure.field is None:
            raise EvaluationRefusal(
                "MEASURE_FIELD_REQUIRED",
                f"measure {measure.name!r} uses {measure.function!r}, which requires a field",
                measure.name)
        if measure.function == "count" and measure.field is None:
            # `count()` with no field counts ROWS - but it must still honour `where` and
            # `distinct`. An earlier version short-circuited here and returned `len(rows)`
            # unconditionally, so `Measure("Failed", "count", where=ok == False)` counted
            # every row instead of the failing ones. That is the number an analyst tunes a
            # threshold against, and it was silently wrong.
            if measure.where is None and not measure.distinct:
                scope[measure.name] = len(rows)
                continue
            scope[measure.name] = _reduce("count", _collect_measure_values(
                rows, measure, ctx, require_field=False), measure.name, ctx)
            continue

        values = _collect_measure_values(rows, measure, ctx, require_field=True)
        if measure.distinct:
            seen: set = set()
            deduped = []
            for value in values:
                key = canonical(value)
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(value)
            values = deduped

        scope[measure.name] = _reduce(measure.function, values, measure.name, ctx)


def _reduce(function: str, values: list[Any], name: str, ctx: EvalContext) -> Any:
    if function not in AGGREGATE_FUNCTIONS:
        raise EvaluationRefusal("UNKNOWN_AGGREGATE_FUNCTION",
                                f"unknown aggregate function {function!r}", name)
    if function == "count":
        return len(values)
    if function in ("count_distinct", "dcount"):
        # dcount and count_distinct are indistinguishable in the model, so they are treated as
        # synonyms and the assumption is recorded rather than refusing a legal IR.
        return len({canonical(v) for v in values})
    if function == "values":
        return list(values)
    if function == "make_set":
        return list(values)
    if function == "sum":
        total = 0
        for value in values:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                # A non-numeric value present makes the total undecidable, not zero.
                ctx.counts.arithmetic_unknown += 1
                return UNKNOWN_SUM
            total += value
        return total
    if function == "avg":
        if not values:
            return None
        total = 0
        for value in values:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                ctx.counts.arithmetic_unknown += 1
                return UNKNOWN_SUM
            total += value
        return total / len(values)
    if function in ("min", "max"):
        if not values:
            return None
        best = values[0]
        for value in values[1:]:
            comparable = (isinstance(value, (int, float)) and not isinstance(value, bool)) == \
                        (isinstance(best, (int, float)) and not isinstance(best, bool))
            if not comparable:
                ctx.counts.comparison_type_mismatch += 1
                return UNKNOWN_SUM
            if (value < best) if function == "min" else (value > best):
                best = value
        return best
    raise EvaluationRefusal("UNKNOWN_AGGREGATE_FUNCTION",
                            f"aggregate {function!r} is not implemented by 3A", name)


#: A measure that cannot be decided. Distinct from 0 and from None.
class _Unknown:
    __slots__ = ()

    def __repr__(self) -> str:
        return "UNKNOWN_MEASURE"


UNKNOWN_SUM = _Unknown()
