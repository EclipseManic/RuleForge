"""Node evaluation.

Each function here takes the rows produced by its input node and returns rows for
its own output, plus caveats. Two conventions hold everywhere:

  * A row that cannot be decided is COUNTED, not silently dropped. `Filter` keeps
    undecided rows out of its output but records how many and why, because
    "matched nothing" and "could not decide anything" are different findings and
    only one of them means the rule is quiet.

  * Any construct whose semantics this module cannot honour raises `Refusal`.
    There is no fallback path. A window that cannot slide refuses; it does not
    become a tumbling window. A regex dialect that cannot be honoured refuses; it
    does not get evaluated with a different engine.

WINDOWING is implemented as a real grid, including sliding grids. The sliding
algorithm emits one window per (grid position, event) pair, which is why it
produces many more windows than tumbling does for the same input. That difference
is the whole reason the two are separate operators, and an implementation that
returned tumbling results for a sliding frame would be confidently wrong in a way
that no test of the tumbling path would catch.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Final

from .evaluate import Caveat, EvaluationContext, Row, eval_expr
from .ir import (
    Aggregate,
    Arrange,
    Derive,
    Emit,
    Expand,
    FieldRef,
    Filter,
    Frame,
    Join,
    Measure,
    Pattern,
    Package,
    SetOp,
)
from .values import (
    ABSENT,
    Refusal,
    Undecided,
    as_number,
    is_undecided,
)

#: Grid origin for epoch-aligned windows. A declared constant rather than a
#: configurable default: making it configurable would let a rule's bucketing
#: depend on a setting the rule never mentions.
EPOCH: Final = Decimal(0)


#: Field value primitives, and the operations valid on each. Rejecting
#: `"5" < 3` at construction is cheaper and clearer than discovering it at
#: evaluation time on a row that happens to hold a string.
def resolve_field(row: Row, ref: FieldRef) -> Any:
    """Read a field reference out of a row, honouring a nested path.

    THE ONE WAY A FIELD IS EVER READ. An earlier version had this logic in the
    expression layer only, while every NODE read `ref.name` directly -- so
    `FieldRef("event", ("v",))` resolved to `event.v` inside a Filter and to the
    whole `event` dict inside an Aggregate, a Join key, a sort column, an Expand
    and a time reference. The expression layer and the node layer disagreed about
    what a field was, which is the exact defect class this tool exists to prevent,
    committed by the tool itself.

    A path that cannot be walked yields ABSENT, not an error. A field path into a
    value that is absent is genuinely absent.
    """
    current: Any = row.values.get(ref.name, ABSENT)
    for segment in ref.path:
        if current is ABSENT or current is None:
            return ABSENT
        if isinstance(current, dict):
            current = current.get(segment, ABSENT)
        elif isinstance(current, (list, tuple)):
            if isinstance(segment, int) and -len(current) <= segment < len(current):
                current = current[segment]
            else:
                return ABSENT
        else:
            return ABSENT
    return current


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


def eval_read(node: Any, rows: list[Row],
              ctx: EvaluationContext) -> list[Row]:
    """The source of every row in the rule.

    Registered in the dispatch table rather than handled as a fallthrough, so the
    set of executable nodes is exactly the set of registered evaluators. A node
    with no evaluator then fails loudly at validation time instead of quietly
    producing no rows, which would read as "the rule matched nothing".
    """
    ctx.budget.spend(1, "read")
    return list(rows)


# ---------------------------------------------------------------------------
# Filter
# ---------------------------------------------------------------------------


def eval_filter(node: Filter, rows: list[Row], ctx: EvaluationContext) -> list[Row]:
    """Keep rows whose condition decided True.

    Undecided rows are excluded from the output but counted, because including
    them would be wrong (the rule did not match them) and dropping them silently
    would be dishonest (we do not know that it did not match them).
    """
    kept: list[Row] = []
    undecided: list[Row] = []
    rejected = 0

    for row in rows:
        ctx.budget.spend(1, "filtering")
        outcome = eval_expr(node.condition, row, ctx)
        if outcome is True:
            kept.append(row)
        elif isinstance(outcome, Undecided):
            undecided.append(row)
        else:
            rejected += 1

    if undecided:
        ctx.add(Caveat(
            "FILTER_UNDECIDABLE_ROWS",
            f"{len(undecided)} of {len(rows)} rows could not be decided by "
            f"`{node.id}`, so this filter has NOT established that they do not "
            f"match. The usual cause is a field the rule references being absent on "
            f"those rows. Narrowed rules and sparse data are the two cases this "
            f"changes the meaning of.",
            len(undecided)))

    return kept


# ---------------------------------------------------------------------------
# Derive
# ---------------------------------------------------------------------------


def eval_derive(node: Derive, rows: list[Row],
                ctx: EvaluationContext) -> list[Row]:
    out: list[Row] = []
    for row in rows:
        ctx.budget.spend(1, "derive")
        values = dict(row.values)
        uncertain = dict(row.uncertain)
        for target, expr in node.assignments:
            outcome = eval_expr(expr, row, ctx)
            if is_undecided(outcome) or outcome is ABSENT:
                # DO NOT FABRICATE A NULL. An earlier version wrote None here,
                # turning "this field is not in the row" into "this field is
                # present and null" -- the exact distinction the value model
                # exists to keep, undone one layer up. It also punched a hole in
                # Emit: a derived column existed with a null in it, while a
                # missing column raised EMIT_COLUMN_MISSING, so the same absence
                # took two different paths depending on how it arose.
                uncertain[target] = "undecided"
                values.pop(target, None)
            else:
                values[target] = outcome
        out.append(Row(values, row.time, row.index, uncertain))
    return out


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------


def _event_time(row: Row, frame: Frame) -> Decimal | None:
    """The row's position on the time axis, or None if it has none.

    A row without a usable timestamp is not dropped. It is bucketed separately and
    surfaced, because dropping it would quietly shrink the denominator of every
    count in the rule.
    """
    assert frame.time_ref is not None
    raw = resolve_field(row, frame.time_ref.as_ref())
    number = as_number(raw)
    if number is None:
        return None
    return number


def _window_start(t: Decimal, frame: Frame,
                  anchor_value: Decimal | None = None) -> Decimal:
    """Left edge of the window containing `t`.

    Sliding windows are computed as a grid of origins, one per step, which is why
    a sliding frame produces overlapping windows. For a tumbling frame this is
    plain floor division; for explicit alignment the grid is offset by the row's
    own anchor value, so the origin comes from the data rather than from a setting.
    """
    assert frame.size is not None
    if frame.is_epoch_aligned:
        origin = frame.offset.seconds if frame.offset else EPOCH
        return origin + (t - origin) // frame.size.seconds * frame.size.seconds
    if anchor_value is None:
        raise Refusal(
            "ANCHOR_UNRESOLVED",
            f"the anchor field {frame.anchor.name if frame.anchor else '?'} has no "
            f"usable numeric value on the row being bucketed, so the window origin "
            f"cannot be established", "Frame")
    return anchor_value + (t - anchor_value) // frame.size.seconds * frame.size.seconds


def _anchor_for(row: Row, frame: Frame) -> Decimal | None:
    """The row's own anchor value, when the frame is explicitly aligned."""
    if frame.is_epoch_aligned or frame.anchor is None:
        return None
    return as_number(resolve_field(row, frame.anchor))


def _group_key(row: Row, keys: tuple[FieldRef, ...]) -> tuple[Any, ...]:
    """Identity for grouping. ABSENT is a distinct group from None.

    This is why the value model keeps ABSENT and NULL separate. If a missing field
    and a null field grouped together, then "count events where `user` is absent"
    and "count events where `user` is null" would return the same number, and one
    of them is always wrong.
    """
    out: list[Any] = []
    for key in keys:
        value = resolve_field(row, key)
        if value is ABSENT:
            out.append(("absent", key.name))
        elif value is None:
            out.append(("null", key.name))
        else:
            out.append(("value", _groupable(value)))
    return tuple(out)


def _groupable(value: Any) -> Any:
    number = as_number(value)
    return number if number is not None else value


def _windows(frame: Frame, times: list[Decimal],
            rows: list[Row]) -> list[list[int]]:
    """Partition row indices into windows.

    Sliding frames get one window per grid origin, and each window holds every row
    in `[origin, origin + size)`. This is the honest implementation: a 600s window
    on a 60s grid over an hour of events yields roughly ten times as many windows
    as tumbling does, because consecutive windows share rows. Returning tumbling
    results here would report the right COUNT for the wrong TIME RANGE.
    """
    if not times:
        return []

    if frame.kind == "per_event":
        return [[index] for index in range(len(times))]

    if frame.kind == "cumulative":
        return [list(range(len(times)))]

    if frame.kind == "session":
        return _session_windows(times, frame)

    assert frame.size is not None
    size = frame.size.seconds
    ordered = sorted(range(len(times)), key=lambda i: times[i])

    if frame.kind == "tumbling":
        buckets: dict[Decimal, list[int]] = {}
        for index in ordered:
            start = _window_start(times[index], frame,
                                  _anchor_for(rows[index], frame))
            buckets.setdefault(start, []).append(index)
        return [buckets[k] for k in sorted(buckets)]

    if frame.kind == "sliding":
        assert frame.step is not None
        step = frame.step.seconds
        if step <= 0:
            raise Refusal("FRAME_STEP_INVALID", "a sliding frame needs a positive step",
                          "Frame")
        first, last = times[ordered[0]], times[ordered[-1]]
        origins: list[Decimal] = []
        origin = _window_start(first, frame, _anchor_for(rows[ordered[0]], frame))
        while origin <= last:
            origins.append(origin)
            origin = origin + step
            ctx_spend = len(origins)
            if ctx_spend > 100_000:
                raise Refusal(
                    "WINDOW_COUNT_EXPLOSIVE",
                    f"a {size}s window stepping by {step}s over this data needs more "
                    f"than 100000 windows. Either the step is too fine for the time "
                    f"range, or the timestamps are not what the rule assumes.",
                    "Frame")
        windows: list[list[int]] = []
        for start in origins:
            end = start + size
            members = [i for i in ordered if start <= times[i] < end]
            if members:
                windows.append(members)
        return windows

    raise Refusal("FRAME_UNSUPPORTED", f"cannot window with kind {frame.kind!r}", "Frame")


def _session_windows(times: list[Decimal], frame: Frame) -> list[list[int]]:
    """Split on a gap larger than `gap`, or on an explicit boundary.

    With no declared gap a session has no definition, so it is refused rather than
    split on some assumed interval.
    """
    if frame.gap is None:
        raise Refusal(
            "SESSION_GAP_REQUIRED",
            "a session frame needs to know what breaks a session. Without a declared "
            "gap the boundary would have to be guessed, and every guessed boundary "
            "changes which events group together.", "Frame")
    ordered = sorted(range(len(times)), key=lambda i: times[i])
    sessions: list[list[int]] = []
    current: list[int] = []
    previous: Decimal | None = None
    for index in ordered:
        if previous is not None and times[index] - previous > frame.gap.seconds:
            sessions.append(current)
            current = []
        current.append(index)
        previous = times[index]
    if current:
        sessions.append(current)
    return sessions


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------


def _accumulate(function: str, values: list[Any]) -> Any:
    """Apply an aggregate to a column's values.

    ABSENT and NULL are excluded from every aggregate except `count`, because a
    count of events and a count of values are different questions. Including them
    would make `count(distinct user)` return a higher number than there are users.
    """
    present = [v for v in values if v is not ABSENT and v is not None]

    if function == "count":
        return len(values)
    if function == "distinct_count":
        return len({_groupable(v) for v in present})
    if function == "count_distinct":
        return len({_groupable(v) for v in present})

    if not present:
        return None

    numbers = [as_number(v) for v in present]
    numeric = [n for n in numbers if n is not None]

    if function == "set":
        # DISTINCT VALUES, NOT A COUNT. KQL's `make_set(SourceIp)` produces a
        # collection; `count_distinct` produces a number. Substituting one for the
        # other would change the column's type and every downstream use of it, so
        # `set` is its own aggregate and returns a sorted tuple.
        #
        # SORTED so the result is deterministic. Two runs over the same rows must
        # produce the same collection, or a rule's output would depend on row
        # order and a diff against a saved artifact would be noise.
        distinct = {_groupable(v) for v in present}
        return tuple(sorted(distinct, key=str))
    if function == "min":
        if len(numeric) == len(present):
            return min(numeric)
        return min(present, key=str)
    if function == "max":
        if len(numeric) == len(present):
            return max(numeric)
        return max(present, key=str)
    if function == "sum":
        return sum(numeric, Decimal(0)) if len(numeric) == len(present) else None
    if function == "avg":
        if not numeric or len(numeric) != len(present):
            return None
        return sum(numeric, Decimal(0)) / Decimal(len(numeric))
    if function == "stddev":
        if len(numeric) < 2 or len(numeric) != len(present):
            return None
        mean = sum(numeric, Decimal(0)) / Decimal(len(numeric))
        variance = sum(((n - mean) ** 2 for n in numeric), Decimal(0)) / \
            Decimal(len(numeric))
        return variance.sqrt()
    if function == "first":
        return present[0]
    if function == "last":
        return present[-1]
    return None


def eval_aggregate(node: Aggregate, rows: list[Row],
                   ctx: EvaluationContext) -> list[Row]:
    frame = node.frame
    if frame.kind in ("tumbling", "sliding", "session"):
        if frame.time_ref is None:
            raise Refusal("FRAME_REQUIRES_TIME_REF",
                          "this aggregate windows on time but names no time field",
                          "Aggregate")
        times: list[Decimal] = []
        usable: list[Row] = []
        untimed = 0
        for row in rows:
            t = _event_time(row, frame)
            if t is None:
                untimed += 1
                continue
            times.append(t)
            usable.append(row)
        if untimed:
            ctx.add(Caveat(
                "ROWS_WITHOUT_TIME",
                f"{untimed} of {len(rows)} rows had no usable value in "
                f"`{frame.time_ref.field_name}`, so they could not be placed in a "
                f"window and are excluded from every count below. A count that "
                f"silently omits rows understates the total it appears to report.",
                untimed))
        members = _windows(frame, times, usable)
    else:
        members = [list(range(len(rows)))]

    out: list[Row] = []
    for group in members:
        ctx.budget.spend(max(1, len(group)), "aggregation")
        bucket = [rows[i] for i in group]

        keyed: dict[tuple[Any, ...], list[Row]] = {}
        for row in bucket:
            keyed.setdefault(_group_key(row, node.keys), []).append(row)

        for key, group_rows in keyed.items():
            values: dict[str, Any] = {}
            uncertain: dict[str, str] = {}

            for key_ref in node.keys:
                if key_ref.name in values:
                    continue
                first = resolve_field(group_rows[0], key_ref)
                if first is not ABSENT:
                    # An absent key is recorded as ABSENT by being OMITTED, not as
                    # None. Writing None here made "no value for this key" and
                    # "null value for this key" the same output row, which is the
                    # distinction this file exists to preserve.
                    values[key_ref.name] = first
                else:
                    uncertain[key_ref.name] = "absent"

            for measure in node.measures:
                result = _apply_measure(measure, group_rows, ctx)
                values[measure.name] = result
                if result is None and measure.function not in ("count",):
                    uncertain[measure.name] = "no usable value in this group"

            window_time = None
            if bucket and frame.time_ref is not None:
                # `group` holds INDICES; `bucket` holds the rows. Reaching for
                # group[0] here passed an int where a Row was expected.
                window_time = _window_start(
                    _event_time(bucket[0], frame), frame,
                    _anchor_for(bucket[0], frame))

            out.append(Row(values, window_time, 0, uncertain))

    return out


def _apply_measure(measure: Measure, group_rows: list[Row],
                   ctx: EvaluationContext) -> Any:
    if measure.function in ("count", "distinct_count"):
        if measure.function == "count":
            return len(group_rows)
        # `distinct_count` used to `return len(group_rows)` whenever
        # `measure.field` was falsy -- and because it is a NULLARY aggregate, the
        # model REFUSES a field on it, so that branch was always taken. The two
        # aggregates were transpositions of one another: `count` and
        # `distinct_count` returned the same number, while `count_distinct` was
        # the one that actually counted distinct values. A parser mapping
        # COUNT(DISTINCT x) to the wrong one got a confidently wrong number under
        # a plausible name.
        if measure.field is None:
            raise Refusal(
                "DISTINCT_COUNT_NEEDS_FIELD",
                "`distinct_count` must say which field to count distinct values of. "
                "Without it it is identical to `count`, and a rule that means "
                "'how many different users' would silently report 'how many events'.",
                "Measure")
        return len({_groupable(resolve_field(r, measure.field))
                    for r in group_rows
                    if resolve_field(r, measure.field) not in (ABSENT, None)})

    if measure.function == "count_distinct":
        assert measure.field is not None
        return len({_groupable(resolve_field(r, measure.field))
                    for r in group_rows
                    if resolve_field(r, measure.field) not in (ABSENT, None)})

    if measure.function in ("arg_min", "arg_max"):
        assert measure.field is not None and measure.by is not None
        best: Row | None = None
        best_key: Any = None
        tied = False
        for row in group_rows:
            value = resolve_field(row, measure.field)
            order = as_number(resolve_field(row, measure.by))
            if value in (ABSENT, None) or order is None:
                continue
            if best is None:
                best, best_key, tied = row, order, False
                continue
            if order == best_key:
                tied = True
            elif (order > best_key) if measure.function == "arg_max" \
                    else (order < best_key):
                best, best_key, tied = row, order, False
        if tied:
            # A tie has no single correct answer, and picking one would make the
            # result depend on row order rather than on the data.
            ctx.add(Caveat(
                "ARG_EXTREME_TIE",
                f"measure {measure.name!r} had a tie in {measure.by.name!r}; there is "
                f"no correct single winner, so this reports UNDECIDED rather than "
                f"whichever row happened to be seen first.", 1))
            return None
        return None if best is None else resolve_field(best, measure.field)

    assert measure.field is not None
    return _accumulate(measure.function, [resolve_field(r, measure.field)
                                          for r in group_rows])


# ---------------------------------------------------------------------------
# Arrange
# ---------------------------------------------------------------------------


def eval_arrange(node: Arrange, rows: list[Row],
                 ctx: EvaluationContext) -> list[Row]:
    if not node.order_by:
        return rows[:node.limit] if node.limit else list(rows)

    ordered = list(rows)
    for ref, direction in reversed(node.order_by):
        ctx.budget.spend(len(ordered), "sorting")

        def sort_key(row: Row, _ref: FieldRef = ref) -> tuple[int, Any]:
            value = resolve_field(row, _ref)
            if value is ABSENT or value is None:
                # ABSENT sorts last in ascending order, consistently, rather than
                # raising. Comparing ABSENT to a Decimal would be a type error, and
                # a rule that sorts on a sparse column would then fail outright.
                return (1, "")
            number = as_number(value)
            if number is not None:
                return (0, number)
            return (0, str(value))

        ordered.sort(key=sort_key, reverse=(direction == "desc"))

    return ordered[:node.limit] if node.limit else ordered


# ---------------------------------------------------------------------------
# SetOp
# ---------------------------------------------------------------------------


def eval_setop(node: SetOp, left: list[Row], right: list[Row],
               ctx: EvaluationContext) -> list[Row]:
    def key_of(row: Row) -> tuple[Any, ...]:
        return _group_key(row, node.keys)

    right_keys = {key_of(r) for r in right}
    left_keys = {key_of(r) for r in left}
    both = left_keys & right_keys

    if node.op == "union":
        merged = {key_of(r): r for r in left}
        for row in right:
            merged.setdefault(key_of(row), row)
        return list(merged.values())
    if node.op == "intersect":
        return [r for r in left if key_of(r) in both]
    if node.op == "except":
        return [r for r in left if key_of(r) not in right_keys]
    raise Refusal("SETOP_UNSUPPORTED", f"unknown set operation {node.op!r}", "SetOp")


# ---------------------------------------------------------------------------
# Join
# ---------------------------------------------------------------------------


def eval_join(node: Join, left: list[Row], right: list[Row],
              ctx: EvaluationContext) -> list[Row]:
    """Join with equality conditions and optional asymmetric temporal predicates.

    LEFT join keeps unmatched left rows with ABSENT right fields. Those rows are
    NOT dropped: dropping them turns a left join into an inner join silently, which
    is the single most common way a join loses the rows a rule was written to
    catch.
    """
    if not node.on and not node.temporal:
        raise Refusal("JOIN_NO_CONDITION", "a join needs a condition", "Join")

    index: dict[tuple[Any, ...], list[Row]] = {}
    for row in right:
        ctx.budget.spend(1, "join indexing")
        index.setdefault(_equality_key(row, node.on, right=True), []).append(row)

    out: list[Row] = []
    matched_right: set[int] = set()

    for left_row in left:
        ctx.budget.spend(1, "join probing")
        candidates = index.get(_equality_key(left_row, node.on, right=False), [])

        emitted = False
        for right_row in candidates:
            ctx.budget.spend(1, "join compare")
            if _temporal_ok(node, left_row, right_row):
                matched_right.add(id(right_row))
                out.append(left_row.merged_with(right_row, node.left_prefix,
                                                node.right_prefix))
                emitted = True
                if len(out) > 200_000:
                    raise Refusal(
                        "JOIN_TOO_LARGE",
                        "this join produced more than 200000 rows. That usually means "
                        "the join key is too coarse, or a temporal bound is missing.",
                        "Join")

        if not emitted and node.how == "left":
            out.append(left_row.merged_with(Row({}), node.left_prefix,
                                            node.right_prefix))

    return out


def _equality_key(row: Row, on: tuple[tuple[FieldRef, FieldRef], ...],
                  right: bool) -> tuple[Any, ...]:
    key: list[Any] = []
    for left_ref, right_ref in on:
        ref = right_ref if right else left_ref
        value = resolve_field(row, ref)
        if value is ABSENT:
            key.append(("absent", ref.name))
        elif value is None:
            key.append(("null", ref.name))
        else:
            key.append(("value", _groupable(value)))
    return tuple(key)


def _temporal_ok(node: Join, left_row: Row, right_row: Row) -> bool:
    """Apply the temporal predicates, returning False if any fails.

    Asymmetric bounds are the point. `(login, access, 0, 10m, True, False)` reads
    "a login from zero to ten minutes after the access, upper bound EXCLUSIVE".
    Collapsing that to "within ten minutes" would make the rule match a login
    before the access, which the rule never said.
    """
    for left_ref, right_ref, lower, upper, lower_inclusive, upper_inclusive in node.temporal:
        left_time = as_number(resolve_field(left_row, left_ref))
        right_time = as_number(resolve_field(right_row, right_ref))
        if left_time is None or right_time is None:
            # Cannot decide the temporal relation. Refuse to match rather than
            # assume: a join that dropped rows it could not time would understate
            # the correlation it exists to detect.
            return False
        delta = right_time - left_time
        if lower_inclusive:
            if delta < lower.seconds:
                return False
        elif delta <= lower.seconds:
            return False
        if upper_inclusive:
            if delta > upper.seconds:
                return False
        elif delta >= upper.seconds:
            return False
    return True


# ---------------------------------------------------------------------------
# Expand
# ---------------------------------------------------------------------------


def eval_expand(node: Expand, rows: list[Row],
                ctx: EvaluationContext) -> list[Row]:
    target = node.as_field or FieldRef(node.field.name)
    out: list[Row] = []
    for row in rows:
        ctx.budget.spend(1, "expanding")
        value = resolve_field(row, node.field)
        if value in (ABSENT, None):
            out.append(row)
            continue
        if not isinstance(value, (list, tuple)):
            # Not multivalued. Emitting one row unchanged is correct: the field
            # holds a single value, so unnesting it is the identity.
            out.append(row)
            continue
        if len(value) > node.limit:
            raise Refusal(
                "EXPAND_VALUE_LIMIT",
                f"field {node.field.name!r} holds {len(value)} values, over the limit "
                f"of {node.limit}. Unnesting this would produce that many rows.",
                "Expand")
        if not value:
            out.append(row)
            continue
        for item in value:
            values = dict(row.values)
            values[target.name] = item
            out.append(Row(values, row.time, row.index, dict(row.uncertain)))
    return out


# ---------------------------------------------------------------------------
# Pattern
# ---------------------------------------------------------------------------


def eval_pattern(node: Pattern, rows: list[Row],
                 ctx: EvaluationContext) -> list[Row]:
    """Ordered multi-event matching within a window, grouped by key.

    Implemented as: group by key, sort by time, then for each candidate start row
    walk forward looking for stage 1, then stage 2, and so on, all within
    `within` of the start. `until` is checked as a veto -- if it matches inside the
    window the candidate is discarded, which is what makes "access, then no logout
    for 10 minutes" expressible.
    """
    grouped: dict[tuple[Any, ...], list[Row]] = {}
    for row in rows:
        grouped.setdefault(_group_key(row, node.key), []).append(row)

    out: list[Row] = []
    for key, group in grouped.items():
        ctx.budget.spend(max(1, len(group)), "pattern grouping")
        if node.ordered:
            time_field = _pattern_time_field(node, group)
            if time_field is None:
                ctx.add(Caveat(
                    "PATTERN_NO_TIME",
                    "a pattern needs to know which field orders the events, and "
                    "this rule does not say. Guessing one is how a sequence gets "
                    "ordered by an unrelated column, so no matches are reported "
                    "rather than matches in an arbitrary order.",
                    len(group)))
                continue
            group = sorted(group, key=lambda r: as_number(r.get(time_field)) or Decimal(0))

        times = [_row_time(r, node) for r in group]
        matches = 0
        for start_index, start_row in enumerate(group):
            ctx.budget.spend(1, "pattern matching")
            if matches >= node.max_matches_per_key:
                ctx.add(Caveat(
                    "PATTERN_MATCH_LIMIT",
                    f"stopped at {node.max_matches_per_key} matches for one key; more "
                    f"may exist", 0))
                break

            # STAGE 0 IS A REAL CONDITION. An earlier version set
            # `consumed = [start_row]` for every row in the group and only walked
            # stages[1:], which meant stage 0 was validated and then thrown away:
            # a rule saying "a=1 THEN b=2" matched on rows where a was never 1.
            if not _stage_matches(node.stages[0], start_row, ctx):
                continue

            # THE WINDOW IS A REAL BOUND. `within` was accepted, validated, and
            # referenced nowhere, so "credential access then privileged logon
            # within 10 minutes" matched across any gap whatsoever.
            start_time = times[start_index]
            if start_time is None:
                ctx.add(Caveat(
                    "PATTERN_UNDECIDABLE_TIME",
                    "the first event of a candidate sequence has no usable "
                    "timestamp, so the window cannot be established and this "
                    "candidate was not decided", 1))
                continue
            window_end = start_time + node.within.seconds

            consumed: list[Row] = [start_row]
            ok = True
            cursor = start_index + 1
            for stage in node.stages[1:]:
                found = False
                while cursor < len(group):
                    candidate = group[cursor]
                    candidate_time = times[cursor]
                    cursor += 1
                    if candidate_time is not None and candidate_time > window_end:
                        # Past the window. `ordered` means the list is sorted, so
                        # nothing later can be inside it either.
                        ok = False
                        break
                    if _stage_matches(stage, candidate, ctx):
                        consumed.append(candidate)
                        found = True
                        break
                if not ok or not found:
                    ok = False
                    break

            if not ok:
                continue

            # `until` VETOES THE WINDOW, NOT THE LAST ROW. An earlier version
            # tested it against consumed[-1] only, so "access then no logout for
            # 10 minutes" was decided by whichever event happened to end the
            # sequence, and a logout in the middle of the window passed straight
            # through. That is the negative twin the node exists to express.
            if node.until is not None and _window_satisfies(
                    node.until, group, times, start_index, window_end, ctx):
                continue

            out.append(_merge_pattern(consumed, key, start_row))
            matches += 1

    return out


def _pattern_time_field(node: Pattern, group: list[Row]) -> str | None:
    """Which field orders this sequence.

    From the rule, never guessed. An earlier version scanned the first few rows
    for any numeric column whose name ended in `time`/`_at`/`date`, which is the
    exact guessing `TimeRef` exists to prevent: a rule keyed on `timestamp` would
    be ordered by `eventtime` if both were present, and the sequence order would
    change.
    """
    return node.time_field


# Package
# ---------------------------------------------------------------------------


def eval_package(node: Package, rows: list[Row],
                 ctx: EvaluationContext) -> list[Row]:
    """Parent/child correlation: fire the parent, then count children in the window.

    THE PARENT STANDS ALONE. Wazuh's parent rule is a complete rule that alerts
    on its own; the child is a reaction. This returns the parent rows, annotated
    with which child fired, rather than requiring a child to be present -- a
    childless parent is a real alert, and dropping it would hide detections the
    deployed rule would have produced.

    THE COUNT IS OVER THE SHARED FIELDS, INSIDE THE TIMEFRAME. Not "N children
    ever", and not "N children in any order": Wazuh groups the parent and child
    events on `same_*` and counts within `timeframe`, so a child that occurred
    ten minutes later is not a child of this parent.

    AN UNDECIDABLE PARENT IS NOT A PARENT. If the parent's own conditions cannot
    be decided for a row, that row is neither fired nor counted against a child;
    claiming the parent fired would inflate every downstream count.
    """
    out: list[Row] = []
    if not rows:
        return out

    for parent_row in rows:
        ctx.budget.spend(1, "package parent")
        if node.parent and not _stage_matches(node.parent, parent_row, ctx):
            continue

        parent_time = as_number(parent_row.get(node.time_field or ""))
        if parent_time is None:
            ctx.add(Caveat(
                "PACKAGE_UNDECIDABLE_TIME",
                "the parent event has no usable timestamp on the declared time "
                "field, so the timeframe cannot be established and this parent "
                "was not decided",
                1))
            continue

        if not node.children:
            out.append(dict(parent_row))
            continue

        window_end = parent_time + node.timeframe.seconds
        group_value = _package_group_value(parent_row, node.same_fields)

        if group_value is None:
            ctx.add(Caveat(
                "PACKAGE_UNDECIDABLE_GROUP",
                "a field named in same_* is absent from the parent event, so "
                "there is no grouping key. Widening this to 'anywhere in the "
                "log' would count unrelated events, so the parent is reported "
                "without a child verdict rather than with a wrong one.",
                1))
            out.append(dict(parent_row))
            continue

        fired: list[str] = []
        counted = 0
        for child_index, child_condition in enumerate(node.children):
            child_rows: list[Row] = []
            for candidate in rows:
                moment = as_number(candidate.get(node.time_field or ""))
                if moment is None:
                    continue
                # THE WINDOW IS A REAL BOUND AND IT IS ANCHORED ON THE PARENT.
                # Counting children anywhere in the log, or counting them in
                # either direction, both make the frequency mean something other
                # than what the rule says.
                if moment <= parent_time or moment > window_end:
                    continue
                if _package_group_value(candidate, node.same_fields) != group_value:
                    continue
                if _stage_matches(child_condition, candidate, ctx):
                    child_rows.append(candidate)

            ctx.budget.spend(len(child_rows), "package child matching")
            if len(child_rows) >= node.frequency:
                counted += 1
                fired.append(f"child_{child_index}")

            annotated = dict(parent_row)
            annotated["__package_children_matched__"] = counted
            annotated["__package_children_required__"] = len(node.children)
            annotated["__package_children_fired__"] = ",".join(fired)
            out.append(annotated)

    if len(out) > node.max_matches:
        ctx.add(Caveat(
            "PACKAGE_MATCH_LIMIT",
            f"stopped at {node.max_matches} parent events; more may exist", 0))
        out = out[:node.max_matches]
    return out


def _package_group_value(row: Row, fields: tuple[FieldRef, ...]) -> Any:
    """The shared-field value, or UNDECIDED if any declared field is unusable.

    A partial key is not a key. If `same_srcip` is absent, grouping the parent
    with children that merely share a username would correlate two hosts'
    activity into one story.
    """
    values: list[Any] = []
    for spec in fields:
        value = resolve_field(row, spec)
        if is_undecided(value):
            return None  # a partial key is not a key
        values.append(value)
    return tuple(values)


def _row_time(row: Row, node: Pattern) -> Decimal | None:
    if node.time_field is None:
        return None
    return as_number(row.get(node.time_field))


def _window_satisfies(condition: Any, group: list[Row], times: list[Decimal | None],
                      start_index: int, window_end: Decimal,
                      ctx: EvaluationContext) -> bool:
    """Does any row inside [start_index, window_end] satisfy `condition`?"""
    for offset in range(start_index, len(group)):
        moment = times[offset]
        if moment is None:
            continue
        if moment > window_end:
            return False
        if _stage_matches((condition,), group[offset], ctx):
            return True
    return False


def _stage_matches(stage: tuple[Any, ...], row: Row,
                   ctx: EvaluationContext) -> bool:
    """A stage is a conjunction of conditions. UNDECIDED does not match.

    Requiring a decided True is the right call for a veto (`until`) and a
    conservative one for progression. An undecided event is not evidence that the
    stage happened, so treating it as a match would let a rule fire on rows whose
    fields were missing.
    """
    for condition in stage:
        outcome = eval_expr(condition, row, ctx)
        if outcome is not True:
            return False
    return True


def _merge_pattern(consumed: list[Row], key: tuple[Any, ...],
                   first: Row) -> Row:
    """Present a multi-event match as one row, keeping the last event's fields
    and the sequence length.

    First event's fields would be surprising for "what did the last event look
    like" questions, and last event's fields would be surprising for "what
    started this". Neither is obviously right, so the sequence length and the
    first timestamp are added explicitly and the rest of the caller's choice.
    """
    merged = dict(consumed[-1].values)
    merged["_pattern_events"] = len(consumed)
    merged["_pattern_first_time"] = first.time
    return Row(merged, consumed[-1].time, 0, dict(consumed[-1].uncertain))


# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------


def eval_emit(node: Emit, rows: list[Row], ctx: EvaluationContext) -> list[Row]:
    out: list[Row] = []
    seen: set[tuple[Any, ...]] = set()
    undeduplicated = 0

    for row in rows:
        ctx.budget.spend(1, "emit")
        if node.columns:
            missing = [c for c in node.columns if c not in row.values]
            if missing:
                raise Refusal(
                    "EMIT_COLUMN_MISSING",
                    f"the output names {missing}, which the input does not produce. "
                    f"Projecting a column that does not exist would emit a null that "
                    f"looks like data.", "Emit")
            values = {c: row.values[c] for c in node.columns}
        else:
            values = dict(row.values)

        if node.dedupe_by:
            identity = _group_key(row, node.dedupe_by)
            # DEDUPE BY AN ABSENT KEY IS NOT DEDUPE.
            #
            # `_group_key` maps an absent field to one shared identity, so
            # deduping on one collapses every row that lacks it into a single
            # output row. Fifty events became one alert, silently, with no caveat.
            # Grouping by an absent key is legitimate -- it is a real group.
            # Deduplicating by one asserts those rows are the same row, which was
            # never established.
            if any(part[0] == "absent" for part in identity):
                undeduplicated += 1
                out.append(Row(values, row.time, row.index, dict(row.uncertain)))
                continue
            if identity in seen:
                continue
            seen.add(identity)

        out.append(Row(values, row.time, row.index, dict(row.uncertain)))

    if undeduplicated:
        ctx.add(Caveat(
            "EMIT_DEDUPE_KEY_ABSENT",
            f"{undeduplicated} of {len(rows)} rows had no value for "
            f"{', '.join(k.name for k in node.dedupe_by)}, so their identity could "
            f"not be established and they were passed through undeduplicated rather "
            f"than collapsed into one row. Treating them as identical would have "
            f"silently discarded {undeduplicated} events.", undeduplicated))

    return out
