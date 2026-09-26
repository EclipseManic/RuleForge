"""The relational tier: two-input execution for Phase 3B.

Ships DARK.

WHAT IS IMPLEMENTED, AND WHAT IS REFUSED, AND WHY
-------------------------------------------------
Join: `inner`, `left`, `right`, `left_anti`, `right_anti`. The kernel evaluates the declared
`on` predicate over the two sides and merges the matching rows. Field collisions between the
sides are resolved by the declared `collision` policy.

`full` is REFUSED. A full outer join needs unmatched rows from BOTH sides preserved, and
`unmatched` has only `drop`, `preserve_left` and `preserve_right` - there is no value meaning
"preserve both". Rather than pick the closest reading, the kernel reports that the IR cannot
express a full outer join. This is an IR gap, not a kernel limitation, and it is reported as
one.

`kind` and `unmatched` OVERLAP, and can contradict. `kind="left"` already means "preserve
unmatched left rows", so pairing it with `unmatched="drop"` is incoherent. The kernel treats
`kind` as authoritative and REFUSES a contradictory pairing rather than silently honouring
one field and ignoring the other - the same rule that applies to a contradictory version
bound.

A TEMPORAL `match_window` WITH NO TEMPORAL PREDICATE IS REFUSED. If `on` already contains the
temporal comparison, `match_window` is a declared bound and is used as a cheap pre-filter. But
if `on` is a plain equi-join and only `match_window` is set, the kernel is being asked to imply
a temporal predicate, and "symmetric within the window" versus "asymmetric, right after left"
are two different rules. Choosing between them is precisely the plausible-but-wrong temporal
guess this project must not make.

CARDINALITY IS CHECKED, NOT ASSUMED. The declared `cardinality` is verified against what
actually happened. If it says one_to_one or many_to_one and a row matched more than one
counterpart, the kernel refuses: silently keeping the first match would be a guess, and
silently keeping all of them would contradict the declaration.

Expand: `unnest` only. `cross` and `generate` are REFUSED because `Expand` carries a single
`input` and no second operand, so neither has anything to cross or generate from. That is an
IR gap, reported as one.
"""

from __future__ import annotations

from typing import Any

from kernel.eval_errors import EvaluationRefusal
from kernel.eval_expr import EvalContext, evaluate
from kernel.eval_types import Caveat, Row, canonical
from models.rule_ir import EventExpr, FieldExpr, Join, TimeExpr

#: The only `unmatched` value coherent with each `kind`. A pairing outside this table is a
#: contradiction and is refused rather than half-honoured.
_COHERENT_UNMATCHED = {
    "inner": "drop",
    "left": "preserve_left",
    "right": "preserve_right",
    "left_anti": "drop",
    "right_anti": "drop",
}

_SUPPORTED_KINDS = frozenset(_COHERENT_UNMATCHED)

#: Row counts above which a join refuses rather than building an unbounded result.
MAX_JOIN_ROWS = 500_000


def _has_temporal_predicate(expr: Any, time_fields: frozenset[str], depth: int = 0) -> bool:
    """Does the predicate reference a field the caller has DECLARED to be a clock?

    An earlier version treated any `EventExpr` as temporal, which was wrong: `EventExpr` is
    SIDE SCOPING ("this side's host"), not a clock. Every equi-join uses it, so every equi-join
    looked temporal and this refusal - the one that exists to catch a guess - never fired.

    The IR carries no types, so the kernel cannot tell that `left.t` is a clock from the shape
    alone. It uses the caller's declared time fields instead: the sample's time bindings and any
    `TimeRef` in the predicate. That is declared data, not a guess. A field that is neither
    declared nor obviously a clock is NOT treated as one.

    The walk visits every field, because the temporal term is normally nested:
    `left.host = right.host AND right.t <= left.t + 600`.
    """
    if depth > 64:
        return False
    if isinstance(expr, TimeExpr):
        return True
    if isinstance(expr, (EventExpr, FieldExpr)) and expr.ref.name in time_fields:
        return True
    if isinstance(expr, (tuple, list)):
        return any(_has_temporal_predicate(e, time_fields, depth + 1) for e in expr)
    import dataclasses
    if dataclasses.is_dataclass(expr) and not isinstance(expr, type):
        return any(_has_temporal_predicate(getattr(expr, f.name, None), time_fields, depth + 1)
                   for f in dataclasses.fields(expr))
    return False


def _declared_time_field(node: Join) -> str | None:
    """The field name a `TimeRef` inside `on` declares, if any."""
    import dataclasses
    stack = [node.on]
    while stack:
        current = stack.pop()
        if isinstance(current, TimeExpr):
            return current.time_ref.field_name
        if isinstance(current, (tuple, list)):
            stack.extend(current)
        elif dataclasses.is_dataclass(current) and not isinstance(current, type):
            stack.extend(getattr(current, f.name, None) for f in dataclasses.fields(current))
    return None


def _check_join(node: Join, caveats: list[Caveat], time_fields: frozenset[str]) -> None:
    if node.kind not in _SUPPORTED_KINDS:
        if node.kind == "full":
            raise EvaluationRefusal(
                "JOIN_KIND_INEXPRESSIBLE",
                "a full outer join must preserve unmatched rows from BOTH sides, and "
                "`unmatched` offers only drop / preserve_left / preserve_right; the IR cannot "
                "express it, so the kernel refuses rather than approximating it", node.id)
        raise EvaluationRefusal(
            "UNKNOWN_JOIN_KIND", f"unknown join kind {node.kind!r}", node.id)

    coherent = _COHERENT_UNMATCHED[node.kind]
    if node.unmatched != coherent:
        raise EvaluationRefusal(
            "JOIN_KIND_UNMATCHED_CONTRADICTION",
            f"kind={node.kind!r} already means {coherent!r}, so unmatched="
            f"{node.unmatched!r} contradicts it; the kernel will not honour one field and "
            f"ignore the other", node.id)

    if node.match_window is not None and not _has_temporal_predicate(node.on, time_fields):
        raise EvaluationRefusal(
            "JOIN_TEMPORAL_WINDOW_WITHOUT_PREDICATE",
            "a match_window is declared but `on` contains no reference to a declared time "
            "field, so the kernel would have to invent one. Symmetric (right within the window "
            "of left) and asymmetric (right after left) are different rules; write the "
            "comparison in `on` and the window becomes a declared bound, not an instruction",
            node.id)

    if node.match_window is not None:
        caveats.append(Caveat("JOIN_TEMPORAL_BOUNDARY_INCLUSIVE", nodes=(node.id,)))


def _side_scoped_fields(expr: Any, depth: int = 0) -> set[str]:
    """Field names the predicate reads through an explicit SIDE reference.

    These are NOT merged into the output under a single name. `left.t` and `right.t` are
    different quantities - in a temporal join they differ by construction, and collapsing them
    into one column would fabricate a value that exists on neither side. The merged view keeps
    the left value; the right's stays reachable through `side("right")`.
    """
    if depth > 64:
        return set()
    if isinstance(expr, EventExpr):
        return {expr.ref.name}
    if isinstance(expr, (tuple, list)):
        return set().union(*(_side_scoped_fields(e, depth + 1) for e in expr)) if expr else set()
    import dataclasses
    if dataclasses.is_dataclass(expr) and not isinstance(expr, type):
        found: set[str] = set()
        for f in dataclasses.fields(expr):
            found |= _side_scoped_fields(getattr(expr, f.name, None), depth + 1)
        return found
    return set()


def _merge(left: Row, right: Row, node: Join, ctx: EvalContext,
           side_scoped: set[str]) -> Row:
    """Merge two rows under the declared collision policy.

    A name present on BOTH sides is only a collision when the two sides DISAGREE about it AND
    the predicate did not read it through an explicit side reference. The field a join is keyed
    on is by definition present on both inputs, so treating a shared name as a collision would
    make the default `error` policy refuse essentially every join - firing on the normal case
    rather than the exceptional one.
    """
    values = dict(left.values)
    for name, value in right.values.items():
        if name in values:
            if name in side_scoped:
                continue        # two different quantities; keep the left in the merged view
            if canonical(values[name]) == canonical(value):
                continue        # the two sides agree; nothing to decide
            if node.collision == "error":
                raise EvaluationRefusal(
                    "JOIN_FIELD_COLLISION",
                    f"field {name!r} is present on both sides with DIFFERENT values "
                    f"({values[name]!r} vs {value!r}) and the collision policy is 'error'; the "
                    f"kernel will not pick a winner", node.id)
            if node.collision == "keep_left":
                continue
            if node.collision == "keep_right":
                values[name] = value
        else:
            values[name] = value
    times = [t for t in (left.time, right.time) if t is not None]
    return Row(values=values, index=left.index,
               time=max(times) if times else None,
               time_source=left.time_source or right.time_source,
               sides={"left": left.values, "right": right.values})


def _unmatched_row(row: Row, node: Join, ctx: EvalContext) -> Row:
    """A row that found no counterpart. Kept under its own values, not merged with anything."""
    side = "left" if node.kind == "left" else "right"
    return Row(values=dict(row.values), index=row.index, time=row.time,
               time_source=row.time_source, sides={side: row.values})


def _exec_join(node: Join, left: list[Row], right: list[Row], ctx: EvalContext,
               caveats: list[Caveat], time_fields: frozenset[str]) -> list[Row]:
    _check_join(node, caveats, time_fields)

    bound = node.match_window.seconds if node.match_window is not None else None
    side_scoped = _side_scoped_fields(node.on)
    if side_scoped:
        caveats.append(Caveat("JOIN_SIDE_SCOPED_FIELDS_NOT_MERGED",
                              count=len(side_scoped), nodes=(node.id,)))
    out: list[Row] = []
    matched_right: set[int] = set()

    for lrow in left:
        hits: list[Row] = []
        for rrow in right:
            if bound is not None and not _within(lrow.time, rrow.time, bound):
                continue
            verdict = evaluate(node.on, _paired(lrow, rrow, node), ctx, None)
            if verdict is True:
                hits.append(rrow)
                matched_right.add(rrow.index)
            # A UNKNOWN or FALSE match is not a match. For a join, UNKNOWN is not counted as
            # unmatched either: the row is simply not a match, and a row whose predicate cannot
            # be decided is left out rather than invented into a match.

        if not hits:
            if node.kind in ("left",):
                out.append(_unmatched_row(lrow, node, ctx))
            elif node.kind == "left_anti":
                out.append(lrow)
            continue

        if node.kind in ("left_anti", "right_anti"):
            # Anti-joins emit ONLY unmatched rows, so a matched row contributes nothing.
            continue

        if node.cardinality in ("one_to_one", "many_to_one") and len(hits) > 1:
            raise EvaluationRefusal(
                "JOIN_CARDINALITY_VIOLATION",
                f"join {node.id!r} declares {node.cardinality!r} but one left row matched "
                f"{len(hits)} right rows; keeping the first would be a guess and keeping all "
                f"would contradict the declaration", node.id)
        for rrow in hits:
            out.append(_merge(lrow, rrow, node, ctx, side_scoped))
            if len(out) > MAX_JOIN_ROWS:
                raise EvaluationRefusal(
                    "EVAL_OUTPUT_TOO_LARGE",
                    f"the join produced more than {MAX_JOIN_ROWS} rows; refusing rather than "
                    f"building an unbounded result", node.id)

    if node.kind in ("right", "right_anti"):
        for rrow in right:
            if rrow.index not in matched_right:
                if node.kind == "right":
                    out.append(_unmatched_row(rrow, node, ctx))
                else:
                    out.append(rrow)

    return out


def _within(left_time: float | None, right_time: float | None, bound: float) -> bool:
    """A cheap PRE-FILTER only. It never decides the join on its own.

    Being inclusive here is deliberate and is declared as a caveat: `right.t <= left.t + W`
    with equality is a different rule from a strict `<`, and the authoritative answer comes
    from the `on` predicate, not from this bound.
    """
    if left_time is None or right_time is None:
        return True
    return abs(right_time - left_time) <= bound


def _paired(lrow: Row, rrow: Row, node: Join) -> Row:
    """A row carrying both sides so `on` can be evaluated with side-scoped references."""
    values = dict(lrow.values)
    for name, value in rrow.values.items():
        values.setdefault(name, value)
    times = [t for t in (lrow.time, rrow.time) if t is not None]
    return Row(values=values, index=lrow.index,
               time=max(times) if times else None,
               time_source=lrow.time_source or rrow.time_source,
               sides={"left": lrow.values, "right": rrow.values})
