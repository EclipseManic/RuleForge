"""The stateful tier: sequence matching and fixed-point iteration.

Phase 3C. Ships DARK.

WHY THE UNTIL NEGATIVE TWIN MATTERS MOST
----------------------------------------
`until` is the construct that exists to produce SILENCE, and a false detection is the most
expensive bug a detection engine can have. An `until` pattern that reports a match when the
stop condition was met fires on exactly the behaviour it was written to exclude. So the first
test written for this module is the negative twin of `until`, before any positive one.

WHY A STEP BUDGET IS DECLARED BEFORE THE LOOP
---------------------------------------------
3B taught this expensively: a limit checked AFTER the work is done bounds nothing. A join's
output-row cap never fired for a join that matched nothing, leaving 2.5e9 predicate
evaluations legal. Sequence matching is worse - it is combinatorially worse - so
`MAX_SEQUENCE_STEPS` counts matcher transitions and is decremented BEFORE each attempt. An
over-long search refuses; it does not run for minutes and then return a plausible answer.

THE FIVE MODES, DEFINED PRECISELY
---------------------------------
ordered      Stages match in declared order, each on a distinct row, inside `max_span`.
unordered    Each stage is satisfied exactly once per its quantifier, in any order, on
             distinct rows.
missing      Stages whose quantifier is `none` must NOT match anywhere inside the span. A
             stage that appears AFTER the match point does not satisfy `missing`; only one
             inside the window does. That boundary is the whole meaning of the mode and is
             the off-by-one this module is most likely to get wrong.
until        `stages[-1]` is the STOP condition. `stages[:-1]` must match in order, and the
             stop condition must not match at any point after that sequence, inside the span.
             A match is the preceding sequence completing while the stop condition stayed
             false - which is what makes the negative twin necessary.
overlapping  As `ordered`, but one row may satisfy more than one stage. A stage requiring two
             occurrences can be satisfied by the same row twice.

`terminal` distinguishes a MAXIMAL match (`all`: the sequence cannot be extended by another
stage without exceeding the span) from any complete stage sequence (`any`). The distinction is
recorded as a caveat because the model does not define it further, and a Pattern's output is
ordinarily fed to an Arrange for "first and last seen" - so an unstated reading here changes
which event a rule reports as first.

A STATIC SAMPLE CANNOT KNOW MORE. A sequence that matches at the very end of a sample is
provisional: the event that would have continued it may simply not have been supplied. That is
declared per match, for the same reason 3A declares SESSION_NOT_EXTENDED_BY_TRAILING_GAP.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from kernel.eval_errors import EvaluationRefusal
from kernel.eval_expr import EvalContext
from kernel.eval_types import ABSENT, Caveat, Row, canonical
from models.rule_ir import Pattern, Stage

#: Matcher transitions allowed per Pattern node. Counted BEFORE each attempt, so an
#: over-long search refuses instead of running for minutes and then answering confidently.
MAX_SEQUENCE_STEPS = 2_000_000

#: Matches emitted per Pattern node. A sliding window over a long stream can match at every
#: position, and one output row per position is how a modest sample becomes gigabytes.
MAX_SEQUENCE_MATCHES = 200_000

_MODES = frozenset({"ordered", "unordered", "missing", "until", "overlapping"})
_QUANTIFIERS = frozenset({"exactly", "at_least", "all", "none"})


class _Budget:
    """A countdown, decremented before the work so a runaway search refuses."""

    def __init__(self, limit: int) -> None:
        self.remaining = limit

    def spend(self, node_id: str, what: str) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise EvaluationRefusal(
                "EVAL_SEQUENCE_SEARCH_EXCEEDED",
                f"the sequence search for {node_id!r} needed more than {what}; refusing "
                f"rather than spending unbounded time to produce an answer the analyst cannot "
                f"act on", node_id)


def _check_pattern(node: Pattern) -> None:
    if node.mode not in _MODES:
        raise EvaluationRefusal("UNKNOWN_PATTERN_MODE",
                                f"unknown pattern mode {node.mode!r}; the model permits "
                                f"{sorted(_MODES)}", node.id)
    if node.terminal not in ("all", "any"):
        raise EvaluationRefusal("UNKNOWN_PATTERN_TERMINAL",
                                f"unknown terminal policy {node.terminal!r}", node.id)
    if not node.stages:
        raise EvaluationRefusal("PATTERN_HAS_NO_STAGES",
                                f"pattern {node.id!r} declares no stages, so it cannot match "
                                f"anything", node.id)
    for stage in node.stages:
        if stage.quantifier not in _QUANTIFIERS:
            raise EvaluationRefusal("UNKNOWN_STAGE_QUANTIFIER",
                                    f"unknown stage quantifier {stage.quantifier!r}", stage.id)
        if stage.quantifier in ("exactly", "at_least") and stage.count < 1:
            raise EvaluationRefusal("STAGE_COUNT_MUST_BE_POSITIVE",
                                    f"stage {stage.id!r} declares count {stage.count}, which "
                                    f"can never be satisfied", stage.id)
        if stage.quantifier == "all" and node.mode == "missing":
            raise EvaluationRefusal(
                "INCOMPATIBLE_STAGE_QUANTIFIER",
                f"stage {stage.id!r} uses quantifier 'all' in 'missing' mode, where the point "
                f"is that a stage does NOT match; 'all' and 'missing' contradict each other",
                stage.id)


def _clock(value: Any) -> float | None:
    """Epoch seconds from a raw value, or None. Never a bool, never a guess."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _stage_matches(stage: Stage, row: Row) -> bool:
    """Does one row satisfy one stage's boolean condition?

    A Stage carries no predicate of its own: its condition is whatever the node named by
    `stage.input` produced, so a row's PRESENCE in that node's output IS the test. The
    substantive filtering happened upstream, which is why an `until` sequence is built from
    Filters rather than from stage-local conditions.
    """
    return True


def _positions_for(stage: Stage, order: list[Row], members: list[int], budget: _Budget,
                   node_id: str) -> list[int]:
    """Indices (into `order`) at which this stage is satisfied, honouring its own `within`."""
    found: list[int] = []
    for position in members:
        budget.spend(node_id, f"{MAX_SEQUENCE_STEPS} position checks")
        if not _stage_matches(stage, order[position]):
            continue
        if stage.within is not None and found:
            anchor = order[found[0]].time
            here = order[position].time
            if anchor is None or here is None or abs(here - anchor) > stage.within.seconds:
                continue
        found.append(position)
    return found


def _quantifier_ok(stage: Stage, hits: int, partition_size: int) -> bool:
    if stage.quantifier == "exactly":
        return hits == stage.count
    if stage.quantifier == "at_least":
        return hits >= stage.count
    if stage.quantifier == "all":
        return hits == partition_size
    return hits == 0          # `none`


def _exec_pattern(node: Pattern, rows_by_stage: Mapping[str, list[Row]], ctx: EvalContext,
                  caveats: list[Caveat], time_field: str | None) -> list[Row]:
    """Match a sequence.

    `rows_by_stage` maps each `Stage.input` to the rows that node produced. It is NOT merged
    into one list: an earlier version concatenated every stage's rows, and the matcher then
    treated all rows as interchangeable, so it could not tell which stage a row belonged to. A
    Pattern would match rows that never satisfied the stage's own condition - which for `until`
    means firing on exactly the behaviour the rule was written to exclude.
    """
    _check_pattern(node)

    if node.min_matches < 0:
        raise EvaluationRefusal("PATTERN_MIN_MATCHES_INVALID",
                                f"min_matches is {node.min_matches}", node.id)

    span = node.max_span.seconds if node.max_span is not None else None
    if node.mode in ("ordered", "overlapping", "until", "missing") and span is None:
        # Without a span, "ordered" is not a sequence at all - it is "some stage matched
        # somewhere in the stream, in no particular time relationship". Saying so is better
        # than inventing an unbounded window.
        raise EvaluationRefusal(
            "PATTERN_SPAN_NOT_DECLARED",
            f"pattern {node.id!r} is in {node.mode!r} mode with no max_span, so the stages "
            f"would have no time relationship to each other; declare the span rather than "
            f"letting the kernel assume one", node.id)

    if node.mode == "until" and len(node.stages) < 2:
        raise EvaluationRefusal(
            "PATTERN_UNTIL_NEEDS_A_STOP_STAGE",
            f"pattern {node.id!r} is in 'until' mode but declares no stop condition, so it "
            f"cannot distinguish 'matched' from 'stopped'", node.id)

    # A SPAN THAT CANNOT BE ENFORCED MUST NOT BE SILENTLY IGNORED. `Pattern` carries no
    # `time_ref`, so the clock can only come from the caller's declared time binding - and
    # `Row.time` is otherwise set only by an Aggregate frame, which a Pattern's stages are not.
    # Without a resolvable clock every row has `time=None`, the span comparison is inert, and
    # "ordered" quietly degrades into "both stages appeared somewhere in the stream" - the
    # exact thing PATTERN_SPAN_NOT_DECLARED exists to prevent. So it refuses instead.
    stamped: dict[str, list[Row]] = {}
    usable = 0
    for stage_input, rows in rows_by_stage.items():
        out = []
        for row in rows:
            raw = row.get(time_field) if time_field else ABSENT
            parsed = _clock(raw)
            if parsed is None:
                out.append(Row(values=row.values, index=row.index, time=None,
                               sides=row.sides))
            else:
                usable += 1
                out.append(Row(values=row.values, index=row.index, time=parsed,
                               time_source=time_field, sides=row.sides))
        stamped[stage_input] = out
    rows_by_stage = stamped
    if span is not None and usable == 0:
        raise EvaluationRefusal(
            "TIME_FIELD_UNRESOLVED",
            f"pattern {node.id!r} declares a {span}-second max_span, but no row carries a "
            f"usable value in {time_field!r} and a Pattern declares no time_ref of its own, "
            f"so the span cannot be enforced; bind a time field in the sample rather than "
            f"letting 'ordered' degrade into 'both stages appeared somewhere'", node.id)

    # One ordered timeline across every stage's rows. A stage may only consume positions
    # drawn from ITS OWN input; `_stage_positions` enforces that.
    everything = [row for rows in rows_by_stage.values() for row in rows]
    ordered = sorted(everything, key=lambda r: (r.time if r.time is not None else 0.0, r.index))
    position_of: dict[int, int] = {}
    for position, row in enumerate(ordered):
        position_of[id(row)] = position
    stage_positions: dict[str, list[int]] = {}
    for stage in node.stages:
        stage_positions[stage.id] = sorted(
            position_of[id(r)] for r in rows_by_stage.get(stage.input, ()))

    partitions: dict[tuple, list[int]] = {}
    if node.key:
        for position in range(len(ordered)):
            partitions.setdefault(
                tuple(canonical(ordered[position].get(f.name)) for f in node.key),
                []).append(position)
    else:
        partitions = {(): list(range(len(ordered)))}

    budget = _Budget(MAX_SEQUENCE_STEPS)
    matches: list[tuple[list[int], bool]] = []

    for _key, members in partitions.items():
        for start in members:
            budget.spend(node.id, f"{MAX_SEQUENCE_STEPS} start positions")
            if node.mode == "until":
                found, stopped = _match_until(node, ordered, members, stage_positions,
                                              start, budget)
            else:
                found = _match_sequence(node, ordered, members, stage_positions, start, budget)
                stopped = False
            if found is None:
                continue
            if stopped:
                # The stop condition fired, so this is NOT a match. This line is the whole
                # point of `until`, and omitting it is the most expensive possible bug in this
                # module: the rule would fire on exactly the behaviour it was written to
                # exclude, and nothing in the result would say so.
                continue
            if node.mode == "missing" and not _missing_respected(
                    node, ordered, members, stage_positions, found, budget):
                continue
            if node.terminal == "all" and not _is_maximal(
                    node, ordered, members, stage_positions, found, budget):
                continue
            matches.append((found, True))
            if len(matches) > MAX_SEQUENCE_MATCHES:
                raise EvaluationRefusal(
                    "EVAL_SEQUENCE_MATCHES_EXCEEDED",
                    f"pattern {node.id!r} produced more than {MAX_SEQUENCE_MATCHES} matches; "
                    f"refusing rather than building an unbounded result", node.id)

    if not matches:
        return []
    if node.min_matches > 1 and len(matches) < node.min_matches:
        # A genuine, correctly-computed "not enough" - not a refusal. The pattern's declared
        # threshold simply was not reached by the sample.
        return []
    if max(max(found) for found, _ok in matches) >= len(ordered) - 1:
        # The final match reaches the end of the sample, so the event that would have
        # continued it may simply not have been supplied. The same reason 3A declares
        # SESSION_NOT_EXTENDED_BY_TRAILING_GAP.
        caveats.append(Caveat("SEQUENCE_MATCH_REACHES_END_OF_SAMPLE", nodes=(node.id,)))
    caveats.append(Caveat(f"PATTERN_TERMINAL_POLICY_{node.terminal.upper()}_ASSUMED",
                          nodes=(node.id,)))

    return [_match_row(node, ordered, found) for found, _ok in matches]


def _match_sequence(node: Pattern, ordered: list[Row], members: list[int],
                    stage_positions: Mapping[str, list[int]], start: int,
                    budget: _Budget) -> list[int] | None:
    """Greedy walk over the declared stages.

    A stage may only consume a position that belongs to ITS OWN input, and positions are
    consumed in order. That per-stage restriction is the whole reason `rows_by_stage` is not
    merged: without it, stage 1 could consume a row that only stage 3's filter produced.
    """
    span = node.max_span.seconds if node.max_span is not None else None
    used: set[int] = set()
    chosen: list[int] = []
    cursor = start
    anchor = ordered[start].time

    for stage in node.stages:
        if stage.quantifier == "none":
            continue        # a `none` stage constrains the window; it consumes nothing
        mine = [p for p in stage_positions.get(stage.id, ())
                if p in members and p >= cursor
                and (span is None or anchor is None or ordered[p].time is None
                     or ordered[p].time - anchor <= span)]
        if stage.quantifier == "all":
            # Every row of this stage's input, inside the window.
            placed = mine
        else:
            need = stage.count
            placed = []
            for position in mine:
                budget.spend(node.id, f"{MAX_SEQUENCE_STEPS} stage placements")
                if node.mode != "overlapping" and position in used:
                    continue
                placed.append(position)
                if stage.quantifier == "exactly" and len(placed) >= need:
                    break
            if not placed:
                return None
            if stage.quantifier == "at_least" and len(placed) < stage.count:
                return None
        if not placed:
            return None
        chosen.extend(placed)
        used.update(placed)
        cursor = max(placed) + 1

    if not chosen:
        return None

    # Post-conditions over the whole partition: a `none` stage must not match anywhere in the
    # sequence's span, and an `all` stage must have covered every one of its own rows.
    for stage in node.stages:
        if stage.quantifier == "none" and _positions_for(
                stage, ordered, [p for p in members if p in stage_positions.get(stage.id, ())
                                 or True], budget, node.id, stage_positions):
            return None
        if stage.quantifier == "all":
            inside = [p for p in stage_positions.get(stage.id, ()) if p in members
                      and (span is None or anchor is None or ordered[p].time is None
                           or ordered[p].time - anchor <= span)]
            if len(inside) != stage.count:
                return None
    return chosen


def _positions_for(stage: Stage, order: list[Row], members: list[int], budget: _Budget,
                   node_id: str,
                   stage_positions: Mapping[str, list[int]] | None = None) -> list[int]:
    """Positions at which this stage is satisfied, restricted to the stage's own rows."""
    own = set(stage_positions.get(stage.id, ())) if stage_positions else None
    found: list[int] = []
    for position in members:
        if own is not None and position not in own:
            continue
        budget.spend(node_id, f"{MAX_SEQUENCE_STEPS} position checks")
        found.append(position)
        if stage.within is not None and found:
            anchor = order[found[0]].time
            here = order[position].time
            if anchor is not None and here is not None \
                    and abs(here - anchor) > stage.within.seconds:
                found.pop()
    return found


def _match_until(node: Pattern, ordered: list[Row], members: list[int],
                 stage_positions: Mapping[str, list[int]], start: int,
                 budget: _Budget) -> tuple[list[int] | None, bool]:
    """The preceding stages must complete; the stop stage must never fire.

    A `True` here means the stop condition WAS met, which DISQUALIFIES the match. Returning
    the flag rather than silently dropping it is what makes the negative twin testable: the
    common bug is to report a match anyway, firing on the very behaviour the rule excludes.
    """
    prefix = Pattern(id=node.id, stages=node.stages[:-1], mode="ordered",
                     key=node.key, max_span=node.max_span)
    found = _match_sequence(prefix, ordered, members, stage_positions, start, budget)
    if found is None:
        return None, False

    stop = node.stages[-1]
    span = node.max_span.seconds if node.max_span is not None else None
    anchor = ordered[start].time
    stop_positions = stage_positions.get(stop.id, ())
    for position in members:
        if position <= max(found) or position not in stop_positions:
            continue
        budget.spend(node.id, f"{MAX_SEQUENCE_STEPS} until checks")
        if span is not None and anchor is not None and ordered[position].time is not None \
                and ordered[position].time - anchor > span:
            break
        return found, True
    return found, False


def _missing_respected(node: Pattern, ordered: list[Row], members: list[int],
                       stage_positions: Mapping[str, list[int]], found: list[int],
                       budget: _Budget) -> bool:
    """Every `none` stage must be absent from the window, not merely absent so far.

    The window is bounded by the MATCH, not by the end of the partition: a `none` stage that
    fires long after the sequence completed does not retroactively invalidate the match.
    """
    span = node.max_span.seconds if node.max_span is not None else None
    origin = ordered[min(found)].time
    window = [p for p in members
              if span is None or origin is None or ordered[p].time is None
              or ordered[p].time - origin <= span]
    for stage in node.stages:
        if stage.quantifier != "none":
            continue
        if _positions_for(stage, ordered, window, budget, node.id, stage_positions):
            return False
    return True


def _is_maximal(node: Pattern, ordered: list[Row], members: list[int],
                stage_positions: Mapping[str, list[int]], found: list[int],
                budget: _Budget) -> bool:
    """`terminal='all'`: the sequence cannot be extended by another stage inside the span."""
    span = node.max_span.seconds if node.max_span is not None else None
    origin = ordered[min(found)].time
    end = max(found)
    last = node.stages[-1]
    for position in members:
        if position <= end or position not in stage_positions.get(last.id, ()):
            continue
        if span is not None and origin is not None and ordered[position].time is not None \
                and ordered[position].time - origin > span:
            return True
        budget.spend(node.id, f"{MAX_SEQUENCE_STEPS} maximality checks")
        return False
    return True


def _match_row(node: Pattern, ordered: list[Row], positions: list[int]) -> Row:
    """One output row per match: the participating rows' fields, plus the match's shape."""
    values: dict[str, Any] = {}
    for field in node.key:
        name = field.name
        values[name] = ordered[positions[0]].get(name)
    merged: dict[str, Any] = {}
    for position in positions:
        for name, value in ordered[position].values.items():
            merged.setdefault(name, value)
    values.update(merged)
    values["pattern_id"] = node.id
    values["matched_stages"] = len(node.stages)
    values["matched_positions"] = list(positions)
    times = [ordered[p].time for p in positions if ordered[p].time is not None]
    return Row(values=values, index=ordered[min(positions)].index,
               time=max(times) if times else None)
