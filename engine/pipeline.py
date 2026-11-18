"""Pipeline execution.

THE VERDICT IS DEFAULT-DENY
---------------------------
If any stage could not decide a row, the run does not report `no_match`. It
reports `not_evaluated` and says which stage and how many rows. An earlier
posture checked two specific caveat codes and treated everything else as
advisory, so a Pattern that could not decide its middle stage reported a
confident `no_match` with the caveat sitting unread beside it -- and a confident
`no_match` is the single most expensive thing this tool can say, because an
analyst reads it as "this rule is clean".

    MATCHED        at least one row survived
    NO_MATCH       every stage decided, nothing survived
    NOT_EVALUATED  something could not be decided; the count is not a number

Nothing here ever returns a verdict it cannot support.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Final

from .evaluate import (
    Budget,
    Caveat,
    Context,
    EvaluationResult,
    Row,
    Scope,
    Trace,
    Verdict,
    eval_expr,
)
from .ir import (
    Aggregate,
    Binding,
    Correlation,
    Derive,
    Distinct,
    Emit,
    Expand,
    FieldRef,
    Filter,
    Join,
    Limit,
    Node,
    Project,
    Read,
    Rule,
    Sequence,
    Sort,
    Span,
    Window,
)
from .values import (
    ABSENT,
    UNDECIDED,
    Capability,
    Refusal,
    Seq,
    Undecided,
    as_number,
    is_undecided,
    type_name,
)

__all__ = ["evaluate", "EvaluationResult", "Verdict", "ADVISORY_CODES",
           "MAX_JOIN_ROWS", "storage_key"]

def storage_key(ref: Any) -> str:
    """The key a field reference actually has in a row.

    `ref.full` is the FIELD NAME; a scoped reference's key in a merged row is
    `left.<name>` / `right.<name>`. Using `.full` for a scoped field reads a key
    that does not exist, so the value is ABSENT -- which is how
    `make_set(SourceIp)` after a join returns an empty list: the field is
    `left.SourceIp` and the code asks for `SourceIp`.

    One function for this, because every reader that guesses between the two
    spellings is a place a scoped field silently becomes absent.
    """
    return ref.scoped if ref.scope != "current" else ref.full


def storage_key_text(name: str) -> str:
    """A plain column name, split on a scope prefix if it carries one.

    Used for the Read's declared `time_field`, which a dialect may write as
    `left.TimeGenerated` after a join.
    """
    for prefix in ("left.", "right.", "current."):
        if name.lower().startswith(prefix):
            return name
    return name


#: Caveats that describe a LIMITATION OF THE ANSWER rather than a defect in it.
#: Everything else blocks `no_match`.
#:
#: Deliberately short. When this list was longer, a stage that dropped undecided
#: rows was listed as advisory and the rule still reported `no_match` -- which is
#: the bug this set exists to prevent. When in doubt, a caveat is NOT advisory.
ADVISORY_CODES: Final[frozenset[str]] = frozenset({
    "DECLARED_ONLY",       # modelled faithfully, not locally executable
})

#: The most rows one stage may produce before it stops and says so.
#:
#: Bounds MEMORY, which the `Budget` does not: the budget counts operations,
#: so 100 rows holding two 100-item lists expanded to 1,000,000 rows while
#: spending only a quarter of the ceiling. Four million rows held at once is
#: an out-of-memory kill, and a killed process is the hang the budget exists
#: to prevent wearing a different hat.
MAX_STAGE_ROWS: Final = 200_000

#: Caveats that stop blocking a confident NO-MATCH when the rule is monotone
#: in its input -- see `_is_monotone_in_input`.
#:
#: An index-time filter can only ever REMOVE rows from what the engine saw.
#: For a monotone rule, removing rows cannot create a match, so a local
#: `no_match` stays true whether or not the store would have narrowed the
#: input first: the honest claim is "no match against the sample you gave me",
#: and the caveat still says the selector was not applied.
#:
#: Treating it as blocking meant NO rule carrying a selector could ever report
#: a confident negative -- and every Sigma rule has a `logsource`, every SPL
#: rule with `index=` and every AQL rule with `LAST n HOURS` emits it. So
#: "paste a rule and test it against events" could confirm a match and never
#: confirm a non-match, which is most of what that feature is for.
MONOTONE_ADVISORY_CODES: Final[frozenset[str]] = frozenset({
    "INDEX_TIME_FILTER",
})

MAX_JOIN_ROWS = 200_000


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _State:
    """Rows flowing between stages, plus the trace so far."""

    rows: dict[str, list[Row]] = dc_field(default_factory=dict)
    trace: list[Trace] = dc_field(default_factory=list)
    context: Context = dc_field(default_factory=Context)
    #: Binding names, so a Read that names one reads THAT binding's rows.
    bindings: set[str] = dc_field(default_factory=set)
    #: Whether anything in this rule depends on a timestamp.
    #:
    #: Every dialect names a default time field, so warning that the sample
    #: lacks it put TIME_FIELD_NOT_FOUND on rules with no time logic at all --
    #: noise on every rule, which is how a real caveat gets ignored.
    timed: bool = False

    def put(self, stage: str, rows: list[Row]) -> None:
        self.rows[stage] = rows

    def get(self, stage: str) -> list[Row]:
        found = self.rows.get(stage)
        if found is None:
            raise Refusal(
                "STAGE_NOT_PRODUCED",
                f"`{stage}` is read before anything produces it. Every stage that "
                f"feeds another has to come earlier in the pipeline.",
                "run",
            )
        return found


def evaluate(
    rule: Rule,
    events: list[dict[str, Any]] | list[Row] | None = None,
    *,
    budget: Budget | None = None,
) -> EvaluationResult:
    """Run a rule against events.

    `events` is the sample. A rule that cannot be decided from the sample says
    so; it never estimates a match rate, a volume, or a false-positive rate from
    the rule text, because a number invented from a static read is a number an
    analyst will quote in a ticket.
    """
    ctx = Context(budget=budget or Budget())
    state = _State(context=ctx, timed=_needs_timestamps(rule))
    result = EvaluationResult()

    try:
        rows = _as_rows(events)
        state.bindings = {b.name for b in rule.bindings}
        _run_bindings(rule, rows, state)
        _run_pipeline(rule.pipeline, rows, state)
    except Refusal as refusal:
        result.verdict = Verdict.NOT_EVALUATED
        result.refusal = refusal
        result.caveats = list(ctx.caveats)
        result.trace = list(state.trace)
        return result

    output = state.get(rule.emit_id)
    result.rows = output
    result.caveats = _merge_caveats(ctx, state)
    result.trace = list(state.trace)
    advisory = ADVISORY_CODES
    if _is_monotone_in_input(rule):
        advisory = advisory | MONOTONE_ADVISORY_CODES
    if not _needs_timestamps(rule):
        advisory = advisory | frozenset({"TIME_FIELD_NOT_FOUND"})
    result.verdict = _verdict(output, result.caveats, advisory)
    return result


def _as_rows(events: Any) -> list[Row]:
    if events is None:
        return []
    out: list[Row] = []
    for index, item in enumerate(events):
        if isinstance(item, Row):
            out.append(item)
        elif isinstance(item, dict):
            out.append(Row(dict(item), _time_of(item)))
        else:
            raise Refusal(
                "EVENT_NOT_AN_OBJECT",
                f"event {index} is a {type(item).__name__}, not an object. Each "
                f"event must be a JSON object.",
                "run",
            )
    return out


def _time_of(event: dict[str, Any]) -> Any:
    for key in ("TimeGenerated", "timestamp", "_time", "@timestamp", "time",
                "StartTime", "event_timestamp"):
        if key in event:
            return _timestamp_number(event[key])
    metadata = event.get("metadata")
    if isinstance(metadata, dict) and "event_timestamp" in metadata:
        return _timestamp_number(metadata["event_timestamp"])
    return None


def _timestamp_number(value: Any) -> Decimal | None:
    """Turn numeric or ISO-8601 SIEM timestamps into epoch seconds.

    Real telemetry commonly carries ISO strings (`2026-10-25T12:00:00Z`),
    while the evaluator historically accepted only numeric epoch values. That
    made otherwise valid joins, sequences, and windows report
    `TIME_FIELD_NOT_FOUND` and `not_evaluated` in the browser. Numeric values
    remain unchanged; ISO values are normalized to UTC epoch seconds so all
    temporal operators use one representation.
    """
    number = as_number(value)
    if number is not None:
        return number
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return Decimal(str(parsed.timestamp()))


def _merge_caveats(ctx: Context, state: _State) -> list[Caveat]:
    return list(ctx.caveats)


def _is_monotone_in_input(rule: Rule) -> bool:
    """True when removing input rows can never CREATE a match.

    This decides whether an unapplied index-time filter blocks a confident
    `no_match`. The intuition "fewer rows cannot match more" holds for
    filters, thresholds and aggregates -- but NOT for an anti-join, which asks
    for rows with no counterpart: take rows away from the right-hand side and
    left rows become unmatched, so a rule that found nothing locally can fire
    once the store has narrowed the input.

    `kind=leftanti` lowers to `how="anti"`, so this is reachable from ordinary
    KQL rather than hypothetical. Those rules keep the strict verdict.
    """
    streams = [rule.pipeline] + [b.pipeline for b in rule.bindings]
    for stream in streams:
        for node in stream:
            if isinstance(node, Join) and node.how == "anti":
                return False
    return True


def _needs_timestamps(rule: Rule) -> bool:
    """Whether missing declared timestamps can change this rule's answer."""
    streams = [rule.pipeline] + [binding.pipeline for binding in rule.bindings]
    for stream in streams:
        for node in stream:
            if isinstance(node, (Correlation, Sequence)):
                return True
            if isinstance(node, Aggregate) and node.window is not None:
                return True
            if isinstance(node, Join) and isinstance(node.predicate, Span):
                return True
    return False


def _verdict(
    rows: list[Row],
    caveats: list[Caveat],
    advisory: frozenset[str] = ADVISORY_CODES,
) -> str:
    """Default-deny. See the module docstring for why this is the whole point."""
    blocking = sorted({c.code for c in caveats if c.code not in advisory})
    if blocking:
        return Verdict.NOT_EVALUATED
    if rows:
        return Verdict.MATCHED
    return Verdict.NO_MATCH


# ---------------------------------------------------------------------------
# Bindings
# ---------------------------------------------------------------------------


def _run_bindings(rule: Rule, rows: list[Row], state: _State) -> None:
    """Materialise every named sub-pipeline.

    A binding is a whole pipeline under a name, so it can be built once and
    joined twice. A binding with a `guard` produces its rows only if the guard
    holds for at least one row -- which is what a sub-search does, and what a
    plain definition cannot express.
    """
    for binding in rule.bindings:
        # The binding's own name is removed while its pipeline runs. A binding
        # called `logon` whose source table is also called `logon` would
        # otherwise read ITSELF -- a not-yet-populated slot -- and produce zero
        # rows, which reads as "the filter matched nothing" rather than as a
        # wiring bug.
        available = set(state.bindings)
        available.discard(binding.name)
        outer, state.bindings = state.bindings, available
        try:
            produced = _run_pipeline(
                binding.pipeline, rows, state, terminal=binding.name
            )
        finally:
            state.bindings = outer
        if binding.guard is not None:
            kept: list[Row] = []
            decided = 0
            for row in produced:
                value = eval_expr(binding.guard, Scope(current=row), state.context)
                if value is True:
                    kept.append(row)
                elif value is False:
                    decided += 1
                else:
                    state.context.uncertain(
                        "BINDING_GUARD_UNDECIDABLE",
                        f"the guard on binding `{binding.name}` could not be "
                        f"decided for {len(produced) - decided - len(kept)} of "
                        f"{len(produced)} rows, so those rows are in the binding "
                        f"or not by no decision at all.",
                        where=binding.name,
                    )
            produced = kept
        state.put(binding.name, produced)


def _run_pipeline(
    pipeline: tuple[Node, ...],
    seed: list[Row],
    state: _State,
    terminal: str | None = None,
) -> list[Row]:
    """Run stages in order, threading rows from each into the next."""
    current: list[Row] | None = None

    #: Stages that consume the previous stage's rows, versus stages that name
    #: their own sources. Getting this wrong is the silent-empty-input bug: a
    #: Filter with nothing before it would read as "no rows" and report a clean
    #: no-match for a rule that is simply malformed.
    _NEEDS_PREVIOUS = (
        Filter, Project, Derive, Aggregate, Sort, Limit, Distinct, Expand, Emit,
    )

    for node in pipeline:
        # A stage a dialect marked DECLARED_ONLY cannot be run here, and
        # `pipeline.py` never looked at `capability` at all -- the word appeared
        # only as a string in `ADVISORY_CODES`. So `| tstats count by src_ip`,
        # which reads an index-time acceleration summary no sample of events
        # carries, had its count computed FROM the sample instead. The number
        # was fabricated, the stage trace looked ordinary, and the verdict
        # came back `matched`.
        #
        # Rows stop here rather than passing through. Passing them on would
        # hand the next stage input this one never legitimately produced, and
        # the caveat is BLOCKING (it is not in `ADVISORY_CODES`), so the
        # verdict is `not_evaluated` -- which is the true answer: this rule
        # cannot be decided locally.
        if getattr(node, "capability", None) is Capability.DECLARED_ONLY:
            detail = (getattr(node, "note", "") or "").strip()
            state.context.uncertain(
                "STAGE_DECLARED_ONLY",
                f"`{node.id}` is a {type(node).__name__} stage that this "
                f"dialect modelled faithfully and marked as not locally "
                f"executable"
                + (f": {detail}" if detail else "")
                + ". It is NOT run, so nothing downstream of it is decided -- "
                  "computing it from the sample would report a number the "
                  "appliance would have read from somewhere else.",
                where=node.id,
            )
            _record(state, node, len(current or []), 0, detail="declared only")
            current = []
            state.put(node.id, current)
            continue

        if isinstance(node, Read):
            current = _eval_read(node, seed, state)
        elif isinstance(node, _NEEDS_PREVIOUS):
            if current is None:
                raise Refusal(
                    "STAGE_HAS_NO_INPUT",
                    f"`{node.id}` is a {type(node).__name__} stage but nothing "
                    f"before it produces rows. Treating that as an empty input "
                    f"would report a clean no-match for a rule that is malformed, "
                    f"which is the most expensive thing this tool can do.",
                    "run",
                )
            handler = {
                Filter: _eval_filter,
                Project: _eval_project,
                Derive: _eval_derive,
                Aggregate: _eval_aggregate,
                Sort: _eval_sort,
                Limit: _eval_limit,
                Distinct: _eval_distinct,
                Expand: _eval_expand,
                Emit: _eval_emit,
            }[type(node)]
            current = handler(node, current, state)
        elif isinstance(node, Join):
            current = _eval_join(node, state)
        elif isinstance(node, Correlation):
            current = _eval_correlation(node, state)
        elif isinstance(node, Sequence):
            if current is None:
                raise Refusal(
                    "STAGE_HAS_NO_INPUT",
                    f"`{node.id}` is a Sequence stage but nothing before it "
                    f"produces rows. Treating that as an empty input would "
                    f"report a clean no-match for a rule that is malformed.",
                    "run",
                )
            current = _eval_sequence(node, current, state)
        else:
            # A new stage type added to the IR without an executor lands here.
            # A SILENT `else` is the defect class that produced a Wazuh rule
            # which matched every event and reported success, so an unknown stage
            # is a refusal, not a pass-through.
            raise Refusal(
                "STAGE_NOT_EXECUTABLE",
                f"this engine has no executor for a {type(node).__name__} stage, "
                f"so the rule cannot be run. It is refused rather than skipped, "
                f"because skipping it would return a match count for a rule that "
                f"was not the one written.",
                "run",
            )
        state.put(node.id, current)

    if current is None:
        raise Refusal(
            "PIPELINE_EMPTY",
            "the pipeline produced nothing to return",
            "run",
        )
    return current


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------


def _record(
    state: _State, node: Node, rows_in: int, rows_out: int,
    dropped: int = 0, undecided: int = 0, detail: str = "",
) -> None:
    state.trace.append(
        Trace(
            node.id,
            type(node).__name__,
            rows_in,
            rows_out,
            dropped,
            undecided,
            detail,
        )
    )


def _eval_read(node: Read, seed: list[Row], state: _State) -> list[Row]:
    """A Read passes rows through, stamping each row's time.

    IF THE SOURCE NAMES A BINDING, IT READS THAT BINDING. This is what makes
    `let X = T | where ...` followed by `X | join ...` mean anything. Reading the
    raw sample instead would hand the main pipeline every event rather than the
    filtered subset, so a `let` would silently do nothing and the correlation
    would run against unfiltered input -- a rule that matches far more than the
    one written, with no warning.

    The index-time `selector` is NOT applied here and that is deliberate: an
    index-time filter is evaluated by the store before any row exists, and
    applying it locally would claim a match the engine cannot produce. It is
    carried as data and rendered back out.
    """
    if node.table in state.bindings:
        rows_in = list(state.rows.get(node.table, []))
    else:
        rows_in = list(seed)

    if node.selector:
        state.context.caveats.append(
            Caveat(
                "INDEX_TIME_FILTER",
                f"`{node.selector}` is an INDEX-TIME filter, evaluated by the "
                f"store before any event is read. It is carried through "
                f"untouched and is not applied to your sample, because no sample "
                f"of events can reproduce it.",
                "note",
                node.id,
            )
        )

    rows: list[Row] = []
    stamped = 0
    carried = 0
    for row in rows_in:
        if node.time_field:
            number = _timestamp_number(row.get(storage_key_text(node.time_field)))
            if number is not None:
                row = Row(row.values, number, row.origin)
                stamped += 1
            elif row.time is not None:
                # The row already carries a time from the binding it came out
                # of. Re-stamping is unnecessary and warning about it would be
                # noise on every stage after the first.
                carried += 1
        rows.append(row)
    if state.timed and node.time_field and stamped == 0 and carried == 0 and rows_in:
        state.context.caveats.append(
            Caveat(
                "TIME_FIELD_NOT_FOUND",
                f"this stage declares `{node.time_field}` as its timestamp, and "
                f"none of the {len(rows_in)} events supplied have that field. "
                f"Every window, threshold and correlation below it is therefore "
                f"counting rows with no time at all, which is not the same as "
                f"counting them in a window.",
                "caution",
                node.id,
            )
        )
    _record(state, node, 0, len(rows), detail=f"source={node.table}")
    return rows


def _eval_filter(node: Filter, rows: list[Row], state: _State) -> list[Row]:
    """Three ways out: kept, undecided, rejected.

    The undecided count is the point. A filter that quietly drops the rows it
    cannot decide produces a number the analyst cannot audit, and the rows it
    dropped are exactly the ones most likely to be interesting.
    """
    kept: list[Row] = []
    undecided = 0
    for row in rows:
        state.context.budget.spend()
        value = eval_expr(node.condition, Scope(current=row), state.context)
        if value is True:
            kept.append(row)
        elif value is UNDECIDED:
            undecided += 1
        # False is the only silent drop.
    if undecided:
        state.context.uncertain(
            "FILTER_UNDECIDABLE_ROWS",
            f"`{node.id}` could not decide {undecided} of {len(rows)} rows. They "
            f"are NOT counted as non-matches: an absent field is not an empty "
            f"one, so the rule's match count for those rows is unknown rather "
            f"than zero.",
            where=node.id,
        )
    _record(state, node, len(rows), len(kept), len(rows) - len(kept) - undecided,
            undecided)
    return kept


def _eval_project(node: Project, rows: list[Row], state: _State) -> list[Row]:
    """A projection that actually projects.

    The three lists COMPOSE, matching the node's contract: a keeps-list or a
    rename-list means the output is exactly those columns, a drops-list means
    everything else, and an empty node is a pass-through.

    A renderer or evaluator that treated "rename" as "copy" left the source
    column in the output; one that treated it as "move" dropped a column the
    author meant to keep. Both produced a rule that renders plausibly and
    returns the wrong fields.
    """
    if node.is_identity:
        _record(state, node, len(rows), len(rows))
        return list(rows)

    renamed_sources = {source.full for source, _ in node.renames}
    out: list[Row] = []
    for row in rows:
        state.context.budget.spend()
        if node.keeps or node.renames:
            values: dict[str, Any] = {}
            for source, target in node.renames:
                values[target] = row.get(source.full)
            for ref in node.keeps:
                values[ref.full] = row.get(ref.full)
        else:
            values = dict(row.values)
            for drop in node.drops:
                values.pop(drop.full, None)
                _pop_nested(values, drop.path)
        out.append(Row(values, row.time, row.origin))
    _record(state, node, len(rows), len(out))
    return out


def _pop_nested(values: dict[str, Any], path: tuple[str, ...]) -> None:
    if not path:
        return
    cursor: Any = values
    for segment in path[:-1]:
        if isinstance(cursor, dict) and segment in cursor:
            cursor = cursor[segment]
        else:
            return
    if isinstance(cursor, dict):
        cursor.pop(path[-1], None)


def _eval_derive(node: Derive, rows: list[Row], state: _State) -> list[Row]:
    """Computed columns.

    An assignment that cannot be decided does NOT become None. It removes the
    column and records the reason, because writing None would make the column
    look present-and-null, which is a different and more misleading thing.
    """
    out: list[Row] = []
    for row in rows:
        state.context.budget.spend()
        values = dict(row.values)
        for target, expr in node.assignments:
            value = eval_expr(expr, Scope(current=row), state.context)
            if value is UNDECIDED:
                _assign(values, target, ABSENT)
                continue
            _assign(values, target, value)
        out.append(Row(values, row.time, row.origin))
    _record(state, node, len(rows), len(out))
    return out


def _assign(values: dict[str, Any], target: str, value: Any) -> None:
    parts = target.split(".")
    cursor = values
    for segment in parts[:-1]:
        nxt = cursor.get(segment)
        if not isinstance(nxt, dict):
            nxt = {}
            cursor[segment] = nxt
        cursor = nxt
    cursor[parts[-1]] = value


def _eval_join(node: Join, state: _State) -> list[Row]:
    """A join with a real predicate, evaluated per candidate pair.

    The predicate is where scoped references live, so this is the only place a
    `left.`/`right.` reference is meaningful. The equality keys are evaluated
    first as an index probe, then the full predicate per surviving pair -- which
    keeps a two-key temporal join from degenerating into a full cross product.
    """
    left_rows = state.get(node.left)
    right_rows = state.get(node.right)

    # Hash the right side on its keys. Read the RAW field from each side, NOT the
    # prefixed name: prefixing happens at merge time, so the rows in the store
    # are still unprefixed and looking up `R.Computer` finds nothing. Reading the
    # prefixed name here silently produces zero candidates, which looks exactly
    # like a rule that matched nothing.
    def _key(row: Row, ref: Any) -> Any:
        return row.get(storage_key(ref))

    def _unscoped(row: Row, ref: Any) -> Any:
        """Read a join key from a row that has not been merged yet.

        `storage_key` returns `right.Computer` for a ref whose scope is
        `right`, and that prefix only exists AFTER the merge -- the rows in the
        store are still bare. So the right key is read by its field name, with
        the scope deliberately ignored.
        """
        return row.get(ref.full)

    # `node.on` holds (LEFT key, RIGHT key) pairs, and both loops below used
    # to destructure it as `for ref, _ in node.on` -- taking the LEFT key on
    # both sides. So the right-hand rows were indexed under the left field's
    # NAME: a join written `on src_ip == ip` hashed the right rows by `src_ip`,
    # which they do not have, so every probe missed and the join returned
    # nothing. An inner join between two differently-named keys silently
    # matched zero rows, and a rule built on it reported a clean no_match.
    #
    # It only worked when both sides happened to spell the key the same way,
    # which is the common case in the tests and not in real rules.
    index: dict[tuple, list[Row]] = defaultdict(list)
    if node.on:
        for row in right_rows:
            index[
                tuple(_unscoped(row, right) for _left, right in node.on)
            ].append(row)

    out: list[Row] = []
    undecided = 0
    matched_right: set[int] = set()

    for left_row in left_rows:
        state.context.budget.spend(len(right_rows) if not node.on else 1)
        if len(out) > MAX_JOIN_ROWS:
            raise Refusal(
                "JOIN_TOO_LARGE",
                f"this join produced more than {MAX_JOIN_ROWS:,} rows. That "
                f"usually means the join keys do not narrow anything -- check "
                f"that both sides are keyed on the same fields.",
                "run",
            )
        candidates: list[Row]
        if node.on:
            # The LEFT key probes the index the RIGHT key built. Both sides are
            # read unscoped, because neither row has been merged yet.
            candidates = index.get(
                tuple(_unscoped(left_row, left) for left, _right in node.on), []
            )
        else:
            candidates = right_rows

        joined_any = False
        for right_row in candidates:
            merged = left_row.merged(right_row, node.left_prefix, node.right_prefix)
            if node.predicate is not None:
                value = eval_expr(
                    node.predicate,
                    Scope(current=merged, left=left_row, right=right_row),
                    state.context,
                )
                if value is UNDECIDED:
                    undecided += 1
                    continue
                if value is not True:
                    continue
            if node.how == "anti":
                continue
            out.append(merged)
            joined_any = True
            matched_right.add(id(right_row))

        if not joined_any and node.how in ("left", "full"):
            # Emitted with the right side's columns ABSENT, not null. A left
            # join produces a row where the right fields were never there.
            out.append(left_row.merged(Row({}), node.left_prefix, node.right_prefix))

    if node.how in ("right", "full"):
        for right_row in right_rows:
            if id(right_row) not in matched_right:
                out.append(Row({}, right_row.time).merged(
                    right_row, node.left_prefix, node.right_prefix))

    if undecided:
        state.context.uncertain(
            "JOIN_UNDECIDABLE_PAIRS",
            f"`{node.id}` could not decide {undecided} candidate pairs, so the "
            f"join's row count is a lower bound rather than a number.",
            where=node.id,
        )
    _record(state, node, len(left_rows), len(out), undecided=undecided)
    return out


def _key_part(row: Row, ref: Any, prefix: str) -> Any:
    return row.get(f"{prefix}{ref.full}")


def _time_field_of(event: dict[str, Any], declared: str) -> Any:
    """The event's timestamp.

    The Read's DECLARED `time_field` wins over a guess. A previous version
    auto-selected any column whose name looked like a timestamp, which meant a
    rule silently windowed on `EventTimeCreated` when the author meant
    `TimeGenerated` -- and produced a count for a window nobody asked for.
    """
    if declared:
        value = event.get(declared)
        number = as_number(value)
        if number is not None:
            return number
        return None
    return _time_of(event)


def _eval_aggregate(node: Aggregate, rows: list[Row], state: _State) -> list[Row]:
    """Group, then measure.

    Group keys are tagged so a missing key and a null key never land in the same
    bucket -- merging them produces a group count that is right for neither.
    """
    groups: dict[tuple, list[Row]] = defaultdict(list)
    for row in rows:
        state.context.budget.spend()
        groups[tuple(_group_tag(row, ref) for ref in node.keys)].append(row)

    windows = _windows_for(node.window, rows, state)

    out: list[Row] = []
    for window_rows in windows:
        local: dict[tuple, list[Row]] = defaultdict(list)
        for row in window_rows:
            local[tuple(_group_tag(row, ref) for ref in node.keys)].append(row)
        for key, members in local.items():
            values: dict[str, Any] = {}
            for ref in node.keys:
                _assign(values, ref.full, _untag(members[0], ref))
            for measure in node.measures:
                values[measure.name] = _measure(measure, members, state)
            out.append(Row(values, members[0].time))

    _record(state, node, len(rows), len(out),
            detail=f"groups={len(out)}")
    return out


def _group_tag(row: Row, ref: Any) -> tuple:
    key = storage_key(ref)
    value = row.get(key)
    if value is ABSENT:
        return ("absent", key)
    if value is None:
        return ("null", key)
    if isinstance(value, (list, Seq)):
        return ("list", key, tuple(str(v) for v in value))
    number = as_number(value)
    if number is not None:
        return ("num", key, str(number))
    return ("value", key, str(value))


def _untag(row: Row, ref: Any) -> Any:
    return row.get(storage_key(ref))


def _windows_for(
    window: Window | None, rows: list[Row], state: _State
) -> list[list[Row]]:
    """Split rows into the windows the aggregate counts over.

    A sliding window emits one bucket PER ORIGIN, not a single bucket over the
    whole range. That is the difference between "how many in any 5 minutes" and
    "how many in total", and for a threshold rule the first is the one an
    analyst means.
    """
    if window is None or window.kind in ("per_event", "cumulative"):
        return [rows]
    if window.kind == "session":
        if window.gap is None:
            raise Refusal(
                "SESSION_GAP_REQUIRED",
                "a session window needs the gap that ends a session",
                "run",
            )
        sessions: list[list[Row]] = []
        current: list[Row] = []
        previous: Decimal | None = None
        for row in sorted(rows, key=lambda r: (r.time is None, r.time)):
            moment = as_number(row.time)
            if moment is None:
                current.append(row)
                continue
            if previous is not None and moment - previous > window.gap.seconds:
                sessions.append(current)
                current = []
            current.append(row)
            previous = moment
        if current:
            sessions.append(current)
        return sessions or [rows]

    size = window.size.seconds if window.size else None
    step = window.step.seconds if window.step else size
    if size is None or step is None:
        return [rows]

    timed = [r for r in rows if as_number(r.time) is not None]
    if not timed:
        return [rows]

    origin = min(as_number(r.time) for r in timed if as_number(r.time) is not None)
    last = max(as_number(r.time) for r in timed if as_number(r.time) is not None)

    out: list[list[Row]] = []
    cursor = origin
    while cursor <= last:
        upper = cursor + size
        bucket = [
            r for r in timed
            if (as_number(r.time) is not None
                and cursor <= as_number(r.time) < upper)  # type: ignore[operator]
        ]
        if bucket:
            out.append(bucket)
        cursor += step
        if len(out) > 100_000:
            raise Refusal(
                "WINDOW_TOO_MANY",
                "this window produces more than 100,000 buckets. Widen the "
                "window or step, or the rule is asking for a per-event scan.",
                "run",
            )
    return out or [rows]


def _measure(measure: Any, members: list[Row], state: _State) -> Any:
    """One aggregate. List-valued where the vendor's is list-valued.

    `values()` and `make_set()` return collections, and collapsing them to a
    scalar would lose exactly the evidence a correlation rule is correlating on.
    """
    name = measure.function.lower()
    field_key = storage_key(measure.field) if measure.field else None
    present = [r for r in members
               if field_key is None or r.get(field_key) is not ABSENT]
    values = [r.get(field_key) for r in present] if field_key else []
    numbers = [n for n in (as_number(v) for v in values) if n is not None]

    if name in ("count", "count_if", "countif"):
        if measure.condition is not None:
            count = 0
            undecided = 0
            for row in members:
                verdict = eval_expr(
                    measure.condition, Scope(current=row), state.context
                )
                if verdict is True:
                    count += 1
                elif verdict is UNDECIDED:
                    undecided += 1
            if undecided:
                state.context.uncertain(
                    "MEASURE_CONDITION_UNDECIDABLE",
                    f"`{measure.name}` could not decide its conditional count "
                    f"for {undecided} of {len(members)} rows.",
                    where=measure.name,
                )
            return Decimal(count)
        return Decimal(len(present))
    if name in ("values", "make_set", "make_list", "array_agg", "collect_set"):
        items = [v for v in values if v is not ABSENT and v is not None]
        if measure.distinct or name in ("values", "make_set", "collect_set"):
            seen: list[Any] = []
            for item in items:
                if item not in seen:
                    seen.append(item)
            items = seen
        return Seq(tuple(items), distinct=measure.distinct)
    if name in ("min", "max", "avg", "average", "sum", "total", "earliest", "latest"):
        if not numbers:
            return ABSENT
        if name in ("min", "earliest"):
            return min(numbers)
        if name in ("max", "latest"):
            return max(numbers)
        if name in ("sum", "total"):
            return sum(numbers, Decimal(0))
        return sum(numbers, Decimal(0)) / Decimal(len(numbers))
    if name in ("dcount", "distinct_count", "dc"):
        # `dc` belongs HERE, not with `count`. It was grouped with the plain
        # counters and returned the row count, so a Splunk rule reading
        # `stats dc(user) by host` got the number of ATTEMPTS rather than the
        # number of distinct users -- which fires a password-spray rule on one
        # user retrying, and under-reports nothing, so nobody notices.
        #
        # Nulls are not values: a row whose field is null contributes no
        # distinct value, which is what `dc()` does in Splunk and what
        # `dcount()` does in KQL. Stringified because a distinct count has to
        # work across mixed types, where `1` and `"1"` are the same value to
        # every vendor engine that would run this rule.
        return Decimal(len({
            str(v) for v in values if v is not ABSENT and v is not None
        }))
    if name in ("countif",):
        return Decimal(len(present))

    # The four aggregates below are reachable from a dialect spec -- KQL maps
    # `percentile`, `stdev`, `arg_max` and `arg_min` -- and used to fall
    # through to MEASURE_UNKNOWN. That reported a caveat, so it was not
    # silent, but `_verdict` returns MATCHED as soon as any row survives, so a
    # rule reading `summarize p95 = percentile(Duration, 95)` came back
    # `matched` with the column holding nothing at all.

    if name in ("percentile", "percentiles", "percentile_cont"):
        rank = as_number(measure.param)
        if rank is None or not (Decimal(0) <= rank <= Decimal(100)):
            state.context.uncertain(
                "MEASURE_PERCENTILE_RANK",
                f"`{measure.name}` is a percentile with no usable rank "
                f"({measure.param!r}). A percentile without one has no value, "
                f"and defaulting to the median would report a number the rule "
                f"never asked for.",
                where=measure.name,
            )
            return ABSENT
        if not numbers:
            return ABSENT
        return _percentile(sorted(numbers), rank)

    if name in ("stdev", "stdevp", "stddev"):
        if len(numbers) < 2:
            # One observation has no spread. Returning zero would read as
            # "perfectly consistent", which is a claim about data that does
            # not exist.
            state.context.uncertain(
                "MEASURE_STDEV_TOO_FEW",
                f"`{measure.name}` needs at least two values to have a "
                f"standard deviation and this group has {len(numbers)}. "
                f"Reporting zero would read as 'no variation' rather than "
                f"'not enough data'.",
                where=measure.name,
            )
            return ABSENT
        mean = sum(numbers, Decimal(0)) / Decimal(len(numbers))
        # SAMPLE deviation: divided by n-1, which is what KQL's `stdev()`
        # computes. The population form is smaller, so a threshold tuned in
        # Sentinel would fire later here than it does there.
        variance = sum(
            (n - mean) * (n - mean) for n in numbers
        ) / Decimal(len(numbers) - 1)
        return variance.sqrt()

    if name in ("arg_max", "arg_min"):
        if measure.param is None or not str(measure.param).strip():
            state.context.uncertain(
                "MEASURE_ARG_NO_SUBJECT",
                f"`{measure.name}` reports a field taken from the row with "
                f"the largest or smallest value, and does not say which "
                f"field. There is nothing to return.",
                where=measure.name,
            )
            return ABSENT
        if field_key is None or not numbers:
            return ABSENT
        subject = storage_key(FieldRef.parse(str(measure.param)))
        best: Row | None = None
        best_value: Decimal | None = None
        for candidate in present:
            value = as_number(candidate.get(field_key))
            if value is None:
                continue
            if best_value is None or (
                value > best_value if name == "arg_max" else value < best_value
            ):
                # Ties keep the FIRST row in input order, so two runs over the
                # same sample cannot disagree about which row won.
                best, best_value = candidate, value
        if best is None:
            return ABSENT
        return best.get(subject)

    state.context.uncertain(
        "MEASURE_UNKNOWN",
        f"`{name}()` is not an aggregate this engine computes, so the measure "
        f"`{measure.name}` is not evaluated. The stage is reported rather than "
        f"silently producing zero.",
        where=measure.name,
    )
    return ABSENT


def _percentile(ordered: list[Decimal], rank: Decimal) -> Decimal:
    """The rank-th percentile, interpolating between neighbours.

    Linear interpolation rather than nearest-rank, because a nearest-rank p95
    over 20 samples jumps a whole observation at a time and a threshold set
    just above it never fires.
    """
    if len(ordered) == 1:
        return ordered[0]
    position = (rank / Decimal(100)) * Decimal(len(ordered) - 1)
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    weight = position - Decimal(low)
    return ordered[low] + (ordered[high] - ordered[low]) * weight


def _eval_sort(node: Sort, rows: list[Row], state: _State) -> list[Row]:
    if not node.keys:
        _record(state, node, len(rows), len(rows))
        return list(rows)
    ordered = sorted(rows, key=lambda r: _sort_key(r, node.keys))
    # Metered per row. Sorting a million rows is work the budget is supposed
    # to account for, and it spent nothing -- so a sort placed after an
    # expansion ran unbounded.
    state.context.budget.spend(len(rows))
    if node.limit is not None:
        # `Sort.limit` was declared on the node and never applied, so a stage
        # meaning "the top 2 by severity" returned every row -- an alert built
        # on it fires on rows the author excluded, and the stage trace
        # reported the full count as if that were correct.
        #
        # Always the first N AFTER the ordering. That is what separates this
        # from a trailing `Limit`, which has its own `keep_last` flag and
        # applies to whatever order it happens to receive.
        ordered = ordered[:node.limit]
    _record(state, node, len(rows), len(ordered))
    return ordered


class _Descending:
    """One sort key, ordered backwards.

    Python cannot negate a string, so descending order was attempted by
    negating the numeric component and appending a high sentinel:

        out[-1] = out[-1] + ("\\uffff",)
        out[-1] = (out[-1][0], -out[-1][1], out[-1][2])

    The second line rebuilds a three-tuple and throws the sentinel away, and
    it negates only the NUMBER -- so the string component and the type tag
    were left ascending. `| sort by Name desc` returned alphabetical order,
    and `| sort by Severity desc | take 1` returned the LOWEST severity: the
    opposite of the row the rule asked for.

    Wrapping the whole key inverts every component consistently, including
    the tag that orders absent and null.
    """

    __slots__ = ("key",)

    def __init__(self, key: tuple) -> None:
        self.key = key

    def __lt__(self, other: "_Descending") -> bool:
        return other.key < self.key

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Descending) and self.key == other.key

    def __hash__(self) -> int:
        return hash(self.key)


def _sort_key(row: Row, keys: tuple[tuple[Any, bool], ...]) -> tuple:
    """A total order across mixed types.

    Numbers and strings cannot be compared in Python, and every vendor dialect
    disagrees about what that means. Tagging the type makes the sort TOTAL --
    numbers before strings, absent last -- rather than raising halfway through
    and losing the whole result to an internal error.
    """
    out: list[Any] = []
    for ref, descending in keys:
        value = row.get(storage_key(ref))
        number = as_number(value)
        if value is ABSENT:
            key = (3, Decimal(0), "")
        elif value is None:
            key = (2, Decimal(0), "")
        elif number is not None:
            key = (0, number, "")
        else:
            key = (1, Decimal(0), str(value))
        out.append(_Descending(key) if descending else key)
    return tuple(out)



def _eval_limit(node: Limit, rows: list[Row], state: _State) -> list[Row]:
    if node.keep_last:
        out = rows[-node.count:] if node.count < len(rows) else list(rows)
    else:
        out = rows[:node.count]
    if len(out) < len(rows):
        state.context.caveats.append(
            Caveat(
                "STAGE_ROW_LIMIT",
                f"`{node.id}` kept the first {len(out)} of {len(rows)} rows, so "
                f"anything past it was never evaluated. The count below is a "
                f"floor, not a total.",
                "note",
                node.id,
            )
        )
    _record(state, node, len(rows), len(out))
    return out


def _eval_distinct(node: Distinct, rows: list[Row], state: _State) -> list[Row]:
    # Metered per row: building the key set over a large input is real work,
    # and an unmetered stage downstream of an expansion is how a bounded
    # pipeline becomes an unbounded one again.
    seen: set[tuple] = set()
    out: list[Row] = []
    for row in rows:
        state.context.budget.spend()
        key = tuple(_group_tag(row, ref) for ref in node.keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    _record(state, node, len(rows), len(out))
    return out


def _eval_expand(node: Expand, rows: list[Row], state: _State) -> list[Row]:
    """One row per item in a multivalue field.

    The budget is spent per OUTPUT row, not per input row, because this is the
    one stage that MULTIPLIES. `Budget`'s docstring says the ceiling is spent
    by "the operations that can actually blow up" and this spent nothing at
    all -- so 100 rows holding two 100-item lists expanded to 1,000,000 rows
    for free against a 4,000,000 ceiling, and a third list or a longer one is
    a memory exhaustion with no refusal. That hang is precisely what the
    budget exists to turn into a named error.
    """
    out: list[Row] = []
    truncated = False
    for row in rows:
        value = row.get(storage_key(node.field))
        items = list(value) if isinstance(value, (Seq, list)) else [value]
        for item in items:
            if len(out) >= MAX_STAGE_ROWS:
                # Stopped rather than continued. `STAGE_ROW_LIMIT` was declared
                # as a caveat code and never raised by anything, so the row
                # ceiling existed only on paper and memory was unbounded.
                truncated = True
                break
            state.context.budget.spend()
            values = dict(row.values)
            _assign(values, node.into or node.field.full, item)
            out.append(Row(values, row.time, row.origin))
        if truncated:
            break
    if truncated:
        state.context.uncertain(
            "STAGE_ROW_LIMIT",
            f"`{node.id}` would expand past {MAX_STAGE_ROWS:,} rows, so it "
            f"stopped there. Every row it did produce is real, but the set is "
            f"incomplete -- so a match found here is genuine and a NON-match "
            f"is not decidable, because the rows that would have matched may "
            f"be the ones not expanded. Narrow the sample.",
            where=node.id,
        )
    _record(state, node, len(rows), len(out))
    return out


def _eval_emit(node: Emit, rows: list[Row], state: _State) -> list[Row]:
    out: list[Row] = []
    for row in rows:
        if node.keeps:
            values = {ref.full: row.get(storage_key(ref)) for ref in node.keeps}
            out.append(Row(values, row.time, row.origin))
        else:
            out.append(row)

    if node.dedupe_by:
        seen: set[tuple] = set()
        deduped: list[Row] = []
        collapsed = 0
        for row in out:
            key = tuple(row.get(storage_key(ref)) for ref in node.dedupe_by)
            if any(part is ABSENT for part in key):
                # Fifty events becoming one alert because a dedupe key was
                # missing is a silent data loss, so the rows are kept and the
                # fact is reported.
                deduped.append(row)
                collapsed += 1
                continue
            if key in seen:
                continue
            seen.add(key)
            deduped.append(row)
        if collapsed:
            state.context.uncertain(
                "DEDUPE_KEY_ABSENT",
                f"{collapsed} rows had an absent dedupe key and were kept rather "
                f"than collapsed, because collapsing them would silently merge "
                f"events that may be entirely different.",
                where=node.id,
            )
        out = deduped

    _record(state, node, len(rows), len(out))
    return out


def _eval_correlation(node: Correlation, state: _State) -> list[Row]:
    """A threshold over time, as `frequency` / `timeframe` expresses it.

    The window TRAILS the event, not leads it. A forward-looking window never
    fires on a spray of exactly N events, which is the single most common way a
    threshold rule is deployed and never triggers.

    The count is PER GROUP. `group_by` was accepted and then ignored here, so
    every threshold counted across the whole sample: a brute-force rule written
    as "eight failures from the same source IP" fired on eight failures from
    eight different hosts, which is ordinary background noise on any estate of
    size. `ir.Correlation` refuses an empty `group_by` precisely because an
    ungrouped count is "anywhere in the log" -- the model insisted on the
    group and the evaluator dropped it, so the refusal guarded nothing.

    Rows are also paired with their timestamps BEFORE sorting. The sorted
    times were being used to index the UNSORTED rows, so the row reported as
    closing the window was whichever one happened to sit at that position --
    an arbitrary event, in any sample that did not arrive in time order.
    """
    subject_rows = state.get(node.parent)
    window_size = node.timeframe.seconds

    groups: dict[tuple, list[tuple[Any, Row]]] = {}
    untimed = 0
    ungrouped = 0
    for row in subject_rows:
        when = as_number(row.time)
        if when is None:
            # No timestamp means the row cannot be placed in any window.
            # Counted and reported rather than dropped quietly, because each
            # one lowers the count towards a false no_match.
            untimed += 1
            continue
        key = tuple(row.get(storage_key(ref)) for ref in node.group_by)
        if any(part is ABSENT for part in key):
            # An absent group key is not a group. Lumping every absence
            # together would count unrelated events as one actor, which is the
            # very failure this grouping exists to prevent.
            ungrouped += 1
            continue
        groups.setdefault(key, []).append((when, row))

    if untimed:
        state.context.uncertain(
            "CORRELATION_ROW_UNTIMED",
            f"{untimed} row(s) have no timestamp and could not be placed in a "
            f"window, so they did not count towards the threshold. A "
            f"correlation is a statement about time, and a row without one "
            f"cannot support or refute it.",
            where=node.id,
        )
    if ungrouped:
        state.context.uncertain(
            "CORRELATION_GROUP_KEY_ABSENT",
            f"{ungrouped} row(s) are missing "
            f"`{', '.join(ref.full for ref in node.group_by)}` and were not "
            f"counted. Counting them as one group would treat unrelated "
            f"events as the same actor.",
            where=node.id,
        )

    if not groups:
        _record(state, node, len(subject_rows), 0,
                detail=f"frequency>={node.frequency}")
        return []

    out: list[Row] = []
    for key in groups:
        members = sorted(groups[key], key=lambda pair: pair[0])
        left = 0
        for index in range(len(members)):
            low = members[index][0] - window_size  # type: ignore[operator]
            while left < index and members[left][0] < low:  # type: ignore[operator]
                left += 1
            count = index - left + 1
            if count >= node.frequency:
                source = members[index][1]
                values = dict(source.values)
                _assign(values, "frequency", Decimal(count))
                _assign(values, "timeframe", node.timeframe)
                out.append(Row(values, source.time, source.origin))
                state.context.budget.spend()

    # Sorted by time so the output order does not depend on dict ordering of
    # the groups, which would make two runs over the same sample disagree.
    out.sort(key=lambda row: (as_number(row.time) or 0))

    _record(state, node, len(subject_rows), len(out),
            detail=f"frequency>={node.frequency} within {int(window_size)}s "
                   f"per {', '.join(ref.full for ref in node.group_by)}")
    return out


def _eval_sequence(node: Sequence, rows: list[Row], state: _State) -> list[Row]:
    """An ORDERED series of events, as EQL's `sequence` expresses it.

    The ordering is the whole point, so the matching is deliberately a state
    machine per join key rather than a set intersection. Within one key the
    rows are walked in time order and a step only advances when a row
    satisfies it AFTER the previous step was satisfied. Checking "does some
    row match step 1 and some row match step 2" instead would match the
    reverse order too -- and `procdump` then `lsass` is credential dumping
    where `lsass` then `procdump` is somebody inspecting a memory tool.

    `maxspan` is measured from the FIRST step to the last, not between
    consecutive steps. A per-gap window lets a chain of five steps stretch
    across five windows and still fire, which is not what the rule bounded.

    `until` abandons a partial sequence. A chain that was cancelled -- the
    user logged off, the process exited -- is not a detection, and completing
    it anyway reports an attack that did not happen.
    """
    groups: dict[tuple, list[tuple[Any, Row]]] = {}
    untimed = 0
    ungrouped = 0
    for row in rows:
        when = as_number(row.time)
        if when is None:
            # A sequence is a statement about order. A row with no timestamp
            # cannot be placed in one, and guessing a position would invent
            # the ordering the rule is testing for.
            untimed += 1
            continue
        key = tuple(row.get(storage_key(ref)) for ref in node.by)
        if any(part is ABSENT for part in key):
            ungrouped += 1
            continue
        groups.setdefault(key, []).append((when, row))

    if untimed:
        state.context.uncertain(
            "SEQUENCE_ROW_UNTIMED",
            f"{untimed} row(s) have no timestamp, so they could not be placed "
            f"in the ordering and took no part in the sequence. A sequence is "
            f"a statement about order, and a row without a clock cannot "
            f"support or refute it.",
            where=node.id,
        )
    if ungrouped:
        state.context.uncertain(
            "SEQUENCE_JOIN_KEY_ABSENT",
            f"{ungrouped} row(s) are missing "
            f"`{', '.join(ref.full for ref in node.by)}` and were not "
            f"considered. Pairing them anyway would join events that never "
            f"happened on the same host.",
            where=node.id,
        )

    span = node.maxspan.seconds if node.maxspan is not None else None
    out: list[Row] = []

    for key in groups:
        members = sorted(groups[key], key=lambda pair: pair[0])
        # The scan restarts at every candidate first event, because an early
        # false start must not consume the row that would have begun a real
        # match. Anchoring once and giving up made a sequence miss the second
        # attempt in a sample containing two.
        #
        # But a chain is reported ONCE. `a, a, b` completes from the first `a`
        # and again from the second, and both land on the same closing `b` --
        # so one attack chain produced two identical findings, and a threshold
        # counting them saw twice the traffic that existed. The closing row is
        # what identifies a chain: two anchors reaching the same final event
        # are the same occurrence seen from different starting points.
        closed: set[int] = set()
        for anchor in range(len(members)):
            matched = _match_sequence_from(node, members, anchor, span, state)
            if matched is None:
                continue
            row, closing = matched
            if closing in closed:
                continue
            closed.add(closing)
            out.append(row)
            state.context.budget.spend()

    out.sort(key=lambda row: (as_number(row.time) or 0))
    detail = (
        f"{len(node.steps)} steps in order per "
        f"{', '.join(ref.full for ref in node.by)}"
    )
    if span is not None:
        detail += f" within {int(span)}s"
    _record(state, node, len(rows), len(out), detail=detail)
    return out


def _match_sequence_from(
    node: Sequence,
    members: list[tuple[Any, Row]],
    anchor: int,
    span: Any,
    state: _State,
) -> tuple[Row, int] | None:
    """One attempt at the sequence, beginning at `members[anchor]`.

    Returns the row that COMPLETED the sequence together with the POSITION of
    that closing event, or None. The caller dedupes on the position: two
    anchors that reach the same closing event are the same chain seen from
    different starting points, and reporting both turned one attack chain into
    two findings.
    """
    step_index = 0
    runs_left = node.steps[0].runs
    started: Any = None
    collected: list[Row] = []

    for position in range(anchor, len(members)):
        when, row = members[position]

        if node.until is not None:
            verdict = eval_expr(
                node.until, Scope(current=row), state.context
            )
            if verdict is True:
                # The chain was cancelled. Completing it anyway reports an
                # attack that did not happen.
                return None

        if started is not None and span is not None and when - started > span:
            return None

        step = node.steps[step_index]
        verdict = eval_expr(step.condition, Scope(current=row), state.context)
        if verdict is not True:
            # A row that does not satisfy the current step is simply not part
            # of it. It is NOT a failure: unrelated traffic sits between the
            # steps of every real attack chain.
            continue

        if started is None:
            started = when
        collected.append(row)
        runs_left -= 1
        if runs_left > 0:
            continue
        step_index += 1
        if step_index == len(node.steps):
            values: dict[str, Any] = {}
            for member in collected:
                values.update(member.values)
            _assign(values, "sequence_steps", Decimal(len(node.steps)))
            if started is not None:
                _assign(values, "sequence_span", Decimal(str(when - started)))
            return Row(values, row.time, row.origin), position
        runs_left = node.steps[step_index].runs

    return None
