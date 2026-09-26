"""The graph walker and public entry point.

`evaluate` is the only function the rest of RuleForge calls to run a rule. It
validates first, so an invalid graph can never execute, and it returns an
`EvaluationResult` carrying a verdict, rows, caveats and a per-node trace.

The walk is ITERATIVE. A rule may contain up to 500 nodes, and 500 Python frames
is close enough to the default recursion limit that a large-but-valid graph would
fail with a RecursionError that reads like corruption. A topological order also
gives the trace a meaningful sequence: nodes in the order they ran.
"""

from __future__ import annotations

from typing import Any, Callable, Final

from .evaluate import (
    Budget,
    EvaluationContext,
    EvaluationResult,
    NodeTrace,
    Row,
    Verdict,
)
from .ir import RuleIR
from .nodes import (
    eval_aggregate,
    eval_arrange,
    eval_derive,
    eval_emit,
    eval_expand,
    eval_package,
    eval_filter,
    eval_join,
    eval_pattern,
    eval_read,
    eval_setop,
)
from .validate import validate_graph
from .values import Refusal

#: node class name -> evaluator. One dispatch table, so adding a node type without
#: an evaluator is a visible gap rather than a runtime fallthrough. Every entry in
#: NODE_TYPES must appear here, and `test_every_node_type_is_executable` enforces
#: that. `Join` and `SetOp` were MISSING from this table while their evaluator
#: functions sat unused in nodes.py, so any rule containing a join validated
#: cleanly and then refused to run — validation and executability disagreed, and
#: the Sentinel shape (a temporal join over two event sets) could not run at all.
EVALUATORS: Final[dict[str, Callable[..., list[Row]]]] = {
    "Read": eval_read,
    "Filter": eval_filter,
    "Derive": eval_derive,
    "Aggregate": eval_aggregate,
    "Arrange": eval_arrange,
    "Expand": eval_expand,
    "Pattern": eval_pattern,
    "Package": eval_package,
    "Join": eval_join,
    "SetOp": eval_setop,
    "Emit": eval_emit,
}


def _topological(ids: dict[str, Any], output: str) -> list[str]:
    """Order nodes so every input is computed before its consumer.

    Kahn's algorithm. On a graph already proven acyclic by validation this cannot
    fail, but it raises rather than returning a partial order if it somehow does,
    because a partial order would evaluate a node against missing input and
    produce a wrong answer with no error.
    """
    from .validate import _input_refs

    incoming = {node_id: 0 for node_id in ids}
    consumers: dict[str, list[str]] = {node_id: [] for node_id in ids}
    for node_id, node in ids.items():
        for ref in _input_refs(node):
            if ref in consumers:
                consumers[ref].append(node_id)
                incoming[node_id] += 1

    ready = [n for n, count in incoming.items() if count == 0]
    order: list[str] = []
    while ready:
        current = ready.pop(0)
        order.append(current)
        for consumer in consumers[current]:
            incoming[consumer] -= 1
            if incoming[consumer] == 0:
                ready.append(consumer)

    if len(order) != len(ids):
        remaining = sorted(set(ids) - set(order))
        raise Refusal("GRAPH_NOT_ORDERABLE",
                      f"these nodes could not be ordered, which means a cycle "
                      f"survived validation: {remaining}", "graph")
    return order


def evaluate(ir: RuleIR, rows: Any = None, *,
             budget_limit: int = 2_000_000,
             time_field: str | None = None) -> EvaluationResult:
    """Run `ir` against `rows`.

    `rows` is either a flat list of dicts, for a graph with one Read, or a dict
    keyed by Read node id, for a graph with several. A Join and a SetOp have two
    inputs apiece, so a single shared list cannot supply them honestly -- feeding
    one list to both sides means the join correlates each row with itself, every
    equality key matches, and the result is a square of the input.

    `time_field` supplies the timestamp for graphs that reference one through
    Frame.time_ref. It is a parameter rather than an inference because a rule that
    says "window on `event_time`" must not be silently pointed at `timestamp`.
    """
    try:
        validate_graph(ir)
    except Refusal as refusal:
        return EvaluationResult(Verdict.NOT_EVALUATED, reason=refusal)

    ids = {node.id: node for node in ir.nodes}
    ctx = EvaluationContext(Budget(budget_limit))
    trace: list[NodeTrace] = []
    results: dict[str, list[Row]] = {}

    try:
        per_read, trace, results = _prepare(ir, ids, rows, time_field)
    except Refusal as refusal:
        return EvaluationResult(Verdict.NOT_EVALUATED, reason=refusal)

    try:
        for node_id in _topological(ids, ir.output):
            node = ids[node_id]
            kind = type(node).__name__
            evaluator = EVALUATORS.get(kind)
            if evaluator is None:
                raise Refusal(
                    "NODE_NOT_EXECUTABLE",
                    f"{kind} has no evaluator, so this rule cannot be run. Declaring "
                    f"a node the engine cannot execute would let it look supported "
                    f"while silently going nowhere.", kind)

            produced = _run_node(evaluator, node, results, per_read, ctx, kind)
            results[node_id] = produced
            trace.append(NodeTrace(
                node_id=node_id, primitive=kind, status="evaluated",
                rows_in=_row_count(node, results, per_read),
                rows_out=len(produced), detail=""))

    except Refusal as refusal:
        return EvaluationResult(
            Verdict.NOT_EVALUATED,
            rows=(),
            reason=refusal,
            caveats=tuple(ctx.caveats),
            trace=tuple(trace))

    except (TypeError, ValueError, ArithmeticError, AttributeError,
            RecursionError, IndexError, KeyError) as exc:
        # An internal fault is still a refusal, never a traceback. An analyst
        # pasting a rule must never see a stack trace, and a crash must never be
        # the only signal that a construct was not handled. Catching the broad
        # set is deliberate: a rule that trips an unexpected error is
        # unevaluated, which is honest, whereas a 500 is not.
        return EvaluationResult(
            Verdict.NOT_EVALUATED,
            rows=(),
            reason=Refusal(
                "EVALUATION_INTERNAL",
                f"this rule hit a condition the evaluator did not anticipate "
                f"({type(exc).__name__}: {exc}). It is reported as unevaluated "
                f"rather than as a result, because no result can be trusted from "
                f"a run that failed this way.", "evaluate"),
            caveats=tuple(ctx.caveats),
            trace=tuple(trace))

    output_rows = results.get(ir.output, [])
    return _verdict(output_rows, ctx, trace)


def _as_time(row: dict[str, Any], time_field: str | None) -> Any:
    if time_field is None:
        return None
    return row.get(time_field)


def _prepare(ir: RuleIR, ids: dict[str, Any], rows: Any,
             time_field: str | None) -> tuple[dict[str, list[Row]],
                                              list[NodeTrace],
                                              dict[str, list[Row]]]:
    """Bind the caller's rows to this graph's Read nodes.

    Returns the per-Read row sets, an empty trace, and an empty result map, so
    that a refusal here surfaces as an `EvaluationResult` rather than an
    exception escaping `evaluate`. An analyst pasting a rule must never see a
    stack trace.
    """
    read_ids = [n.id for n in ir.nodes if type(n).__name__ == "Read"]
    supplied: dict[str, list[dict[str, Any]]] = {}

    if not read_ids:
        raise Refusal("SAMPLE_BUT_NO_READ", "this rule reads nothing", "evaluate")

    if rows is None:
        supplied = {read_id: [] for read_id in read_ids}
    elif isinstance(rows, dict):
        unknown = sorted(set(rows) - set(read_ids))
        if unknown:
            raise Refusal(
                "SAMPLE_UNKNOWN_READ",
                f"rows were supplied for {unknown}, which are not Read nodes in this "
                f"graph. This rule reads from {read_ids}.", "evaluate")
        supplied = {read_id: list(rows.get(read_id, [])) for read_id in read_ids}
    elif len(read_ids) > 1:
        # One list for two Reads would mean assuming they see the same events, which
        # is an invention: every equality key would match its own twin, and a join
        # would return the square of its input while looking entirely plausible.
        raise Refusal(
            "SAMPLE_AMBIGUOUS_FOR_MULTIPLE_READS",
            f"this rule has {len(read_ids)} Read nodes ({read_ids}) but one set of "
            f"rows was supplied. Which events each Read sees must be stated, because "
            f"assuming they are the same is an invention. Pass rows as a dict keyed "
            f"by Read id.", "evaluate")
    else:
        supplied = {read_ids[0]: list(rows)}

    per_read = {
        read_id: [Row(dict(r), _as_time(r, time_field)) for r in data]
        for read_id, data in supplied.items()
    }
    return per_read, [], {}


def _run_node(evaluator: Callable[..., list[Row]], node: Any,
              results: dict[str, list[Row]],
              per_read: dict[str, list[Row]],
              ctx: EvaluationContext, kind: str) -> list[Row]:
    if kind in ("Filter", "Derive", "Aggregate", "Arrange", "Expand", "Pattern",
                "Package"):
        return evaluator(node, results[node.input], ctx)
    if kind in ("Join", "SetOp"):
        return evaluator(node, results[node.left], results[node.right], ctx)
    if kind == "Emit":
        return evaluator(node, results[node.input], ctx)
    # Read: the only node that consumes the caller's rows. Each Read is handed its
    # OWN rows, keyed by node id. A single shared list would make a Join correlate
    # every row with itself -- every equality key would match, and the output
    # would be the square of the input.
    return list(per_read.get(node.id, []))


def _row_count(node: Any, results: dict[str, list[Row]],
               per_read: dict[str, list[Row]]) -> int:
    kind = type(node).__name__
    if kind in ("Filter", "Derive", "Aggregate", "Arrange", "Expand", "Pattern",
                "Package"):
        return len(results.get(node.input, ()))
    if kind in ("Join", "SetOp"):
        return len(results.get(node.left, ()))
    if kind == "Emit":
        return len(results.get(node.input, ()))
    return len(per_read.get(node.id, []))


#: Caveat codes that mean "this evaluation could not decide", as opposed to
#: caveats that are advisory. Any of these BLOCKS a clean NO_MATCH, because
#: NO_MATCH claims the rule was quiet, and it has not been established that.
#:
#: An earlier version checked only two specific codes, so undecidability reported
#: by Pattern, Join, Aggregate or Emit produced a confident `no_match` with the
#: caveat sitting unread beside it. Default-deny: anything not on the ADVISORY
#: list blocks.
ADVISORY_CAVEATS: Final = frozenset({
    "SCHEMA_INFERRED",
    "ARG_EXTREME_TIE",
    "PATTERN_MATCH_LIMIT",
})


def _verdict(rows: list[Row], ctx: EvaluationContext,
             trace: list[NodeTrace]) -> EvaluationResult:
    """Decide MATCHED / NO_MATCH / NOT_EVALUATED.

    The subtle case is NO_MATCH. It is correct only when the rule genuinely
    decided nothing matched. If any row was undecidable, the rule has not
    established that, and saying `no_match` would be a definitive claim the
    evaluation never earned. Default-deny: any non-advisory caveat blocks it.
    """
    blocking = [c for c in ctx.caveats if c.code not in ADVISORY_CAVEATS]
    if rows:
        verdict = Verdict.MATCHED
    elif blocking:
        verdict = Verdict.NOT_EVALUATED
    else:
        verdict = Verdict.NO_MATCH

    result = EvaluationResult(verdict, tuple(rows), caveats=tuple(ctx.caveats),
                              trace=tuple(trace))
    if verdict is Verdict.NOT_EVALUATED and result.reason is None:
        result.reason = Refusal(
            "NOTHING_DECIDED",
            "no row could be decided either way, so this result does not establish "
            "that the rule is quiet. It establishes that the rule could not run "
            "decisively on this data. Reported caveats: "
            + ", ".join(sorted({c.code for c in blocking})),
            "evaluate")
    return result
