"""Structural validation.

Node-level rules live in `ir.py`, at construction, because a malformed node
should be impossible to create. What lives here is the graph-level truth, which
cannot be checked until the graph exists:

    * every input reference resolves to a real node
    * the graph is acyclic
    * exactly one node is the output, and it is an Emit
    * every node is reachable from a Read
    * the graph is within its node budget
    * expressions are within their depth budget

The evaluator calls this before running. An unvalidated graph cannot be
executed, which means a validation gap is a crash rather than a wrong answer.
That ordering is deliberate: a crash is recoverable, a silently wrong verdict
in a detection pipeline is not.
"""

from __future__ import annotations

from typing import Any, Final

from .ir import (
    BOOLEAN_FUNCTIONS,
    MAX_EXPRESSION_DEPTH,
    MAX_NODES,
    NODE_CLASSES,
    Arith,
    BoolOp,
    Call,
    Comparison,
    Emit,
    FieldExpr,
    Frame,
    Literal,
    Not,
)
from .values import Refusal

#: Node classes that terminate a branch. Only Emit may be the graph output.
TERMINALS: Final = frozenset({Emit})

#: Node classes that may start a branch.
SOURCES: Final = frozenset()


def _input_refs(node: Any) -> list[str]:
    """Node ids this node reads from.

    Used for BOTH edge directions: forward for cycle detection and topological
    ordering, backward for reachability from the output. So it must include
    Emit, which has exactly one input like a Filter does. An earlier version
    omitted it, which made every node look unreachable and made the whole engine
    refuse every rule with a graph-related error while appearing to work.
    """
    name = type(node).__name__
    if name in ("Filter", "Derive", "Aggregate", "Arrange", "Expand", "Pattern",
                "Emit"):
        return [node.input]
    if name in ("Join", "SetOp"):
        return [node.left, node.right]
    return []


def _expression_depth(expr: Any, depth: int = 0) -> int:
    """Recursion depth of an expression tree, with a hard stop.

    The stop matters. A malformed or hostile tree can be deep enough to exhaust
    the interpreter stack, and a RecursionError escaping as an opaque crash tells
    the analyst nothing. Here it is a named refusal at a known depth.
    """
    if depth > MAX_EXPRESSION_DEPTH:
        raise Refusal(
            "EXPRESSION_TOO_DEEP",
            f"expression nests deeper than {MAX_EXPRESSION_DEPTH} levels", "expr")
    if isinstance(expr, Call):
        return 1 + max((_expression_depth(c, depth + 1) for c in expr.args),
                       default=0)
    if isinstance(expr, Comparison):
        # A Comparison has exactly two operands, `left` and `right`. A Call has
        # `args` and no such attributes, which an earlier version of this function
        # got wrong by building one child tuple for both and reaching for
        # `expr.left` on a Call.
        return 1 + max((_expression_depth(c, depth + 1)
                        for c in (expr.left, expr.right) if c is not None),
                       default=0)
    if isinstance(expr, BoolOp):
        return 1 + max((_expression_depth(c, depth + 1) for c in expr.operands),
                       default=0)
    if isinstance(expr, Arith):
        return 1 + max((_expression_depth(c, depth + 1) for c in expr.operands),
                       default=0)
    if isinstance(expr, FieldExpr):
        return 1
    if isinstance(expr, Literal):
        return 1
    return 0


def validate_graph(ir: Any) -> None:
    """Raise `Refusal` unless the graph is executable.

    Checks run cheapest-and-most-likely first, so the error an analyst sees is the
    one nearest their mistake rather than an incidental one further down.
    """
    nodes = ir.nodes

    if len(nodes) > MAX_NODES:
        raise Refusal(
            "GRAPH_TOO_LARGE",
            f"graph has {len(nodes)} nodes, limit is {MAX_NODES}", "graph")

    if not nodes:
        raise Refusal("GRAPH_EMPTY", "a rule needs at least one node", "graph")

    ids: dict[str, Any] = {}
    for node in nodes:
        known = type(node).__name__
        if known not in {c.__name__ for c in NODE_CLASSES}:
            raise Refusal("NODE_TYPE_UNKNOWN", f"{known} is not a RuleForge node",
                          "graph")
        if node.id in ids:
            raise Refusal(
                "DUPLICATE_NODE_ID",
                f"two nodes both call themselves {node.id!r}; references would be "
                f"ambiguous", "graph")
        ids[node.id] = node

    if ir.output not in ids:
        raise Refusal("OUTPUT_NOT_FOUND",
                      f"output {ir.output!r} is not a node in this graph", "graph")
    if not isinstance(ids[ir.output], Emit):
        raise Refusal(
            "OUTPUT_NOT_AN_EMIT",
            f"output is a {type(ids[ir.output]).__name__}; a rule's output must be an "
            f"Emit, so what gets projected is stated rather than implied", "graph")

    for node in nodes:
        for ref in _input_refs(node):
            if ref not in ids:
                raise Refusal(
                    "DANGLING_INPUT",
                    f"node {node.id!r} reads from {ref!r}, which is not in this graph",
                    "graph")

    _reject_cycles(ids)

    reachable = _reachable_from_sources(ids, ir.output)
    orphans = sorted(set(ids) - reachable)
    if orphans:
        raise Refusal(
            "UNREACHABLE_NODES",
            f"{orphans} are not connected to the output, so they would be computed "
            f"and thrown away. A rule containing that is usually a mistake in wiring.",
            "graph")

    for node in nodes:
        _validate_expressions(node)


def _reject_cycles(ids: dict[str, Any]) -> None:
    """Depth-first cycle detection with an explicit colour map.

    Iterative rather than recursive: node count is bounded at 500, and 500 Python
    frames is uncomfortably close to the default limit, so a graph that is
    *nearly* over budget would fail with a RecursionError instead of the accurate
    "this graph is cyclic".
    """
    WHITE, GREY, BLACK = 0, 1, 2
    colour: dict[str, int] = dict.fromkeys(ids, WHITE)
    for start in ids:
        if colour[start] != WHITE:
            continue
        stack: list[tuple[str, int]] = [(start, 0)]
        path: list[str] = [start]
        while stack:
            node_id, index = stack[-1]
            if index == 0:
                if colour[node_id] == GREY:
                    cycle = " -> ".join(path[path.index(node_id):] + [node_id])
                    raise Refusal("GRAPH_CYCLE",
                                  f"these nodes form a loop: {cycle}", "graph")
                colour[node_id] = GREY
            refs = _input_refs(ids[node_id])
            if index < len(refs):
                stack[-1] = (node_id, index + 1)
                nxt = refs[index]
                if colour.get(nxt) == GREY:
                    cycle = " -> ".join(path[path.index(nxt):] + [nxt])
                    raise Refusal("GRAPH_CYCLE",
                                  f"these nodes form a loop: {cycle}", "graph")
                if colour.get(nxt) == WHITE:
                    stack.append((nxt, 0))
                    path.append(nxt)
                continue
            colour[node_id] = BLACK
            stack.pop()
            if path:
                path.pop()


def _reachable_from_sources(ids: dict[str, Any], output: str) -> set[str]:
    """Walk backwards from the output, iteratively."""
    seen: set[str] = set()
    stack = [output]
    while stack:
        current = stack.pop()
        if current in seen or current not in ids:
            continue
        seen.add(current)
        stack.extend(_input_refs(ids[current]))
    return seen


def _validate_expressions(node: Any) -> None:
    """Depth-check and shape-check every expression a node carries."""
    name = type(node).__name__

    if name == "Filter":
        _require_predicate(node.condition, f"Filter {node.id!r}")

    elif name == "Derive":
        for target, expr in node.assignments:
            _expression_depth(expr)

    elif name == "Aggregate":
        for measure in node.measures:
            if measure.field is not None:
                _expression_depth(measure.field)
            if measure.by is not None:
                _expression_depth(measure.by)
        _validate_frame(node.frame, node.id)

    elif name == "Join":
        for left, right in node.on:
            _expression_depth(left)
            _expression_depth(right)
        for spec in node.temporal:
            _expression_depth(spec[0])
            _expression_depth(spec[1])

    elif name == "Pattern":
        for stage in node.stages:
            for condition in stage:
                _require_predicate(condition, f"Pattern {node.id!r} stage")
        if node.until is not None:
            _require_predicate(node.until, f"Pattern {node.id!r} until")

    elif name == "SetOp":
        # keys and op are validated at construction; nothing graph-level to add.
        pass


def _require_predicate(expr: Any, where: str) -> None:
    """A predicate must be built from comparisons, boolean operators, or a
    predicate-returning function call.

    Enforced because a bare field reference in a filter position is the classic
    half-built predicate: it is truthy for any non-empty string, so it "works" and
    matches almost everything. Accepting it would mean shipping a rule that
    silently matches every row instead of failing.
    """


    if isinstance(expr, (Comparison, BoolOp)):
        _expression_depth(expr)
        return
    if isinstance(expr, Not):
        # `NOT <predicate>` is a predicate. Rejecting it made `NOT ILIKE '%x%'`
        # unbuildable, which is ordinary AQL and ordinary YARA-L.
        _expression_depth(expr)
        _require_predicate(expr.operand, where)
        return
    if isinstance(expr, Call) and expr.function in BOOLEAN_FUNCTIONS:
        # `matches_regex(...)` answers a yes/no question about its arguments.
        # Wrapping it in a Comparison would ask "is this string equal to True",
        # which is undecidable on every row.
        _expression_depth(expr)
        return
    raise Refusal(
        "PREDICATE_INCOMPLETE",
        f"{where} needs a comparison, and/or, or a predicate function "
        f"({sorted(BOOLEAN_FUNCTIONS)}); got {type(expr).__name__}. A bare field is "
        f"true for any non-empty value, so accepting one here would match nearly "
        f"every row instead of failing.", where)


def _validate_frame(frame: Frame, node_id: str) -> None:
    """Graph-level frame checks that node construction cannot see."""
    if frame.kind in ("tumbling", "sliding") and frame.time_ref is None:
        raise Refusal("FRAME_REQUIRES_TIME_REF",
                      f"Aggregate {node_id!r} windows on time but declares no time "
                      f"field", "Aggregate")
    if frame.is_epoch_aligned and frame.anchor is not None:
        raise Refusal("FRAME_ANCHOR_NOT_APPLICABLE",
                      "epoch-aligned frames ignore an anchor", "Aggregate")
