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

from engine.ir import (
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
from engine.values import Refusal

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
                "Package", "Emit"):
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
    # `Not` WAS MISSING, AND THAT IS THE SAME BUG AS THE ONES ABOVE.
    #
    # A `Not` has no arm here, so it fell through to `return 0` -- depth zero,
    # whatever the nesting. Which means `MAX_EXPRESSION_DEPTH` never applied to
    # it at all:
    #
    #     BoolOp chain x101  ->  REFUSED: EXPRESSION_TOO_DEEP
    #     Not x5000          ->  _expression_depth = 0
    #
    # And then the recursion that this function exists to stop happened anyway:
    # `validate_graph(Not x2000)` was ACCEPTED, and `Not x2000` escaped as a
    # RecursionError from `jobs.py`, which `web.py` turned into
    # INPUT_TOO_DEEP / "the pasted events are nested too deeply to read" --
    # when no events had been pasted. AQL builds genuinely nested `NOT` chains
    # (`NOT x40` is Not at depth 40), so this was reachable from a rule.
    #
    # The docstring above promises "a RecursionError escaping as an opaque crash
    # tells the analyst nothing. Here it is a named refusal at a known depth."
    # For `Not` that was not true, and the promise is now the test.
    if isinstance(expr, Not):
        return 1 + _expression_depth(expr.operand, depth + 1)

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


def _screen_regexes(node: Any) -> None:
    """Refuse a catastrophic pattern ANYWHERE in this node, at author time.

    Deliberately blind to the dialect. The executable check lives in
    `regex.compile_pattern` and knows what this engine can run; this one does
    not need to, because the pattern is being shipped to somebody ELSE's engine
    and a refusal here is the last point at which the tool can still say no.
    """
    from engine.redos import catastrophic_reason

    def check(pattern: Any) -> None:
        if not isinstance(pattern, str) or not pattern:
            return
        reason = catastrophic_reason(pattern)
        if reason is not None:
            raise Refusal(
                "REGEX_CATASTROPHIC_BACKTRACKING",
                f"this rule contains the pattern {pattern!r}, which can take "
                f"exponential time on a subject that does not match: {reason}. "
                f"It is refused here because this pattern is about to be "
                f"written into a rule you will DEPLOY -- a Wazuh agent, a "
                f"Splunk indexer or a Sentinel rule -- and that engine will run "
                f"it with none of this tool's guards. Refused rather than given "
                f"a time limit, because a limit would still let one row exhaust "
                f"the budget. Rewrite it with a character class, a bounded "
                f"length, or fewer quantifiers.", "regex")

    def walk(value: Any, depth: int = 0) -> None:
        # THE DEPTH CUTOFF MUST NOT BE BELOW WHAT THE VALIDATOR ACCEPTS.
        #
        # This was `if depth > 32: return` with no refusal -- the walk simply
        # stopped looking. `MAX_EXPRESSION_DEPTH` is 100, so depths 33 to 100 were
        # an unguarded band, and one extra pair of parentheses was the difference
        # between a refusal and a deployable artifact:
        #
        #     AQL, MATCHES(payload, '(a|aa)+$')
        #       29 parens -> REGEX_CATASTROPHIC_BACKTRACKING
        #       31 parens -> ok=True, and the pattern is in the artifact
        #
        # The anti-drift test written after round 8 could not catch this, because
        # it inspects container TYPES and a depth cutoff is not a type. "The walk
        # must reach every node" was true of every type and false of the tree past
        # 32 levels.
        #
        # So the cutoff is derived from the same limit the validator enforces, not
        # written as its own smaller number, and going past it REFUSES rather than
        # returning. A silent `return` here means "I stopped looking and said
        # nothing", which is how the guard came to be believed total.
        if depth > MAX_EXPRESSION_DEPTH:
            raise Refusal(
                "SCREEN_DEPTH_EXCEEDED",
                f"the rule nests expressions more than {MAX_EXPRESSION_DEPTH} "
                f"levels deep, which is the most the validator accepts. Refusing "
                f"rather than screening part of it: stopping the walk early would "
                f"leave the deepest terms unscreened, and a pattern there would "
                f"ship undetected.", "regex")
        # A PATTERN ARRIVES WRAPPED. A `<field>` lowers to
        # `Call(matches_regex, (FieldExpr, Literal("...")))`, so testing
        # `isinstance(arg, str)` found nothing and every pattern walked straight
        # through the screen. The first version of this function MISSED all five
        # known-bad patterns for exactly that reason, and reported no error --
        # which is the failure mode this whole project keeps hitting.
        if hasattr(value, "value") and not isinstance(value, (str, bytes)):
            walk(getattr(value, "value", None), depth + 1)
        if isinstance(value, (list, tuple)):
            for item in value:
                walk(item, depth + 1)
            return
        if isinstance(value, dict):
            for item in value.values():
                walk(item, depth + 1)
            return
        # `operands` IS ITS OWN CASE, NOT PART OF THE `Call` BRANCH.
        #
        # The descent into `operands` used to live at the end of the `Call` arm,
        # behind `hasattr(value, "function") and hasattr(value, "args")`. A
        # `BoolOp` has `operands` and NEITHER of those, so it never reached the
        # loop -- the arm returned nothing and the walk stopped. The result was
        # that `Filter(eq)` was screened and `Filter(BoolOp("and", (eq, rx)))`
        # was not, so the ReDoS guard was defeated by ADDING A SECOND `<field>`
        # to a Wazuh rule, or an `and` to a KQL `where`. App-reachable, and the
        # guard is the whole reason `validate_graph` screens patterns at all.
        if hasattr(value, "operands"):
            for operand in getattr(value, "operands", ()) or ():
                walk(operand, depth + 1)
            return
        # `Not` IS ITS OWN CASE TOO, AND IT WAS THE SAME BUG AGAIN.
        #
        # The `operands` fix above handles a `BoolOp`, which holds a tuple called
        # `operands`. `Not` holds a SINGLE child called `operand` -- singular, no
        # tuple. So the arm above does not match, `walk` falls past every later
        # arm, and the guard dead-ends. Measured, app-reachable, and the
        # difference between two rules that differ by one word:
        #
        #     | where cmd matches regex "(a|aa)+$"     -> REFUSED
        #     | where not cmd matches regex "(a|aa)+$"  -> ok=True, deployable
        #
        # 0.028s at n=24, 0.198s at n=28, 1.430s at n=32 -- about 7x per four
        # characters, and unbounded. Reached through `POST /api/author` ->
        # `jobs.author` -> `kql_ir.py`, so this was one `not` away from putting a
        # catastrophic-backtracking pattern into an artifact the analyst ships.
        #
        # THE RULE, SO THE NEXT MISS IS A NEW `if` AND NOT A NEW BUG: this walk
        # must reach EVERY node in the tree. A container type added to the IR
        # later is a blind spot the day it is added, and the symptom is a guard
        # that silently stops guarding. The `screening must not miss a container`
        # test below is the thing that catches that, not any individual arm.
        if isinstance(value, Not):
            walk(value.operand, depth + 1)
            return
        if hasattr(value, "function") and hasattr(value, "args"):
            for arg in getattr(value, "args", ()):
                if isinstance(arg, str) and "regex" in str(
                        getattr(value, "function", "")):
                    check(arg)
            for arg in getattr(value, "args", ()):
                walk(arg, depth + 1)
            for attr in ("left", "right"):
                walk(getattr(value, attr, None), depth + 1)
            return
        if hasattr(value, "name"):
            walk(getattr(value, "pattern", None), depth + 1)
            walk(getattr(value, "left", None), depth + 1)
            walk(getattr(value, "right", None), depth + 1)
            # AND THEN THE REST OF THE NODE, WHICH THE `return` WAS DISCARDING.
            #
            # A `SourceSelector` has `name`, so it entered this arm -- and then the
            # three walks above found nothing, because a selector has no
            # `pattern`, `left` or `right`, and the bare `return` ended the visit.
            # `binding` and `kind` were never looked at. Executed:
            #
            #     Read(selector=SourceSelector(name="e", binding="(a|aa)+$"))
            #       -> the walk finishes without screening it
            #
            # Not a live hole today, because `binding` is a datamodel name by
            # contract and `kind` is a node class name. That is a CONTRACT, not a
            # guarantee, and the round-8 comment says this walk "must reach EVERY
            # node in the tree" precisely so that a new attribute cannot be a new
            # hole. It is the same shape as the `Emit` dedup drop and the `Not`
            # node miss: the walk stopped and said nothing.
            #
            # Mirrors the attribute sweep at the top of this function, so a node
            # with attributes nobody thought to name here is still visited.
            for attribute in dir(value):
                if attribute.startswith("_") or attribute in ("pattern",
                                                              "left", "right"):
                    continue
                walk(getattr(value, attribute, None), depth + 1)
            return
        if isinstance(value, str):
            check(value)

    for attribute in dir(node):
        if attribute.startswith("_"):
            continue
        walk(getattr(node, attribute, None))


def _validate_expressions(node: Any) -> None:
    """Depth-check and shape-check every expression a node carries.

    AND SCREEN EVERY REGEX IN THE GRAPH, WHICH UNTIL NOW NOTHING DID.

    `redos.py` had exactly one caller -- `regex.compile_pattern` -- which is
    called from exactly one place: the evaluator. So the ReDoS check ran only
    when RuleForge executed a rule LOCALLY, and never when it AUTHORED or
    RENDERED one. That is the wrong side of the boundary: this tool's product is
    a rule someone deploys to a Wazuh agent or a Splunk indexer, and those
    engines run the pattern with no such guard. `jobs.author("wazuh",
    '<field name="cmd">([a-c]?x|[a-c]?y)+$</field>')` returned `ok=True` and
    wrote that pattern into deployable XML.

    Three rounds were spent making that analyzer good -- first-set overlap,
    separator detection, a real depth bound -- and all of it was on the local
    path. A control has to sit where the value is still known to be right AND
    where it is shipped, not only where it happens to be exercised.
    """
    _screen_regexes(node)
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

    elif name == "Package":
        # PACKAGE CONDITIONS ARE VALIDATED LIKE ANY OTHER PREDICATE. This branch
        # did not exist, so a `Package` whose parent or child held a half-built
        # expression produced a clean `no_match` with zero rows and no caveat --
        # the exact shape of the `dict(row)` silent-zero defect, reached through
        # a different door. `_require_predicate` also enforces
        # `MAX_EXPRESSION_DEPTH`, so a 400-deep chain inside a child used to
        # evaluate fine.
        for condition in node.parent:
            _require_predicate(condition, f"Package {node.id!r} parent")
        for index, child in enumerate(node.children):
            for condition in child:
                _require_predicate(condition,
                                   f"Package {node.id!r} child {index}")

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
