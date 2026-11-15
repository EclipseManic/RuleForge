"""Graph validation, and the ReDoS screen on the DEPLOY path.

WHY THE REGEX SCREEN IS HERE AND NOT ONLY IN THE EVALUATOR
-----------------------------------------------------------
The catastrophic-backtracking check in `evaluate.py` only runs when a rule is
EXECUTED locally. That is the wrong side of the boundary. The product is a rule
someone deploys to an agent or an indexer that has none of these guards, so a
pattern that RuleForge would refuse to run locally must also never be *authored*
or *rendered* by it.

Concretely: a Wazuh rule whose field regex is `([a-c]?x|[a-c]?y)+$` is perfectly
representable -- it renders to valid XML, the lowerer is happy, and the author
path reports success. It is also a pattern that will hang the Wazuh agent's
regex engine in production, which is the manager, not the search. So the screen
is called from `validate_graph`, which every author and render path goes through.

It is DIALECT-BLIND on purpose. The pattern is going to be executed by somebody
else's engine, and which dialect this tool thinks it is in does not change what
that engine will do with the bytes.
"""

from __future__ import annotations

from typing import Any, Final

from .evaluate import (
    REJECTED_DIALECTS,
    _catastrophic_reason,
    _screen_portable,
    split_inline_flags,
)
from .ir import (
    Aggregate,
    Arith,
    BoolOp,
    Call,
    Comparison,
    Correlation,
    Derive,
    Distinct,
    Emit,
    Expand,
    Expr,
    FieldRef,
    Filter,
    Join,
    ListExpr,
    Measure,
    Not,
    Node,
    Project,
    Read,
    Regex,
    Rule,
    Sequence,
    Sort,
    Span,
    SubQuery,
    Window,
)
from .values import Refusal

__all__ = [
    "validate",
    "MAX_STAGES",
    "MAX_EXPRESSION_DEPTH",
    "SCREENABLE_EXPR_TYPES",
    "CANNOT_HOLD_A_PATTERN",
]

MAX_STAGES = 500
MAX_EXPRESSION_DEPTH = 100

#: Expression types that can hold a pattern, EXHAUSTIVELY.
#:
#: A coverage test asserts this list still covers every container in
#: `ir.EXPR_TYPES`, so adding a new expression type to the model FAILS that test
#: on the day it is added rather than leaving a hole in the screen. An earlier
#: version of this screen missed `BoolOp` and then `Not`, and both times the whole
#: suite stayed green -- so the test is not "does it catch the two I know about"
#: but "is the list provably complete".
SCREENABLE_EXPR_TYPES: Final[tuple[type, ...]] = (
    Comparison, BoolOp, Not, Arith, Call, ListExpr, Regex, Span, SubQuery,
)

#: Types that structurally cannot carry a pattern, each with the reason written
#: down. A future change to one of these has to delete its exemption, which is the
#: point: the exemption is a claim, and a claim should be expensive.
CANNOT_HOLD_A_PATTERN: Final[dict[str, str]] = {
    "Read": "an index-time selector is evaluated by the store, not the regex engine",
    "Literal": "a literal holds a constant; a pattern is a Regex node, never a "
               "constant, because its dialect has to travel with it",
    "FieldRef": "a field reference holds a name and a path, never a value",
    "Project": "a projection holds field references, not values",
    "Sort": "a sort holds field references, not values",
    "Limit": "a limit holds an integer",
    "Distinct": "a distinct holds field references, not values",
    "Emit": "an output stage holds field references, not values",
    "Measure": "a measure holds a field reference, not a value",
    "Window": "a window holds durations, not patterns",
}


def validate(rule: Rule) -> None:
    """Validate a rule, or refuse with the reason.

    Called on EVERY author and render path, not just on execution. A limit that
    guards one entrance is not a limit.
    """
    stages = list(rule.pipeline) + [n for b in rule.bindings for n in b.pipeline]
    if len(stages) > MAX_STAGES:
        raise Refusal(
            "RULE_TOO_LARGE",
            f"this rule has {len(stages)} stages, over the {MAX_STAGES} this tool "
            f"works with. A rule that long is usually several rules.",
            "validate",
        )

    if not rule.pipeline:
        raise Refusal("RULE_EMPTY", "the rule has no stages", "validate")

    ids: set[str] = set()
    for node in stages:
        if node.id and node.id in ids:
            raise Refusal(
                "DUPLICATE_STAGE_ID",
                f"two stages are both called `{node.id}`. Stage names are how "
                f"joins and bindings refer to each other, so a duplicate makes "
                f"the reference ambiguous.",
                "validate",
            )
        ids.add(node.id)

    # A join side or correlation parent may name a BINDING or a STAGE. Both are
    # legal, so the set of legal references is both -- and a check that knows
    # only about stage ids refuses every KQL rule that joins a `let`, which is
    # the shape most enterprise correlation rules are written in.
    sources = set(ids) | {rule.rule_id} | {b.name for b in rule.bindings}

    if not any(isinstance(n, Emit) for n in rule.pipeline):
        raise Refusal(
            "RULE_HAS_NO_EMIT",
            "the rule does not say what it returns. Without an output stage, "
            "what the rule produces is implied rather than stated.",
            "validate",
        )

    for node in stages:
        _validate_node(node, sources)

    # The deploy-path screen. Every stage, not just the reachable ones: a stage
    # a rule does not currently use still renders into the artifact.
    for node in stages:
        _screen_node(node)


# ---------------------------------------------------------------------------
# Per-stage checks
# ---------------------------------------------------------------------------


def _validate_node(node: Node, known: set[str]) -> None:
    kind = type(node).__name__

    if isinstance(node, Filter):
        _require_predicate(node.condition, f"filter `{node.id}`")

    elif isinstance(node, Project):
        for source, target in node.renames:
            if not _is_identifier(target):
                raise Refusal(
                    "PROJECT_TARGET_NOT_IDENTIFIER",
                    f"`{target}` is not usable as a column name. A name with a "
                    f"space, a quote or a newline in it will not survive being "
                    f"written into the dialect's syntax.",
                    "validate",
                )
        for drop in node.drops:
            if not drop.full:
                raise Refusal(
                    "PROJECT_DROP_EMPTY", "a drop names no field", "validate"
                )

    elif isinstance(node, Derive):
        for target, expr in node.assignments:
            if not _is_identifier(target):
                raise Refusal(
                    "DERIVE_TARGET_NOT_IDENTIFIER",
                    f"`{target}` is not usable as a column name",
                    "validate",
                )
            _walk_expression(expr, 0)

    elif isinstance(node, Join):
        if node.left not in known:
            raise Refusal(
                "JOIN_SOURCE_UNKNOWN",
                f"`{node.id}` joins from `{node.left}`, which is not a stage in "
                f"this rule",
                "validate",
            )
        if node.right not in known:
            raise Refusal(
                "JOIN_SOURCE_UNKNOWN",
                f"`{node.id}` joins to `{node.right}`, which is not a stage in "
                f"this rule",
                "validate",
            )
        if node.left == node.right:
            raise Refusal(
                "JOIN_SELF",
                f"`{node.id}` joins `{node.left}` to itself. That is a real thing "
                f"analysts write, and it needs the two sides distinguished -- the "
                f"engine does that with a prefix, but say so here rather than "
                f"letting it happen silently.",
                "validate",
            )
        for left, right in node.on:
            if left.scope != "current" or right.scope not in ("current", "right"):
                raise Refusal(
                    "JOIN_KEY_SCOPE_INVALID",
                    f"a join key is read from the stage's own rows, so it cannot "
                    f"be `{left.scoped}`. Put the cross-row comparison in the "
                    f"join's predicate instead, where a scope means something.",
                    "validate",
                )
        if node.predicate is not None:
            _walk_expression(node.predicate, 0)
            if not _uses_both_scopes(node.predicate):
                raise Refusal(
                    "JOIN_PREDICATE_NOT_CROSS_ROW",
                    f"`{node.id}` has a predicate that never reads the other side "
                    f"of the join. Every key is already in the join's `on` list, "
                    f"so a predicate that only reads the current row is either "
                    f"redundant or was meant to compare the two sides.",
                    "validate",
                )

    elif isinstance(node, Aggregate):
        for measure in node.measures:
            if measure.field is not None:
                _walk_expression(measure.field, 0)
        for key in node.keys:
            _walk_expression(key, 0)

    elif isinstance(node, Correlation):
        if node.parent not in known:
            raise Refusal(
                "CORRELATION_PARENT_UNKNOWN",
                f"`{node.id}` counts occurrences of `{node.parent}`, which is "
                f"not a stage in this rule",
                "validate",
            )

    elif isinstance(node, Sort):
        for ref, _ in node.keys:
            _walk_expression(ref, 0)

    elif isinstance(node, Sequence):
        # The structural invariants -- at least two steps, a join key -- are
        # enforced by `ir.Sequence.__post_init__`. What is checked here is what
        # the IR cannot see on its own: that each step is a real predicate, and
        # that the patterns inside it would not hang the engine that runs it.
        for index, step in enumerate(node.steps, start=1):
            _require_predicate(
                step.condition, f"step {index} of sequence `{node.id}`"
            )
            _walk_expression(step.condition, 0)
        if node.until is not None:
            _require_predicate(
                node.until, f"the `until` of sequence `{node.id}`"
            )
            _walk_expression(node.until, 0)
        for ref in node.by:
            _walk_expression(ref, 0)
        if node.maxspan is not None and node.maxspan.seconds <= 0:
            raise Refusal(
                "SEQUENCE_MAXSPAN_NOT_POSITIVE",
                f"`{node.id}` bounds the sequence to "
                f"{node.maxspan.seconds} seconds, so no two events can ever "
                f"fall inside it and the rule can never fire.",
                "validate",
            )


def _require_predicate(expr: Expr, where: str) -> None:
    """A condition must be a condition.

    A bare field reference is refused: a non-empty string is truthy, so
    `| where field` "works" and matches almost everything, and the author sees a
    rule that runs.
    """
    if isinstance(expr, FieldRef):
        raise Refusal(
            "CONDITION_IS_A_FIELD",
            f"the condition on {where} is the field `{expr.scoped}` on its own. "
            f"A field is not a condition: any non-empty string is truthy, so "
            f"`{expr.scoped}` matches every row where the field is present and "
            f"is not empty. Say what you mean -- `{expr.full} == \"something\"`.",
            "validate",
        )
    _walk_expression(expr, 0)


def _walk_expression(expr: Any, depth: int) -> None:
    """Depth-checked walk over an expression tree.

    The depth stop REFUSES rather than returning. An earlier version had
    `if depth > 32: return`, which created an unguarded band: 29 nested parens
    were refused and 31 shipped, and the test written to check that the walk
    reached every node was blind to it because a depth cutoff is not a type.
    """
    if depth > MAX_EXPRESSION_DEPTH:
        raise Refusal(
            "EXPRESSION_TOO_DEEP",
            f"this condition nests more than {MAX_EXPRESSION_DEPTH} levels deep. "
            f"That is almost always a generator accident rather than something "
            f"an analyst wrote, and no vendor engine will read it either.",
            "validate",
        )
    if isinstance(expr, (BoolOp,)):
        for operand in expr.operands:
            _walk_expression(operand, depth + 1)
    elif isinstance(expr, Not):
        _walk_expression(expr.operand, depth + 1)
    elif isinstance(expr, (Comparison, Arith)):
        _walk_expression(expr.left, depth + 1)
        _walk_expression(expr.right, depth + 1)
    elif isinstance(expr, Span):
        _walk_expression(expr.value, depth + 1)
        _walk_expression(expr.low, depth + 1)
        _walk_expression(expr.high, depth + 1)
    elif isinstance(expr, ListExpr):
        for item in expr.items:
            _walk_expression(item, depth + 1)
    elif isinstance(expr, Call):
        for argument in expr.args:
            _walk_expression(argument, depth + 1)


def _uses_both_scopes(expr: Any) -> bool:
    scopes: set[str] = set()

    def visit(node: Any, depth: int) -> None:
        if depth > MAX_EXPRESSION_DEPTH:
            return
        if isinstance(node, FieldRef):
            scopes.add(node.scope)
        elif isinstance(node, BoolOp):
            for operand in node.operands:
                visit(operand, depth + 1)
        elif isinstance(node, Not):
            visit(node.operand, depth + 1)
        elif isinstance(node, (Comparison, Arith)):
            visit(node.left, depth + 1)
            visit(node.right, depth + 1)
        elif isinstance(node, Span):
            visit(node.value, depth + 1)
            visit(node.low, depth + 1)
            visit(node.high, depth + 1)
        elif isinstance(node, ListExpr):
            for item in node.items:
                visit(item, depth + 1)
        elif isinstance(node, Call):
            for argument in node.args:
                visit(argument, depth + 1)

    visit(expr, 0)
    return "left" in scopes and "right" in scopes


def _is_identifier(name: str) -> bool:
    if not name:
        return False
    if name[0].isdigit():
        return False
    return all(ch.isalnum() or ch in "_.$@-" for ch in name)


# ---------------------------------------------------------------------------
# The deploy-path regex screen
# ---------------------------------------------------------------------------


def _screen_node(node: Node) -> None:
    """Refuse a stage that holds a pattern which would hang a real engine.

    Deliberately reaches every attribute of the node, not just its expressions:
    a pattern can arrive wrapped in a `Literal` rather than a `Regex`, and a
    screen that only inspects the typed expression slots is defeated by wrapping.
    """
    for value in _everything_reachable(node):
        if isinstance(value, Regex):
            _screen_regex(value, node.id)


def _everything_reachable(node: Node):
    """Every attribute value on a node, recursively, including nested nodes.

    The `dir()` sweep is what makes this total. A container type added to the IR
    later is a blind spot on the day it is added unless something forces the
    author of that type to think about this walk -- and `validate` running on
    every author and render path is what forces them.
    """
    for attribute in dir(node):
        if attribute.startswith("__"):
            continue
        try:
            value = getattr(node, attribute)
        except Exception:  # pragma: no cover - a property that raises
            continue
        if callable(value):
            continue
        yield from _walk_value(value, 0)


def _walk_value(value: Any, depth: int):
    if depth > 12:
        return
    if isinstance(value, Regex):
        yield value
        return
    if isinstance(value, (str, int, float, bool, bytes)) or value is None:
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _walk_value(item, depth + 1)
        return
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk_value(item, depth + 1)
        return
    if hasattr(value, "__dataclass_fields__"):
        for attribute in dir(value):
            if attribute.startswith("__"):
                continue
            try:
                nested = getattr(value, attribute)
            except Exception:  # pragma: no cover
                continue
            if callable(nested):
                continue
            yield from _walk_value(nested, depth + 1)


def _screen_regex(pattern: Regex, where: str) -> None:
    dialect = pattern.dialect

    # The PORTABILITY screen only applies to a dialect this engine can execute.
    # A PCRE pattern in a Wazuh or AQL rule is legitimate and must render, so
    # refusing it for containing `\d` would refuse a real vendor rule on the
    # grounds that OUR subset does not cover it -- which is our limitation, not
    # the rule's.
    #
    # The CATASTROPHIC check below applies to EVERY dialect, because the vendor's
    # engine will hang on `(a|aa)+$` exactly as this one would.
    if dialect not in REJECTED_DIALECTS:
        try:
            # A leading `(?i)` is a FLAG, not a group extension. Lifted here
            # exactly as `compile_pattern` does, or this path refuses a pattern
            # the evaluator accepts -- so a rule would validate and not run, or
            # run and not validate.
            body, _nocase = split_inline_flags(pattern.pattern)
            _screen_portable(body)
        except Refusal as exc:
            raise Refusal(
                exc.code,
                f"{exc.message} This pattern is in stage `{where}`, and the "
                f"rule is about to be written out as deployable text, so it is "
                f"checked here rather than only when a rule is run locally.",
                exc.where,
            ) from exc

    reason = _catastrophic_reason(pattern.pattern)
    if reason:
        raise Refusal(
            "REGEX_CATASTROPHIC_BACKTRACKING",
            f"stage `{where}` holds a pattern that backtracks catastrophically: "
            f"{reason}. It would hang whatever engine runs it, which is usually "
            f"the indexer or the agent rather than the search. This is checked "
            f"before the rule is written out, because a rule that is deployed and "
            f"then hangs is worse than one that was never written.",
            "validate",
        )
