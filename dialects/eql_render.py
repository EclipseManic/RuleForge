"""Render a single-event graph back to EQL: `[ category where condition ]`.

Only the shape slice 1 lowers is renderable. Anything else -- an `Aggregate`,
an `Arrange`, a `Pattern`, a `Derive` -- is refused by name rather than
flattened into an event query, because a graph with an aggregation in it is not
a single event and rendering it as one would drop the aggregation the way
`eventstats` was once dropped into `stats`.
"""

from __future__ import annotations

from typing import Any

from dialects.eql import DIALECT
from engine.ir import (
    BoolOp,
    Comparison,
    FieldExpr,
    Literal,
    Not,
    RuleIR,
)
from engine.values import Refusal


def render(ir: RuleIR) -> str:
    """    A single event back to `[ category where condition ]`, or a `Pattern`
    back to `sequence`."""
    pattern = next((n for n in ir.nodes if type(n).__name__ == "Pattern"), None)

    if pattern is not None:
        return _render_pattern(pattern)
    read = next((n for n in ir.nodes if type(n).__name__ == "Read"), None)
    filt = next((n for n in ir.nodes if type(n).__name__ == "Filter"), None)

    if read is None or filt is None:
        raise Refusal("EQL_RENDER_NO_EVENT",
                      "this graph has no single event to render: EQL slice 1 "
                      "renders one `[ category where condition ]` and nothing "
                      "else.", DIALECT)
    for node in ir.nodes:
        kind = type(node).__name__
        if kind in ("Read", "Filter", "Emit"):
            continue
        raise Refusal(
            "EQL_RENDER_NODE_UNSUPPORTED",
            f"a {kind} cannot appear in a single-event EQL query. Rendering "
            f"it as `[ ... where ... ]` would drop the {kind.lower()} the way "
            f"a command name was once dropped.", DIALECT)
    category = getattr(getattr(read, "selector", None), "name", "any")
    return f"[{category} where {render_expr(filt.condition)}]"


def _render_pattern(pattern: Any) -> str:
    """A `Pattern` back to `sequence` text.

    Only the shapes the lowerer produces are renderable. Anything else
    is refused rather than flattened, for the same reason an `Aggregate` is.
    """
    if not getattr(pattern, "ordered", True):
        return _render_sample(pattern)
    lines = []
    if getattr(pattern, "key", ()):
        lines.append("sequence by " + ", ".join(
            ref.name if hasattr(ref, "name") else str(ref)
            for ref in pattern.key))
    else:
        lines.append("sequence")
    within = getattr(pattern, "within", None)
    seconds = getattr(within, "seconds", None) if within is not None else None
    if seconds is None:
        raise Refusal("EQL_RENDER_PATTERN_NO_WINDOW",
                      "this pattern has no window, and a `sequence` without "
                      "`maxspan` has no spelling here.", DIALECT)
    lines[0] += f" with maxspan={_format_span(seconds)}"
    # `runs` IS RENDERED BACK, and a repeat count is not cosmetic: emitting
    # `with maxspan=...` for a `runs=2` rule would produce a query that matches
    # ONE occurrence where the analyst wrote two. That is the same failure as
    # rendering `eval` as `rename`, and it is invisible to any test that only
    # compares the IR.
    runs = getattr(pattern, "runs", 1)
    if runs != 1:
        lines[0] += f" with runs={runs}"
    for index, stage in enumerate(pattern.stages):
        if len(stage) != 1:
            raise Refusal("EQL_RENDER_PATTERN_STAGE",
                          "a sequence stage holds one event condition here.",
                          DIALECT)
        # A NEGATIVE STAGE IS RENDERED BY THE `until` BRANCH BELOW, not here,
        # because the lowerer stores it once (as the veto it is) rather than
        # twice. Rendering it in both places emitted the step twice.
        if index in getattr(pattern, "negative_stages", ()):
            continue
        # The category was folded into the condition at lowering time as
        # `event.category == "<name>"`. Reading it back out is what makes the
        # round trip exact; rendering every step as `[any where ...]` would
        # silently widen each one.
        condition = stage[0]
        category = "any"
        if isinstance(condition, BoolOp) and condition.op == "and" \
                and len(condition.operands) == 2:
            first, rest = condition.operands
            name = _category_name(first)
            if name is not None:
                category, condition = name, rest
        lines.append(f"  [{category} where {render_expr(condition)}]")
    if getattr(pattern, "until", None) is not None:
        # A MISSING-EVENT STEP LOWERED ONTO `until` IS RENDERED AS THE STEP, not
        # as an `until` clause. The two are semantically the same here, but the
        # analyst wrote `![ ... ]` and round-tripping to a different construct
        # invites the reader to wonder whether something was lost. It is
        # distinguished by the `window` scope: a missing-event step ranges over
        # the whole window, which is exactly what `until` with no `between`
        # means.
        if getattr(pattern, "until_scope", "window") == "window" \
                and getattr(pattern, "negative_stages", ()):
            condition = pattern.until
            category = "any"
            if isinstance(condition, BoolOp) and condition.op == "and" \
                    and len(condition.operands) == 2:
                first, rest = condition.operands
                name = _category_name(first)
                if name is not None:
                    category, condition = name, rest
            lines.append(f"  ![{category} where {render_expr(condition)}]")
            return "\n".join(lines)
        condition = pattern.until
        category = "any"
        if isinstance(condition, BoolOp) and condition.op == "and" \
                and len(condition.operands) == 2:
            first, rest = condition.operands
            name = _category_name(first)
            if name is not None:
                category, condition = name, rest
        lines.append(f"  until [{category} where {render_expr(condition)}]")
    return "\n".join(lines)


def _category_name(expr: Any) -> str | None:
    """`event.category == "<name>"` back to `<name>`, else None.

    HONEST LIMITATION, STATED NOT HIDDEN: this matches ANY two-operand `and`
    whose first operand has that shape -- including a user-written
    `[any where event.category == "file" and a == 1]`, which renders as
    `[file where a == 1]`. That is semantically equivalent (no widening, no
    narrowing), but the round trip is not stable: rendering the output again
    gives the same text, yet the input's explicit `any` is gone. An earlier
    version of this docstring claimed a buried user filter "is not mistaken";
    it is, for exactly that shape, and claiming otherwise is how a cosmetic
    difference becomes a trust problem later.
    """
    if not isinstance(expr, Comparison) or expr.op != "=":
        return None
    left = expr.left
    if not isinstance(left, FieldExpr):
        return None
    ref = left.ref
    if getattr(ref, "name", None) != "event.category":
        return None
    right = expr.right
    value = right.value if isinstance(right, Literal) else right
    return value if isinstance(value, str) else None


def _render_sample(pattern: Any) -> str:
    """An unordered, windowless `Pattern` back to `sample by ...` text.

    Only the shape the lowerer produces is renderable: `ordered=False`,
    `within=None`, a non-empty `key`, and no `until`. Anything else is refused
    rather than flattened into a `sample`, because a windowed or ordered
    pattern is not a sample and rendering it as one would drop the window or
    the order.
    """
    if getattr(pattern, "within", None) is not None:
        raise Refusal("EQL_RENDER_SAMPLE_WITH_WINDOW",
                      "this unordered pattern has a window, which `sample` "
                      "does not take. Refused rather than dropped.", DIALECT)
    if getattr(pattern, "until", None) is not None:
        raise Refusal("EQL_RENDER_SAMPLE_WITH_UNTIL",
                      "this unordered pattern has an expiry, which `sample` "
                      "does not take. Refused rather than dropped.", DIALECT)
    key = getattr(pattern, "key", ())
    if not key:
        raise Refusal("EQL_RENDER_SAMPLE_NO_KEY",
                      "`sample` requires at least one `by` join key.",
                      DIALECT)
    lines = ["sample by " + ", ".join(
        ref.name if hasattr(ref, "name") else str(ref) for ref in key)]
    for stage in pattern.stages:
        if len(stage) != 1:
            raise Refusal("EQL_RENDER_PATTERN_STAGE",
                          "a sample filter holds one event condition here.",
                          DIALECT)
        condition = stage[0]
        category = "any"
        if isinstance(condition, BoolOp) and condition.op == "and" \
                and len(condition.operands) == 2:
            first, rest = condition.operands
            name = _category_name(first)
            if name is not None:
                category, condition = name, rest
        lines.append(f"  [{category} where {render_expr(condition)}]")
    return "\n".join(lines)


def _format_span(seconds: int) -> str:
    """Seconds back to the largest whole unit, so `3600` renders as `1h` and
    not as `3600s` -- which is valid but not what anyone writes."""
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def render_expr(expr: Any) -> str:
    """An IR condition back to EQL source."""
    if isinstance(expr, BoolOp):
        joiner = " or " if expr.op == "or" else " and "
        return "(" + joiner.join(render_expr(o) for o in expr.operands) + ")"
    if isinstance(expr, Not):
        return f"not {render_expr(expr.operand)}"
    if isinstance(expr, Comparison):
        op = "==" if expr.op == "=" else expr.op
        return f"{_field(expr.left)} {op} {_value(expr.right)}"
    if isinstance(expr, Literal):
        return _value(expr)
    raise Refusal("EQL_RENDER_EXPR_UNSUPPORTED",
                  f"a {type(expr).__name__} has no EQL spelling in the lowered "
                  f"subset.", DIALECT)


def _field(expr: Any) -> str:
    if isinstance(expr, FieldExpr):
        return expr.ref.name if hasattr(expr.ref, "name") else str(expr.ref)
    return str(expr)


def _value(expr: Any) -> str:
    value = expr.value if isinstance(expr, Literal) else expr
    if isinstance(value, bool):
        return "true"
    if isinstance(value, str):
        return f'"{value}"'
    return str(value)
