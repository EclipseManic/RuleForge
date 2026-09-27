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
    """`Read` -> `Filter` -> `Emit` back to `[ category where condition ]`."""
    {node.id: node for node in ir.nodes}
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
