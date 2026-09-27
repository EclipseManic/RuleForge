"""Render a single-filter graph back to FQL: `property:[operator]value`.

Only the shape slice 1 lowers is renderable. Anything else is refused by name
rather than flattened, for the same reason an `Aggregate` is refused by the EQL
renderer: a graph with structure in it is not a flat filter, and rendering it
as one would drop the structure.
"""

from __future__ import annotations

from typing import Any

from dialects.fql import DIALECT
from engine.ir import BoolOp, Comparison, FieldExpr, Literal, Not, RuleIR
from engine.values import Refusal


def render(ir: RuleIR) -> str:
    """One `Filter` back to `property:[operator]value` joined by `+`/`,`."""
    filt = next((n for n in ir.nodes if type(n).__name__ == "Filter"), None)
    if filt is None:
        raise Refusal("FQL_RENDER_NO_FILTER",
                      "this graph has no filter to render: FQL slice 1 "
                      "renders one flat filter and nothing else.", DIALECT)
    for node in ir.nodes:
        kind = type(node).__name__
        if kind in ("Read", "Filter", "Emit"):
            continue
        raise Refusal(
            "FQL_RENDER_NODE_UNSUPPORTED",
            f"a {kind} cannot appear in a flat FQL filter. Rendering it as "
            f"`property:value` would drop the {kind.lower()}.", DIALECT)
    return render_expr(filt.condition)


def render_expr(expr: Any, nested: bool = False) -> str:
    """An IR condition back to FQL source. `+` is AND, `,` is OR.

    Parens mark NESTING, not count: a nested `BoolOp` is always parenthesised,
    the top level never is. Same-operator chains are associative so they need
    nothing, and a tighter operator inside a looser one needs nothing either --
    but tracking "which" is how a renderer starts being clever, and clever is
    how `a OR (b AND c)` once became `((a OR b) AND c)` in another dialect.
    Always parenthesising the nested node is dumber and cannot be wrong.
    """
    if isinstance(expr, BoolOp):
        joiner = "," if expr.op == "or" else "+"
        inner = joiner.join(render_expr(o, nested=True)
                            for o in expr.operands)
        return f"({inner})" if nested else inner
    if isinstance(expr, Not):
        inner = expr.operand
        # `!` negates the operator inside a term (`prop:!value`), but ONLY for
        # equality: `prop:!>5` is not valid FQL. A `Not` around anything else --
        # a ranged comparison, a compound -- has no spelling here and is refused
        # rather than rendered as something that means less.
        if isinstance(inner, Comparison) and inner.op == "=":
            return f"{_field(inner.left)}:!{_value(inner.right)}"
        raise Refusal("FQL_RENDER_NOT_COMPOUND",
                      "only `Not` around an equality has an FQL spelling "
                      "(`prop:!value`). Refused rather than misrendered.",
                      DIALECT)
    if isinstance(expr, Comparison):
        op = "" if expr.op == "=" else expr.op
        return f"{_field(expr.left)}:{op}{_value(expr.right)}"
    raise Refusal("FQL_RENDER_EXPR_UNSUPPORTED",
                  f"a {type(expr).__name__} has no FQL spelling in the "
                  f"lowered subset.", DIALECT)


def _field(expr: Any) -> str:
    if isinstance(expr, FieldExpr):
        ref = expr.ref
        return getattr(ref, "name", str(ref))
    return str(expr)


def _value(expr: Any) -> str:
    value = expr.value if isinstance(expr, Literal) else expr
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return f"'{value}'"
    return str(value)
