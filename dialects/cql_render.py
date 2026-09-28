"""Render a filter graph back to CQL: `filter` plus `| table`.

Only the shape slice 1 lowers is renderable. Anything else is refused by name
rather than flattened, for the same reason an `Aggregate` is refused by every
other renderer in this project.
"""

from __future__ import annotations

from typing import Any

from dialects.cql import DIALECT
from engine.ir import BoolOp, Comparison, FieldExpr, Literal, Not, RuleIR
from engine.values import Refusal


def render(ir: RuleIR) -> str:
    """A `Filter` (+ `fields` Derive) back to CQL source."""
    filt = next((n for n in ir.nodes if type(n).__name__ == "Filter"), None)
    if filt is None:
        raise Refusal("CQL_RENDER_NO_FILTER",
                      "this graph has no filter to render: CQL slice 1 "
                      "renders one filter plus `| table`, nothing else.",
                      DIALECT)
    out = [render_expr(filt.condition)]
    for node in ir.nodes:
        kind = type(node).__name__
        if kind in ("Read", "Filter", "Emit"):
            continue
        if kind == "Derive" and getattr(node, "kind", "") == "fields":
            out.append("| table " + ", ".join(
                alias for alias, _ in node.assignments))
            continue
        raise Refusal(
            "CQL_RENDER_NODE_UNSUPPORTED",
            f"a {kind} cannot appear in this CQL slice. Rendering it as a "
            f"filter would drop the {kind.lower()}.", DIALECT)
    return " ".join(out)


def render_expr(expr: Any, nested: bool = False) -> str:
    """An IR condition back to CQL source. `AND`/`OR` uppercase, parens mark
    nesting -- same rule as the FQL renderer, for the same reason: tracking
    "which needs it" is how a renderer starts being clever."""
    if isinstance(expr, BoolOp):
        joiner = " OR " if expr.op == "or" else " AND "
        inner = joiner.join(render_expr(o, nested=True)
                            for o in expr.operands)
        return f"({inner})" if nested else inner
    if isinstance(expr, Not):
        inner = expr.operand
        if isinstance(inner, Comparison) and inner.op == "=":
            return f"{_field(inner.left)} != {_value(inner.right)}"
        raise Refusal("CQL_RENDER_NOT_COMPOUND",
                      "only `Not` around an equality has a CQL spelling "
                      "here. Refused rather than misrendered.", DIALECT)
    if isinstance(expr, Comparison):
        return f"{_field(expr.left)} {expr.op} {_value(expr.right)}"
    raise Refusal("CQL_RENDER_EXPR_UNSUPPORTED",
                  f"a {type(expr).__name__} has no CQL spelling in the "
                  f"lowered subset.", DIALECT)


def _field(expr: Any) -> str:
    if isinstance(expr, FieldExpr):
        ref = expr.ref
        return getattr(ref, "name", str(ref))
    return str(expr)


def _value(expr: Any) -> str:
    value = expr.value if isinstance(expr, Literal) else expr
    if isinstance(value, bool):
        return "true"
    if value is None:
        return "null"
    if isinstance(value, str):
        # Bare when safe, quoted when needed. A single token without spaces or
        # quotes means the same quoted or bare in CQL, so `"admin"` and `admin`
        # both render bare -- while a value with a space must stay quoted, or
        # it becomes two things. The IR does not record which form arrived, and
        # it does not need to, because the normalisation is meaning-preserving.
        if value and " " not in value and '"' not in value and "'" not in value:
            return value
        return f'"{value}"'
    return str(value)

