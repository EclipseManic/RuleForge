"""Render a filter graph back to CQL: a filter plus its pipe stages.

Renders exactly the shapes the CQL slice lowers -- `| table`, `| sort`,
`| rename`, `| name :=` -- in the order the IR carries them, which is the order
the analyst wrote. Anything else is refused by name rather than flattened, for
the same reason an `Aggregate` is refused by every other renderer in this
project.
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
        # NAMED FOR WHAT THIS RENDERS, not for the slice it was written in.
        # This string ships to an analyst, so "slice 1 renders one filter plus
        # `| table`" became a lie the day sort, rename, and `:=` landed -- and a
        # misleading refusal is worse than no refusal, because it sends someone
        # looking for a limitation that has moved.
        raise Refusal("CQL_RENDER_NO_FILTER",
                      "this graph has no filter to render. CQL renders a filter "
                      "plus `| table`, `| sort`, `| rename`, and `| :=` stages; "
                      "a graph with no filter in it is a different shape.",
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
        if kind == "Arrange":
            # `| sort(field[, limit=N])`, ascending -- the only form this
            # parser accepts, so the direction is data, not a default. A
            # descending order here would render as ascending and invert the
            # rule; since the lowerer cannot produce one, reaching this branch
            # with anything but "asc" is refused rather than rendered wrong.
            pairs = node.order_by
            if len(pairs) != 1 or pairs[0][1] != "asc":
                raise Refusal(
                    "CQL_RENDER_SORT_NOT_ASCENDING",
                    "this sort is not a plain ascending single field, which "
                    "is all this CQL slice lowers. Refused rather than "
                    "rendered as ascending.", DIALECT)
            ref = pairs[0][0]
            name = ref.full if hasattr(ref, "full") else str(ref)
            if node.limit is not None:
                out.append(f"| sort({name}, limit={node.limit})")
            else:
                out.append(f"| sort({name})")
            continue
        if kind == "Derive" and getattr(node, "kind", "") == "rename":
            # `| rename old as new`, in that order -- the main SPL loop and the
            # subpipeline disagreed about this once, in opposite directions, so
            # the order is asserted by test rather than left to memory.
            if len(node.assignments) != 1:
                raise Refusal(
                    "CQL_RENDER_RENAME_NOT_A_PAIR",
                    "a rename here holds one pair; anything else is refused "
                    "rather than flattened.", DIALECT)
            alias, expr = node.assignments[0]
            old = expr.ref.full if hasattr(expr, "ref") \
                and hasattr(expr.ref, "full") else str(expr)
            out.append(f"| rename {old} as {alias}")
            continue
        if kind == "Derive" and getattr(node, "kind", "") == "eval":
            # `| name := operand`. Only single-operand assigns lower, so a
            # multi-assignment or computed value here came from somewhere else
            # and is refused rather than rendered as a bare `:=` that would
            # compute something different.
            if len(node.assignments) != 1:
                raise Refusal(
                    "CQL_RENDER_ASSIGN_NOT_SINGLE",
                    "an eval here holds one assignment; anything else is "
                    "refused rather than flattened.", DIALECT)
            alias, expr = node.assignments[0]
            # Strings stay QUOTED on the right of `:=`, even single-token
            # ones. Elsewhere a bare token and a quoted string mean the same
            # (`a = lit` compares against the string "lit"), but here they
            # differ completely: `x := lit` copies FIELD lit, while
            # `x := "lit"` assigns the CONSTANT. Rendering the constant bare
            # would turn a fixed value into a field read -- a different rule
            # that fails open on rows where the field is absent.
            if isinstance(expr, Literal) and isinstance(expr.value, str):
                rhs = f'"{expr.value}"'
            else:
                rhs = render_expr(expr)
            out.append(f"| {alias} := {rhs}")
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
    if isinstance(expr, FieldExpr):
        return _field(expr)
    if isinstance(expr, Literal):
        return _value(expr)
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

