"""RuleIR -> Splunk SPL.

THE TRAP HERE IS THE INDEX/SOURCETYPE SELECTOR.

In SPL, `index=windows sourcetype=WinEventLog:Security` at the head of the
search is a SELECTOR: it chooses which data to search, before any filtering. The
lowerer turns it into a `Filter` over the events, because the IR has no separate
concept of a source selection.

Rendering that as a leading `| where index == "windows"` would be a filter, not a
selector, and the difference is real: a selector restricts what is SEARCHED, so
the query planner can use the index; a filter scans and then discards. The
rendered query would still return the same rows and cost far more, which is the
kind of regression nobody notices until the query times out.

So the renderer puts the selector back at the head, where SPL wants it, and only
when the filter is exactly the selector shape. A filter that also tests something
else is emitted as a `where`, because a selector cannot express that.
"""
from __future__ import annotations

import re
from decimal import Decimal
from typing import Any

from ..engine.ir import (
    Aggregate,
    Arith,
    BoolOp,
    Call,
    Comparison,
    FieldExpr,
    Join,
    Literal,
    Not,
    Read,
    RuleIR,
)
from ..engine.values import Refusal
from .spl import DIALECT

#: IR measure function -> the SPL function that computes it. `dc` is what a Splunk
#: analyst writes, so that is what comes back out.
_MEASURE = {
    "count": "count",
    "distinct_count": "dc",
    "set": "values",
    "avg": "avg",
    "min": "min",
    "max": "max",
    "sum": "sum",
    "first": "first",
    "last": "last",
}

#: SPL's spelling for the comparison operators.
_COMPARISON = {"=": "=", "!=": "!=", "<": "<", "<=": "<=", ">": ">", ">=": ">="}

#: The fields that are a SOURCE SELECTION rather than a filter. A `Filter` over
#: only these, and only with equality, IS a selector and belongs at the head.
_SELECTOR_FIELDS = frozenset({"index", "sourcetype", "host", "source"})


def render(ir: RuleIR) -> str:
    """Render a RuleIR back to an SPL search."""
    reads = [n for n in ir.nodes if isinstance(n, Read)]
    if not reads:
        raise Refusal("SPL_RENDER_NO_READ",
                      "an SPL search starts from data, and this rule has no Read",
                      DIALECT)

    by_id = {n.id: n for n in ir.nodes if hasattr(n, "id")}
    head: list[str] = []
    stages: list[str] = []
    selector_emitted = False

    for node in ir.nodes:
        kind = type(node).__name__

        if kind == "Read":
            selector = node.selector.name
            if selector not in ("events", ""):
                head.append(selector)
            continue

        if kind == "Emit":
            continue

        if kind == "Filter":
            # SPLIT THE HEAD FILTER. The lowerer now puts EVERY head term in one
            # Filter, because reading only the selectors silently dropped the
            # rest -- `index=windows EventCode=4625` lost its EventCode filter and
            # reported ok:true. But a selector and a filter are not the same
            # thing: a selector restricts what is SEARCHED so the planner can use
            # the index, and a filter scans and discards. So selector terms go to
            # the head and everything else stays a `search`, and both survive.
            # ONLY THE FIRST FILTER'S SELECTORS CAN BE HOISTED. A head selector
            # is a search-time restriction; the same shape appearing later in
            # the pipeline is a filter at that point, and hoisting it would move
            # a filter to search time -- or, with two `index=` terms, produce a
            # search nothing satisfies.
            #
            # AND WHEN THE LATCH IS ALREADY SET, THE WHOLE CONDITION MUST BE
            # EMITTED AS A `search`. It used to be neither hoisted nor emitted,
            # so `index=main | search sourcetype=WinEventLog:Security` rendered
            # as `index=main ` -- the sourcetype gone, the search silently
            # widened to every event in the index, and ok:true. That is the exact
            # "silently dropped term" defect this function exists to prevent,
            # reintroduced one branch below where it had just been fixed.
            if not selector_emitted:
                selector_terms, rest = _split_selector(node.condition)
                if selector_terms:
                    head.extend(selector_terms)
                    selector_emitted = True
                    if rest is not None:
                        stages.append(f"| search {render_expr(rest)}")
                    continue
            stages.append(f"| search {render_expr(node.condition)}")
            continue

        if kind == "Aggregate":
            stages.append("| " + _render_aggregate(node))
            continue

        if kind == "Derive":
            parts = [f"{alias}={render_expr(expr)}"
                     for alias, expr in node.assignments]
            stages.append("| eval " + ", ".join(parts))
            continue

        if kind == "Join":
            stages.append("| " + _render_join(node, by_id))
            continue

        if kind == "Arrange":
            if node.limit is not None:
                ordering = next(iter(node.order_by), None)
                if ordering is None:
                    raise Refusal("SPL_RENDER_HEAD_WITH_NO_ORDER",
                                  "`head` needs a field to order by", DIALECT)
                stages.append(f"| head {node.limit} {ordering[0].full}")
            else:
                pairs = ", ".join(f"{ref.full} {direction}"
                                  for ref, direction in node.order_by)
                stages.append(f"| sort {pairs}")
            continue

        raise Refusal(
            "SPL_RENDER_NODE_UNSUPPORTED",
            f"a {kind} has no SPL rendering. Emitting the rest and dropping this "
            f"would produce a search that looks complete and matches a different "
            f"set of events.", DIALECT)

    return (" ".join(head) + " " if head else "") + " ".join(stages)


#: A selector value safe to emit bare. Anything with whitespace, a quote, a pipe
#: or a brace changes the meaning of the search if it is not quoted. Matched with
#: `fullmatch`, because `re.match` with a trailing `$` accepts a value ENDING in a
#: newline -- and a newline in a selector value is exactly the injection this
#: guard exists to stop.
_BARE_SAFE = re.compile(r"[A-Za-z0-9_.:@\-*]+")


def _selector_value(value: Any) -> str:
    text = str(value)
    if text and _BARE_SAFE.fullmatch(text):
        return text
    return render_literal(value)


def _split_selector(condition: Any) -> tuple[list[str], Any]:
    """Split a head filter into (selector terms, everything else).

    A term is a SELECTOR only if it is an un-negated equality on a known selector
    field with a literal value. `index=main EventCode=4628` is therefore half
    selector and half filter: `index=main` restricts what is searched, and
    `EventCode=4628` does not. Emitting both at the head would be wrong, and
    dropping the second would lose the analyst's filter -- which is what used to
    happen.

    Returns `(terms, rest)` where `rest` is `None` when every term was a selector.
    """
    terms = _flatten_and(condition)
    if not terms:
        return [], None

    selectors: list[str] = []
    others: list[Any] = []

    for term in terms:
        if (isinstance(term, Comparison) and term.op == "="
                and isinstance(term.left, FieldExpr)
                and term.left.ref.full in _SELECTOR_FIELDS
                and isinstance(term.right, Literal)):
            # THE VALUE IS QUOTED ONLY WHEN IT MUST BE. Always quoting is safe
            # but rewrites the analyst's bytes for no reason, and the diff against
            # the search they pasted stops matching. Always NOT quoting is the
            # injection: a value of `a | stats count by host` becomes an extra
            # pipeline stage. So a simple token is left bare and anything with a
            # space, quote, pipe or brace is quoted.
            selectors.append(
                f"{term.left.ref.full}="
                f"{_selector_value(term.right.value)}")
        else:
            others.append(term)

    if not selectors:
        return [], condition
    if not others:
        return selectors, None
    rest = (others[0] if len(others) == 1
            else BoolOp("and", tuple(others)))
    return selectors, rest


def _as_selector(condition: Any) -> list[str] | None:
    """The head-of-search terms this filter represents, or None.

    Kept as a whole-or-nothing helper for callers that need to know whether the
    ENTIRE filter is a selector. `_split_selector` is what the renderer uses.
    """
    selectors, rest = _split_selector(condition)
    if rest is not None:
        return None
    return selectors or None


def _flatten_and(expression: Any) -> list[Any]:
    if isinstance(expression, BoolOp) and expression.op == "and":
        out: list[Any] = []
        for operand in expression.operands:
            out.extend(_flatten_and(operand))
        return out
    return [expression]


def _render_aggregate(node: Aggregate) -> str:
    measures: list[str] = []
    for measure in node.measures:
        function = _MEASURE.get(measure.function)
        if function is None:
            raise Refusal(
                "SPL_MEASURE_NOT_RENDERABLE",
                f"measure {measure.name!r} is a {measure.function}, which SPL has "
                f"no function for. Naming it beats rendering a different "
                f"statistic under the same name.", DIALECT)
        if measure.field is None:
            measures.append(f"{function} AS {measure.name}")
        else:
            measures.append(
                f"{function}({measure.field.full}) AS {measure.name}")

    keys = [key.full for key in node.keys if key.full != "__bucket__"]
    text = f"stats {', '.join(measures)}"
    if keys:
        text += " by " + ", ".join(keys)
    return text


def _render_join(node: Join, by_id: dict[str, Any]) -> str:
    """`join type=inner maxout=...` with a sub-search on the right.

    The right side is a whole sub-pipeline, not a table name. SPL writes it as a
    parenthesised search, so the sub-graph is rendered and nested rather than
    referenced by node id -- a node id is not a table and would not resolve.
    """
    left_keys = ", ".join(left.full for left, _ in node.on)
    if not left_keys:
        raise Refusal("SPL_JOIN_NOT_RENDERABLE",
                      "a temporal or cross join has no SPL `join` rendering",
                      DIALECT)

    sub_nodes = _chain_from(node.right, by_id)
    if not sub_nodes:
        raise Refusal("SPL_JOIN_RIGHT_MISSING",
                      f"the join's right side points at {node.right!r}, which is "
                      f"not in this rule", DIALECT)
    sub = _render_subpipeline(sub_nodes, by_id)
    kind = "inner" if node.how == "inner" else "left"
    return f"join type={kind} {left_keys} {sub}"


def _chain_from(node_id: str, by_id: dict[str, Any]) -> list[Any]:
    """The nodes feeding `node_id`, in order, back to a Read."""
    chain: list[Any] = []
    cursor: str | None = node_id
    seen: set[str] = set()
    while cursor and cursor in by_id and cursor not in seen:
        seen.add(cursor)
        node = by_id[cursor]
        chain.append(node)
        if isinstance(node, Read):
            break
        cursor = getattr(node, "input", None)
    chain.reverse()
    return chain


def _render_subpipeline(nodes: list[Any], by_id: dict[str, Any]) -> str:
    body: list[str] = []
    for node in nodes:
        kind = type(node).__name__
        if kind == "Read":
            continue
        if kind == "Filter":
            body.append(f"search {render_expr(node.condition)}")
        elif kind == "Aggregate":
            body.append(_render_aggregate(node))
        elif kind == "Derive":
            body.append("eval " + ", ".join(
                f"{alias}={render_expr(expr)}" for alias, expr in node.assignments))
        elif kind == "Emit":
            continue
        else:
            raise Refusal("SPL_RENDER_SUBSEARCH_NODE_UNSUPPORTED",
                          f"a {kind} cannot appear inside a join sub-search",
                          DIALECT)
    return "[ " + " | ".join(body) + " ]"


def render_expr(expr: Any) -> str:
    if isinstance(expr, BoolOp):
        joiner = " AND " if expr.op == "and" else " OR "
        return "(" + joiner.join(render_expr(o) for o in expr.operands) + ")"
    if isinstance(expr, Not):
        return f"NOT {render_expr(expr.operand)}"
    if isinstance(expr, Comparison):
        left = render_expr(expr.left)
        right = render_expr(expr.right)
        return f"{left}{_COMPARISON.get(expr.op, expr.op)}{right}"
    if isinstance(expr, FieldExpr):
        return expr.ref.full
    if isinstance(expr, Literal):
        return render_literal(expr.value)
    if isinstance(expr, Arith):
        return "(" + " ".join(
            f"{expr.op} {render_expr(o)}" for o in expr.operands) + ")"
    if isinstance(expr, Call):
        return _render_call(expr)
    raise Refusal("SPL_EXPR_NOT_RENDERABLE",
                  f"a {type(expr).__name__} has no SPL rendering", DIALECT)


def _render_call(expr: Call) -> str:
    if expr.function == "in_set":
        subject = render_expr(expr.args[0])
        values = getattr(expr.args[1], "value", expr.args[1])
        rendered = ", ".join(render_literal(v) for v in values)
        return f"{subject} IN ({rendered})"
    if expr.function == "is_not_null":
        return f"isnotnull({render_expr(expr.args[0])})"
    if expr.function == "is_null":
        return f"isnull({render_expr(expr.args[0])})"
    if expr.function == "contains":
        return (f"like({render_expr(expr.args[0])}, "
                f"%{render_expr(expr.args[1])}%)")
    if expr.function == "starts_with":
        return f"like({render_expr(expr.args[0])}, {render_expr(expr.args[1])}%)"
    if expr.function == "ends_with":
        return f"like({render_expr(expr.args[0])}, %{render_expr(expr.args[1])})"
    if expr.function == "matches_regex":
        # THROUGH `render_literal`, NOT AN F-SRING. The pattern was interpolated
        # raw, so a pattern of `x" | stats count by host; #` emitted
        # `match(cmd, "x" | stats count by host; #")` and injected two extra
        # pipeline stages into the search the analyst pastes into Splunk.
        return (f"match({render_expr(expr.args[0])}, "
                f"{render_literal(expr.args[1].value)})")
    if expr.function == "coalesce":
        return "coalesce(" + ", ".join(
            render_expr(a) for a in expr.args) + ")"
    raise Refusal("SPL_CALL_NOT_RENDERABLE",
                  f"`{expr.function}` has no SPL rendering", DIALECT)


def render_literal(value: Any) -> str:
    from ..engine.ir import Duration

    if isinstance(value, Duration):
        return _timespan(value.seconds)
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    # DECIMAL IS NEITHER int NOR float, so `isinstance(Decimal("1"), (int, float))`
    # is False and every count threshold would render as `>="1"` -- a number
    # compared against a string.
    if isinstance(value, Decimal):
        return format(value.normalize(), "f")
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (tuple, list)):
        return "(" + ", ".join(render_literal(v) for v in value) + ")"
    # BACKSLASH BEFORE QUOTE. Escaping only `"` meant a value ending in `\` came
    # out as `"a\"` -- the quote escaped, so the literal never closed and the rest
    # of the stage was swallowed into the string. Windows paths and regexes are
    # full of backslashes, so this was not an edge case.
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def _timespan(seconds: Any) -> str:
    total = Decimal(str(seconds))
    for suffix, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if total >= size and (total % size) == 0:
            return f"{int(total / size)}{suffix}"
    return f"{int(total)}s"
