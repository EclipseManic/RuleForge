"""RuleIR -> Sentinel KQL.

THE ONE THING THAT MAKES THIS NON-TRIVIAL

The engine's `Join` stores merged columns prefixed -- `l_`, `r_` -- so a self-join
cannot have one side silently overwrite the other. KQL has ONE namespace, so the
analyst writes those columns bare. A renderer therefore has to turn `r_LoginTime`
back into `LoginTime`.

THE OBVIOUS WAY IS WRONG. Strip the prefix. Except `l_Process` is a legal KQL
field name: a rule about `l_Process` would render as a rule about `Process`, with
no warning, no diff anyone reads, and a different rule in production.

So the renderer inverts `Join.column_map`, which the lowering recorded at the only
moment the answer was knowable -- while it was doing the renaming. A name the join
did not rename is left exactly as it is, because then it is a genuine KQL field
name and not an artefact of the merge. That is the same discipline as deleting the
duplicate field resolver: one source of truth for what a name means, and no
string matching standing in for knowledge.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any

from ..engine.ir import (
    Aggregate,
    Arith,
    BoolOp,
    Call,
    Comparison,
    Derive,
    Duration,
    FieldExpr,
    FieldRef,
    Join,
    Literal,
    Not,
    Read,
    RuleIR,
)
from ..engine.values import Refusal
from .kql import DIALECT

#: An aggregate measure -> the KQL function that computes it.
_MEASURE_FUNCTION = {
    "count": "count",
    "distinct_count": "dcount",
    "set": "make_set",
    "min": "min",
    "max": "max",
    "sum": "sum",
    "avg": "avg",
    "first": "first",
    "last": "last",
}

#: A call -> KQL text. `is_not_null` and friends become the KQL predicate Kusto
#: spells the same way; only the names that genuinely differ are listed.
_CALL_TEXT = {
    "in_set": None,          # handled specially, it is a value list
    "is_not_null": "isnotnull",
    "is_null": "isnull",
    "coalesce": "coalesce",
    "lower": "tostring",
    "cidr_contains": "ipv4_is_in_range",
}

#: THESE ARE INFIX IN KQL, NOT FUNCTIONS. KQL writes
#: `TargetImage endswith "\\lsass.exe"`, not `endswith(TargetImage, ...)`. The
#: function-call form is not KQL, so a query built from it would not run.
_CALL_INFIX = {
    "contains": "contains",
    "starts_with": "startswith",
    "ends_with": "endswith",
    "has": "has",
}

_COMPARISON = {
    "=": "==", "!=": "!=", "<": "<", "<=": "<=", ">": ">", ">=": ">=",
}


class _Names:
    """Resolves stored (possibly prefixed) names back to the author's spelling.

    Built from the joins actually in the graph, so it is the inverse of the
    renaming that happened rather than a guess at it. Where a name could belong to
    either side and the join did not record it -- a genuinely ambiguous column --
    it is returned unchanged, because there is no correct bare name to produce.
    """

    def __init__(self, ir: RuleIR) -> None:
        self._stored_to_bare: dict[str, str] = {}
        for node in ir.nodes:
            if isinstance(node, Join):
                for original, stored in node.column_map:
                    self._stored_to_bare.setdefault(stored, original)

    def field(self, name: str) -> str:
        return self._stored_to_bare.get(name, name)

    def ref(self, ref: FieldRef) -> str:
        return self.field(ref.full)


def render(ir: RuleIR) -> str:
    """Render a RuleIR back to a KQL query."""
    names = _Names(ir)

    reads = [n for n in ir.nodes if isinstance(n, Read)]
    if not reads:
        raise Refusal("KQL_RENDER_NO_READ",
                      "a KQL query starts from a table, and this rule has no Read",
                      DIALECT)

    lines: list[str] = [f"{reads[0].selector.name}"]
    emitted_emit = False

    for node in ir.nodes:
        kind = type(node).__name__

        if kind == "Read":
            continue

        if kind == "Filter":
            if node.id == "selectors":
                # KQL has no leading `index=`. A selector is part of the table
                # name, so it is emitted as a `where` rather than invented as a
                # search-time term the dialect does not have.
                lines.append(f"| where {render_expr(node.condition, names)}")
            else:
                lines.append(f"| where {render_expr(node.condition, names)}")
            continue

        if kind == "Derive":
            parts = [f"{alias} = {render_expr(expr, names)}"
                     for alias, expr in node.assignments]
            operator = "project" if _is_projection(node) else "extend"
            lines.append(f"| {operator} " + ", ".join(parts))
            continue

        if kind == "Aggregate":
            lines.append("| " + _render_aggregate(node, names))
            continue

        if kind == "Arrange":
            ordering = ", ".join(f"{names.ref(ref)} {direction}"
                                 for ref, direction in node.order_by)
            if node.limit is not None:
                lines.append(f"| top {node.limit} by {ordering}")
            else:
                lines.append(f"| sort by {ordering}")
            continue

        if kind == "Join":
            lines.append("| " + _render_join(node, names))
            continue

        if kind == "Emit":
            emitted_emit = True
            continue

        raise Refusal(
            "KQL_RENDER_NODE_UNSUPPORTED",
            f"a {kind} has no KQL rendering. Emitting the rest and dropping this "
            f"would produce a query that looks complete and matches a different "
            f"set of events.", DIALECT)

    if not emitted_emit:
        raise Refusal("KQL_RENDER_NO_EMIT",
                      "the rule declares no output, so there is nothing to render",
                      DIALECT)
    return "\n".join(lines)


def _is_projection(node: Derive) -> bool:
    """`project` REPLACES the row; `extend` ADDS to it.

    THEY ARE NOT INTERCHANGEABLE. After a `project`, a field the rule did not
    project no longer exists, and a later stage reading it would match nothing.
    Rendering a `project` as `extend` would keep every column alive and quietly
    change the rule.

    The lowerer names nodes `{prefix}_{operator}_{index}` and the prefix may
    itself contain underscores, so the operator is the SECOND-TO-LAST
    underscore-separated token, not the last. An earlier version read the last
    token -- the index -- and therefore never detected a projection at all.
    """
    return node.projects


def _render_aggregate(node: Aggregate, names: _Names) -> str:
    measures: list[str] = []
    for measure in node.measures:
        function = _MEASURE_FUNCTION.get(measure.function)
        if function is None:
            raise Refusal(
                "KQL_MEASURE_NOT_RENDERABLE",
                f"measure {measure.name!r} is a {measure.function}, which KQL has "
                f"no function for. Naming it is better than rendering a different "
                f"statistic under the same name.", DIALECT)
        target = names.ref(measure.field) if measure.field is not None else "*"
        measures.append(f"{measure.name} = {function}({target})")

    keys = [names.ref(key) for key in node.keys if key.full != "__bucket__"]
    text = f"summarize {', '.join(measures)}"
    if keys:
        text += " by " + ", ".join(keys)
    return text


def _render_join(node: Join, names: _Names) -> str:
    if not node.on:
        raise Refusal("KQL_JOIN_NOT_RENDERABLE",
                      "a temporal or cross join has no KQL `join` rendering",
                      DIALECT)
    keys = ", ".join(names.ref(left) for left, _ in node.on)
    # The right-hand side is the NODE ID of the sub-pipeline. KQL joins a TABLE
    # and the sub-search is named by the `let` that produced it, so the id is
    # emitted verbatim rather than turned into a table name that does not exist.
    return f"join kind={node.how} ({keys}) on {keys} = {node.right}"


def render_expr(expr: Any, names: _Names) -> str:
    if isinstance(expr, BoolOp):
        joiner = " and " if expr.op == "and" else " or "
        return "(" + joiner.join(render_expr(o, names) for o in expr.operands) + ")"
    if isinstance(expr, Not):
        return f"not({render_expr(expr.operand, names)})"
    if isinstance(expr, Comparison):
        left = render_expr(expr.left, names)
        right = render_expr(expr.right, names)
        return f"{left} {_COMPARISON.get(expr.op, expr.op)} {right}"
    if isinstance(expr, FieldExpr):
        return names.ref(expr.ref)
    if isinstance(expr, Literal):
        return render_literal(expr.value)
    if isinstance(expr, Arith):
        return _render_arith(expr, names)
    if isinstance(expr, Call):
        return _render_call(expr, names)
    raise Refusal("KQL_EXPR_NOT_RENDERABLE",
                  f"a {type(expr).__name__} has no KQL rendering", DIALECT)


#: IR arithmetic operator -> KQL operator.
_ARITH = {"+": "+", "-": "-", "*": "*", "/": "/"}


def _render_arith(expr: Arith, names: _Names) -> str:
    """Arithmetic, and the one thing here that is a TIME SHIFT.

    The user's rule says `LoginTime between (LSASSTime .. LSASSTime + 10m)`. The
    lowerer turned `+ 10m` into `Arith('+', field, Duration(600))`, and KQL spells
    that `datetime + 10m` -- so the Duration has to come back out as a TIMESPAN
    literal. Rendering it as a bare number would be `LoginTime <= 600`, comparing
    a timestamp to a count, which is a different rule that still looks plausible.
    """
    if expr.op not in _ARITH:
        raise Refusal("KQL_ARITH_NOT_RENDERABLE",
                      f"`{expr.op}` has no KQL rendering", DIALECT)
    # `Arith` is N-ARY over `operands`, not a binary left/right pair. Reading
    # `.left` raised AttributeError on the user's very first rule.
    joiner = f" {_ARITH[expr.op]} "
    return "(" + joiner.join(render_expr(o, names) for o in expr.operands) + ")"


def _render_call(expr: Call, names: _Names) -> str:
    if expr.function == "in_set":
        subject = render_expr(expr.args[0], names)
        options = expr.args[1]
        values = getattr(options, "value", options)
        if not isinstance(values, (tuple, list)):
            raise Refusal("KQL_IN_NOT_A_LIST",
                          "an in_set's second argument is not a value list", DIALECT)
        rendered = ", ".join(render_literal(v) for v in values)
        return f"{subject} in ({rendered})"

    if expr.function == "matches_regex":
        subject = render_expr(expr.args[0], names)
        # KQL VERBATIM STRINGS DECODE `""` AS ONE `"`. Interpolating the pattern
        # raw meant a pattern carrying `a"" | take 0"` closed the literal early
        # and injected a stage into the DEPLOYED rule -- and `take 0` returns
        # nothing, so the rule silently matched zero events. This is the same
        # bug as the SPL one, fixed there and missed here.
        pattern = str(expr.args[1].value).replace('"', '""')
        # The DIALECT goes back in as KQL's own `kind` argument. It is not
        # dropped: a `pcre` pattern rendered without it would be read as KQL's
        # default RE2 and would silently change what it matches.
        kind = {"pcre": "regex", "posix_extended": "regex"}.get(
            expr.dialect or "", "regex")
        return f'{subject} matches regex @"{pattern}" kind="{kind}"'

    name = _CALL_TEXT.get(expr.function)
    if name is not None:
        return f"{name}({', '.join(render_expr(a, names) for a in expr.args)})"

    infix = _CALL_INFIX.get(expr.function)
    if infix is not None:
        if len(expr.args) != 2:
            raise Refusal("KQL_INFIX_ARITY",
                          f"`{expr.function}` takes 2 arguments, got "
                          f"{len(expr.args)}", DIALECT)
        subject = render_expr(expr.args[0], names)
        operand = render_expr(expr.args[1], names)
        # PARENTHESES AROUND THE SUBJECT. `a endswith "x" and b` parses the `and`
        # as part of the operand without them, which is a different rule.
        return f"({subject}) {infix} {operand}"

    raise Refusal("KQL_CALL_NOT_RENDERABLE",
                  f"`{expr.function}` has no KQL rendering", DIALECT)


def render_literal(value: Any) -> str:
    # A Duration is a SPAN, not a number. This is what turns the lowered
    # `LSASSTime + 600` back into KQL's `LSASSTime + 10m`. Emitting `600` would
    # compare a timestamp against a count and produce a rule that is wrong in a
    # way nobody notices until it stops matching.
    if isinstance(value, Duration):
        return _timespan(value.seconds)
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return str(value)
    # DECIMAL IS NEITHER int NOR float. `isinstance(Decimal("1"), (int, float))`
    # is False, so every count threshold fell through to the string branch and
    # rendered as `>= "1"` -- a comparison of a number against a string. The
    # engine uses Decimal throughout precisely to avoid float error, so the
    # renderer has to know that.
    if isinstance(value, Decimal):
        return format(value.normalize(), "f")
    if isinstance(value, (tuple, list)):
        return "[" + ", ".join(render_literal(v) for v in value) + "]"
    # BACKSLASH BEFORE QUOTE. KQL regular strings treat `\` as an escape, so a
    # trailing backslash escaped the closing quote and the REST OF THE STAGE
    # became live KQL: `"a\" | take 0"` rendered a rule that returned zero rows
    # in production, with no error anywhere. It also broke every trailing
    # backslash Windows path. The SPL renderer had this fixed; KQL was missed.
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def _timespan(seconds: Any) -> str:
    """Kusto's timespan literal, choosing the largest unit that divides evenly."""
    total = Decimal(str(seconds))
    for suffix, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if total >= size and (total % size) == 0:
            return f"{int(total / size)}{suffix}"
    return f"{int(total)}s"
