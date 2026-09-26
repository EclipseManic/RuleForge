"""Expression evaluation for the semantic execution kernel, with three-valued logic.

Phase 3A. Ships DARK.

THREE-VALUED LOGIC
------------------
Comparisons return TRUE, FALSE or UNKNOWN. UNKNOWN is `None`, never False. The Kleene tables:

    AND   T&T=T  T&F=F  T&U=U  F&U=F  U&U=U
    OR    T|T=T  T|F=T  T|U=T  F|U=U  U|U=U
    NOT   T->F  F->T  U->U

`False AND Unknown` is False because one decisive falsifier settles a conjunction;
`True AND Unknown` is Unknown because the unknown still has to be checked.

A `Filter` keeps a row only on TRUE. FALSE drops it, and UNKNOWN ALSO drops it. That is a
deliberate, argued position, not a shrug:

  We are not claiming "this row does not match". We are claiming "no row in this output is a
  row we have not affirmatively shown matches" - the only claim an analyst can safely tune
  against. A row with no `event.category` is genuinely not-true for `event.category = 'auth'`.
  Nothing is invented: the field NAME was authored and resolved, only the VALUE is missing.

It is not a silent guess because UNKNOWN and FALSE are counted SEPARATELY
(`rows_predicate_unknown` vs `rows_predicate_false`), so an engineer can always see that N rows
were dropped for absence of evidence rather than evidence of absence.

The alternative was rejected: making an undecidable comparison poison the whole graph means a
field present on 60% of rows - the norm in real SIEM data - turns every rule into
`not_evaluated`, and a UI that always says `not_evaluated` trains analysts to ignore it.

THE LINE, STATED ONCE
---------------------
Construct-level unverifiability => refuse the whole graph. Data-level undecidability =>
UNKNOWN per row, counted. Every refusal in kernel/eval_errors.py is construct-level; every
UNKNOWN raised here is data-level.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from typing import Any

from kernel.eval_errors import EvaluationRefusal
from kernel.eval_types import ABSENT, MAX_EXPRESSION_DEPTH, UNKNOWN, Row, canonical
from models.rule_ir import (FUNCTION_CONTRACTS, Arith, BoolOp, Call, Comparison, EventExpr,
                            FieldExpr, InList, Literal, MeasureExpr, TimeExpr)

#: Ops whose truth value is meaningful. `not` is unary, the rest are n-ary.
_BOOL_OPS = frozenset({"and", "or", "not"})
_COMPARISON_OPS = frozenset({"=", "!=", "<", "<=", ">", ">="})


@dataclass
class EvalContext:
    """Mutable counters shared by one evaluation. Counters are the honesty mechanism."""
    counts: Any
    unmodelled: list[str]
    depth: int = 0

    def unknown(self, bucket: str) -> None:
        """Record an UNKNOWN. An uncounted UNKNOWN is a silent guess."""
        self.counts.arithmetic_unknown += 0  # keep attribute access explicit
        setattr(self.counts, bucket, getattr(self.counts, bucket) + 1)

    def caveat(self, code: str, node: str | None = None) -> None:
        self.unmodelled.append(f"{code}{f' at {node}' if node else ''}")


def _is_scalar(value: Any) -> bool:
    return not isinstance(value, (list, tuple, set, frozenset, dict)) and value is not ABSENT


def _numeric(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _parse_clock(value: Any) -> Any:
    """Epoch seconds from a raw value, or ABSENT. Never a bool, never a guess."""
    if isinstance(value, bool) or value is None:
        return ABSENT
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return ABSENT
    return ABSENT


# --------------------------------------------------------------------------
# Kleene logic
# --------------------------------------------------------------------------


def k_and(values: list[bool | None]) -> bool | None:
    if any(v is False for v in values):
        return False
    if any(v is None for v in values):
        return None
    return True


def k_or(values: list[bool | None]) -> bool | None:
    if any(v is True for v in values):
        return True
    if any(v is None for v in values):
        return None
    return False


def k_not(value: bool | None) -> bool | None:
    return None if value is None else (not value)


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------


def evaluate(expr: Any, row: Row, ctx: EvalContext, scope: Any = None) -> Any:
    """Evaluate an expression against a row. May return ABSENT, None, or a scalar."""
    ctx.depth += 1
    if ctx.depth > MAX_EXPRESSION_DEPTH:
        ctx.depth -= 1
        raise EvaluationRefusal(
            "EXPRESSION_TOO_DEEP",
            f"expression nests more than {MAX_EXPRESSION_DEPTH} deep; refusing to evaluate it",
            _where(expr))
    try:
        return _evaluate(expr, row, ctx, scope)
    finally:
        ctx.depth -= 1


def _where(expr: Any) -> str:
    return type(expr).__name__


def _evaluate(expr: Any, row: Row, ctx: EvalContext, scope: Any) -> Any:
    if isinstance(expr, Literal):
        # A Literal(None) is a KNOWN null, which is not the same as an absent field.
        return expr.value

    if isinstance(expr, FieldExpr):
        return row.get(expr.ref.name)

    if isinstance(expr, MeasureExpr):
        # An Aggregate writes its measures into its output rows, so a measure is just a field
        # on the row by the time a downstream Filter reads it. That is what makes the canonical
        # threshold shape work: Aggregate, then a Filter over MeasureExpr.
        value = row.get(expr.name)
        if value is ABSENT:
            raise EvaluationRefusal(
                "UNKNOWN_MEASURE_REFERENCE",
                f"measure {expr.name!r} is not present on this row; a measure can only be read "
                f"downstream of the aggregate that defines it", _where(expr))
        return value

    if isinstance(expr, TimeExpr):
        # A time reference inside a join predicate must say WHICH side's clock it means.
        # `FieldExpr` on the time field is the explicit form; a bare `TimeRef` is resolved
        # against the sides FIRST, because the merged view always holds one side's value and
        # would silently answer for both.
        field = expr.time_ref.field_name
        if field and row.sides is not None:
            carriers = [name for name, side in row.sides.items() if field in side]
            if len(carriers) == 1:
                return _parse_clock(row.side(carriers[0])[field])
            if len(carriers) > 1:
                raise EvaluationRefusal(
                    "TIME_SIDE_AMBIGUOUS",
                    f"field {field!r} exists on both join sides, so a bare time reference does "
                    f"not say which clock is meant; reference it through EventExpr instead",
                    _where(expr))
        value = row.get(field) if field else ABSENT
        if value is ABSENT:
            return ABSENT
        return _parse_clock(value)

    if isinstance(expr, EventExpr):
        # Resolved against the NAMED side, never against the merged view. 3A refused these
        # outright; 3B gives them meaning, and the meaning is exactly "this side's value", not
        # "whichever side happened to have that field".
        if expr.side not in ("left", "right"):
            raise EvaluationRefusal(
                "IR_UNSUPPORTED_CONSTRUCT",
                f"EventExpr side {expr.side!r} names a pattern stage, which phase 3B does not "
                f"execute; stage-scoped references belong to 3C", _where(expr),
                deferred_to="3C")
        if row.sides is None:
            raise EvaluationRefusal(
                "EVENT_SIDE_NOT_AVAILABLE",
                f"an event-scoped reference to the {expr.side!r} side was used outside a "
                f"two-input node, so there is no such side to read", _where(expr))
        return row.side(expr.side).get(expr.ref.name, ABSENT)

    if isinstance(expr, InList):
        value = evaluate(expr.value, row, ctx, scope)
        options = evaluate(expr.options, row, ctx, scope) if not isinstance(
            expr.options, tuple) else expr.options
        if not _is_scalar(value):
            ctx.unknown("comparison_type_mismatch")
            return UNKNOWN
        return any(canonical(value) == canonical(o) for o in options)

    if isinstance(expr, BoolOp):
        return _evaluate_bool(expr, row, ctx, scope)

    if isinstance(expr, Comparison):
        return _evaluate_comparison(expr, row, ctx, scope)

    if isinstance(expr, Arith):
        return _evaluate_arith(expr, row, ctx, scope)

    if isinstance(expr, Call):
        return _evaluate_call(expr, row, ctx, scope)

    raise EvaluationRefusal(
        "IR_UNSUPPORTED_CONSTRUCT",
        f"the kernel cannot evaluate a {type(expr).__name__}", _where(expr))


def _evaluate_bool(expr: BoolOp, row: Row, ctx: EvalContext, scope: Any) -> bool | None:
    if expr.op not in _BOOL_OPS:
        raise EvaluationRefusal("UNKNOWN_BOOLEAN_OPERATOR",
                                f"unknown boolean operator {expr.op!r}", "BoolOp")
    values = [evaluate(child, row, ctx, scope) for child in expr.children]
    truths: list[bool | None] = []
    for value in values:
        if value is ABSENT or value is None:
            truths.append(UNKNOWN)
        elif isinstance(value, bool):
            truths.append(value)
        else:
            ctx.unknown("comparison_type_mismatch")
            truths.append(UNKNOWN)
    if expr.op == "not":
        return k_not(truths[0]) if len(truths) == 1 else UNKNOWN
    if expr.op == "and":
        return k_and(truths)
    return k_or(truths)


def _evaluate_comparison(expr: Comparison, row: Row, ctx: EvalContext,
                         scope: Any) -> bool | None:
    if expr.op not in _COMPARISON_OPS:
        raise EvaluationRefusal("UNKNOWN_COMPARISON_OPERATOR",
                                f"unknown comparison operator {expr.op!r}; the model permits "
                                f"{sorted(_COMPARISON_OPS)}", "Comparison")
    left = evaluate(expr.left, row, ctx, scope)
    right = evaluate(expr.right, row, ctx, scope)

    if left is ABSENT or right is ABSENT or left is None or right is None:
        # The algebra collapses ABSENT to a known null here, which is why the model cannot
        # currently express "field is present". Recorded as a known IR limitation.
        return UNKNOWN
    if not _is_scalar(left) or not _is_scalar(right):
        ctx.unknown("comparison_type_mismatch")
        return UNKNOWN

    if _numeric(left) != _numeric(right):
        # bool is not a number, and a str is not a number. Comparing across those is
        # undecidable rather than false, so it is UNKNOWN and counted.
        ctx.unknown("comparison_type_mismatch")
        return UNKNOWN

    if isinstance(left, str) != isinstance(right, str):
        ctx.unknown("comparison_type_mismatch")
        return UNKNOWN

    if expr.op == "=":
        return canonical(left) == canonical(right)
    if expr.op == "!=":
        return canonical(left) != canonical(right)
    try:
        if expr.op == "<":
            return left < right
        if expr.op == "<=":
            return left <= right
        if expr.op == ">":
            return left > right
        return left >= right
    except TypeError:
        ctx.unknown("comparison_type_mismatch")
        return UNKNOWN


def _evaluate_arith(expr: Arith, row: Row, ctx: EvalContext, scope: Any) -> Any:
    left = evaluate(expr.left, row, ctx, scope)
    right = evaluate(expr.right, row, ctx, scope)
    if expr.op == "+" and (isinstance(left, str) or isinstance(right, str)):
        # `+` meaning concatenation in one engine and addition in another is a portability
        # trap, and there is no way to tell which a target means. Refuse rather than pick.
        raise EvaluationRefusal(
            "ARITH_STRING_CONCAT_UNSUPPORTED",
            "Arith('+') on a string operand is ambiguous across targets and is refused; "
            "use the concat() function, whose null contract is declared", "Arith")
    if not _numeric(left) or not _numeric(right):
        ctx.unknown("arithmetic_unknown")
        return UNKNOWN
    if expr.op in ("/", "%") and right == 0:
        # Never inf, never an exception. A divide-by-zero that produced inf would make a
        # threshold comparison silently true or false.
        ctx.unknown("arithmetic_unknown")
        return UNKNOWN
    if expr.op == "+":
        return left + right
    if expr.op == "-":
        return left - right
    if expr.op == "*":
        return left * right
    if expr.op == "/":
        return left / right
    return left % right


def _evaluate_call(expr: Call, row: Row, ctx: EvalContext, scope: Any) -> Any:
    contract = FUNCTION_CONTRACTS.get(expr.function)
    if contract is None:
        raise EvaluationRefusal("UNKNOWN_FUNCTION",
                                f"unregistered function {expr.function!r}", "Call")
    arity = contract["arity"]
    low, high = arity if isinstance(arity, tuple) else (arity, arity)
    if len(expr.args) < low or (high is not None and len(expr.args) > high):
        allowed = f"{low}" if low == high else f"{low}..{high}"
        raise EvaluationRefusal(
            "FUNCTION_ARITY_VIOLATION",
            f"{expr.function!r} called with {len(expr.args)} argument(s); the contract allows "
            f"{allowed}", "Call")

    if contract.get("dialect") == "must_be_declared":
        # `Call` has no `dialect` field, so this is unconditionally true. An undeclared regex
        # dialect is not portable: (?i), \d vs [[:digit:]] and PCRE-vs-POSIX disagree on real
        # analyst input. Refusing is the only honest option until Call carries a dialect.
        raise EvaluationRefusal(
            "FUNCTION_DIALECT_UNDECLARED",
            f"{expr.function!r} requires an explicit dialect declaration, and the expression "
            f"algebra has nowhere to declare one; an undeclared regex dialect is not portable",
            "Call")

    args = [evaluate(a, row, ctx, scope) for a in expr.args]
    return _apply_function(expr.function, args, ctx)


def _apply_function(name: str, args: list[Any], ctx: EvalContext) -> Any:
    if name == "if":
        condition, when_true, when_false = args
        if condition is True:
            return when_true
        if condition is False:
            return when_false
        return UNKNOWN

    if name == "coalesce":
        for value in args:
            if value is not ABSENT and value is not None:
                return value
        return None

    if name == "abs":
        if not _numeric(args[0]):
            ctx.unknown("function_unknown")
            return UNKNOWN
        return abs(args[0])

    if name == "round":
        if not _numeric(args[0]):
            ctx.unknown("function_unknown")
            return UNKNOWN
        digits = args[1] if len(args) > 1 else 0
        if not _numeric(digits):
            ctx.unknown("function_unknown")
            return UNKNOWN
        try:
            # Decimal, not float round: the contract declares ROUND_HALF_EVEN, and
            # round(0.145, 2) in binary floating point does not honour it.
            quantum = Decimal(1).scaleb(-int(digits))
            return float(Decimal(str(args[0])).quantize(quantum, rounding=ROUND_HALF_EVEN))
        except (InvalidOperation, ValueError):
            ctx.unknown("function_unknown")
            return UNKNOWN

    if name == "cidr_contains":
        address, network = args
        if not isinstance(address, str) or not isinstance(network, str):
            ctx.unknown("function_unknown")
            return UNKNOWN
        try:
            return ipaddress.ip_address(address) in ipaddress.ip_network(network, strict=False)
        except ValueError:
            ctx.unknown("function_unknown")
            return UNKNOWN

    if name == "in_set":
        value, options = args
        if not _is_scalar(value):
            ctx.unknown("function_unknown")
            return UNKNOWN
        return any(canonical(value) == canonical(o) for o in options)

    # The remaining functions are string functions whose contract is "nulls propagate".
    if any(a is ABSENT or a is None for a in args):
        return None
    if not all(isinstance(a, str) for a in args):
        ctx.unknown("function_unknown")
        return UNKNOWN
    if name == "lower":
        return args[0].casefold()
    if name == "upper":
        return args[0].upper()
    if name == "concat":
        return "".join(args)
    if name == "contains":
        # Declared case-insensitive.
        return args[0].casefold() in args[1].casefold()
    if name == "starts_with":
        # No `case` key is declared for this one, so it is case-SENSITIVE. Recorded as an IR
        # oversight, but the contract as written is what we honour.
        return args[0].startswith(args[1])
    if name == "ends_with":
        return args[0].endswith(args[1])
    if name == "count_distinct":
        # As a SCALAR expression this is a no-op: one value is trivially distinct. The same
        # name is also an aggregate, and conflating the two would be a different bug.
        return 1 if args[0] is not ABSENT and args[0] is not None else None
    ctx.unknown("function_unknown")
    return UNKNOWN


# NOTE: there is deliberately no `is_true()` helper. An earlier draft had one that returned
# `value if isinstance(value, bool) else False`, which collapses UNKNOWN into False - so a
# caller using it could never distinguish "we cannot decide" from "it did not match", and the
# unknown went uncounted. That is precisely the failure three-valued logic exists to prevent,
# delivered by a convenience wrapper. Both call sites test the RAW value against `is True`,
# which keeps the third value reachable. A helper here is an active hazard, not a convenience.
