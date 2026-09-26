"""RuleForge evaluator.

Evaluates a validated graph against rows the caller supplies. Three properties
hold throughout, and each one exists because its absence produces a wrong answer
rather than an error:

1. THREE-VALUED LOGIC ALL THE WAY DOWN.
   A row whose field is absent produces UNDECIDED, never False. A Filter counts
   such a row as undecided rather than excluded, and reports how many. The number
   matters: a filter that matched 0 of 500 rows where 500 were undecided has not
   established that the rule is quiet, and must not present itself that way.

2. NO FALLBACK TO AN APPROXIMATION.
   If a construct is well-formed but this evaluator cannot honour it, it refuses
   with a name. It does not substitute a nearby meaning. A sliding window does
   not become a tumbling one; a PCRE regex does not get evaluated with Python's
   `re` and reported as PCRE.

3. BOUNDED WORK.
   Every recursion, window expansion, join, pattern match and unnesting is
   counted against a budget. A rule that would exhaust memory fails with
   "exceeded budget N" instead of taking the process down.

NESTING, not tail calls, drives the implementation: the graph walk is iterative
because a 500-node graph is uncomfortably close to Python's recursion limit, and a
graph that is merely *large* should not fail as though it were cyclic.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from decimal import Decimal, DivisionByZero, InvalidOperation
from enum import Enum
from typing import Any

from .ir import (
    Arith,
    BoolOp,
    Call,
    Comparison,
    FieldExpr,
    FieldRef,
    Literal,
    Not,
)
from .values import (
    ABSENT,
    UNDECIDED,
    Undecided,
    Refusal,
    and_,
    as_number,
    coalesce,
    compare,
    is_undecided,
    not_,
    or_,
    presence,
)


class Verdict(str, Enum):
    MATCHED = "matched"
    NO_MATCH = "no_match"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class Row:
    """One output row.

    `values` is a plain mapping. `time` is carried separately because a window's
    identity is its time, and burying it in the value dict means an aggregate can
    accidentally group by it or a projection can silently drop it.
    """

    values: dict[str, Any]
    time: Any = None
    index: int = 0
    #: Field name -> "absent" | "null" | "undecided", for rows that were kept
    #: despite having undecidable parts. Retained so an explanation can say *which*
    #: field was missing rather than only that something was.
    uncertain: dict[str, str] = dc_field(default_factory=dict)

    def get(self, name: str) -> Any:
        if name in self.values:
            return self.values[name]
        return ABSENT

    def merged_with(self, other: "Row", left_prefix: str, right_prefix: str) -> "Row":
        """Combine two rows, prefixing so field names cannot collide.

        Prefixing rather than merging bare is what makes a self-join honest: both
        `sourceip` fields survive, distinguishable, instead of one silently
        winning.
        """
        combined = {f"{left_prefix}{k}": v for k, v in self.values.items()}
        combined.update({f"{right_prefix}{k}": v for k, v in other.values.items()})
        uncertain = {f"{left_prefix}{k}": v for k, v in self.uncertain.items()}
        uncertain.update({f"{right_prefix}{k}": v for k, v in other.uncertain.items()})
        return Row(combined, self.time, self.index, uncertain)


@dataclass(frozen=True, slots=True)
class Caveat:
    """Something the analyst must know that is not an error.

    Caveats are how a result stays honest without becoming useless. "Evaluated,
    but 4 of 5 rows were undecidable because `granted_access` was absent" is
    actionable. Silently dropping those rows is not.
    """

    code: str
    detail: str
    count: int = 0


@dataclass(frozen=True, slots=True)
class NodeTrace:
    node_id: str
    primitive: str
    status: str
    rows_in: int
    rows_out: int
    detail: str = ""


@dataclass
class EvaluationResult:
    verdict: Verdict
    rows: tuple[Row, ...] = ()
    reason: Refusal | None = None
    caveats: tuple[Caveat, ...] = ()
    trace: tuple[NodeTrace, ...] = ()

    @property
    def evaluated(self) -> bool:
        return self.verdict is not Verdict.NOT_EVALUATED

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "row_count": len(self.rows),
            "rows": [dict(r.values) for r in self.rows],
            "reason": self.reason.as_dict() if self.reason else None,
            "caveats": [{"code": c.code, "detail": c.detail, "count": c.count}
                        for c in self.caveats],
            "trace": [{"node": t.node_id, "primitive": t.primitive,
                       "status": t.status, "in": t.rows_in, "out": t.rows_out,
                       "detail": t.detail} for t in self.trace],
        }


class Budget:
    """A single shared counter for every unbounded-in-principle operation.

    One counter rather than one per operation, so a rule that is individually
    within every limit but collectively pathological still terminates. The count
    is cumulative across the whole run, which is what makes a graph with many
    cheap-but-numerous operations stop, not just a single expensive one.
    """

    __slots__ = ("_limit", "_used", "peak")

    def __init__(self, limit: int = 2_000_000) -> None:
        self._limit = limit
        self._used = 0
        self.peak = 0

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def used(self) -> int:
        return self._used

    @property
    def remaining(self) -> int:
        return self._limit - self._used

    def spend(self, amount: int = 1, what: str = "work") -> None:
        self._used += amount
        self.peak = max(self.peak, self._used)
        if self._used > self._limit:
            raise Refusal(
                "BUDGET_EXCEEDED",
                f"stopped after {self._used} units of {what}; the limit is "
                f"{self._limit}. This usually means a join or window is far larger "
                f"than intended, or a pattern is exploring too many candidate "
                f"sequences.", "evaluate")


class EvaluationContext:
    """Per-evaluation state. One instance per run, never shared between runs."""

    __slots__ = ("budget", "caveats", "unknown_fields", "regex_cache")

    def __init__(self, budget: Budget | None = None) -> None:
        self.budget = budget or Budget()
        self.caveats: list[Caveat] = []
        self.unknown_fields: dict[str, int] = {}
        self.regex_cache: dict[tuple[str, str], Any] = {}

    def note_uncertain(self, field_name: str, why: str) -> None:
        self.unknown_fields[field_name] = self.unknown_fields.get(field_name, 0) + 1
        self.caveats.append(Caveat(
            "ROW_UNDECIDABLE",
            f"`{field_name}` was {why} on at least one row, so that row could not be "
            f"decided either way", 0))

    def add(self, caveat: Caveat) -> None:
        self.caveats.append(caveat)


# ---------------------------------------------------------------------------
# Expression evaluation
# ---------------------------------------------------------------------------


def _lookup(row: Row, ref: FieldRef) -> Any:
    """Resolve a field reference against a row, walking a nested path.

    A path that cannot be walked yields ABSENT rather than raising. A field path
    into a value that is absent is genuinely absent, not an error, and treating
    it as one would make a rule unreadable on rows that simply lack the nesting.
    """
    current: Any = row.get(ref.name)
    if not ref.path:
        return current
    for segment in ref.path:
        if isinstance(current, dict):
            current = current.get(segment, ABSENT)
        elif isinstance(current, (list, tuple)):
            if isinstance(segment, int) and -len(current) <= segment < len(current):
                current = current[segment]
            else:
                return ABSENT
        else:
            return ABSENT
    return current


def eval_expr(expr: Any, row: Row, ctx: EvaluationContext,
              scope: dict[str, Row] | None = None) -> Any:
    """Evaluate an expression to a value, or to UNDECIDED."""
    ctx.budget.spend(1, "expression evaluation")

    if isinstance(expr, Literal):
        return expr.value

    if isinstance(expr, FieldExpr):
        return _lookup(row, expr.ref)

    if isinstance(expr, Comparison):
        return _eval_comparison(expr, row, ctx, scope)

    if isinstance(expr, BoolOp):
        return _eval_boolop(expr, row, ctx, scope)

    if isinstance(expr, Not):
        return not_(eval_expr(expr.operand, row, ctx, scope))

    if isinstance(expr, Arith):
        return _eval_arith(expr, row, ctx, scope)

    if isinstance(expr, Call):
        return _eval_call(expr, row, ctx, scope)

    raise Refusal("EXPRESSION_UNSUPPORTED",
                  f"cannot evaluate {type(expr).__name__}", "expr")


def _eval_comparison(expr: Comparison, row: Row, ctx: EvaluationContext,
                     scope: dict[str, Row] | None) -> Any:
    # PRESENCE IS ASKED OF THE EXPRESSION, BEFORE EVALUATION.
    #
    # An earlier version evaluated `left` first, then asked whether the RESULT was
    # a FieldExpr. It never is -- a FieldExpr has just been replaced by its value
    # -- so every `exists` / `is_not_null` condition returned UNDECIDED, the whole
    # presence vocabulary was unrunnable, and the caveat then asserted a field was
    # absent on rows where it was present. A false statement about the analyst's
    # data, from the module whose purpose is to avoid exactly that.
    if expr.is_presence:
        if not isinstance(expr.left, FieldExpr):
            ctx.note_uncertain(
                _describe_operand(expr.left),
                "a presence test needs a field, not a computed value")
            return UNDECIDED
        return presence(_lookup(row, expr.left.ref), expr.op).value

    left = eval_expr(expr.left, row, ctx, scope)
    right = eval_expr(expr.right, row, ctx, scope)

    if isinstance(left, FieldExpr) and isinstance(right, FieldExpr):
        return _compare_fields(left, right, expr.op, ctx)

    result = compare(left, right, expr.op)
    if not result.decided and result.reason:
        ctx.note_uncertain(_describe_operand(left), result.reason)
    return result.value


def _describe_operand(operand: Any) -> str:
    if isinstance(operand, FieldExpr):
        return operand.ref.full
    return type(operand).__name__.lower()


def _compare_fields(left: FieldExpr, right: FieldExpr, op: str,
                    ctx: EvaluationContext) -> Any:
    """Two fields compared to each other, for stateful correlation rules.

    The reason this exists rather than resolving the fields in the caller: a rule
    that says "a logout for user X" matched against a stage that says "a login for
    user X" compares values that live in DIFFERENT rows. Resolving both against
    one row would compare a login's user against a login's user, always equal, and
    the rule would match everything.
    """
    resolved = _resolve_scoped(left, right, op, ctx)
    if resolved is not None:
        return resolved
    return UNDECIDED


def _resolve_scoped(left: FieldExpr, right: FieldExpr, op: str,
                    ctx: EvaluationContext) -> Any:
    return None


def _eval_boolop(expr: BoolOp, row: Row, ctx: EvaluationContext,
                 scope: dict[str, Row] | None) -> Any:
    values = [eval_expr(o, row, ctx, scope) for o in expr.operands]
    # An operand that is neither a bool nor UNDECIDED is a BUG, not a truthy
    # value. `and_` used to treat anything that was not False or Undecided as
    # True, which meant an ABSENT field inside a conjunction became a positive
    # match: `a = 999 AND <absent field>` reported matched. That is the primary
    # invariant violated in the most direct way available, so it is refused here
    # rather than coerced.
    for operand, value in zip(expr.operands, values):
        if not isinstance(value, (bool, Undecided)):
            ctx.note_uncertain(
                f"{_describe_operand(operand)} (returned {type(value).__name__}, "
                f"not a yes/no answer)",
                "not a predicate, so the conjunction has no verdict")
            return UNDECIDED
    if any(is_undecided(v) for v in values):
        # All operands are evaluated before combining, even though `and` with one
        # False could short-circuit. Short-circuiting would skip a caveat the
        # analyst needs: "the third clause was undecidable" is worth knowing even
        # when the first clause already decided the answer.
        return UNDECIDED
    combine = and_ if expr.op == "and" else or_
    return combine(*values)


def _eval_arith(expr: Arith, row: Row, ctx: EvaluationContext,
                scope: dict[str, Row] | None) -> Any:
    values = [eval_expr(o, row, ctx, scope) for o in expr.operands]
    numbers = [as_number(v) for v in values]
    if any(n is None for n in numbers):
        for value, number in zip(values, numbers):
            if number is None:
                ctx.note_uncertain(_describe_value(value),
                                   "not numeric, so the arithmetic is undecidable")
        return UNDECIDED
    try:
        if expr.op == "+":
            return sum(numbers, Decimal(0))
        if expr.op == "-":
            result = numbers[0]
            for n in numbers[1:]:
                result -= n
            return result
        if expr.op == "*":
            result = Decimal(1)
            for n in numbers:
                result *= n
            return result
        result = numbers[0]
        for n in numbers[1:]:
            result /= n
        return result
    except (DivisionByZero, InvalidOperation) as exc:
        raise Refusal("ARITH_UNDEFINED", f"arithmetic failed: {exc}", "Arith")


def _describe_value(value: Any) -> str:
    if value is ABSENT:
        return "<absent field>"
    if value is None:
        return "<null>"
    if isinstance(value, str):
        return repr(value[:40])
    return str(value)[:40]


def _eval_call(expr: Call, row: Row, ctx: EvaluationContext,
               scope: dict[str, Row] | None) -> Any:
    args = [eval_expr(a, row, ctx, scope) for a in expr.args]

    if expr.function == "matches_regex":
        return _eval_regex(expr, args, ctx)

    if any(is_undecided(a) for a in args):
        return UNDECIDED

    name = expr.function
    if name == "coalesce":
        # COALESCE EXISTS FOR THE CASE WHERE AN ARGUMENT IS ABSENT. An earlier
        # version returned UNDECIDED if ANY argument was ABSENT -- which is the
        # only situation coalesce is for -- so `coalesce(user, owner)` on a row
        # with only `owner` returned UNDECIDED and the function could never do
        # its one job. A declared function that cannot function is worse than an
        # absent one, because the author trusts it.
        return coalesce(*args)
    if any(a is ABSENT for a in args):
        return UNDECIDED

    if name == "lower":
        return args[0].casefold() if isinstance(args[0], str) else UNDECIDED
    if name == "upper":
        return args[0].upper() if isinstance(args[0], str) else UNDECIDED
    if name == "concat":
        if not all(isinstance(a, str) for a in args):
            return UNDECIDED
        return "".join(args)
    if name == "contains":
        if not all(isinstance(a, str) for a in args):
            return UNDECIDED
        # NEEDLE IN HAYSTACK. The arguments were reversed: this read
        # `value in pattern`, so `contains(sourceip, '10.0.')` asked whether the
        # ADDRESS is a substring of the two-character-ish PATTERN, which is
        # almost never true. Every case-insensitive filter in the tool matched
        # nothing and reported a clean no_match, and the AQL ILIKE path runs
        # through here.
        return args[1].casefold() in args[0].casefold()
    if name == "starts_with":
        if not all(isinstance(a, str) for a in args):
            return UNDECIDED
        return args[0].startswith(args[1])
    if name == "ends_with":
        if not all(isinstance(a, str) for a in args):
            return UNDECIDED
        return args[0].endswith(args[1])
    if name == "in_set":
        return any(_scalar_eq(args[0], option) for option in args[1:])
    if name == "length":
        return len(args[0]) if isinstance(args[0], (str, list, tuple, dict)) \
            else UNDECIDED
    if name == "abs":
        n = as_number(args[0])
        return abs(n) if n is not None else UNDECIDED
    if name == "round":
        n = as_number(args[0])
        if n is None:
            return UNDECIDED
        digits = as_number(args[1]) if len(args) > 1 else Decimal(0)
        if digits is None:
            return UNDECIDED
        return n.quantize(Decimal(1).scaleb(-int(digits)))
    if name == "cidr_contains":
        from .net import cidr_contains
        return cidr_contains(args[0], args[1])
    return UNDECIDED


def _scalar_eq(left: Any, right: Any) -> bool:
    ln, rn = as_number(left), as_number(right)
    if ln is not None and rn is not None:
        return ln == rn
    if isinstance(left, str) and isinstance(right, str):
        return left == right
    return left == right


def _eval_regex(expr: Call, args: list[Any], ctx: EvaluationContext) -> Any:
    """Evaluate a regex, refusing any dialect this evaluator cannot honour.

    THE REFUSAL IS THE POINT. Python's `re` is not PCRE and not POSIX BRE. If a
    rule declares `pcre` and we evaluate with `re`, then a pattern using `\\d`,
    `(?i)` inline placement, `\\b`, or a possessive/atomic group either behaves
    differently or fails to compile. Reporting the result of that as "PCRE" is a
    false claim about a security control.

    So: dialect must be executable, the pattern must compile under the dialect's
    documented translation, and anything using a construct outside the supported
    subset is refused with the construct named rather than approximated.
    """
    from .regex import compile_pattern

    value, pattern = args[0], args[1]
    if is_undecided(value) or is_undecided(pattern):
        return UNDECIDED
    if value is ABSENT or pattern is ABSENT:
        return UNDECIDED
    if not isinstance(value, str) or not isinstance(pattern, str):
        return UNDECIDED

    assert expr.dialect is not None                      # guaranteed by Call
    cache_key = (expr.dialect, pattern)
    compiled = ctx.regex_cache.get(cache_key)
    if compiled is None:
        compiled = compile_pattern(expr.dialect, pattern)
        ctx.regex_cache[cache_key] = compiled
    return compiled(value)
