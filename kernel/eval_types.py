"""Public contract for the RuleIR semantic execution kernel.

Phase 3A of docs/ruleforge-redesign-plan.md. Ships DARK: nothing imports this.

THE ONE INVARIANT
-----------------
`not_evaluated` implies `rows == ()` AND `columns == ()`. Never one without the other.
That is not a convention, it is enforced by `EvaluationResult.__post_init__`, so a consumer
physically cannot render rows out of an unevaluated result.

The two states mean different things and must never be conflated:

  evaluated     + no rows  =>  the rule definitively matched nothing in the supplied sample
  not_evaluated             =>  we could not decide, and here is precisely why

A consumer branches on `state`, never on emptiness. `plan.md` rule 6 - "`not_evaluated` is
never displayed as `would_fire`" - is enforced structurally here: the verdict is a derived
function of `(state, len(rows))` returning one of three verdicts, and the display strings are
constants in this module rather than assembled in a front end.

ABSENT IS NOT NULL
------------------
A missing key and a present key holding None are different, and the difference is load-bearing
at every place an answer changes: group keys, order keys, set-operation identity and row
identity. `ABSENT` is a distinct sentinel, not `None`. Collapsing them would silently merge
"no such column on this row" with "the column exists and is empty", which is the difference
between a partition you can trust and one you cannot.

WHERE APPROXIMATION LIVES
-------------------------
Every place the kernel makes a defensible choice that is not the only defensible choice emits
a `Caveat` into the result. Nothing approximate lives only in a docstring. If a reader cannot
see it in the returned value, it does not happen here.

This module never claims to know what a SIEM will do. It models OUR IR semantics. Vendor
comparison is the capability layer's job, and it is marked inferred because no vendor engine
has ever been executed against it - Docker is unavailable in this environment.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

from models.rule_ir import (Aggregate, Arrange, Derive, Emit, Expand, Filter, Iterate, Join,
                            Pattern, Read, SetOp)

#: Bound on a single expression walk. The kernel validator in models/rule_ir.py has the same
#: gap and is reachable from here; this at least bounds the kernel's own recursion.
MAX_EXPRESSION_DEPTH = 64

#: Input caps. These REFUSE rather than truncate: silently dropping rows changes tumbling
#: bucket contents, therefore changes the verdict, which is exactly the false tuning
#: confidence the plan lists as risk 5.
MAX_INPUT_ROWS = 100_000
MAX_TRACE_SAMPLES = 5
MAX_CAVEATS = 64
#: `Expand` output cap. Separate from MAX_INPUT_ROWS because one input row can hold an
#: arbitrarily long list, and every output row copies the row's whole value mapping.
MAX_EXPAND_ROWS = 200_000

#: The third truth value. `None` means UNKNOWN, never "false".
UNKNOWN = None


class _Absent:
    """The absent-field sentinel. A singleton, and not equal to anything including None."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "ABSENT"

    def __bool__(self) -> bool:
        return False


#: Returned when a field is not present on a row. Distinct from a present-but-null value.
ABSENT = _Absent()


class EvalState(str, Enum):
    EVALUATED = "evaluated"
    NOT_EVALUATED = "not_evaluated"


class Verdict(str, Enum):
    """The only three answers. There is deliberately no `partial` and no `would_fire`."""

    MATCHED = "matched"
    NO_MATCH = "no_match"
    NOT_EVALUATED = "not_evaluated"


#: Display strings live HERE, not in a template, so the rule that `not_evaluated` is never
#: shown as a firing verdict is enforced by import rather than by reviewer vigilance.
VERDICT_LABELS: Mapping[str, str] = MappingProxyType({
    Verdict.MATCHED.value: "Matched the sample",
    Verdict.NO_MATCH.value: "Matched nothing in the sample",
    Verdict.NOT_EVALUATED.value: "Could not be evaluated - no verdict available",
})


@dataclass(frozen=True)
class Row:
    """One runtime row.

    `values` distinguishes absent (key missing) from null (key present, value None). `index`
    is the row's position in the caller's supplied order and is the mandatory sort tie-break:
    a sort without a stable tie-break is not reproducible, and a non-reproducible evaluator is
    worse than no evaluator.

    `sides` holds the pre-merge rows of a two-input node, keyed by side name ("left"/"right").
    It exists so an `EventExpr` can say WHICH side it means. Without it, a joined row's `values`
    is already a merge, and resolving `host` would be a guess between the two sources - the
    same class of error as assuming a time field name. `None` for a single-source row.
    """
    values: Mapping[str, Any]
    index: int
    time: float | None = None
    time_source: str | None = None
    sides: Mapping[str, Mapping[str, Any]] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", MappingProxyType(dict(self.values)))
        if self.sides is not None:
            object.__setattr__(self, "sides",
                               MappingProxyType({k: MappingProxyType(dict(v))
                                                 for k, v in self.sides.items()}))

    def get(self, name: str) -> Any:
        """The value, or ABSENT if the key is not present. Never returns None for absence."""
        return self.values.get(name, ABSENT)

    def side(self, name: str) -> Any:
        """One side's pre-merge values, or ABSENT when that side does not exist on this row.

        There is NO fallback to the merged view. An earlier version returned `self.values` when
        the named side was missing, so a left-join row with no right counterpart reported the
        LEFT row's value as the right side's - fabricating a value for a stream that was not in
        the result at all. Under a name asserting which side it came from, that is precisely
        the invention this whole module exists to prevent. The `EventExpr` evaluator turns this
        ABSENT into a visible UNKNOWN rather than a number.
        """
        if self.sides is not None:
            return self.sides.get(name, ABSENT)
        return self.values

    @property
    def columns(self) -> tuple[str, ...]:
        return tuple(sorted(self.values))


def canonical(value: Any) -> tuple[str, Any]:
    """A hashable, type-tagged identity for a value.

    Type tagging matters because Python says `1 == True` and `1 == 1.0`. A set operation that
    unions the integer 1 with the boolean True is a bug, not a feature. ABSENT never equals
    NULL.
    """
    if value is ABSENT:
        return ("absent", None)
    if value is None:
        return ("null", None)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("num", value)
    if isinstance(value, float):
        # Keep floats distinct from ints rather than pretending 1.0 and 1 are the same row.
        return ("flt", value)
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, (list, tuple)):
        return ("seq", tuple(canonical(v) for v in value))
    if isinstance(value, (set, frozenset)):
        return ("set", frozenset(canonical(v) for v in value))
    if isinstance(value, Mapping):
        return ("map", frozenset((k, canonical(v)) for k, v in value.items()))
    return ("other", repr(value))


def eq_value(left: Any, right: Any) -> bool:
    """EQUALITY, as distinct from identity.

    `canonical()` is row identity, and there the type tag is load-bearing: a set operation
    must not union the integer 1 with the boolean True. Reusing it for `=` was wrong in the
    other direction - a JSON float 1024.0 never equalled the integer literal 1024, so every
    numeric comparison against a float field was a silent, definitive wrong negative counted
    as `rows_predicate_false` rather than as an unknown. That is the worst direction for this
    module to be wrong in.

    So numbers compare NUMERICALLY here, `bool` stays distinct from numbers, and everything
    else falls back to the type-tagged identity.
    """
    if left is ABSENT or right is ABSENT:
        return False
    if isinstance(left, bool) or isinstance(right, bool):
        return canonical(left) == canonical(right)
    if _is_number(left) and _is_number(right):
        return left == right
    if isinstance(left, str) and isinstance(right, str):
        return left == right
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        return len(left) == len(right) and all(
            eq_value(a, b) for a, b in zip(left, right))
    return canonical(left) == canonical(right)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def row_key(row: Row) -> tuple[tuple[str, tuple[str, Any]], ...]:
    """A row's identity for set operations: its fields, order-independent."""
    return tuple(sorted((k, canonical(v)) for k, v in row.values.items()))


@dataclass(frozen=True)
class Caveat:
    """A declared approximation. Present in the result, not merely in a comment."""
    code: str
    count: int = 1
    nodes: tuple[str, ...] = ()

    def __str__(self) -> str:
        where = f" at {', '.join(self.nodes)}" if self.nodes else ""
        return f"{self.code} (x{self.count}){where}"


@dataclass(frozen=True)
class NodeTrace:
    """Per-node outcome. Counters only - never row content, because traces get logged and
    sample events contain the very fields being hunted for."""
    node_id: str
    primitive: str
    status: str                       # evaluated | not_evaluated | skipped | refused
    rows_in: int = 0
    rows_out: int = 0
    detail: Mapping[str, Any] = field(default_factory=dict)
    refusal_code: str | None = None
    samples: tuple[int, ...] = ()     # row INDICES only, capped
    samples_truncated: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "detail", MappingProxyType(dict(self.detail)))


@dataclass
class EvalCounts:
    """O(1) counters. Every UNKNOWN is counted; an uncounted UNKNOWN is a silent guess."""
    rows_in: int = 0
    rows_out: int = 0
    rows_predicate_true: int = 0
    rows_predicate_false: int = 0
    rows_predicate_unknown: int = 0
    rows_without_time: int = 0
    rows_unparseable_time: int = 0
    windows: int = 0
    groups: int = 0
    groups_with_absent_key: int = 0
    measure_where_unknown: int = 0
    rows_with_unknown_order_key: int = 0
    emit_column_absent: int = 0
    arithmetic_unknown: int = 0
    function_unknown: int = 0
    comparison_type_mismatch: int = 0
    setop_rows_dropped: int = 0
    emit_dedupe_dropped: int = 0


@dataclass(frozen=True)
class EvaluationResult:
    """The verdict, and the evidence for it.

    Two states only. `reason` is non-None IFF the state is not_evaluated. `rows` and
    `columns` are empty IFF the state is not_evaluated. All four are enforced below.
    """
    state: EvalState
    reason: Any = None                              # EvaluationRefusal | None
    rows: tuple[Row, ...] = ()
    columns: tuple[str, ...] = ()
    trace: tuple[NodeTrace, ...] = ()
    counts: EvalCounts = field(default_factory=EvalCounts)
    caveats: tuple[Caveat, ...] = ()
    #: True when the result came from a single-event projection. The plan requires a
    #: single-event result to announce itself, and a UI cannot render what the type omits.
    single_event_projection: bool = False
    #: Declared execution-policy parameters this kernel did NOT honour. Present so nothing
    #: pretends they were applied.
    unmodelled: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.state is EvalState.NOT_EVALUATED:
            # `len()` and an explicit `tuple` check, never truthiness. A tuple SUBCLASS that
            # overrides `__bool__` can defeat a truthiness test, which would let a not_evaluated
            # result carry rows - the one thing this class exists to make impossible.
            if len(self.rows) or len(self.columns):
                raise ValueError(
                    "a not_evaluated result must carry no rows and no columns; otherwise a "
                    "consumer can render output for a rule we could not evaluate")
            if not isinstance(self.rows, tuple) or not isinstance(self.columns, tuple):
                raise ValueError("rows and columns must be plain tuples")
            if self.reason is None:
                raise ValueError("a not_evaluated result must name its reason")

    @property
    def evaluated(self) -> bool:
        return self.state is EvalState.EVALUATED

    @property
    def verdict(self) -> Verdict:
        """The only sanctioned verdict. Derived, never stored, never settable."""
        if self.state is EvalState.NOT_EVALUATED:
            return Verdict.NOT_EVALUATED
        return Verdict.MATCHED if len(self.rows) else Verdict.NO_MATCH

    @property
    def verdict_label(self) -> str:
        return VERDICT_LABELS[self.verdict.value]

    def caveat_codes(self) -> tuple[str, ...]:
        return tuple(c.code for c in self.caveats)

    def to_dict(self) -> dict[str, Any]:
        """A JSON-safe view. Used by the API layer later; nothing in the kernel calls it."""
        return {
            "state": self.state.value,
            "verdict": self.verdict.value,
            "verdict_label": self.verdict_label,
            "reason": self.reason.to_dict() if self.reason is not None else None,
            "columns": list(self.columns),
            "row_count": len(self.rows),
            "single_event_projection": self.single_event_projection,
            "counts": dict(vars(self.counts)),
            "caveats": [str(c) for c in self.caveats],
            "unmodelled": list(self.unmodelled),
            "trace": [
                {
                    "node_id": t.node_id,
                    "primitive": t.primitive,
                    "status": t.status,
                    "rows_in": t.rows_in,
                    "rows_out": t.rows_out,
                    "detail": dict(t.detail),
                    "refusal_code": t.refusal_code,
                    "samples": list(t.samples),
                    "samples_truncated": t.samples_truncated,
                }
                for t in self.trace
            ],
        }


def columns_of(rows: Sequence[Row]) -> tuple[str, ...]:
    """The union of observed keys, in sorted order.

    We have no authoritative field list for any target, so this is the union of what the
    SAMPLE contained and is recorded as a caveat wherever it is used. It is never presented
    as a verified schema.
    """
    names: set[str] = set()
    for row in rows:
        names.update(row.values.keys())
    return tuple(sorted(names))


#: The primitive name for each concrete node class, so identity is decided by `type(node) is
#: cls` rather than by `__class__.__name__`. A lookalike class named `Read` with none of the
#: real fields must not be treated as a Read.
NODE_TYPES: Mapping[str, type] = MappingProxyType({
    "Read": Read, "Derive": Derive, "Filter": Filter, "Expand": Expand,
    "Aggregate": Aggregate, "Arrange": Arrange, "Join": Join, "SetOp": SetOp,
    "Pattern": Pattern, "Iterate": Iterate, "Emit": Emit,
})


def primitive_of(node: Any) -> str | None:
    """The kernel primitive this node IS, or None if it is not a kernel node at all."""
    for name, cls in NODE_TYPES.items():
        if type(node) is cls:
            return name
    return None
