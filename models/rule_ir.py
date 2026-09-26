"""RuleIR v2 - the semantic kernel.

A detection rule is a typed, time-aware dataflow over records:

    Input records + transformations + temporal/state semantics -> result rows,
    under an execution and deployment contract.

That statement yields a CLOSED set of primitives, because a plan can only have a finite
set of effects on row identity, row multiplicity, schema, ordering, grouping, state, and
time visibility. The primitives are therefore the effects, not a catalogue of vendor
shapes. Anything expressible as one of those effects is a node PARAMETER or a typed
EXPRESSION; anything introducing a genuinely new structural effect requires a deliberate
IR version and cannot be smuggled in as an ad-hoc node.

Replaces the v1 `CorrelationModel` bag of parallel lists, which had no ordering and no
dataflow and therefore could not represent "filter -> aggregate -> filter on the aggregate"
at all. See docs/ruleforge-redesign-plan.md section 6.

HARD INVARIANT: this module never invents a field, table, index or source. An unresolved
name is None with low confidence and blocks deployment; it is never replaced with a
plausible name. The only legal movement is explicit analyst input, or a NAMED deterministic
normalisation (OPERATOR_ALIASES) recorded as such.

Stdlib only, frozen dataclasses, no runtime dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Literal as TypingLiteral, TypeAlias

SCHEMA_VERSION = "2.0"

#: Structural bounds. The graph and expression walks in `validate_ir` recurse, so a legal but
#: very large graph would exhaust the interpreter stack and raise a RecursionError out of a
#: function whose contract is to raise `RuleIRValidationError` with a code. Measured before
#: these bounds: a 1,200-node chain and a ~3,000-deep expression both crashed. A refusal
#: naming the limit is strictly more useful than a stack trace, and it costs nothing on any
#: graph a human would write.
MAX_GRAPH_NODES = 500
MAX_EXPRESSION_DEPTH = 200

# A v1 name that means the same thing under v2's canonical vocabulary. This is a NAMED
# normalisation, not a silent coercion: the adapter records that it happened.
#
# Every entry must be (a) a truthful synonym and (b) a target that actually exists in the
# vocabulary it feeds. Two earlier entries broke (b): `gt -> gte` widened a strictly-greater
# predicate, and `ne -> not_equals` pointed at a name absent from v1's CANONICAL_OPERATORS.
# Both are gone. `eq`/`ne` need no alias at all - the adapter's COMPARISON_MAP already maps
# them - so keeping them only created a second, disagreeing spelling of the same thing.
OPERATOR_ALIASES = {
    "endswith": "ends_with",
    "startswith": "starts_with",
}

# --------------------------------------------------------------------------
# Names and provenance
# --------------------------------------------------------------------------

NameConfidence = TypingLiteral["authored", "parsed", "mapped", "unverified", "inferred"]


@dataclass(frozen=True)
class FieldRef:
    """A field in some namespace. `namespace='source'` means the field exists in the
    pasted source verbatim and must not be translated."""

    name: str
    namespace: TypingLiteral["canonical", "source"] = "canonical"
    source_target: str | None = None
    confidence: NameConfidence = "authored"

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise RuleIRValidationError(
                "EMPTY_FIELD_NAME", "a field reference must name something; use SourceSelector "
                "with name=None to mean unresolved", "field")


@dataclass(frozen=True)
class SourceSelector:
    """What a Read node reads. `name=None` means UNRESOLVED and a renderer must not
    substitute a concrete index/table."""

    name: str | None
    confidence: NameConfidence = "authored"
    strategy: TypingLiteral["raw", "accelerated", "reference", "prior_emission"] = "raw"
    schema_id: str | None = None

    def __post_init__(self) -> None:
        if self.name is None and self.confidence == "authored":
            raise RuleIRValidationError(
                "UNRESOLVED_SOURCE_CONFIDENCE",
                "SourceSelector(name=None) must not have confidence 'authored'", "selector")


@dataclass(frozen=True)
class TimeRef:
    """Which clock. Never silently replaced with a guessed timestamp field name."""

    which: TypingLiteral["event", "ingestion", "processing"] = "event"
    field_name: str | None = None


# --------------------------------------------------------------------------
# Time
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Duration:
    seconds: int

    def __post_init__(self) -> None:
        if isinstance(self.seconds, bool) or not isinstance(self.seconds, int):
            raise RuleIRValidationError("INVALID_DURATION", f"duration must be int seconds, got {self.seconds!r}", "duration")
        if self.seconds < 1:
            raise RuleIRValidationError("INVALID_DURATION", f"duration must be >= 1s, got {self.seconds}s", "duration")


FrameKind = TypingLiteral["tumbling", "sliding", "session", "per_event", "cumulative"]


@dataclass(frozen=True)
class Frame:
    """Temporal/partition visibility. This is where every 'window' in the old model
    belonged, and they are still distinct from one another.

    `anchor` and `step` close two gaps that made whole kinds inexpressible. `alignment` said
    "explicit" with no slot to say explicit ABOUT WHAT, so any origin the kernel picked was
    invented; and `sliding` had a size but no advance rate, which is two different operators
    wearing one name - a grid advancing by the size is a tumbling window, and a grid advancing
    by something smaller is a sliding one. Both are optional, and both are REQUIRED when the
    rest of the frame says they are, because a new field that can be omitted with no consequence
    is just a new way to be quietly wrong.
    """

    kind: FrameKind
    size: Duration | None = None
    time_ref: TimeRef = field(default_factory=TimeRef)
    alignment: TypingLiteral["epoch", "explicit"] = "epoch"
    offset_seconds: int = 0
    partition_by: tuple[FieldRef, ...] = ()
    anchor: FieldRef | None = None
    step: Duration | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "partition_by", tuple(self.partition_by or ()))
        if self.kind in {"tumbling", "sliding", "session"} and self.size is None:
            raise RuleIRValidationError(
                "FRAME_REQUIRES_SIZE", f"Frame(kind={self.kind!r}) needs a size", "frame")
        if self.alignment == "explicit" and self.anchor is None:
            raise RuleIRValidationError(
                "FRAME_REQUIRES_ANCHOR",
                "alignment='explicit' says the window is aligned to something specific, so "
                "that something must be named in `anchor`; without it any origin would be "
                "invented", "frame")
        if self.alignment == "epoch" and self.anchor is not None:
            raise RuleIRValidationError(
                "FRAME_ANCHOR_NOT_APPLICABLE",
                "alignment='epoch' already fixes the origin at the Unix epoch, so `anchor` "
                "has no meaning here; a declared-but-ignored parameter is a parameter that "
                "goes missing unnoticed", "frame")
        if self.kind == "sliding" and self.step is None:
            raise RuleIRValidationError(
                "FRAME_REQUIRES_STEP",
                "a sliding frame needs an advance rate in `step`; a grid advancing by `size` "
                "is a tumbling window under another name, and any other rate is a different "
                "rule, so the kernel will not pick one", "frame")
        if self.kind != "sliding" and self.step is not None:
            raise RuleIRValidationError(
                "FRAME_STEP_NOT_APPLICABLE",
                f"`step` has no meaning for a {self.kind!r} frame, whose advance is already "
                f"fixed by its kind", "frame")


@dataclass(frozen=True)
class ExecutionPolicy:
    """When the rule runs and over what range. A PROGRAM property, not a graph node:
    grouping, execution policy and packaging have no independent result."""

    kind: TypingLiteral["event", "scheduled"] = "event"
    lookback: Duration | None = None
    cadence: Duration | None = None
    late_arrival: Duration | None = None
    state_retention: Duration | None = None

    def __post_init__(self) -> None:
        if self.kind == "scheduled" and self.cadence is None:
            raise RuleIRValidationError(
                "SCHEDULED_REQUIRES_CADENCE",
                "ExecutionPolicy(kind='scheduled') needs a cadence; a missing cadence is "
                "unresolved configuration, never a guessed default", "execution")


# --------------------------------------------------------------------------
# Closed expression algebra
# --------------------------------------------------------------------------
# Scalar values and boolean predicates inside ONE typed row scope. No subqueries, joins,
# state machines, or target-language fragments. `if`, `coalesce`, regex match, string
# containment and CIDR membership are REGISTERED FUNCTIONS, not syntax variants.

Scalar: TypeAlias = str | int | float | bool | None
FunctionID: TypeAlias = str

# Declared null/case/ordering/determinism behaviour per function. A function used in a
# rule but absent here is refused: there is no raw-function escape hatch.
FUNCTION_CONTRACTS: dict[str, dict[str, Any]] = {
    "lower": {"arity": 1, "returns": "string", "null": "null", "deterministic": True},
    "upper": {"arity": 1, "returns": "string", "null": "null", "deterministic": True},
    "concat": {"arity": (1, 8), "returns": "string", "null": "null", "deterministic": True},
    "coalesce": {"arity": (2, 8), "returns": "any", "null": "skips_null", "deterministic": True},
    "if": {"arity": 3, "returns": "any", "null": "branches", "deterministic": True},
    "contains": {"arity": 2, "returns": "boolean", "null": "null", "case": "insensitive_by_default",
                 "deterministic": True},
    "starts_with": {"arity": 2, "returns": "boolean", "null": "null", "deterministic": True},
    "ends_with": {"arity": 2, "returns": "boolean", "null": "null", "deterministic": True},
    "in_set": {"arity": 2, "returns": "boolean", "null": "null", "deterministic": True},
    "matches_regex": {"arity": 2, "returns": "boolean", "null": "null", "dialect": "must_be_declared",
                      "deterministic": True},
    "cidr_contains": {"arity": 2, "returns": "boolean", "null": "null", "deterministic": True},
    "abs": {"arity": 1, "returns": "number", "null": "null", "deterministic": True},
    "round": {"arity": (1, 2), "returns": "number", "null": "null", "rounding": "half_even",
              "deterministic": True},
    "count_distinct": {"arity": 1, "returns": "integer", "null": "counts_nulls", "deterministic": True},
}

#: Functions legal inside a Measure. A scalar expression may not aggregate.
AGGREGATE_FUNCTIONS = frozenset({"count", "count_distinct", "min", "max", "sum", "avg",
                                "values", "make_set", "dcount", "arg_min", "arg_max"})


class Expr:
    """Base for every expression form. Closed by construction: the only subclasses are the
    ones below."""


@dataclass(frozen=True)
class Literal(Expr):
    value: Scalar


@dataclass(frozen=True)
class FieldExpr(Expr):
    ref: FieldRef


@dataclass(frozen=True)
class MeasureExpr(Expr):
    """A named measure. Legal only after the producing Aggregate in the graph path."""

    name: str


@dataclass(frozen=True)
class EventExpr(Expr):
    """A field of a scoped correlated event (left/right of a join, or a pattern stage).
    Legal only inside a Join or Pattern predicate."""

    side: TypingLiteral["left", "right", "stage"]
    stage: str | None
    ref: FieldRef


@dataclass(frozen=True)
class TimeExpr(Expr):
    time_ref: TimeRef


@dataclass(frozen=True)
class Call(Expr):
    function: FunctionID
    args: tuple[Expr, ...] = ()
    #: Which regex dialect a pattern is written in, for functions whose contract says so.
    #: `matches_regex` is unportable without it - `(?i)`, `\d` vs `[[:digit:]]` and
    #: PCRE-vs-POSIX genuinely disagree on real analyst input - so the contract demanded a
    #: declaration that had no field to be declared in, and the kernel could only refuse.
    #: Named values, not free text: an unrecognised dialect is a guess wearing a label.
    dialect: TypingLiteral["pcre", "posix_extended", "posix_basic"] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", tuple(self.args or ()))
        if self.function not in FUNCTION_CONTRACTS:
            raise RuleIRValidationError(
                "UNKNOWN_FUNCTION", f"unknown function {self.function!r}; there is no raw "
                "function-name escape hatch", "expr")
        contract = FUNCTION_CONTRACTS[self.function]
        if contract.get("dialect") == "must_be_declared" and self.dialect is None:
            raise RuleIRValidationError(
                "DIALECT_REQUIRED",
                f"{self.function!r} requires an explicit `dialect`, because its behaviour "
                f"differs between engines and an undeclared one is not portable", "expr")
        if self.dialect is not None and contract.get("dialect") != "must_be_declared":
            raise RuleIRValidationError(
                "DIALECT_NOT_APPLICABLE",
                f"{self.function!r} has no dialect-sensitive behaviour, so declaring one is "
                f"a parameter that would be silently ignored", "expr")


@dataclass(frozen=True)
class Comparison(Expr):
    #: `exists` and `is_not_null` make the ABSENT-vs-NULL distinction ASKABLE. The kernel
    #: preserves it everywhere - a missing key and a present-but-null value are different at
    #: group keys, order keys, set-operation identity and row identity - but with only the six
    #: ordering operators there was no way for an author to ask the question, so "did this
    #: field appear?" was inexpressible. `exists` is about PRESENCE, `is_not_null` about VALUE.
    op: TypingLiteral["=", "!=", "<", "<=", ">", ">=", "exists", "is_not_null"]
    left: Expr
    right: Expr

    def __post_init__(self) -> None:
        if self.op in ("exists", "is_not_null"):
            # These take a boolean right-hand side and nothing else, so a value comparison
            # against one is a mistake rather than a shorthand.
            from models.rule_ir import Literal as _L
            if not isinstance(self.right, _L) or not isinstance(self.right.value, bool):
                raise RuleIRValidationError(
                    "PRESENCE_PREDICATE_NEEDS_BOOLEAN",
                    f"{self.op!r} tests whether a field is present, so its right-hand side "
                    f"must be a boolean literal; got {self.right!r}", "expr")


@dataclass(frozen=True)
class BoolOp(Expr):
    op: TypingLiteral["and", "or", "not"]
    children: tuple[Expr, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "children", tuple(self.children or ()))
        if not self.children:
            raise RuleIRValidationError("EMPTY_BOOLEAN", f"BoolOp(op={self.op!r}) has no children", "expr")
        if self.op == "not" and len(self.children) != 1:
            raise RuleIRValidationError(
                "BOOLEAN_NOT_ARITY",
                f"BoolOp(op='not') must have exactly one child, got {len(self.children)}", "expr")


@dataclass(frozen=True)
class Arith(Expr):
    op: TypingLiteral["+", "-", "*", "/", "%"]
    left: Expr
    right: Expr


@dataclass(frozen=True)
class InList(Expr):
    value: Expr
    options: tuple[Expr, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "options", tuple(self.options or ()))


ConditionExpr: TypeAlias = "Comparison | BoolOp | InList | Call | Literal | FieldExpr | EventExpr | TimeExpr"


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


class RuleIRValidationError(ValueError):
    """Typed rejection carrying a machine-readable code and a path into the IR.

    A generic ValueError is not enough: the refusal code is what a target lowering, a UI
    banner and a regression test all key on.
    """

    def __init__(self, code: str, message: str, path: str | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.path = path

    def __reduce__(self):
        return (self.__class__, (self.code, self.message, self.path))


# --------------------------------------------------------------------------
# Graph nodes: the twelve primitives
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Read:
    """Primitive 1. The only boundary where records, reference data or prior emissions
    enter. Accelerated/reference/prior-emission are STRATEGIES, not subclasses."""

    id: str
    selector: SourceSelector
    bound: Frame | None = None


@dataclass(frozen=True)
class Derive:
    """Primitive 2. Changes a row's values or schema without changing whether the row
    exists. Renames, projections, extensions, casts, typed outcomes."""

    id: str
    input: str
    assignments: tuple[tuple[FieldRef, Expr], ...] = ()
    drop: tuple[FieldRef, ...] = ()
    collision: TypingLiteral["overwrite", "keep_left", "keep_right", "error"] = "error"

    def __post_init__(self) -> None:
        object.__setattr__(self, "assignments", tuple(self.assignments or ()))
        object.__setattr__(self, "drop", tuple(self.drop or ()))


@dataclass(frozen=True)
class Filter:
    """Primitive 3. Changes row membership. A filter over measures is the SAME node with a
    stricter input scope - there is no separate PostAggregationFilter."""

    id: str
    input: str
    condition: Expr


@dataclass(frozen=True)
class Expand:
    """Primitive 4. Changes row MULTIPLICITY. Array unnest, row generation. Missing from
    the earlier node list entirely."""

    id: str
    input: str
    field: FieldRef
    mode: TypingLiteral["unnest", "cross", "generate"] = "unnest"
    alias: str | None = None


@dataclass(frozen=True)
class Aggregate:
    """Primitive 5. Collapses groups into NAMED measures. A measure has NO threshold: a
    threshold is a following Filter over MeasureExpr."""

    id: str
    input: str
    measures: tuple["Measure", ...] = ()
    group_by: tuple[FieldRef, ...] = ()
    frame: Frame | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "measures", tuple(self.measures or ()))
        object.__setattr__(self, "group_by", tuple(self.group_by or ()))
        names = [m.name for m in self.measures]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise RuleIRValidationError(
                "MEASURE_NAME_COLLISION",
                f"measure name(s) {sorted(duplicates)} collide within aggregate {self.id!r}", self.id)


@dataclass(frozen=True)
class Measure:
    """One named measure. `where` makes it conditional - this is how
    `Failed = countif(ResultType != 0), Success = countif(ResultType == 0)` is represented
    without a vendor-specific function.

    `by` is the ORDERING field, and it is what makes `arg_max`/`arg_min` expressible at all:
    "the value of A where B is largest" needs two fields, and with only `field` the intent is
    unrecoverable. Reading `arg_max(f)` as `max(f)` would make it identical to max and pass as
    an implementation while guessing, so the kernel refused - correctly, given this model.
    """

    name: str
    function: str
    field: FieldRef | None = None
    where: Expr | None = None
    distinct: bool = False
    by: FieldRef | None = None

    def __post_init__(self) -> None:
        if self.function not in AGGREGATE_FUNCTIONS:
            raise RuleIRValidationError(
                "UNKNOWN_AGGREGATE_FUNCTION",
                f"aggregate function {self.function!r} is not registered", self.name)
        if self.function in ("arg_max", "arg_min"):
            if self.field is None or self.by is None:
                raise RuleIRValidationError(
                    "ARG_EXTREME_REQUIRES_TWO_FIELDS",
                    f"{self.function!r} returns the value of `field` at the extreme of `by`, so "
                    f"both are required; with one field the intent cannot be recovered without "
                    f"guessing", self.name)
        elif self.by is not None:
            raise RuleIRValidationError(
                "ORDERING_FIELD_NOT_APPLICABLE",
                f"`by` only means something for arg_max/arg_min, and {self.function!r} does "
                f"not use it; a declared-but-ignored parameter is a parameter that goes missing "
                f"unnoticed", self.name)


@dataclass(frozen=True)
class Arrange:
    """Primitive 6. Relation-wide ordering, distinct, offset, limit, top-N. Missing from
    the earlier node list entirely."""

    id: str
    input: str
    order_by: tuple[tuple[Expr, TypingLiteral["asc", "desc"]], ...] = ()
    distinct_on: tuple[FieldRef, ...] = ()
    limit: int | None = None
    offset: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "order_by", tuple(self.order_by or ()))
        object.__setattr__(self, "distinct_on", tuple(self.distinct_on or ()))
        if self.limit is not None and self.limit < 1:
            raise RuleIRValidationError("INVALID_LIMIT", f"Arrange limit must be >= 1, got {self.limit}", self.id)


@dataclass(frozen=True)
class Join:
    """Primitive 7. Combines rows from independent inputs by predicate, optionally with
    time. Equality keys, temporal comparisons, kind, null behaviour, multiplicity and
    fan-out are all explicit, because guessing any of them changes the result."""

    id: str
    left: str
    right: str
    on: Expr
    kind: TypingLiteral["inner", "left", "right", "full", "left_anti", "right_anti"] = "inner"
    cardinality: TypingLiteral["one_to_one", "one_to_many", "many_to_one", "many_to_many"] = "one_to_many"
    unmatched: TypingLiteral["drop", "preserve_left", "preserve_right"] = "drop"
    collision: TypingLiteral["overwrite", "keep_left", "keep_right", "error"] = "error"
    match_key: str | None = None
    match_window: Duration | None = None


@dataclass(frozen=True)
class SetOp:
    """Primitive 8. Combines sibling result sets: union, intersect, except, append.
    Missing from the earlier node list entirely."""

    id: str
    left: str
    right: str
    op: TypingLiteral["union", "intersect", "except", "append", "except_both"]
    all: bool = False


@dataclass(frozen=True)
class Pattern:
    """Primitive 9. Recognises ordered, unordered, absent, repeating or session-related
    event structures. The old `Sequence` was only the positive linear case; `until`,
    missing stages and unordered "two of three" are all in here.

    This is the node that YARA-L cross-event comparison must NOT use: that is a scoped
    expression, not a stage transition.
    """

    id: str
    stages: tuple["Stage", ...] = ()
    mode: TypingLiteral["ordered", "unordered", "missing", "until", "overlapping"] = "ordered"
    key: tuple[FieldRef, ...] = ()
    max_span: Duration | None = None
    min_matches: int = 1
    terminal: TypingLiteral["all", "any"] = "all"

    def __post_init__(self) -> None:
        object.__setattr__(self, "stages", tuple(self.stages or ()))
        object.__setattr__(self, "key", tuple(self.key or ()))
        if not self.stages:
            raise RuleIRValidationError("PATTERN_REQUIRES_STAGES", f"Pattern {self.id!r} has no stages", self.id)
        if self.min_matches < 1:
            raise RuleIRValidationError("INVALID_MIN_MATCHES", "Pattern min_matches must be >= 1", self.id)


@dataclass(frozen=True)
class Stage:
    id: str
    input: str
    quantifier: TypingLiteral["exactly", "at_least", "all", "none"] = "exactly"
    count: int = 1
    within: Duration | None = None


@dataclass(frozen=True)
class Iterate:
    """Primitive 10. Recursive / fixed-point relations: graph closure, path traversal.
    Missing from the earlier node list entirely. This is why the IR is a typed GRAPH, not
    always a DAG."""

    id: str
    input: str
    step: "Derive | Filter | Join | SetOp"
    until: Expr
    max_iterations: int = 32

    def __post_init__(self) -> None:
        if self.max_iterations < 1:
            raise RuleIRValidationError("INVALID_MAX_ITERATIONS", "Iterate max_iterations must be >= 1", self.id)


@dataclass(frozen=True)
class Emit:
    """Primitive 11. The terminal result and alert contract."""

    id: str
    input: str
    columns: tuple[FieldRef, ...] = ()
    dedupe_by: tuple[FieldRef, ...] = ()
    cooldown: Duration | None = None
    order_by: tuple[tuple[Expr, TypingLiteral["asc", "desc"]], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "columns", tuple(self.columns or ()))
        object.__setattr__(self, "dedupe_by", tuple(self.dedupe_by or ()))
        object.__setattr__(self, "order_by", tuple(self.order_by or ()))


IRNode: TypeAlias = "Read | Derive | Filter | Expand | Aggregate | Arrange | Join | SetOp | Pattern | Iterate | Emit"

PRIMITIVE_NAMES = ("Read", "Derive", "Filter", "Expand", "Aggregate", "Arrange",
                   "Join", "SetOp", "Pattern", "Iterate", "Emit")


# --------------------------------------------------------------------------
# Envelopes: NOT graph nodes
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ParseLoss:
    """A construct the parser could not represent. Severity 'must' blocks `exact`."""

    code: str
    severity: TypingLiteral["must", "should", "advisory"]
    message: str
    source_span: tuple[int, int] | None = None
    affected_targets: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.severity not in {"must", "should", "advisory"}:
            raise RuleIRValidationError("INVALID_LOSS_SEVERITY", f"bad severity {self.severity!r}", self.code)


@dataclass(frozen=True)
class SourceArtifact:
    """The original pasted text, preserved verbatim. Never regenerated from a projection."""

    target: str
    media_type: str
    raw_text: str
    sha256: str
    parser: str
    parser_version: str


@dataclass(frozen=True)
class RulePackage:
    """Packaging: one or more deployable units with ids and a dependency graph.

    A Wazuh parent/child bundle is THIS, not a graph node. It is not a primitive because it
    has no independent result. Dependency cycles are rejected.
    """

    schema_version: str = SCHEMA_VERSION
    rule_id: str = ""
    title: str = ""
    description: str = ""
    units: tuple[dict[str, Any], ...] = ()
    dependencies: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "units", tuple(self.units or ()))
        object.__setattr__(self, "dependencies", tuple(self.dependencies or ()))
        known = {u.get("id") for u in self.units}
        for src, dst in self.dependencies:
            for endpoint in (src, dst):
                if endpoint not in known:
                    raise RuleIRValidationError(
                        "UNKNOWN_PACKAGE_UNIT",
                        f"dependency endpoint {endpoint!r} is not a unit in this package", "package")
        if _has_cycle({s: d for s, d in self.dependencies}):
            raise RuleIRValidationError("PACKAGE_DEPENDENCY_CYCLE",
                                        "package dependencies form a cycle", "package")


@dataclass(frozen=True)
class RuleIR:
    """A complete rule: one executable graph, plus its execution and package envelopes."""

    rule_id: str
    title: str = ""
    description: str = ""
    nodes: tuple[IRNode, ...] = ()
    output: str = ""
    execution: ExecutionPolicy = field(default_factory=ExecutionPolicy)
    package: RulePackage | None = None
    source_artifacts: tuple[SourceArtifact, ...] = ()
    parse_diagnostics: tuple[ParseLoss, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "nodes", tuple(self.nodes or ()))
        object.__setattr__(self, "source_artifacts", tuple(self.source_artifacts or ()))
        object.__setattr__(self, "parse_diagnostics", tuple(self.parse_diagnostics or ()))


def _has_cycle(edges: dict[str, str]) -> bool:
    seen: set[str] = set()

    def walk(node: str) -> bool:
        if node in seen:
            return True
        seen.add(node)
        nxt = edges.get(node)
        return bool(nxt) and walk(nxt)

    return any(walk(start) for start in edges)


# --------------------------------------------------------------------------
# The validator
# --------------------------------------------------------------------------

#: Inputs each primitive produces a relation from (vs. a scalar). A Join needs relations.
_RELATION_PRIMITIVES = frozenset({"Read", "Derive", "Filter", "Expand", "Aggregate",
                                  "Arrange", "Join", "SetOp", "Pattern", "Iterate"})


#: The one place a primitive name is bound to its concrete class.
#:
#: This used to be duplicated in `rule_capabilities` and again in `kernel/eval_types`, while
#: `validate_ir` identified nodes by `node.__class__.__name__`. Three copies of one fact, and
#: they disagreed: the validator ACCEPTED a lookalike class that the resolver then REFUSED, so
#: one graph produced two different answers and the disagreement fell in the direction that
#: decides deployability. A hand-written second copy of a vocabulary is guaranteed to drift -
#: it is how a 21-entry comparison allowlist came to certify fifteen operators this model
#: cannot express. So the mapping lives here, once, and every layer imports it.
NODE_TYPES: Mapping[str, type] = MappingProxyType({
    "Read": Read, "Derive": Derive, "Filter": Filter, "Expand": Expand,
    "Aggregate": Aggregate, "Arrange": Arrange, "Join": Join, "SetOp": SetOp,
    "Pattern": Pattern, "Iterate": Iterate, "Emit": Emit,
})


def primitive_of(node: Any) -> str | None:
    """The primitive this node IS, or None if it is not a kernel node at all.

    Exact type identity, never the class name: a plain class called `Read` with none of the
    real fields must not be treated as a Read by any layer.
    """
    for name, cls in NODE_TYPES.items():
        if type(node) is cls:
            return name
    return None


def _inputs_of(node: IRNode) -> list[tuple[str, str]]:
    """(input_id, role) pairs referenced by a node."""
    out: list[tuple[str, str]] = []
    if isinstance(node, (Derive, Filter, Expand, Iterate, Emit)):
        out.append((node.input, "input"))
    elif isinstance(node, Aggregate):
        out.append((node.input, "input"))
    elif isinstance(node, Arrange):
        out.append((node.input, "input"))
    elif isinstance(node, Join):
        out.extend([(node.left, "left"), (node.right, "right")])
    elif isinstance(node, SetOp):
        out.extend([(node.left, "left"), (node.right, "right")])
    elif isinstance(node, Pattern):
        out.extend((s.input, f"stage:{s.id}") for s in node.stages)
    return out


def validate_ir(ir: RuleIR, *, target: str | None = None) -> None:
    """Validate structure, references and scope. Raises RuleIRValidationError.

    `target` enables the cross-target check: a graph whose source or fields are unresolved
    is structurally valid but not deployable, and must be refused rather than rendered with
    a guessed name.

    SIZE IS BOUNDED HERE, NOT BY THE CALLER. The graph and expression walks below recurse, so
    a legal but very large graph exhausts the interpreter stack. A caller that catches
    RecursionError is patching a symptom, and only this one does: the v1 adapter and the
    capability layer both call `validate_ir` and neither had that guard, so a deep graph
    crashed in both. A refusal with a code is a better answer than a stack trace.
    """
    if ir.schema_version != SCHEMA_VERSION:
        raise RuleIRValidationError(
            "INVALID_SCHEMA_VERSION", f"schema_version must be {SCHEMA_VERSION!r}, got {ir.schema_version!r}",
            "ir")

    if len(ir.nodes) > MAX_GRAPH_NODES:
        raise RuleIRValidationError(
            "GRAPH_TOO_LARGE",
            f"the graph has {len(ir.nodes)} nodes, above the {MAX_GRAPH_NODES}-node bound; "
            f"refusing rather than walking a structure that cannot be checked in bounded time",
            "nodes")

    by_id: dict[str, IRNode] = {}
    for node in ir.nodes:
        # Exact type identity, via the single shared NODE_TYPES. The previous check was
        # `isinstance(node, tuple(PRIMITIVE_NAMES and ()))`, which evaluates
        # `isinstance(node, ())` - always False - so it never tested anything and fell through
        # to `node.__class__.__name__`. A lookalike class was therefore accepted here and then
        # refused by the resolver: one graph, two answers.
        if primitive_of(node) is None:
            raise RuleIRValidationError(
                "INVALID_NODE_TYPE",
                f"{type(node).__name__!r} is not a RuleIR primitive; node identity is decided "
                f"by exact type, not by class name, so a lookalike cannot pass", "nodes")
        if node.id in by_id:
            raise RuleIRValidationError("DUPLICATE_NODE_ID", f"duplicate node id: {node.id!r}", node.id)
        by_id[node.id] = node

    for node in ir.nodes:
        for ref, _role in _inputs_of(node):
            if ref not in by_id:
                raise RuleIRValidationError(
                    "DANGLING_NODE_REF", f"dangling node reference: {ref!r}", node.id)

    edges = {node.id: [ref for ref, _role in _inputs_of(node)] for node in ir.nodes}
    if _graph_cycle(edges):
        raise RuleIRValidationError("GRAPH_CYCLE", "graph contains a cycle", "nodes")

    if not ir.output:
        raise RuleIRValidationError("MISSING_OUTPUT", "RuleIR.output must name the terminal node", "ir")
    if ir.output not in by_id:
        raise RuleIRValidationError("DANGLING_NODE_REF", f"dangling node reference: {ir.output!r}", "output")
    if by_id[ir.output].__class__.__name__ != "Emit":
        raise RuleIRValidationError(
            "OUTPUT_MUST_EMIT", f"output must be an Emit node, got {by_id[ir.output].__class__.__name__}",
            ir.output)

    for node in ir.nodes:
        kind = node.__class__.__name__
        if kind == "Join":
            for side in (node.left, node.right):
                if by_id[side].__class__.__name__ not in _RELATION_PRIMITIVES:
                    raise RuleIRValidationError(
                        "JOIN_INPUT_NOT_RELATION",
                        f"join input {side!r} is not a relation", node.id)
        if kind == "Filter":
            visible = _visible_measures(node.input, by_id)
            _require_scope(node.condition, by_id, node, allow_measures=visible is not None,
                           allow_events=False, path=node.id)
            if visible is not None:
                _require_known_measures(node.condition, visible, node.id)
        if kind == "Aggregate":
            for measure in node.measures:
                if measure.where is not None:
                    _require_scope(measure.where, by_id, node, allow_measures=False,
                                   allow_events=False, path=f"{node.id}.{measure.name}")
        if kind == "Pattern":
            known = {s.id for s in node.stages}
            for stage in node.stages:
                _require_scope(Literal(True), by_id, node, allow_measures=False,
                               allow_events=True, path=f"{node.id}.{stage.id}")
            del known

    if target is not None:
        _require_resolved(ir, by_id, target)
    for loss in ir.parse_diagnostics:
        if loss.severity == "must":
            continue


def _produces_measures(node_id: str, by_id: dict[str, IRNode]) -> bool:
    return by_id.get(node_id).__class__.__name__ == "Aggregate"


def _graph_cycle(edges: dict[str, list[str]]) -> bool:
    """True if the graph contains a cycle.

    Recursion is a first-class primitive, so cycles are legal WITHIN an Iterate step. They
    are not legal in the plan graph, where a cycle means the nodes can never be ordered
    into an execution.
    """
    WHITE, GREY, BLACK = 0, 1, 2
    colour: dict[str, int] = {}

    def visit(node: str) -> bool:
        state = colour.get(node, WHITE)
        if state == GREY:
            return True
        if state == BLACK:
            return False
        colour[node] = GREY
        for nxt in edges.get(node, ()):
            if visit(nxt):
                return True
        colour[node] = BLACK
        return False

    # NOTE: this walk is still recursive and is bounded only indirectly, by
    # MAX_GRAPH_NODES above. A depth counter was tried here and removed: it could not be shown
    # to fire even at a bound of 5, so it was decorative. Recursion here is a DFS whose depth
    # is bounded by the node count, and MAX_GRAPH_NODES is what actually keeps it finite.
    # The honest gap is that the bound is INDIRECT, and it stays on the record as such rather
    # than being papered over with a guard that does not work.
    return any(visit(node) for node in edges)


def _visible_measures(node_id: str, by_id: dict[str, IRNode]) -> set[str] | None:
    """Measure names visible at this point, or None when no aggregate precedes it.

    Scope is positional in the dataflow, not lexical: measures are visible only directly
    downstream of the aggregate that produced them, which is why a sibling aggregate's
    measure cannot be referenced through a different branch.
    """
    node = by_id.get(node_id)
    if node is None:
        return None
    if node.__class__.__name__ == "Aggregate":
        return {m.name for m in node.measures}
    return None


def _require_known_measures(expr: Expr, visible: set[str], path: str) -> None:
    if isinstance(expr, MeasureExpr) and expr.name not in visible:
        raise RuleIRValidationError(
            "UNKNOWN_MEASURE_REFERENCE",
            f"measure {expr.name!r} is not produced by the aggregate feeding this filter; "
            f"available: {sorted(visible)}", path)
    for child in _expr_children(expr):
        _require_known_measures(child, visible, path)


def _require_scope(expr: Expr, by_id: dict[str, IRNode], owner: IRNode, *, allow_measures: bool,
                   allow_events: bool, path: str, depth: int = 0) -> None:
    if depth > MAX_EXPRESSION_DEPTH:
        # Recursion over nested expressions. Without this the walk raises RecursionError out of
        # a function whose contract is to raise with a code, and a ~3,000-deep expression did
        # exactly that. Refusing names the limit; a stack trace names nothing.
        raise RuleIRValidationError(
            "EXPRESSION_TOO_DEEP",
            f"the expression nests more than {MAX_EXPRESSION_DEPTH} levels; refusing rather "
            f"than exhausting the call stack", path)
    """Walk an expression rejecting refs that are not legal in this scope."""
    if isinstance(expr, MeasureExpr) and not allow_measures:
        raise RuleIRValidationError(
            "MEASURE_OUT_OF_SCOPE",
            f"measure {expr.name!r} is not visible here; only a filter directly downstream "
            f"of an aggregate may reference measures", path)
    if isinstance(expr, EventExpr) and not allow_events:
        raise RuleIRValidationError(
            "EVENT_REF_OUT_OF_SCOPE",
            f"event-scoped reference on side {expr.side!r} is only legal inside a join or pattern",
            path)
    for child in _expr_children(expr):
        _require_scope(child, by_id, owner, allow_measures=allow_measures,
                       allow_events=allow_events, path=path, depth=depth + 1)


def _expr_children(expr: Expr) -> list[Expr]:
    if isinstance(expr, (Comparison, Arith)):
        return [expr.left, expr.right]
    if isinstance(expr, BoolOp):
        return list(expr.children)
    if isinstance(expr, Call):
        return list(expr.args)
    if isinstance(expr, InList):
        return [expr.value, *expr.options]
    return []


def _require_resolved(ir: RuleIR, by_id: dict[str, IRNode], target: str) -> None:
    """Cross-target deployability: nothing unresolved may reach a rendered artifact."""
    for node in ir.nodes:
        if node.__class__.__name__ == "Read":
            if node.selector.name is None:
                raise RuleIRValidationError(
                    "UNRESOLVED_SOURCE",
                    f"source of {node.id!r} is unresolved; refusing to invent a table or index "
                    f"for {target}", node.id)
            if node.selector.strategy == "accelerated" and not node.selector.schema_id:
                raise RuleIRValidationError(
                    "ACCELERATED_SOURCE_WITHOUT_SCHEMA",
                    f"accelerated source {node.id!r} names no schema/summary contract", node.id)
    for loss in ir.parse_diagnostics:
        if loss.severity == "must":
            raise RuleIRValidationError(
                "MUST_LOSS", f"unresolved construct: {loss.message}", loss.code)


# --------------------------------------------------------------------------
# Normalisation helper - the ONLY sanctioned way a v1 name changes
# --------------------------------------------------------------------------


def canonical_operator(operator: str) -> tuple[str, bool]:
    """Map a v1/Sigma operator to the canonical vocabulary.

    Returns (canonical, changed) so a caller can RECORD the change. Returning a bool is
    the point: a silent alias map is how a wrong operator reaches a generated rule.
    """
    text = (operator or "").strip()
    canonical = OPERATOR_ALIASES.get(text, text)
    return canonical, canonical != text


def explain(ir: RuleIR) -> str:
    """A short structural summary, for the UI outline and for diffs."""
    counts: dict[str, int] = {}
    for node in ir.nodes:
        name = node.__class__.__name__
        counts[name] = counts.get(name, 0) + 1
    order = [name for name in PRIMITIVE_NAMES if name in counts]
    parts = [name if counts[name] == 1 else f"{name} x{counts[name]}" for name in order]
    unresolved = sum(1 for n in ir.nodes if n.__class__.__name__ == "Read" and n.selector.name is None)
    tail = f"  [unresolved source: {unresolved}]" if unresolved else ""
    return " -> ".join(parts) + tail
