"""RuleForge typed intermediate representation.

WHAT THIS IS

The single neutral form that every vendor syntax parses into and every vendor
syntax renders from. It exists so that the five supported SIEMs are five
front-ends onto one engine rather than five engines.

    Wazuh XML ─┐
    SPL       ─┤
    KQL       ─┼──▶  THIS  ──┬──▶ author / tune / debug / understand
    AQL       ─┤             │
    YARA-L    ─┘             └──▶ render back to any supported syntax

WHY CONSTRUCTION-TIME VALIDATION

Every node refuses to be built if it cannot mean anything. This is not
defensiveness for its own sake; it is that a detection rule is deployed into a
security pipeline, and a rule that is subtly malformed fails open or fails closed
in production. Better to refuse to construct than to construct something whose
meaning is ambiguous.

Concretely, this is why `Frame(kind="sliding")` cannot exist without a step:

    A sliding window with a size but no advance rate is two different operators
    wearing one name. A grid advancing by the size is a tumbling window. A grid
    advancing by less is a sliding one. They disagree about which rows belong
    together, so which bucket an event lands in changes, so the alert changes.

    Rather than pick one, the frame cannot be built.

The same reasoning applies to every other required-parameter rule in this file.

CLOSED, NOT EXTENSIBLE-BY-CONVENTION

The operator and function vocabularies are defined once, here, and everything
else imports them. The moment a second copy of that list exists anywhere in the
codebase, the parser and the renderer will eventually disagree about whether an
operator is valid, and that disagreement surfaces as a rule that parses on one
path and renders on another.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Final, Literal as TypingLiteral

from .values import Refusal

#: Which regex dialects can actually be EXECUTED lives in `regex.py`, next to the
#: engine that implements them, and is re-exported here for convenience.
#:
#: It used to be DEFINED HERE as well, giving two copies: one in the capability
#: surface and one in the guard that enforces it. That is precisely the drift
#: this file's own header warns about, and the review found it. One definition,
#: imported everywhere.
from .regex import EXECUTABLE_DIALECTS  # noqa: E402,F401  (re-exported)

SCHEMA_VERSION: Final = "1.0"

# --------------------------------------------------------------------------
# Closed vocabularies. Defined once. Imported everywhere.
# --------------------------------------------------------------------------

FRAME_KINDS: Final = frozenset({
    "tumbling", "sliding", "per_event", "cumulative", "session",
})

FRAME_ALIGNMENTS: Final = frozenset({
    "epoch",        # buckets start at 0, the Unix epoch
    "explicit",     # buckets start at a declared anchor field
})

#: Kinds that advance on a declared step rather than by their own size. A sliding
#: frame emits OVERLAPPING windows on that grid, which is why it is a separate
#: operator from tumbling rather than a variant: consecutive windows share rows, so
#: the row count in any window differs, and so the alert differs.
STEP_ONLY_KINDS: Final = frozenset({"sliding"})

ANCHOR_ONLY_ALIGNMENTS: Final = frozenset({"explicit"})

ORDERING_OPS: Final = frozenset({"=", "!=", "<", "<=", ">", ">="})

PRESENCE_OPS: Final = frozenset({"exists", "is_not_null", "is_null"})

BOOL_OPS: Final = frozenset({"and", "or"})

ARITH_OPS: Final = frozenset({"+", "-", "*", "/"})

#: Aggregates that read a single field.
SINGLE_FIELD_AGGREGATES: Final = frozenset({
    "min", "max", "avg", "sum", "first", "last", "stddev",
    # `set` collects the DISTINCT values into a collection rather than counting
    # them. Sentinel's `make_set(SourceIp)` is exactly this, and it appears in the
    # user's rule as a projected column. Without it the column would be dropped,
    # which is a silent loss of something the rule explicitly asked for.
    "set",
})

#: Aggregates that need a value field AND a separate ordering field, because
#: "the value of A where B is largest" is two fields. Reading arg_max(f) as
#: max(f) would make it identical to max and pass as an implementation while
#: quietly changing what the rule means.
TWO_FIELD_AGGREGATES: Final = frozenset({"arg_min", "arg_max"})

#: Aggregates that read one field and count its distinct values. Separate from
#: `count_distinct` because the two names are transpositions of each other, and a
#: parser that maps `COUNT(DISTINCT x)` to the wrong one produces a confidently
#: wrong number under a plausible name.
SINGLE_FIELD_DISTINCT: Final = frozenset({"count_distinct", "distinct_count"})

#: Aggregates that read no field at all.
NULLARY_AGGREGATES: Final = frozenset({"count"})

AGGREGATES: Final = (
    SINGLE_FIELD_AGGREGATES | SINGLE_FIELD_DISTINCT
    | TWO_FIELD_AGGREGATES | NULLARY_AGGREGATES
)

#: Aggregates whose output is order-dependent, so a tie between two rows has no
#: single correct answer. Ties must be broken explicitly or the result depends on
#: evaluation order, which is a silent nondeterminism.
ORDER_DEPENDENT_AGGREGATES: Final = frozenset({
    "first", "last", "arg_min", "arg_max",
})

# --------------------------------------------------------------------------
# Functions
# --------------------------------------------------------------------------

#: name -> (min_args, max_args, case_insensitive, needs_dialect)
#:
#: `case_insensitive` is declared rather than assumed because it is a real
#: behavioural difference: `contains` folding case and `starts_with` not folding
#: it is the kind of detail that silently changes which rows match.
FUNCTIONS: Final[dict[str, tuple[int, int, bool, bool]]] = {
    "lower":        (1, 1, False, False),
    "upper":        (1, 1, False, False),
    "concat":       (1, None, False, False),
    "contains":     (2, 2, True,  False),
    "starts_with":  (2, 2, False, False),
    "ends_with":    (2, 2, False, False),
    "in_set":       (2, None, False, False),
    "matches_regex": (2, 2, False, True),
    "cidr_contains": (2, 2, False, False),
    "length":       (1, 1, False, False),
    "coalesce":     (1, None, False, False),
    "abs":          (1, 1, False, False),
    "round":        (1, 2, False, False),
}

#: Dialects that may be DECLARED. A declaration records the analyst's intent
#: faithfully even when no engine honours it, because losing the declaration
#: would lose information the analyst explicitly provided.
REGEX_DIALECTS: Final = frozenset({"pcre", "posix_extended", "posix_basic"})

#: Pattern MODIFIERS, carried as data on the node rather than baked into the
#: pattern text. Rewriting the pattern to `(?i)...` would change the analyst's
#: bytes and break the render round-trip; dropping the modifier would silently
#: make the rule case-sensitive, so `/lsass/i` would stop matching `LSASS.EXE`.
#: Every platform spells this differently -- YARA-L and YARA write
#: `/pattern/ nocase`, Splunk writes `field="*pattern*"`, SQL uses ILIKE -- so
#: holding it as a node attribute is the only way a render can round-trip.
REGEX_FLAGS: Final = frozenset({"nocase"})

#: Dialects the evaluator can actually run. Kept separate from REGEX_DIALECTS on
#: purpose: a dialect can be declared without being executable, and conflating
#: them lets a declared-but-unimplemented dialect reach a comparison and produce
#: a definitive wrong answer where a refusal was owed.

#: Node registry. The single source of truth for what a graph may contain.
#:
#: `Frame` is deliberately NOT here. It is a PARAMETER of Aggregate, not a graph
#: node, and listing it made the "every registered node must be executable" check
#: fail for a type that was never supposed to be executed on its own.
NODE_TYPES: Final = frozenset({
    "Read", "Filter", "Derive", "Aggregate", "Arrange",
    "SetOp", "Join", "Expand", "Pattern", "Package", "Emit",
})

#: Structural bounds. Enforced during validation, and each has a test that
#: constructs an over-limit graph and asserts the refusal.
MAX_NODES: Final = 500
MAX_EXPRESSION_DEPTH: Final = 100
MAX_FIELD_PATH: Final = 32

# --------------------------------------------------------------------------
# Expressions
# --------------------------------------------------------------------------


#: Functions whose result is a PREDICATE, not a value. These may stand alone as a
#: filter condition, because "does this field match this pattern" is a question
#: with a yes/no answer and there is nothing left to compare it against.
#:
#: Modelled explicitly because getting it wrong is silent. Writing the same rule as
#: `a = matches_regex(a, "^x")` looks reasonable and evaluates as "is the string
#: xyz equal to the boolean True", which is UNDECIDED on every row -- so the rule
#: quietly matches nothing instead of erroring.
BOOLEAN_FUNCTIONS: Final = frozenset({
    "matches_regex", "cidr_contains",
    # `contains`, `starts_with` and `ends_with` are PREDICATES too, not value
    # producers. An AQL `ILIKE '%x%'` lowers to `contains`, and that lowered rule
    # was then REFUSED by the validator with PREDICATE_INCOMPLETE -- so the one
    # adapter in the tree produced IR the engine would not run, and its own test
    # passed because it inspected the IR instead of evaluating it. A function that
    # returns yes/no must be usable as yes/no.
    "contains", "starts_with", "ends_with",
    "in_set",
})


@dataclass(frozen=True, slots=True)
class Not:
    """Logical negation of a predicate.

    Existed in no form until now. `aql_ir` imported it and the import failed, so
    `NOT a = 1` raised ImportError instead of a named refusal -- and negation is
    needed by every dialect: YARA-L's `condition` section, SQL's `NOT`, and the
    ordinary analyst writing "everything except".

    Negation is three-valued by construction: NOT UNDECIDED is UNDECIDED, never
    True. Turning "we could not decide" into "definitely false" is how a rule
    starts matching rows it never examined.
    """

    operand: Any

    def __post_init__(self) -> None:
        if isinstance(self.operand, (Comparison, BoolOp, Not)):
            return
        if isinstance(self.operand, Call) and \
                self.operand.function in BOOLEAN_FUNCTIONS:
            # `NOT (a contains_regex b)` is a predicate. Rejecting it would make
            # `NOT ILIKE '%x%'` -- ordinary AQL, and ordinary YARA-L -- unbuildable.
            return
        raise Refusal(
            "PREDICATE_INCOMPLETE",
            f"NOT needs a predicate, not {type(self.operand).__name__}", "Not")


@dataclass(frozen=True, slots=True)
class FieldRef:
    """A reference to a field by its literal, as-written name.

    Names are never rewritten, normalised, or mapped. `win.eventdata.targetImage`
    stays exactly that. The analyst wrote it, the SIEM will look for that, and any
    transformation in between is a place where a rule silently stops matching.
    """

    name: str
    path: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise Refusal("FIELD_REF_EMPTY", "a field reference needs a name", "expr")
        if len(self.path) > MAX_FIELD_PATH:
            raise Refusal(
                "FIELD_PATH_TOO_DEEP",
                f"field path has {len(self.path)} segments, limit is {MAX_FIELD_PATH}",
                "expr")

    @property
    def full(self) -> str:
        return ".".join((self.name, *self.path)) if self.path else self.name


@dataclass(frozen=True, slots=True)
class Literal:
    """A constant written directly in the rule."""

    value: Any

    def __post_init__(self) -> None:
        if isinstance(self.value, float):
            # Normalise to Decimal at construction so a literal compared later
            # cannot drift on float representation.
            object.__setattr__(self, "value", Decimal(str(self.value)))


@dataclass(frozen=True, slots=True)
class FieldExpr:
    ref: FieldRef


@dataclass(frozen=True, slots=True)
class Call:
    """A function application.

    `dialect` is required exactly when the function's behaviour differs between
    engines. `matches_regex` is the case that matters: `\\d`, `[[:digit:]]`, `\\b`
    and inline flags all mean different things in PCRE and POSIX, so a regex
    without a declared dialect is not a portable rule and cannot be built.

    `flags` carries MODIFIERS, which are separate from the pattern text and
    separate from the dialect. YARA-L writes `/\\lsass\\.exe$/ nocase`; YARA and
    Splunk write `(?i)`. Two honest options existed and both were wrong:

      * bake `(?i)` into the pattern string -- preserves the matched language
        exactly, but REWRITES the analyst's bytes, so the render no longer
        round-trips and a diff against the pasted rule shows a change the author
        never made;
      * drop the modifier -- the rule silently becomes case-SENSITIVE, and
        `/lsass/i` starts failing to match `LSASS.EXE`.

    So the modifier is carried as data, on the node, and rendered back in the
    vendor's own syntax. The pattern is never rewritten.
    """

    function: str
    args: tuple[Any, ...]
    dialect: TypingLiteral["pcre", "posix_extended", "posix_basic"] | None = None
    flags: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        contract = FUNCTIONS.get(self.function)
        if contract is None:
            raise Refusal(
                "UNKNOWN_FUNCTION", f"{self.function!r} is not a known function",
                "Call")
        lo, hi, _case, needs_dialect = contract
        if len(self.args) < lo or (hi is not None and len(self.args) > hi):
            allowed = f"{lo}" if hi == lo else (
                f"{lo} or more" if hi is None else f"{lo} to {hi}")
            raise Refusal(
                "FUNCTION_ARITY_VIOLATION",
                f"{self.function!r} takes {allowed} argument(s), got {len(self.args)}",
                "Call")
        if needs_dialect and self.dialect is None:
            raise Refusal(
                "DIALECT_REQUIRED",
                f"{self.function!r} behaves differently between engines, so it needs an "
                f"explicit dialect. An undeclared one is not portable.", "Call")
        if not needs_dialect and self.dialect is not None:
            raise Refusal(
                "DIALECT_NOT_APPLICABLE",
                f"{self.function!r} has no dialect-sensitive behaviour, so declaring one "
                f"would be a parameter that is silently ignored", "Call")
        if self.dialect is not None and self.dialect not in REGEX_DIALECTS:
            raise Refusal(
                "DIALECT_UNKNOWN",
                f"{self.dialect!r} is not one of {sorted(REGEX_DIALECTS)}", "Call")

        unknown = self.flags - REGEX_FLAGS
        if unknown:
            raise Refusal(
                "REGEX_FLAG_UNKNOWN",
                f"{sorted(unknown)} is not a supported modifier; supported modifiers "
                f"are {sorted(REGEX_FLAGS)}. An unrecognised modifier would be "
                f"dropped on render, quietly changing what the rule matches.", "Call")
        if self.flags and not needs_dialect:
            raise Refusal(
                "REGEX_FLAG_NOT_APPLICABLE",
                f"{self.function!r} takes no modifiers, so declaring "
                f"{sorted(self.flags)} would be a parameter that is silently ignored",
                "Call")
        if "nocase" in self.flags and self.dialect not in EXECUTABLE_DIALECTS:
            # Not a refusal -- an explicit note. The modifier is RECORDED so the
            # rule renders correctly and QRadar runs it correctly; this tool simply
            # cannot execute it, which it will say when asked.
            pass


@dataclass(frozen=True, slots=True)
class Comparison:
    """A predicate.

    Presence operators (`exists`, `is_not_null`) take a boolean right-hand side
    only. Comparing a presence question to a value is a mistake, not a
    shorthand, and accepting `"5" exists "5"` would let it through.
    """

    op: str
    left: Any
    right: Any
    side: TypingLiteral["left", "right"] = "left"

    def __post_init__(self) -> None:
        if self.op in ORDERING_OPS or self.op in PRESENCE_OPS:
            return
        raise Refusal(
            "UNKNOWN_COMPARISON_OPERATOR",
            f"{self.op!r} is not an operator; expected one of "
            f"{sorted(ORDERING_OPS | PRESENCE_OPS)}", "Comparison")

    @property
    def is_presence(self) -> bool:
        return self.op in PRESENCE_OPS


@dataclass(frozen=True, slots=True)
class BoolOp:
    op: TypingLiteral["and", "or"]
    operands: tuple[Any, ...]

    def __post_init__(self) -> None:
        if self.op not in BOOL_OPS:
            raise Refusal("UNKNOWN_BOOL_OPERATOR", f"{self.op!r} is not and/or", "BoolOp")
        if len(self.operands) < 2:
            raise Refusal(
                "BOOL_ARITY", f"{self.op!r} needs at least 2 operands, "
                f"got {len(self.operands)}", "BoolOp")


@dataclass(frozen=True, slots=True)
class Arith:
    op: TypingLiteral["+", "-", "*", "/"]
    operands: tuple[Any, ...]

    def __post_init__(self) -> None:
        if self.op not in ARITH_OPS:
            raise Refusal("UNKNOWN_ARITHMETIC_OPERATOR", f"{self.op!r}", "Arith")
        if len(self.operands) < 2:
            raise Refusal("ARITH_ARITY", f"{self.op!r} needs 2+ operands", "Arith")


# --------------------------------------------------------------------------
# Supporting value objects
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Duration:
    """A span of time.

    Zero is permitted. A temporal join's lower bound is legitimately zero -- "a
    logon from zero to ten minutes after the access" is the ordinary reading, and
    refusing Duration(0) made the most common temporal predicate unbuildable.
    Positivity is required where it actually matters, at the point of use: a
    window's SIZE must be positive, checked in Frame, because a zero-length window
    contains nothing.

    An earlier version refused zero outright, which pushed every zero lower bound
    to be expressed as a one-second bound -- an off-by-one that quietly shifted a
    boundary rather than being visible.
    """

    seconds: Decimal

    def __post_init__(self) -> None:
        if self.seconds < 0:
            raise Refusal(
                "DURATION_NEGATIVE",
                f"a duration cannot be negative, got {self.seconds}", "Duration")

    @property
    def is_positive(self) -> bool:
        return self.seconds > 0

    @classmethod
    def parse(cls, text: str) -> "Duration":
        """Parse `30s`, `5m`, `2h`, `7d` as vendors write them."""
        raw = text.strip().lower()
        units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        if raw and raw[-1] in units and raw[:-1].replace(".", "", 1).isdigit():
            return cls(Decimal(raw[:-1]) * units[raw[-1]])
        if raw.isdigit():
            return cls(Decimal(raw))
        raise Refusal(
            "DURATION_UNPARSEABLE",
            f"{text!r} is not a duration; expected something like 30s, 5m, 2h or 7d",
            "Duration")

    def __str__(self) -> str:
        seconds = self.seconds
        for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
            if seconds >= size and seconds % size == 0:
                return f"{int(seconds // size)}{unit}"
        return f"{int(seconds)}s"


@dataclass(frozen=True, slots=True)
class TimeRef:
    """Which field carries the event timestamp.

    Never defaulted. A rule with no declared time field cannot be windowed, and
    guessing which field is the timestamp is how a rule ends up bucketed by an
    unrelated column.
    """

    field_name: str

    def __post_init__(self) -> None:
        if not self.field_name.strip():
            raise Refusal("TIME_REF_EMPTY", "a time reference needs a field name",
                          "TimeRef")

    def as_ref(self) -> FieldRef:
        """This time reference as a plain field reference.

        So a window reads its timestamp through the SAME resolver as every other
        field. A blanket substitution once routed a TimeRef into a resolver that
        wanted a FieldRef, and every windowed rule failed with an AttributeError.
        Two ways to name a field is exactly the ambiguity to remove.
        """
        return FieldRef(self.field_name)


@dataclass(frozen=True, slots=True)
class Frame:
    """A windowing strategy for aggregation.

    The three refusals here are the load-bearing part:

      * sliding without `step`      two different operators, one name
      * step on a non-sliding kind  a parameter that would be ignored
      * explicit without `anchor`   alignment with no stated origin
      * anchor on a non-explicit    a parameter that would be ignored
    """

    kind: TypingLiteral["tumbling", "sliding", "per_event", "cumulative",
                        "session"] = "tumbling"
    size: Duration | None = None
    time_ref: TimeRef | None = None
    step: Duration | None = None
    alignment: TypingLiteral["epoch", "explicit"] = "epoch"
    anchor: FieldRef | None = None
    offset: Duration | None = None
    gap: Duration | None = None

    def __post_init__(self) -> None:
        if self.kind not in FRAME_KINDS:
            raise Refusal("FRAME_KIND_UNKNOWN",
                          f"{self.kind!r} is not a frame kind; expected one of "
                          f"{sorted(FRAME_KINDS)}", "Frame")

        if self.kind in STEP_ONLY_KINDS:
            if self.step is None:
                raise Refusal(
                    "FRAME_REQUIRES_STEP",
                    "a sliding frame needs an advance rate. A grid advancing by the "
                    "size is a tumbling window under another name, so the two are not "
                    "interchangeable and this cannot be built without saying which.",
                    "Frame")
        elif self.step is not None:
            raise Refusal(
                "FRAME_STEP_NOT_APPLICABLE",
                f"a {self.kind} frame has no advance rate, so `step` would be declared "
                f"and then ignored", "Frame")

        if self.alignment in ANCHOR_ONLY_ALIGNMENTS:
            if self.anchor is None:
                raise Refusal(
                    "FRAME_REQUIRES_ANCHOR",
                    "an explicit alignment says explicit about WHAT? Without an anchor "
                    "field the origin would have to be invented.", "Frame")
        elif self.anchor is not None:
            raise Refusal(
                "FRAME_ANCHOR_NOT_APPLICABLE",
                f"alignment is {self.alignment!r}, so an anchor would be declared and "
                f"then ignored", "Frame")

        if self.kind in ("tumbling", "sliding") and self.size is None:
            raise Refusal("FRAME_REQUIRES_SIZE",
                          f"a {self.kind} frame needs a window size", "Frame")
        if self.size is not None and not self.size.is_positive:
            # A zero-length window contains no events, so every count over it is
            # zero. That is not a narrow filter, it is a rule that cannot fire.
            raise Refusal("FRAME_SIZE_NOT_POSITIVE",
                          f"a window of {self.size}s contains no events, so every "
                          f"count over it would be zero", "Frame")
        if self.kind == "sliding" and not self.step.is_positive:  # type: ignore[union-attr]
            raise Refusal("FRAME_STEP_NOT_POSITIVE",
                          "a sliding step of zero would never advance the window",
                          "Frame")
        if self.kind in ("per_event", "cumulative") and self.size is not None:
            raise Refusal("FRAME_SIZE_NOT_APPLICABLE",
                          f"a {self.kind} frame has no window size", "Frame")
        if self.size is not None and self.time_ref is None:
            raise Refusal("FRAME_REQUIRES_TIME_REF",
                          "a window needs to know which field holds the timestamp",
                          "Frame")
        if self.gap is not None and self.kind != "session":
            raise Refusal(
                "FRAME_GAP_NOT_APPLICABLE",
                f"a {self.kind} frame has no session gap, so gap would be "
                f"declared and then ignored", "Frame")
        if self.kind != "session" and self.gap is None and False:
            pass
        if self.offset is not None and self.kind in ("per_event", "cumulative", "session"):
            raise Refusal("FRAME_OFFSET_NOT_APPLICABLE",
                          f"offset has no meaning for a {self.kind} frame", "Frame")

    @property
    def is_epoch_aligned(self) -> bool:
        return self.alignment == "epoch"


@dataclass(frozen=True, slots=True)
class Measure:
    """One aggregate column.

    `field` is the value read; `by` is the ordering read for the two-field
    aggregates. Both are required for arg_min/arg_max, and `by` is refused on
    every other aggregate because a parameter that is accepted and ignored is
    worse than one that was never offered.
    """

    name: str
    function: str
    field: FieldRef | None = None
    by: FieldRef | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise Refusal("MEASURE_NAME_EMPTY", "a measure needs an output name",
                          "Measure")
        if self.function not in AGGREGATES:
            raise Refusal("MEASURE_FUNCTION_UNKNOWN",
                          f"{self.function!r} is not an aggregate; expected one of "
                          f"{sorted(AGGREGATES)}", "Measure")

        if self.function in TWO_FIELD_AGGREGATES:
            if self.field is None or self.by is None:
                raise Refusal(
                    "ARG_EXTREME_REQUIRES_TWO_FIELDS",
                    f"{self.function!r} needs a value field AND an ordering field: it "
                    f"answers \"the value of A where B is {self.function[4:]}\", which is "
                    f"two fields. With one field it would be identical to max/min and "
                    f"would pass as an implementation while changing what the rule means.",
                    "Measure")
        elif self.by is not None:
            raise Refusal(
                "ORDERING_FIELD_NOT_APPLICABLE",
                f"{self.function!r} takes one field, so an ordering field would be "
                f"declared and then ignored", "Measure")

        if self.function in (SINGLE_FIELD_AGGREGATES | SINGLE_FIELD_DISTINCT) \
                and self.field is None:
            raise Refusal("MEASURE_FIELD_REQUIRED",
                          f"{self.function!r} reads a field", "Measure")
        if self.function in NULLARY_AGGREGATES and self.field is not None:
            raise Refusal("MEASURE_FIELD_NOT_APPLICABLE",
                          f"{self.function!r} reads no field", "Measure")


# --------------------------------------------------------------------------
# Nodes
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SourceSelector:
    """Where rows come from. Carries no credentials and opens no connection.

    `binding` names a pre-existing acceleration or index — a Splunk datamodel, a
    Sentinel table, a QRadar log source type. It is recorded so the tool can say
    which target construct the rule needs, never to connect to anything.
    """

    name: str
    kind: TypingLiteral["events", "flow"] = "events"
    binding: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise Refusal("SOURCE_EMPTY", "a source needs a name", "SourceSelector")


@dataclass(frozen=True, slots=True)
class Read:
    id: str
    selector: SourceSelector


@dataclass(frozen=True, slots=True)
class Filter:
    id: str
    input: str
    condition: Any


@dataclass(frozen=True, slots=True)
class Derive:
    id: str
    input: str
    assignments: tuple[tuple[str, Any], ...]

    def __post_init__(self) -> None:
        if not self.assignments:
            raise Refusal("DERIVE_EMPTY", "Derive with nothing to derive is a no-op",
                          "Derive")
        seen: set[str] = set()
        for name, _expr in self.assignments:
            if name in seen:
                raise Refusal("DERIVE_DUPLICATE_NAME",
                              f"{name!r} is assigned twice; the second would silently "
                              f"overwrite the first", "Derive")
            seen.add(name)


@dataclass(frozen=True, slots=True)
class Aggregate:
    id: str
    input: str
    measures: tuple[Measure, ...]
    frame: Frame = field(default_factory=Frame)
    keys: tuple[FieldRef, ...] = ()

    def __post_init__(self) -> None:
        if not self.measures:
            raise Refusal("AGGREGATE_EMPTY",
                          "an aggregate with no measures computes nothing", "Aggregate")
        seen: set[str] = set()
        for measure in self.measures:
            if measure.name in seen:
                raise Refusal("AGGREGATE_DUPLICATE_MEASURE",
                              f"two measures both output {measure.name!r}", "Aggregate")
            seen.add(measure.name)


@dataclass(frozen=True, slots=True)
class Arrange:
    id: str
    input: str
    order_by: tuple[tuple[FieldRef, TypingLiteral["asc", "desc"]], ...] = ()
    limit: int | None = None

    def __post_init__(self) -> None:
        if self.limit is not None and self.limit <= 0:
            raise Refusal("ARRANGE_LIMIT_INVALID",
                          f"limit must be positive, got {self.limit}", "Arrange")


@dataclass(frozen=True, slots=True)
class SetOp:
    """Union, intersect or difference over two inputs sharing a key set.

    `except` is retained rather than spelled `except_`: the name is read aloud in
    operator previews, and a mangled name there is the kind of thing that gets
    copied into a ticket.
    """

    id: str
    op: TypingLiteral["union", "intersect", "except"]
    left: str
    right: str
    keys: tuple[FieldRef, ...] = ()

    def __post_init__(self) -> None:
        if self.op not in ("union", "intersect", "except"):
            # An unrecognised op used to be accepted here and then fail at
            # evaluation as SETOP_UNSUPPORTED, so a rule could be BUILT that could
            # never run. Refusal moves to construction, where it belongs.
            raise Refusal("SETOP_OP_UNKNOWN",
                          f"{self.op!r} is not a set operation; expected one of "
                          f"union, intersect, except", "SetOp")
        if not self.keys:
            raise Refusal(
                "SETOP_NO_KEYS",
                f"SetOp {self.id!r} has no key fields, so the two sides have no "
                f"basis for comparison. Which rows are 'the same' must be stated.",
                "SetOp")



@dataclass(frozen=True, slots=True)
class Join:
    id: str
    left: str
    right: str
    on: tuple[tuple[FieldRef, FieldRef], ...] = ()
    how: TypingLiteral["inner", "left"] = "inner"
    #: (left_field, right_field, lower, upper, lower_inclusive, upper_inclusive)
    #: Temporal predicates are asymmetric on purpose. "logged in within 10 minutes
    #: after the credential access" is not the same claim as "within 10 minutes of",
    #: and rendering them identically would state something the rule never said.
    temporal: tuple[tuple[FieldRef, FieldRef, Duration, Duration, bool, bool], ...] = ()
    left_prefix: str = "l_"
    right_prefix: str = "r_"
    #: bare column name -> the prefixed name this join actually stores it under.
    #:
    #: THIS EXISTS SO A RENDERER NEVER HAS TO GUESS. The prefixes are an
    #: implementation detail of the merged row, and in a single-namespace dialect
    #: like KQL the author's own text has them bare. Recovering the bare name by
    #: stripping the prefix is WRONG: `l_Process` is a legal KQL field name, so a
    #: blind strip would silently rewrite a rule about `l_Process` into a rule
    #: about `Process`. Only the join that renamed a column knows which is which,
    #: so that is where the answer is recorded.
    #:
    #: Names present on BOTH sides and not proven equal by a join key are
    #: deliberately ABSENT -- the rule does not say which one it means, so there
    #: is no correct answer to record.
    column_map: tuple[tuple[str, str], ...] = ()

    @property
    def rename(self) -> dict[str, str]:
        return dict(self.column_map)

    def bare(self, name: str) -> str:
        """The author's spelling of `name`, or `name` itself if this join did not
        rename it."""
        for original, stored in self.column_map:
            if stored == name:
                return original
        return name

    def __post_init__(self) -> None:
        if not self.on and not self.temporal:
            raise Refusal("JOIN_NO_CONDITION",
                          "a join with neither an equality nor a temporal condition is "
                          "a cross product, which is almost never intended and is "
                          "quadratic in cost", "Join")
        if self.left_prefix == self.right_prefix:
            raise Refusal("JOIN_PREFIX_COLLISION",
                          "left and right rows would write their fields to the same "
                          "names, so one would overwrite the other", "Join")
        if self.how not in ("inner", "left"):
            # `how="outer"` used to validate and then behave as an inner join,
            # silently dropping exactly the rows an outer join exists to keep. That
            # is a left join quietly becoming an inner join -- the single most
            # common way a join loses the events a rule was written to catch.
            raise Refusal("JOIN_HOW_UNKNOWN",
                          f"{self.how!r} is not a join type; expected inner or left",
                          "Join")
        for left_ref, right_ref, lower, upper, lo_inc, hi_inc in self.temporal:
            if lower.seconds > upper.seconds:
                # A window that starts after it ends matches nothing, ever. That is
                # not a subtle runtime outcome, it is a rule that cannot fire.
                raise Refusal("JOIN_TEMPORAL_INVERTED",
                              f"the temporal window on {left_ref.name!r} runs from "
                              f"{lower}s to {upper}s, so it can never contain a "
                              f"difference. A window that starts after it ends "
                              f"matches nothing, which is not a filter, it is a rule "
                              f"that cannot fire.", "Join")


@dataclass(frozen=True, slots=True)
class Expand:
    """Unnest a multivalue field into one row per element."""

    id: str
    input: str
    field: FieldRef
    as_field: FieldRef | None = None
    limit: int = 1000

    def __post_init__(self) -> None:
        if self.limit <= 0:
            raise Refusal("EXPAND_LIMIT_INVALID", "limit must be positive", "Expand")


@dataclass(frozen=True, slots=True)
class Pattern:
    """Ordered multi-event matching over a shared key within a window.

    `stages` are the ordered steps; `within` is the window. `until` is the
    negative twin: stage 0 must occur, stage 1 must NOT occur inside the window,
    and if it does the match is discarded. Modelling "and then not" is what makes
    a rule like "access, then no logout" expressible at all.
    """

    id: str
    input: str
    stages: tuple[tuple[Any, ...], ...]
    within: Duration
    key: tuple[FieldRef, ...] = ()
    until: Any = None
    ordered: bool = True
    max_matches_per_key: int = 100
    #: Which field orders the sequence. REQUIRED for an ordered pattern, and never
    #: inferred. Guessing which column is the timestamp is how a sequence gets
    #: ordered by something unrelated, which changes which events count as "then".
    time_field: str | None = None

    def __post_init__(self) -> None:
        if len(self.stages) < 2:
            raise Refusal(
                "PATTERN_NEEDS_TWO_STAGES",
                "a pattern describes a sequence; with one stage it is a filter", "Pattern")
        for index, stage in enumerate(self.stages):
            if not stage:
                raise Refusal("PATTERN_EMPTY_STAGE",
                              f"stage {index} has no conditions", "Pattern")
        if self.max_matches_per_key <= 0:
            raise Refusal("PATTERN_LIMIT_INVALID", "limit must be positive", "Pattern")
        if self.ordered and self.time_field is None:
            raise Refusal(
                "PATTERN_REQUIRES_TIME_FIELD",
                "an ordered pattern must say which field orders the events. Choosing "
                "one by looking for a column that looks like a timestamp would mean "
                "a rule with a `timestamp` field could be ordered by `eventtime`, "
                "and the sequence would be a different one.", "Pattern")


@dataclass(frozen=True, slots=True)
class Package:
    """A parent trigger with children that react to it, per `if_matched_sid`.

    THIS IS NOT A `Pattern`, and the difference is the whole reason it exists.

    A `Pattern` says "these events happened in this order within this window",
    and every stage is required. Wazuh's parent/child says something weaker and
    different: the PARENT is a complete rule in its own right that fires on its
    own, and a child is a *reaction* to it that is matched by a declared
    frequency over a timeframe. A child with `frequency: 1` is not "the parent
    happened once" -- it is "the parent's trigger, observed once", and Wazuh
    counts occurrences of the shared field within the timeframe. Treating that
    as a two-stage pattern would invent a sequence the rule never asserted, and
    would silently drop the parent's standalone behaviour, which is what a user
    watching the parent rule in the dashboard is actually seeing.

    WHY THE SHARED FIELDS ARE MANDATORY
    Wazuh's parent/child correlation works by grouping the parent and child
    events on the fields listed in `same_*` and then counting within
    `timeframe`. With no shared field there is no grouping key, so there is
    nothing to count over -- the correlation degenerates to "anywhere in the
    log", which is the shape that produces the enormous false-positive counts
    people recognise and rightly distrust. A rule that claims `if_matched_sid`
    with no `same_*` is refused rather than quietly widened.
    """

    id: str
    input: str
    #: The parent's own condition. It fires independently of any child.
    parent: tuple[Any, ...] = ()
    #: Child conditions, each a conjunction evaluated against child events.
    children: tuple[tuple[Any, ...], ...] = ()
    #: WHAT THE FREQUENCY COUNTS. Wazuh allows a child rule that declares no
    #: `<field>` of its own, and that is not an empty child -- it means "the
    #: parent's rule, N times in the timeframe", i.e. the count is over the
    #: PARENT's own occurrences. Reading it as "the parent once, with no child"
    #: would fire on the first event and turn a frequency rule into a plain one,
    #: which is the difference between a brute-force-login detector and a rule
    #: that alerts on the first password spray. `"child"` means the count is over
    #: rows matching `children`.
    count_subject: TypingLiteral["child", "parent"] = "child"
    #: How many child occurrences satisfy a child. Wazuh's `frequency`.
    frequency: int = 1
    #: The window the frequency is counted over. Wazuh's `timeframe`.
    timeframe: Duration = Duration(0)
    #: Fields the parent and child must agree on. Wazuh's `same_srcip` and
    #: friends. MANDATORY: without one there is no grouping key.
    same_fields: tuple[FieldRef, ...] = ()
    #: Which field orders the window. Never inferred, for the same reason
    #: `Pattern.time_field` is not: ordering by a guessed column changes which
    #: events are "then".
    time_field: str | None = None
    #: Set when a child used `if_matched_group`, which is a *group* trigger
    #: rather than a single event. The two are not interchangeable.
    child_uses_group: bool = False
    max_matches: int = 100

    def __post_init__(self) -> None:
        if not self.parent and not self.children:
            raise Refusal(
                "PACKAGE_EMPTY",
                "a package needs a parent or at least one child; with neither it "
                "can never match", "Package")
        if self.frequency <= 0:
            raise Refusal("PACKAGE_FREQUENCY_INVALID",
                          "frequency must be positive", "Package")
        if not self.same_fields:
            raise Refusal(
                "PACKAGE_REQUIRES_SHARED_FIELD",
                "parent/child correlation groups events on the declared same_* "
                "fields and counts them within the timeframe. With no shared "
                "field there is no grouping key, so the rule would mean 'anywhere "
                "in the log' -- which is not what the author wrote and is the "
                "shape that produces the false-positive floods this correlation "
                "style is distrusted for. Declare which field ties them "
                "together.", "Package")
        if not self.timeframe.is_positive:
            raise Refusal(
                "PACKAGE_REQUIRES_TIMEFRAME",
                "a frequency is counted within a timeframe; with a zero "
                "timeframe the count has no window to be counted over", "Package")
        if self.time_field is None:
            raise Refusal(
                "PACKAGE_REQUIRES_TIME_FIELD",
                "a package must say which field orders its window. Choosing one "
                "by looking for a column that looks like a timestamp would let a "
                "rule order by something unrelated and change the count.", "Package")
        for index, child in enumerate(self.children):
            if not child:
                raise Refusal("PACKAGE_EMPTY_CHILD",
                              f"child {index} has no conditions", "Package")
        if self.count_subject == "child" and not self.children:
            raise Refusal(
                "PACKAGE_CHILD_COUNT_WITHOUT_CHILDREN",
                "count_subject is 'child' but there are no child conditions, so "
                "there is nothing to count. Wazuh's way of saying 'count the "
                "parent N times' is a child rule with no <field> of its own, "
                "which is count_subject='parent'.", "Package")


@dataclass(frozen=True, slots=True)
class Emit:
    id: str
    input: str
    columns: tuple[str, ...] = ()
    dedupe_by: tuple[FieldRef, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleIR:
    """A complete rule: a DAG of nodes with one declared output.

    Not validated at construction — a node can be built before the graph that
    contains it exists. `validate_graph` does that, and the evaluator calls it, so
    an unvalidated graph cannot be executed.
    """

    rule_id: str
    nodes: tuple[Any, ...]
    output: str
    title: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise Refusal("RULE_ID_EMPTY", "a rule needs an id", "RuleIR")

    def node(self, node_id: str) -> Any:
        for candidate in self.nodes:
            if candidate.id == node_id:
                return candidate
        raise Refusal("NODE_NOT_FOUND", f"no node with id {node_id!r}", "RuleIR")

    def by_type(self, type_name: str) -> tuple[Any, ...]:
        return tuple(n for n in self.nodes if type(n).__name__ == type_name)

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the UI and for History.

        Field names and expression trees are included verbatim. Nothing is
        normalised on the way out, because a round trip that quietly rewrites a
        field name is a round trip that can change which rows a rule matches.
        """
        from dataclasses import asdict, is_dataclass
        from decimal import Decimal

        def encode(obj: Any) -> Any:
            if isinstance(obj, Decimal):
                return str(obj)
            if is_dataclass(obj) and not isinstance(obj, type):
                return {k: encode(v) for k, v in asdict(obj).items()}
            if isinstance(obj, (list, tuple)):
                return [encode(v) for v in obj]
            if isinstance(obj, dict):
                return {k: encode(v) for k, v in obj.items()}
            return obj

        return {
            "schema_version": SCHEMA_VERSION,
            "rule_id": self.rule_id,
            "title": self.title,
            "output": self.output,
            "metadata": dict(self.metadata),
            "nodes": [{"__type__": type(n).__name__, **encode(n)} for n in self.nodes],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RuleIR":
        """Rebuild a rule from `to_dict` output.

        Nodes are REBUILT, not passed through as raw dicts. An earlier version
        handed the dicts straight to the constructor, so a round-tripped rule
        looked well-formed and then refused with NODE_TYPE_UNKNOWN on every
        evaluation -- any cached, persisted or history-loaded rule was dead on
        arrival while appearing fine.
        """
        version = payload.get("schema_version")
        if version != SCHEMA_VERSION:
            raise Refusal(
                "SCHEMA_VERSION_MISMATCH",
                f"this document is schema {version!r}, this tool speaks "
                f"{SCHEMA_VERSION!r}. Refusing rather than guessing at the difference.",
                "RuleIR")
        nodes = tuple(_node_from_dict(n) for n in payload.get("nodes", ()))
        return cls(
            rule_id=payload["rule_id"],
            nodes=nodes,
            output=payload["output"],
            title=payload.get("title", ""),
            metadata=dict(payload.get("metadata", {})),
        )


#: node class name -> decoder. Populated below by `_register`.
_NODE_DECODERS: dict[str, Any] = {}


def _node_from_dict(payload: dict[str, Any]) -> Any:
    """Rebuild one node.

    REFUSES rather than half-rebuilding. An earlier version passed the raw dicts
    through, so a round-tripped rule looked well-formed and then refused with
    NODE_TYPE_UNKNOWN on every evaluation: any cached, persisted or
    history-loaded rule was dead on arrival while appearing fine.

    A partial decoder is worse than none. It would rebuild the simple nodes and
    refuse the rest, so a rule's fate would depend on which constructs it
    happened to use -- and the failure would surface as a wrong answer rather
    than an error, because a rule that half-rebuilt would quietly be missing its
    aggregate or its join.
    """
    name = payload.get("__type__")
    if name is None:
        raise Refusal(
            "NODE_TYPE_MISSING",
            "a serialised node does not say what kind of node it is, so it cannot "
            "be rebuilt. Guessing from its fields would let a Filter and a Derive "
            "be confused for one another.", "RuleIR")
    if name not in NODE_TYPES:
        raise Refusal("NODE_TYPE_UNKNOWN", f"{name} is not a RuleForge node", "RuleIR")
    raise Refusal(
        "ROUND_TRIP_NOT_IMPLEMENTED",
        f"rebuilding a {name} from serialised form is not implemented yet. The "
        f"serialised form is written correctly and is safe to store and display, "
        f"but it cannot be loaded back into a runnable rule in this version. "
        f"Returning a rule that looks complete but refuses to run would be worse "
        f"than saying so.", "RuleIR")


NODE_CLASSES: Final = (
    Read, Filter, Derive, Aggregate, Arrange, SetOp, Join, Expand, Pattern, Package,
    Emit,
)
