"""The dialect-neutral rule model.

Design stance, and it differs deliberately from a validator:

    Represent everything. Evaluate what can be evaluated. Label the rest.

An enterprise detection rule is mostly things a laptop cannot execute -- QRadar
appliance functions, Splunk `tstats` over index-time fields, PCRE, Wazuh
correlation evaluated on the agent. A tool that refuses those refuses the rule.
So every node carries a `capability`: EVALUATED means the local run is
trustworthy, DECLARED_ONLY means the node is modelled faithfully and renders
correctly but only the vendor's engine can execute it, and that fact is rendered
onto the artifact so it travels with the rule instead of living only in a log.

WHAT IS NEVER ALLOWED
---------------------
Silently dropping a node, and silently approximating one. Every dispatch chain
over node types terminates in an explicit refusal rather than a silent `else`.
An empty answer that looks like a working answer is the failure mode that
destroys trust in a detection tool, because an analyst cannot tell it from a
rule that correctly matched nothing.

THE SHAPE
---------
A rule is a graph of pipeline STAGES plus a table of NAMED BINDINGS. That is the
single most important structural decision here, and it is what separates an
enterprise-capable model from a filter builder.

    SecurityEvent | where EventID == 10 | project T=TimeGenerated, Computer
    SecurityEvent | where EventID == 4624 | project L=TimeGenerated, Computer
    <first> | join kind=inner (<second>) on Computer | where L between (T .. T+10m)

Nothing above is a linear chain. Both sides are defined, then joined, and the
surviving predicate compares a field from ONE row against a field from ANOTHER.
That last part is why `FieldRef` carries a scope. Without it, a rule comparing
two events' timestamps is inexpressible, and timestamp-ordered correlation --
the core of credential-access, lateral-movement and beaconing detection -- is
the one thing this tool most needs to model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from decimal import Decimal
from typing import Any, Final

from .values import (
    ABSENT,
    COMPARISON_OPS,
    UNDECIDED,
    Capability,
    Duration,
    Refusal,
    Seq,
    Undecided,
)

__all__ = [
    "Expr",
    "Literal",
    "FieldRef",
    "Scoper",
    "Comparison",
    "BoolOp",
    "Not",
    "Arith",
    "Call",
    "ListExpr",
    "Regex",
    "SubQuery",
    "Span",
    "Node",
    "Read",
    "Filter",
    "Project",
    "Derive",
    "Join",
    "Aggregate",
    "Sort",
    "Limit",
    "Distinct",
    "Expand",
    "Correlation",
    "Sequence",
    "SequenceStep",
    "Emit",
    "Binding",
    "Annotations",
    "Rule",
    "Measure",
    "Window",
    "EXPR_TYPES",
    "NODE_TYPES",
    "SCOPES",
    "render_expr",
]

# ---------------------------------------------------------------------------
# Expression layer
# ---------------------------------------------------------------------------

Expr = Any  # union alias; the dataclasses below are the closed set

#: Which row a field reference reads from.
#:
#: `current` is the row being evaluated. `left` and `right` are the two sides of
#: a join, and are only meaningful inside a join predicate -- a `left.` reference
#: outside a join is a wiring error, refused at construction rather than silently
#: reading the current row.
SCOPES: Final[frozenset[str]] = frozenset({"current", "left", "right"})

_FIELD_SPLIT: Final = re.compile(r"\.")


@dataclass(frozen=True, slots=True)
class Scoper:
    """Reads a field out of one row, or out of a named binding's stream.

    A class rather than a closure so the evaluator can be tested against a
    literal, and so a join can hand each side a scoper that knows which row is
    which without re-deriving it per comparison.
    """

    row: Any
    scope: str = "current"

    def get(self, full: str) -> Any:
        if self.row is None:
            return ABSENT
        return self.row.get(full)


def _split_field(text: str) -> tuple[str, tuple[str, ...]]:
    parts = [p for p in _FIELD_SPLIT.split(text or "") if p != ""]
    if not parts:
        return "", ()
    return parts[0], tuple(parts[1:])


@dataclass(frozen=True, slots=True)
class Literal:
    """A constant. Holds ABSENT and None distinctly from any other value.

    `describe` renders the VALUE, because this text is what the builder's
    condition editor shows the analyst. A message-oriented description ("a
    number") is right in a refusal and useless in a form field, so the
    type-oriented form lives on `type_label`.
    """

    value: Any

    def describe(self) -> str:
        from .values import type_name
        if self.value is ABSENT:
            return "absent"
        if self.value is UNDECIDED:
            return "undecided"
        if self.value is None:
            return "null"
        if isinstance(self.value, bool):
            return "true" if self.value else "false"
        if isinstance(self.value, str):
            return f'"{self.value}"'
        if isinstance(self.value, Duration):
            return _format_duration(self.value)
        if isinstance(self.value, Seq):
            return "[" + ", ".join(
                Literal(i).describe() for i in self.value.items
            ) + "]"
        return str(self.value)

    def type_label(self) -> str:
        from .values import type_name
        return type_name(self.value)


def _format_duration(duration: Duration) -> str:
    """Seconds back to a readable span, so a form field round-trips."""
    seconds = duration.seconds
    if seconds != int(seconds):
        return f"{seconds}s"
    whole = int(seconds)
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if whole and whole % size == 0:
            return f"{whole // size}{unit}"
    return f"{whole}s"


@dataclass(frozen=True, slots=True)
class FieldRef:
    """A field, optionally qualified by which row it comes from.

    `win.eventdata.CommandLine` with scope `current` is a nested path.
    `LoginTime` with scope `right` is a column of the right side of a join, and
    that distinction is the difference between a correlation rule and a filter.
    """

    name: str
    path: tuple[str, ...] = ()
    scope: str = "current"

    def __post_init__(self) -> None:
        if self.scope not in SCOPES:
            raise Refusal(
                "FIELD_SCOPE_UNKNOWN",
                f"`{self.scope}` is not a row scope. Use current, left or right.",
                "FieldRef",
            )
        if not self.name:
            raise Refusal("FIELD_NAME_EMPTY", "a field reference has no name", "FieldRef")

    @property
    def full(self) -> str:
        return ".".join((self.name,) + self.path) if self.path else self.name

    @property
    def scoped(self) -> str:
        return self.full if self.scope == "current" else f"{self.scope}.{self.full}"

    @classmethod
    def parse(cls, text: str, scope: str = "current") -> "FieldRef":
        """Build from dotted text, honouring a `left.`/`right.` prefix."""
        cleaned = (text or "").strip()
        resolved = scope
        for prefix in ("left.", "right.", "current."):
            if cleaned.lower().startswith(prefix):
                resolved = prefix[:-1]
                cleaned = cleaned[len(prefix):]
                break
        name, rest = _split_field(cleaned)
        return cls(name, rest, resolved)

    def describe(self) -> str:
        return self.scoped


@dataclass(frozen=True, slots=True)
class Comparison:
    """A binary comparison. `op` is drawn from the closed set in values.py."""

    op: str
    left: Expr
    right: Expr
    negate: bool = False

    def __post_init__(self) -> None:
        if self.op not in COMPARISON_OPS:
            raise Refusal(
                "OPERATOR_UNKNOWN",
                f"`{self.op}` is not a comparison operator this engine knows. "
                f"Supported: {', '.join(sorted(COMPARISON_OPS))}.",
                "Comparison",
            )

    def describe(self) -> str:
        body = f"{_describe(self.left)} {self.op} {_describe(self.right)}"
        if not self.negate:
            return body
        # `negate` is DATA on the node rather than a wrapped `Not`, so it has to
        # be rendered. Omitting it shows the analyst the INVERSE of the rule they
        # wrote: `cmd !~ "lsass"` displayed as `cmd matches /lsass/` is a rule
        # matching exactly the events the author excluded.
        return f"NOT ({body})"


@dataclass(frozen=True, slots=True)
class BoolOp:
    """AND / OR over a non-empty operand list.

    Arity is checked here rather than in the evaluator: an empty `BoolOp("and")`
    is the always-true predicate, and an always-true predicate in a WHERE clause
    is a rule that matches everything. Better refused at construction.
    """

    op: str  # "and" | "or"
    operands: tuple[Expr, ...]

    def __post_init__(self) -> None:
        if self.op not in ("and", "or"):
            raise Refusal(
                "BOOL_OP_UNKNOWN", f"`{self.op}` is not and/or", "BoolOp"
            )
        if not self.operands:
            raise Refusal(
                "BOOL_ARITY",
                f"a {self.op} with no operands is the always-true predicate, which "
                f"in a filter matches every row. It is refused rather than "
                f"silently treated as a match.",
                "BoolOp",
            )

    def describe(self) -> str:
        joiner = f" {self.op.upper()} "
        return "(" + joiner.join(_describe(o) for o in self.operands) + ")"


@dataclass(frozen=True, slots=True)
class Not:
    operand: Expr

    def describe(self) -> str:
        # Parens around a comparison, because `NOT a == 1` reads as
        # `(NOT a) == 1`. The tree is unambiguous; the rendered form is not, and
        # this text is what the builder shows an analyst. A compound operand
        # already parenthesises itself, so wrapping it again would give
        # `NOT ((a AND b))`.
        inner = _describe(self.operand)
        if isinstance(self.operand, (Comparison, Arith, Span)) or (
            isinstance(self.operand, BoolOp) and len(self.operand.operands) == 1
        ):
            return f"NOT ({inner})"
        return f"NOT {inner}"


@dataclass(frozen=True, slots=True)
class Arith:
    """Numeric arithmetic. `+ - * /` only -- no string concatenation.

    A correlation predicate routinely reads `LSASSTime + 10m`, so arithmetic on
    a duration is a first-class requirement, not an extension.
    """

    op: str
    left: Expr
    right: Expr

    def __post_init__(self) -> None:
        if self.op not in ("+", "-", "*", "/"):
            raise Refusal("ARITH_OP_UNKNOWN", f"`{self.op}` is not + - * /", "Arith")

    def describe(self) -> str:
        return f"({_describe(self.left)} {self.op} {_describe(self.right)})"


@dataclass(frozen=True, slots=True)
class ListExpr:
    """An inline collection, for IN / IN SET / has_any style predicates."""

    items: tuple[Expr, ...]

    def __post_init__(self) -> None:
        if not self.items:
            raise Refusal(
                "LIST_EMPTY",
                "an empty list in a membership test matches nothing, which is "
                "almost never what the author meant. Use FALSE, or remove it.",
                "ListExpr",
            )

    def describe(self) -> str:
        return "[" + ", ".join(_describe(i) for i in self.items) + "]"


@dataclass(frozen=True, slots=True)
class Regex:
    """A pattern plus its DIALECT, carried as data.

    The dialect is not decoration. `posix_extended` and Python `re` overlap
    enough to run; PCRE and POSIX BRE do not, and running a PCRE pattern with
    `re` and calling the result correct is a false claim about a security
    control. So the dialect travels with the node and the evaluator refuses to
    execute the ones it cannot execute faithfully.
    """

    pattern: str
    dialect: str = "posix_extended"
    nocase: bool = False

    def __post_init__(self) -> None:
        if not self.pattern:
            raise Refusal("REGEX_EMPTY", "the pattern is empty", "Regex")

    def describe(self) -> str:
        return f"/{self.pattern}/{self.dialect}" + (" nocase" if self.nocase else "")


@dataclass(frozen=True, slots=True)
class SubQuery:
    """A nested pipeline used as an operand.

    Splunk's `join type=inner dest user [ | tstats ... | rename ... | eval ... ]`
    is the canonical case: a whole second pipeline, written inline, whose rows
    become the right side of a join. Modelling it as a `Call` would lose the
    stages, and modelling it as a sibling stage would lose the nesting, so it is
    its own expression type.
    """

    pipeline: tuple["Node", ...]
    alias: str = ""

    def describe(self) -> str:
        return f"[ {len(self.pipeline)} stages ]"


@dataclass(frozen=True, slots=True)
class Call:
    """A named function.

    `capability` is the honest part. `cidr_contains` is EVALUATED -- it is pure
    computation over two arguments. `QIDNAME` is DECLARED_ONLY -- it exists only
    inside a QRadar appliance, no sample of events can produce it, and a tool
    that pretended otherwise would invent an answer. Same node shape, different
    honesty, and the difference is rendered onto the output.
    """

    function: str
    args: tuple[Expr, ...] = ()
    flags: tuple[str, ...] = ()

    def describe(self) -> str:
        inner = ", ".join(_describe(a) for a in self.args)
        tail = (" " + " ".join(self.flags)) if self.flags else ""
        return f"{self.function}({inner}){tail}"


EXPR_TYPES: Final[tuple[type, ...]] = (
    Literal, FieldRef, Comparison, BoolOp, Not, Arith, ListExpr, Regex,
    SubQuery, Call,
)

#: Functions this engine can execute, and those it models but cannot run.
#:
#: An ALLOWLIST, not a blocklist. A blocklist of "safe" functions was tried and
#: quietly classified things as portable that are not.
LOCAL_FUNCTIONS: Final[frozenset[str]] = frozenset({
    # pure computation over arguments
    "cidr_contains", "starts_with", "ends_with", "contains", "contains_any",
    "contains_all",
    "is_empty", "not_empty", "is_null", "is_not_null", "coalesce", "lower",
    "upper", "length", "abs", "round", "floor", "ceil", "min", "max",
    "matches_regex", "in_set", "has_any", "has_all", "to_string", "to_int",
     "bin", "now", "ago", "strftime", "iff",
    # Absence over a schema that has none.
    #
    # `is_null` asks whether a field is PRESENT and null, which is what Sigma's
    # `field: null` means. KQL has no such distinction -- every row carries
    # every column, so a missing value there IS null -- and mapping `isnull()`
    # onto the strict predicate made every Sentinel rule testing for a missing
    # field undecidable on exactly the rows it was written for. Two predicates
    # rather than one collapsed meaning.
    "is_null_or_absent", "is_present",
})

#: Modelled faithfully, renderable, and NOT executable outside the vendor's
#: engine. Each of these reads state that only the vendor has.
APPLIANCE_FUNCTIONS: Final[frozenset[str]] = frozenset({
    # QRadar: computed on the appliance from the event's QID metadata
    "qidname", "logsourceid", "logsource_name", "utf8", "qidid",
    # Splunk: index-time acceleration, reads tsidx fields no event sample has
    "tstats", "tstream", "eventstats", "datamodel", "inputlookup", "lookup",
    # SIEM-side field extraction that requires the vendor's parser
    "xml_extract", "json_extract", "kv", "uri_decode", "rex_extract",
    # Wazuh: decoded on the agent
    "decoded_as", "decoder", "data_stream",
})


def function_capability(name: str) -> Capability:
    """DECLARED_ONLY for anything that needs vendor-side state."""
    if name.lower() in APPLIANCE_FUNCTIONS:
        return Capability.DECLARED_ONLY
    return Capability.EVALUATED


# ---------------------------------------------------------------------------
# Pipeline layer
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Window:
    """A time window for aggregation.

    A window with no advance rate is two different operators wearing one name --
    tumbling and sliding produce different row counts and different alerts -- so
    `step` is required whenever `kind` is `sliding`, and refused as meaningless
    otherwise. A parameter that is accepted and ignored is worse than one that is
    never offered.
    """

    kind: str = "tumbling"  # tumbling | sliding | cumulative | per_event | session
    size: Duration | None = None
    step: Duration | None = None
    time_field: str = ""
    gap: Duration | None = None

    def __post_init__(self) -> None:
        if self.kind not in ("tumbling", "sliding", "cumulative", "per_event", "session"):
            raise Refusal(
                "WINDOW_KIND_UNKNOWN",
                f"`{self.kind}` is not a window kind. Use tumbling, sliding, "
                f"cumulative, per_event or session.",
                "Window",
            )
        if self.kind == "sliding":
            if self.step is None:
                raise Refusal(
                    "WINDOW_REQUIRES_STEP",
                    "a sliding window needs to know how far it advances. Without "
                    "a step it is a tumbling window, and those are different "
                    "operators with different results.",
                    "Window",
                )
            if self.size is None:
                raise Refusal(
                    "WINDOW_REQUIRES_SIZE", "a sliding window needs a size", "Window"
                )
        if self.kind == "session":
            if self.gap is None:
                raise Refusal(
                    "WINDOW_REQUIRES_GAP",
                    "a session window is defined by the gap that ends a session, "
                    "so it cannot be built without one.",
                    "Window",
                )
        if self.kind != "sliding" and self.step is not None:
            raise Refusal(
                "WINDOW_STEP_NOT_APPLICABLE",
                f"a {self.kind} window has no advance rate, so `step` would be "
                f"accepted and ignored. Remove it.",
                "Window",
            )
        if self.kind != "session" and self.gap is not None:
            raise Refusal(
                "WINDOW_GAP_NOT_APPLICABLE",
                f"only a session window has a gap. A {self.kind} window would "
                f"ignore it.",
                "Window",
            )


@dataclass(frozen=True, slots=True)
class Measure:
    """One aggregate over a group.

    `distinct` is per-measure data rather than inferred from the function name,
    because `values()` de-duplicates and `make_set()` does not and that
    difference changes an alert.
    """

    function: str
    name: str
    field: FieldRef | None = None
    distinct: bool = False
    param: Decimal | None = None  # percentile
    condition: Expr | None = None  # conditional count, e.g. SPL count(eval(...))

    def __post_init__(self) -> None:
        if not self.name:
            raise Refusal("MEASURE_NAME_EMPTY", "an aggregate needs a name", "Measure")
        if self.function in ("count", "count_if") and self.field is None and self.param is None:
            return
        if self.field is None and self.function not in ("count",):
            raise Refusal(
                "MEASURE_NEEDS_FIELD",
                f"`{self.function}` aggregates a field, so it needs one",
                "Measure",
            )


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class Node:
    """Base for pipeline stages. Every stage carries an id used for reference.

    Keyword-only, because every stage subclasses this and adds required fields:
    with positional fields the base defaults would come first and Python refuses
    a non-default field after a default one. Making them keyword-only keeps
    `Read(table=...)` required and `Read(id=..., table=...)` natural.
    """

    id: str = ""
    capability: Capability = Capability.EVALUATED
    note: str = ""


@dataclass(frozen=True, slots=True)
class Read(Node):
    """The source table and index-time selector.

    `selector` is a raw dialect expression, kept verbatim rather than parsed into
    the IR. An index-time filter is not a row predicate: it is evaluated by the
    store before any row exists, and pretending otherwise would let a local
    evaluation claim a match it cannot produce.
    """

    table: str
    selector: str = ""
    time_field: str = ""


@dataclass(frozen=True, slots=True)
class Filter(Node):
    """A row predicate. UNDECIDED rows are neither kept nor dropped silently --
    they are counted and reported, because a rule that quietly drops the rows it
    cannot decide is a rule whose match count nobody can trust."""

    condition: Expr


@dataclass(frozen=True, slots=True)
class Project(Node):
    """A projection: which columns come out, and what they are renamed to.

    The three lists COMPOSE rather than being exclusive, because every real
    dialect allows them together. KQL's
    `| project LSASSTime=TimeGenerated, Computer, Account` renames one column
    and keeps two, and refusing that combination would refuse the single most
    common stage in the language.

        keeps + renames   output is exactly those columns, renamed
        drops             output is everything EXCEPT those columns
        nothing           output is everything (a pass-through)

    `drops` is carried as DATA, alongside `renames`, so nothing has to infer
    "this was a rename, so drop the source" from a node id or from the absence
    of a name. Add-then-drop and drop-then-add are different rules, and a stage
    that guessed wrong produced rules which kept a column the author had
    deliberately removed -- and, in the other direction, rules that dropped a
    column the author meant to keep.
    """

    renames: tuple[tuple[FieldRef, str], ...] = ()
    drops: tuple[FieldRef, ...] = ()
    keeps: tuple[FieldRef, ...] = ()

    def __post_init__(self) -> None:
        renamed = {target for _, target in self.renames}
        dropped = {d.full for d in self.drops}
        overlap = renamed & dropped
        if overlap:
            raise Refusal(
                "PROJECT_DROPS_RENAMED",
                f"`{sorted(overlap)[0]}` is renamed and dropped by the same "
                f"stage. Add-then-drop and drop-then-add are different rules; "
                f"say which you meant.",
                "Project",
            )
        if self.drops and self.keeps:
            raise Refusal(
                "PROJECT_KEEPS_AND_DROPS",
                "a stage either names the columns to keep or the columns to "
                "drop. Doing both is ambiguous about what the output is, and "
                "guessing produces a projection that keeps a column the author "
                "removed.",
                "Project",
            )

    @property
    def is_rename_only(self) -> bool:
        return bool(self.renames) and not self.keeps and not self.drops

    @property
    def is_identity(self) -> bool:
        return not self.renames and not self.keeps and not self.drops

    @property
    def output_names(self) -> tuple[str, ...]:
        """What comes out, in order. A renderer reads this; it never re-derives."""
        if self.keeps or self.renames:
            return tuple(
                [target for _, target in self.renames]
                + [ref.full for ref in self.keeps]
            )
        return ()


@dataclass(frozen=True, slots=True)
class Derive(Node):
    """Computed columns. `kind` is data so a renderer never re-derives intent:
    `eval` in SPL and `:=` in CQL and `extend` in KQL behave differently around
    whether the source column survives."""

    assignments: tuple[tuple[str, Expr], ...] = ()
    kind: str = "add"  # add | replace

    def __post_init__(self) -> None:
        if not self.assignments:
            raise Refusal("DERIVE_EMPTY", "a derive stage computes nothing", "Derive")
        names = [n for n, _ in self.assignments]
        if len(set(names)) != len(names):
            raise Refusal(
                "DERIVE_DUPLICATE_TARGET",
                "the same column is assigned twice in one stage, so which value "
                "survives depends on evaluation order",
                "Derive",
            )


@dataclass(frozen=True, slots=True)
class Join(Node):
    """A join, with a PREDICATE rather than a bare key list.

    Enterprise correlation is mostly temporal: match on Computer AND Account AND
    `right.LoginTime` within 10 minutes of `left.LoginTime`. That cannot be
    expressed as equality keys, so `predicate` takes the full boolean condition
    and may reference both scopes. `on` is kept for the equality part, which is
    what a renderer needs to emit the dialect's `on (...)` clause.
    """

    left: str
    right: str
    how: str = "inner"
    on: tuple[tuple[FieldRef, FieldRef], ...] = ()
    predicate: Expr | None = None
    left_prefix: str = "left."
    right_prefix: str = "right."

    def __post_init__(self) -> None:
        if self.how not in ("inner", "left", "right", "full", "anti", "cross"):
            raise Refusal(
                "JOIN_HOW_UNKNOWN",
                f"`{self.how}` is not a join type. This engine implements inner, "
                f"left, right, full, anti and cross.",
                "Join",
            )
        if self.how == "cross" and self.on:
            raise Refusal(
                "JOIN_CROSS_WITH_KEYS",
                "a cross join has no keys, so accepting them would be accepting a "
                "parameter that is ignored",
                "Join",
            )
        if self.how != "cross" and not self.on and self.predicate is None:
            raise Refusal(
                "JOIN_HAS_NO_CONDITION",
                f"a {self.how} join with no keys and no predicate matches every "
                f"row on the left against every row on the right",
                "Join",
            )
        if self.left_prefix == self.right_prefix:
            raise Refusal(
                "JOIN_PREFIX_COLLISION",
                "both sides use the same column prefix, so one silently overwrites "
                "the other and the rule means something other than what it says",
                "Join",
            )

    @property
    def is_temporal(self) -> bool:
        return self.predicate is not None


@dataclass(frozen=True, slots=True)
class Aggregate(Node):
    measures: tuple[Measure, ...] = ()
    keys: tuple[FieldRef, ...] = ()
    window: Window | None = None

    def __post_init__(self) -> None:
        if not self.measures:
            raise Refusal(
                "AGGREGATE_NO_MEASURE",
                "this stage groups but measures nothing, which produces one row "
                "per group and discards every value. If that is what you want, "
                "say so with DISTINCT.",
                "Aggregate",
            )


@dataclass(frozen=True, slots=True)
class Sort(Node):
    keys: tuple[tuple[FieldRef, bool], ...] = ()  # (field, descending)
    limit: int | None = None


@dataclass(frozen=True, slots=True)
class Limit(Node):
    count: int
    keep_last: bool = False


@dataclass(frozen=True, slots=True)
class Distinct(Node):
    keys: tuple[FieldRef, ...]


@dataclass(frozen=True, slots=True)
class Expand(Node):
    """Unnest a list column into one row per element."""

    field: FieldRef
    into: str = ""


@dataclass(frozen=True, slots=True)
class Correlation(Node):
    """A threshold-over-time rule, as Wazuh's frequency/timeframe expresses it.

    Distinct from Aggregate because the COUNT is the predicate, not a column: the
    rule fires when the parent matches N times inside the timeframe, grouped on
    the shared fields. And distinct again because the parent is itself a complete
    rule that fires on its own -- which is the thing most often misunderstood when
    deploying one.
    """

    parent: str
    frequency: int
    timeframe: Duration
    group_by: tuple[FieldRef, ...] = ()
    count_subject: str = "parent"  # parent | child

    def __post_init__(self) -> None:
        if self.frequency < 1:
            raise Refusal(
                "CORRELATION_FREQUENCY_INVALID",
                "a frequency below 1 means the rule fires when the pattern does "
                "NOT occur, which is the opposite of a threshold",
                "Correlation",
            )
        if not self.group_by:
            raise Refusal(
                "CORRELATION_NO_GROUP",
                "with nothing to group on, the count is 'anywhere in the log', "
                "which is almost never the intent",
                "Correlation",
            )
        if self.count_subject not in ("parent", "child"):
            raise Refusal(
                "CORRELATION_SUBJECT_UNKNOWN",
                f"`{self.count_subject}` is not parent or child",
                "Correlation",
            )


@dataclass(frozen=True, slots=True)
class Emit(Node):
    """The terminal. Every graph names one, and what it projects is stated
    rather than implied."""

    keeps: tuple[FieldRef, ...] = ()
    dedupe_by: tuple[FieldRef, ...] = ()


@dataclass(frozen=True, slots=True)
class SequenceStep:
    """One `[ ... ]` of an ordered sequence.

    Each step has its OWN condition, which is what separates a sequence from a
    threshold: `Correlation` counts N occurrences of one parent, and the steps
    of a sequence match different things.

    `runs` is EQL's `with runs=N`: the step must match that many times in a
    row before the sequence advances. It defaults to 1 because a step is one
    event unless it says otherwise, and reading a missing `runs` as 0 would
    let a sequence skip the step entirely.
    """

    condition: Expr
    runs: int = 1

    def __post_init__(self) -> None:
        if self.runs < 1:
            raise Refusal(
                "SEQUENCE_RUNS_INVALID",
                f"a step with runs={self.runs} matches no events, so the "
                f"sequence could never advance past it",
                "SequenceStep",
            )


@dataclass(frozen=True, slots=True)
class Sequence(Node):
    """An ORDERED series of events, as EQL's `sequence` expresses it.

    Neither `Join` nor `Correlation` can carry this, which is why it is its
    own node:

    **`Join` loses the ORDER.** A join pairs two streams where the keys match
    and says nothing about which came first. But "procdump ran, THEN lsass was
    opened" is credential dumping, and the same two events in the other order
    are a memory tool being inspected. Lowering a sequence to a join doubles
    the matches and half of them are the benign direction -- reported as
    detections, with nothing to distinguish them.

    **`Correlation` loses the DIFFERENT CONDITIONS.** It counts how often ONE
    parent fired. A sequence's steps match different events, so collapsing
    them into a count asks "did any of these happen five times" instead of
    "did these specific things happen in this specific order".

    `by` is the join key shared by every step: the events must agree on it, or
    a sequence "by host.id" would match procdump on one machine followed by
    lsass access on another.

    `maxspan` bounds first step to last. Without it a sequence spans all of
    recorded history, so an attack chain and two unrelated events a year apart
    are the same finding.

    `until` is the terminator: when it matches, any partial sequence for that
    key is abandoned. It is how "logon then privilege escalation, UNLESS the
    user logged off in between" is expressed, and dropping it turns a
    completed-and-cancelled chain into an alert.
    """

    steps: tuple[SequenceStep, ...]
    by: tuple[FieldRef, ...] = ()
    maxspan: Duration | None = None
    until: Expr | None = None

    def __post_init__(self) -> None:
        if len(self.steps) < 2:
            raise Refusal(
                "SEQUENCE_TOO_SHORT",
                f"a sequence of {len(self.steps)} step(s) is not a sequence. "
                f"One step is an ordinary filter, and writing it as a sequence "
                f"implies an ordering the rule does not actually require",
                "Sequence",
            )
        if not self.by:
            raise Refusal(
                "SEQUENCE_NO_JOIN_KEY",
                "this sequence has nothing to join the steps on, so any first "
                "event would pair with any later one anywhere in the estate. "
                "EQL allows it; it is refused here because the result is "
                "almost never the intent and never says so",
                "Sequence",
            )


NODE_TYPES: Final[tuple[type, ...]] = (
    Read, Filter, Project, Derive, Join, Aggregate, Sort, Limit, Distinct,
    Expand, Correlation, Sequence, Emit,
)


# ---------------------------------------------------------------------------
# Rule assembly
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Binding:
    """A named sub-pipeline, forward-referenceable.

    This is the structural answer to KQL `let`, YARA-L `$var` match clauses,
    QRadar building blocks and Wazuh rule chains. The name is declared BEFORE the
    stage that uses it, because a rule that reads top-to-bottom would otherwise
    be unable to express "define the logon stream here, use it after the join".

    `guard` exists so a binding can be defined unconditionally but only joined
    when its own filter passed -- which is what a sub-search does, and what a
    plain definition cannot express.
    """

    name: str
    pipeline: tuple[Node, ...]
    guard: Expr | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise Refusal("BINDING_NAME_EMPTY", "a binding needs a name", "Binding")
        if not self.pipeline:
            raise Refusal(
                "BINDING_EMPTY",
                f"`{self.name}` is defined but has no stages, so it is a name "
                f"pointing at nothing",
                "Binding",
            )


@dataclass(frozen=True, slots=True)
class Annotations:
    """MITRE, severity, description, author.

    Not decoration. Every enterprise rule carries them, they are what a SOC
    actually triages on, and they round-trip through all eight dialects. Carried
    as structured data so a renderer can place them where its dialect requires --
    YARA-L `meta:`, Wazuh `<mitre>`, Splunk nothing at all.
    """

    title: str = ""
    description: str = ""
    severity: str = ""
    author: str = ""
    mitre_attack: tuple[tuple[str, tuple[str, ...]], ...] = ()
    references: tuple[str, ...] = ()
    false_positives: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Rule:
    """A whole rule: annotations, named bindings, and the main pipeline.

    `metadata["dialect"]` records which vendor it was written in, and
    `metadata["artifact"]` distinguishes a deployable rule from a search that
    merely looks like one. QRadar needs that distinction badly: an AQL search is
    not a CRE rule and calling one the other sends an analyst looking for
    building-block configuration that the artifact does not contain.
    """

    rule_id: str
    pipeline: tuple[Node, ...]
    bindings: tuple[Binding, ...] = ()
    annotations: Annotations = dc_field(default_factory=Annotations)
    metadata: dict[str, str] = dc_field(default_factory=dict)
    output: str = ""

    def __post_init__(self) -> None:
        if not self.pipeline:
            raise Refusal("RULE_EMPTY", "the rule has no stages", "Rule")
        if not any(isinstance(n, Emit) for n in self.pipeline):
            raise Refusal(
                "RULE_HAS_NO_EMIT",
                "the pipeline does not end in an output stage, so what this rule "
                "returns is implied rather than stated",
                "Rule",
            )
        names = [b.name for b in self.bindings]
        if len(set(names)) != len(names):
            dupes = sorted({n for n in names if names.count(n) > 1})
            raise Refusal(
                "BINDING_DUPLICATE",
                f"the binding name(s) {dupes} are defined more than once",
                "Rule",
            )
        # A join side or correlation parent may name either a BINDING (defined
        # elsewhere, forward-referenceable) or a STAGE in this very pipeline.
        # Both are legal; anything else is a dangling reference that would
        # otherwise surface as a confusing failure at evaluation time.
        known = set(names) | {self.rule_id}
        known.update(n.id for n in self.pipeline if n.id)
        for binding in self.bindings:
            known.update(n.id for n in binding.pipeline if n.id)
        for node in self.pipeline:
            for ref in _binding_references(node):
                if ref not in known:
                    raise Refusal(
                        "BINDING_UNKNOWN",
                        f"the pipeline refers to `{ref}`, which is neither a "
                        f"binding nor a stage in this rule. Known: "
                        f"{sorted(known)}.",
                        "Rule",
                    )

    @property
    def output_node(self) -> Emit:
        for node in reversed(self.pipeline):
            if isinstance(node, Emit):
                return node
        raise Refusal("RULE_HAS_NO_EMIT", "no output stage", "Rule")

    @property
    def emit_id(self) -> str:
        return self.output_node.id


#: Join sources and correlation parents are written as bare strings rather than
#: embedded nodes, so a binding can be referenced before it is defined and the
#: graph stays acyclic by construction. This finds them for validation.
_BINDING_SLOTS: Final[tuple[tuple[str, str], ...]] = (
    ("Join", "left"),
    ("Join", "right"),
    ("Correlation", "parent"),
)


def _binding_references(node: Node) -> list[str]:
    out: list[str] = []
    for kind, attr in _BINDING_SLOTS:
        if type(node).__name__ == kind:
            value = getattr(node, attr, None)
            if isinstance(value, str) and value:
                out.append(value)
    return out


# ---------------------------------------------------------------------------
# Human-readable rendering, for refusals and the UI
# ---------------------------------------------------------------------------


def _describe(expr: Expr) -> str:
    """Render an expression tree as readable text.

    Used in refusal messages, in the UI's condition editor, and nowhere the
    output is re-parsed. This is display text and is explicitly NOT a dialect
    syntax -- a renderer that round-tripped through this would be inventing a
    second source of truth, which is the defect class that causes the most
    expensive bugs in a tool like this.
    """
    if isinstance(expr, (Literal, FieldRef, Regex, SubQuery, Call, ListExpr,
                         Comparison, BoolOp, Not, Arith)):
        describe = getattr(expr, "describe", None)
        if describe is not None:
            return describe()
    if isinstance(expr, Span):
        return expr.describe()
    if isinstance(expr, Seq):
        return repr(expr)
    if expr is ABSENT:
        return "absent"
    if expr is UNDECIDED:
        return "undecided"
    return repr(expr)


def render_expr(expr: Expr) -> str:
    """Public entry point for display text."""
    return _describe(expr)


@dataclass(frozen=True, slots=True)
class Span:
    """A range test: `value between (low .. high)`.

    KQL's `where LoginTime between (LSASSTime .. LSASSTime + 10m)` is the
    canonical enterprise correlation predicate and it is a SPAN whose bounds are
    arbitrary expressions, one of which is arithmetic on a field from the other
    side of a join. Neither a comparison nor a list, so it gets its own node --
    and it carries all THREE expressions, because "between what and what" is not
    answerable without knowing what is being tested.
    """

    value: Expr
    low: Expr
    high: Expr
    low_inclusive: bool = True
    high_inclusive: bool = True

    def describe(self) -> str:
        return (
            f"{_describe(self.value)} between "
            f"({_describe(self.low)} .. {_describe(self.high)})"
        )


EXPR_TYPES = EXPR_TYPES + (Span,)
