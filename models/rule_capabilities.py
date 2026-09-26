"""Vendor capability registry.

Phase 2b of docs/ruleforge-redesign-plan.md. Ships DARK alongside the kernel and the v1
adapter.

Three data-only catalogs:

  FUNCTION catalog  canonical function IDs and their full semantic contracts
  OPERATOR catalog  per-primitive schemas, cardinality, ordering, time, state, emitter
  TARGET PROFILE   keyed by (product, engine, artifact kind, target version)

A target profile is DATA. Adding a vendor is a registry entry, not a rewrite of seven
renderers - but only for a surface that already has registered emitter operations, which is
the honesty gate below.

THE ANTI-LIE GATE
------------------
A profile CANNOT declare `native` or `equivalent` unless a registered emitter exists for that
primitive in that dialect. An emitter is not a label: `Emitter.lowering` is a REQUIRED
callable, and only renderers that actually lower a RuleIR node into target syntax are
registered. An `emitter_id` string is not proof of anything, and an earlier draft of this
module was wrong in exactly that way - it listed six `aql.*` ids while no RuleIR-to-AQL
lowering existed anywhere in the repository, so `resolve()` reported a grouped search as
`deployable` on the strength of a string. That is the defect this component exists to
prevent, committed inside the component meant to prevent it.

`EMITTERS` is therefore EMPTY at this phase, and every target correctly refuses every graph.
That is the true state: `compiler/dialects.py` contains AQL/EQL/SPL/KQL PARSERS (target text
in, tokens out) and `compiler/sigma_compiler.py` lowers the v1 `CorrelationModel`, so
nothing here lowers a `RuleIR` yet. Renderers land in later phases and each one registers a
real callable here, which means the capability table can never get ahead of the code that
would honour it.

`PLANNED_EMITTERS` records what we intend to build. It is documentation, it is deliberately
NOT consulted by `resolve()`, and it grants no capability. Keeping intent in a separate
structure is what stops a TODO list from being read as a shipping feature list.

DEFAULT-DENY
------------
An unlisted (primitive, profile) pair refuses. There is no wildcard entry and no permissive
default. Whole-graph resolution: one unsupported node refuses the whole artifact, so there
is no "partial but downloadable" outcome. Version gating FAILS CLOSED: an unknown target
version refuses rather than assuming the newest features exist.

OUR GAPS ARE NOT THE VENDOR'S
------------------------------
A construct the KERNEL cannot represent reports `IR_UNSUPPORTED_CONSTRUCT`. It is never
attributed to a vendor, because blaming a vendor for a gap in our own model is how a tool
loses the analyst's trust for a reason they cannot act on.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, get_args, get_origin, get_type_hints

from models.rule_ir import (FUNCTION_CONTRACTS, NODE_TYPES as _NODE_TYPES, PRIMITIVE_NAMES,
                            BoolOp, Call, Comparison, FieldRef, Read, RuleIR,
                            RuleIRValidationError, SetOp, SourceSelector,
                            primitive_of as _primitive_of, validate_ir)

#: Support levels. `partial` is defined and is NOT allowed to yield a downloadable artifact.
NATIVE = "native"
EQUIVALENT = "equivalent"
REFUSED = "refused"
SUPPORT_LEVELS = frozenset({NATIVE, EQUIVALENT, REFUSED})

_VERSION_RE = re.compile(r"\d+(?:\.\d+)*")


#: Primitive identity comes from the model itself - see `models/rule_ir.NODE_TYPES`. This
#: module used to declare its own copy while `validate_ir` used a third opinion (the class
#: name), so a lookalike node was ACCEPTED by the validator and REFUSED here: one graph, two
#: answers, and the disagreement fell in the direction that decides deployability. A
#: hand-written second copy of a vocabulary is guaranteed to drift - it is how a 21-entry
#: comparison allowlist came to certify fifteen operators this model cannot express.
NODE_TYPES = _NODE_TYPES
primitive_of = _primitive_of


# --------------------------------------------------------------------------
# The emitter registry - the anti-lie gate
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Emitter:
    """A registered way to lower one primitive into one dialect.

    `lowering` is the whole point and is deliberately non-optional. It must be a callable
    that takes a RuleIR node and returns target syntax; if you cannot write that callable,
    the capability does not exist and the entry must not be registered.

    `exact` distinguishes a native target construct from a composition of registered
    capabilities.

    `forbids` exists because capability depends on a primitive's PARAMETERS, not only its
    type. QRadar AQL can group and count, but it has no computed tumbling bucket, so an
    Aggregate carrying a `Frame` must refuse even though a plain Aggregate is fine.
    Registering by primitive alone would have claimed both, and the second claim is a lie.
    """
    dialect: str
    primitive: str
    emitter_id: str
    lowering: Callable[[Any], str]
    exact: bool = True
    forbids: tuple[str, ...] = ()
    version_min: str | None = None
    version_max: str | None = None

    def __post_init__(self) -> None:
        if not callable(self.lowering):
            raise RuleIRValidationError(
                "EMITTER_WITHOUT_LOWERING",
                f"emitter {self.emitter_id!r} has no callable lowering; a string id is not "
                f"proof that the target syntax can be produced", "emitters")
        if self.primitive not in PRIMITIVE_NAMES:
            raise RuleIRValidationError(
                "UNKNOWN_PRIMITIVE",
                f"{self.primitive!r} is not a RuleIR primitive", "emitters")
        if type(self.exact) is not bool:
            # `exact="false"` is truthy, so a string flag would promote an equivalent
            # lowering to native and overstate what the target can do.
            raise RuleIRValidationError(
                "MALFORMED_EXACT_FLAG",
                f"exact must be a real bool, got {self.exact!r}", "emitters")

    def supports_version(self, version: str | None) -> bool:
        """Version gating FAILS CLOSED.

        An unknown version cannot be assumed to have the newest feature. An earlier draft
        returned True when `version` was None, which meant a caller that forgot to pass a
        version silently unlocked every version-gated emitter.
        """
        if version is None:
            return self.version_min is None and self.version_max is None
        if self.version_min and _version_tuple(version) < _version_tuple(self.version_min):
            return False
        if self.version_max and _version_tuple(version) > _version_tuple(self.version_max):
            return False
        return True

    def accepts(self, node: Any) -> bool:
        """Does this emitter handle THIS node, with the parameters it actually carries?

        Presence, not truthiness: a malformed `frame=0` is still a frame and must be denied.
        """
        return all(getattr(node, attribute, None) is None for attribute in self.forbids)


def _version_tuple(text: str) -> tuple[int, ...]:
    """Parse a target version STRICTLY, and only from a string.

    A permissive parser turned '7.4junk', '7.4.0-beta' and 'not-a-version' into usable
    bounds. Coercing through `str()` was also wrong in a quieter way: the float 7.10
    stringifies to '7.1' and silently compares as version 7.1, so a version bound and a
    target version could disagree about which release they are.
    """
    if not isinstance(text, str):
        raise RuleIRValidationError(
            "MALFORMED_VERSION",
            f"version must be a string, got {type(text).__name__}", "emitters")
    text = text.strip()
    if not _VERSION_RE.fullmatch(text):
        raise RuleIRValidationError(
            "MALFORMED_VERSION",
            f"version {text!r} is not a dotted numeric version", "emitters")
    return tuple(int(chunk) for chunk in text.split("."))


@dataclass(frozen=True)
class PlannedEmitter:
    """What we intend to build. Documentation only, and deliberately NOT an `Emitter`.

    This is a separate type with no `lowering` field on purpose. An earlier draft reused the
    `Emitter` type for planned rows and shipped a lowering that raises when called - and the
    registry still reported those rows as `deployable`, because `resolve()` never calls the
    lowering. The capability came from the row's mere existence, not from any code, so a
    placeholder that refuses at call time granted exactly as much capability as a real one.

    Because this type carries no `lowering` and `emitters_for()` filters on the real type,
    a planned row cannot be spliced into the registered set even by accident.
    """
    dialect: str
    primitive: str
    emitter_id: str
    forbids: tuple[str, ...] = ()
    version_min: str | None = None
    version_max: str | None = None

    def supports_version(self, version: str | None) -> bool:
        if version is None:
            return self.version_min is None and self.version_max is None
        if self.version_min and _version_tuple(version) < _version_tuple(self.version_min):
            return False
        if self.version_max and _version_tuple(version) > _version_tuple(self.version_max):
            return False
        return True

    def accepts(self, node: Any) -> bool:
        """Mirrors `Emitter.accepts` so the plan can record which parameter shapes it will
        have to handle. It grants nothing; it just keeps the plan honest."""
        return all(getattr(node, attribute, None) is None for attribute in self.forbids)


#: Emitters with a real lowering behind them. EMPTY, and that is the honest current state.
#: Populated one entry per renderer as renderers land.
EMITTERS: tuple[Emitter, ...] = ()

#: What we intend to build. `resolve()` never reads this, and these rows are not `Emitter`s,
#: so a TODO list can never be read as a shipping feature list.
PLANNED_EMITTERS: tuple[PlannedEmitter, ...] = (
    PlannedEmitter("qradar-aql", "Read", "aql.from_events"),
    PlannedEmitter("qradar-aql", "Filter", "aql.where"),
    # AQL can group and count, but it has no computed tumbling bucket. This denial is what
    # stops a windowed correlation being sold as a grouped historical search.
    PlannedEmitter("qradar-aql", "Aggregate", "aql.groupby", forbids=("frame",)),
    PlannedEmitter("qradar-aql", "Filter", "aql.having", version_min="7.4"),
    PlannedEmitter("qradar-aql", "Arrange", "aql.order_by"),
    PlannedEmitter("qradar-aql", "Emit", "aql.select_list"),
)


def emitters_for(dialect: str, primitive: str, version: str | None = None) -> tuple[Emitter, ...]:
    # The isinstance filter is load-bearing, not defensive noise: it is what makes a
    # PlannedEmitter structurally incapable of granting capability.
    return tuple(e for e in EMITTERS
                 if isinstance(e, Emitter)
                 and e.dialect == dialect and e.primitive == primitive
                 and e.supports_version(version))


def registered_dialects() -> frozenset[str]:
    """Dialects with at least one REAL registered emitter.

    Filters on the concrete type so a corrupted or spliced registry cannot make a planned
    dialect look shipped.
    """
    return frozenset(e.dialect for e in EMITTERS if isinstance(e, Emitter))


# --------------------------------------------------------------------------
# Operator catalog
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class OperatorSpec:
    """What one primitive does, independent of any target.

    `result` is `relation` for anything that can feed a Join, and `scalar` otherwise; the
    Join check in the kernel relies on this distinction.
    """
    primitive: str
    result: str = "relation"
    cardinality: str = "one_to_one"
    ordering: str = "none"
    time_behaviour: str = "none"
    stateful: bool = False
    produces_measures: bool = False
    evaluable_locally: bool = True

    def __post_init__(self) -> None:
        if self.primitive not in PRIMITIVE_NAMES:
            raise RuleIRValidationError("UNKNOWN_PRIMITIVE",
                                        f"{self.primitive!r} is not a RuleIR primitive",
                                        "operators")


OPERATORS: dict[str, OperatorSpec] = {
    spec.primitive: spec for spec in (
        OperatorSpec("Read", time_behaviour="source_bound"),
        OperatorSpec("Derive", cardinality="one_to_one"),
        OperatorSpec("Filter", cardinality="zero_to_many"),
        OperatorSpec("Expand", cardinality="one_to_many"),
        OperatorSpec("Aggregate", produces_measures=True, time_behaviour="frame"),
        OperatorSpec("Arrange"),
        OperatorSpec("Join", cardinality="many_to_many", time_behaviour="optional_temporal"),
        OperatorSpec("SetOp", cardinality="zero_to_many"),
        OperatorSpec("Pattern", cardinality="zero_to_many", time_behaviour="max_span", stateful=True),
        OperatorSpec("Iterate", cardinality="one_to_one", stateful=True),
        OperatorSpec("Emit"),
    )
}


# --------------------------------------------------------------------------
# Target profiles
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetProfile:
    """One (product, engine, artifact kind) combination.

    A saved search and a detecting custom rule are DIFFERENT artifact kinds for the same
    product. Collapsing them is what would let grouped historical AQL be presented as an
    event sequence, so the key carries all three parts.
    """
    product: str
    engine: str
    artifact_kind: str
    dialect: str
    version_range: str | None = None
    inferred_target: bool = False
    grants_execution: bool = True
    notes: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.grants_execution, bool):
            raise RuleIRValidationError(
                "MALFORMED_PROFILE",
                f"grants_execution must be a real bool, got {self.grants_execution!r}; "
                f"a truthy string like 'false' would grant execution", self.profile_id)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.product, self.engine, self.artifact_kind)

    @property
    def profile_id(self) -> str:
        return f"{self.product}+{self.engine}+{self.artifact_kind}"


PROFILES: tuple[TargetProfile, ...] = (
    # QRadar: AQL saved search and CRE custom rule content are separate artifact kinds.
    TargetProfile("qradar", "aql", "saved_search", "qradar-aql", "7.4",
                  inferred_target=True,
                  notes="grouped historical search; NOT an event sequence"),
    TargetProfile("qradar", "cre", "custom_rule_content", "qradar-cre",
                  inferred_target=True, grants_execution=True,
                  notes="stateful sequences and counters live here, not in AQL"),
    # Elastic: ES|QL and EQL are separate engines, not dialects of one.
    TargetProfile("elastic", "esql", "detection_rule", "elastic-esql",
                  notes="no event-stream sequence; LOOKUP JOIN is enrichment"),
    TargetProfile("elastic", "eql", "detection_rule", "elastic-eql",
                  notes="ordered linear sequence with maxspan only"),
    # Sigma is an interchange format: it grants no executable capability at all.
    TargetProfile("sigma", "yaml", "interchange", "sigma-yaml", grants_execution=False,
                  notes="no scheduling, no execution, no query semantics"),
    # The remaining targets have profiles but no registered emitters, so they refuse
    # everything until a renderer lands.
    TargetProfile("splunk", "spl", "correlation_search", "splunk-spl"),
    TargetProfile("sentinel", "kql", "analytic_rule", "sentinel-kql"),
    TargetProfile("google_secops", "yaral", "yaral_rule", "yaral"),
    TargetProfile("falcon", "cql", "search", "falcon-cql"),
    TargetProfile("wazuh", "ruleset_xml", "custom_rule", "wazuh-xml", inferred_target=True),
)

PROFILE_BY_ID: dict[str, TargetProfile] = {p.profile_id: p for p in PROFILES}


def find_profile(product: str, engine: str | None = None,
                 artifact_kind: str | None = None) -> TargetProfile | None:
    """Resolve a profile by key. Refuses to guess.

    Supplying only a product is allowed ONLY when that product has exactly one profile.
    `find_profile("qradar")` therefore returns None, because silently returning the AQL saved
    search would hand a caller grouped-search semantics when it asked for "QRadar" and might
    have meant the CRE detecting rule. That confusion is the R4 defect, and an earlier draft
    of this function reintroduced it through this very call.
    """
    if engine is None and artifact_kind is None:
        candidates = [p for p in PROFILES if p.product == product]
        return candidates[0] if len(candidates) == 1 else None
    if engine is None or artifact_kind is None:
        return None
    for profile in PROFILES:
        if profile.key == (product, engine, artifact_kind):
            return profile
    return None


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Resolution:
    """The answer to "can this graph be expressed in this dialect?".

    This is a CAPABILITY answer, not an EXECUTION result, and it deliberately has no
    `deployable` property. `deployable` is a claim about an artifact that was produced and
    checked; it cannot be answered by looking at a table. An earlier draft carried
    `deployable` here, which meant a catalog entry could assert deployability on its own -
    the exact defect this module exists to prevent. To obtain an artifact, call `lower()`.
    """
    profile_id: str
    status: str                      # "resolvable" | "refused"
    support: str                     # native | equivalent | refused
    refusal_code: str | None = None
    reason: str = ""
    unsupported: tuple[tuple[str, str], ...] = ()   # (primitive, reason) per node
    inferred_target: bool = False
    emitter_ids: tuple[str, ...] = ()                # which emitters `lower()` would use
    bindings: dict[str, "Emitter"] = field(default_factory=dict, compare=False, repr=False)

    @property
    def resolvable(self) -> bool:
        return self.status == "resolvable"

    def emitter_for(self, node: Any) -> "Emitter | None":
        """The exact emitter `resolve()` chose for this node.

        Bound during resolution and replayed by `lower()`, because re-querying the registry
        between the two re-introduces a time-of-check/time-of-use gap: a lowering that
        swapped `EMITTERS` would run a different emitter than the one whose `exact` flag
        produced `support`, so the artifact would carry a support claim no emitter in it
        actually justifies.
        """
        return self.bindings.get(node.id)


@dataclass(frozen=True)
class LoweredArtifact:
    """A real artifact, produced by actually running the registered lowerings."""
    profile_id: str
    text: str
    support: str
    emitter_ids: tuple[str, ...]


def _preflight_semantics(ir: RuleIR) -> tuple[str, str] | None:
    """Target-facing deployability checks that `validate_ir` does not make.

    `validate_ir` refuses an unresolved (`None`) source, but a blank or whitespace-only name
    is just as unusable: a renderer would have to invent it. The same goes for an invented
    schema id, a low-confidence field, an unknown source strategy, an unknown comparison or
    boolean operator, a function whose arity violates its own declared contract, and a
    function whose contract demands a declared dialect.

    Every node is walked over its ACTUAL dataclass fields rather than a hand-listed set of
    attribute names. An earlier version passed only `node.condition` into the checker, which
    silently skipped `Join.on`, `Derive.assignments`, `Measure.where`, `InList`,
    `Expand.field`, `Arrange.order_by`, `Pattern.key` and `Emit` - so an unverified field
    hidden in any of those reached a rendered artifact. Enumerating fields by hand is how
    that hole appeared; walking the fields cannot miss one that already exists.
    """
    for node in ir.nodes:
        if isinstance(node, Read):
            problem = _check_selector(node)
            if problem is not None:
                return problem
            if node.selector.strategy == "prior_emission" and not (
                    ir.package is not None and ir.package.dependencies):
                # Reading another rule's output is a dependency, so a bare package with no
                # edge does not establish one. "There is a package" is not "the dependency
                # is declared".
                return ("PRIOR_EMISSION_WITHOUT_PACKAGE",
                        f"source {node.id!r} reads a prior emission but no package declares "
                        f"a dependency edge to supply it")
        problem = _walk_values(node, node.id, depth=0)
        if problem is not None:
            return problem
    return None


#: Guard against a pathological graph turning the preflight into unbounded recursion. The
#: kernel validator has the same gap; this at least bounds the registry's own walk.
_MAX_PREFLIGHT_DEPTH = 64


def _walk_values(value: Any, owner: str, depth: int) -> tuple[str, str] | None:
    """Recursively inspect every dataclass field, tuple and list reachable from `value`."""
    if depth > _MAX_PREFLIGHT_DEPTH:
        return ("EXPRESSION_TOO_DEEP",
                f"{owner!r} nests expressions more than {_MAX_PREFLIGHT_DEPTH} deep; refusing "
                f"to walk it")
    if isinstance(value, (tuple, list)):
        for item in value:
            # Derive.assignments holds (FieldRef, Expr) pairs, so unpack before recursing.
            if isinstance(item, (tuple, list)) and len(item) == 2:
                problem = _walk_values(item[0], owner, depth + 1) \
                    or _walk_values(item[1], owner, depth + 1)
            else:
                problem = _walk_values(item, owner, depth + 1)
            if problem is not None:
                return problem
        return None
    if not dataclasses.is_dataclass(value) or isinstance(value, type):
        return None

    from models.rule_ir import FUNCTION_CONTRACTS
    if isinstance(value, Call):
        contract = FUNCTION_CONTRACTS.get(value.function)
        if contract is None:
            return ("UNKNOWN_FUNCTION",
                    f"{owner!r} calls unregistered function {value.function!r}")
        arity = contract["arity"]
        count = len(value.args)
        # An int arity is exact; a (min, max) pair is a range, with None for unbounded.
        low, high = arity if isinstance(arity, tuple) else (arity, arity)
        if count < low or (high is not None and count > high):
            allowed = f"{low}" if low == high else f"{low}..{high}"
            return ("FUNCTION_ARITY_VIOLATION",
                    f"{owner!r} calls {value.function!r} with {count} argument(s); the "
                    f"contract allows {allowed}")
        if contract.get("dialect") == "must_be_declared" and not getattr(
                value, "dialect", None):
            return ("FUNCTION_DIALECT_UNDECLARED",
                    f"{owner!r} calls {value.function!r}, whose contract requires an explicit "
                    f"dialect declaration; an undeclared regex dialect is not portable")
    if isinstance(value, BoolOp) and value.op not in _BOOL_OPS:
        return ("UNKNOWN_BOOLEAN_OPERATOR",
                f"{owner!r} uses unknown boolean operator {value.op!r}")
    if isinstance(value, Comparison) and value.op not in _COMPARISON_OPS:
        return ("UNKNOWN_COMPARISON_OPERATOR",
                f"{owner!r} uses unknown comparison operator {value.op!r}")
    if isinstance(value, FieldRef) and value.confidence in ("unverified", "inferred"):
        return ("UNVERIFIED_FIELD_REFERENCE",
                f"{owner!r} references field {value.name!r} at confidence "
                f"{value.confidence!r}; it is not documented")
    if isinstance(value, SourceSelector) and value.name is not None \
            and value.confidence in ("unverified", "inferred"):
        return ("UNVERIFIED_SOURCE_REFERENCE",
                f"{owner!r} names source {value.name!r} at confidence "
                f"{value.confidence!r}; it is not documented")

    for f in dataclasses.fields(value):
        child = getattr(value, f.name, None)
        if child is None:
            continue
        problem = _walk_values(child, owner, depth + 1)
        if problem is not None:
            return problem
    return None


def _literal_values(cls: type, field_name: str) -> frozenset[str]:
    """The strings a `Literal[...]` annotation on `cls.field_name` permits.

    The operator vocabularies are read from the model rather than restated here. An earlier
    draft hard-coded a 21-entry comparison allowlist including `exists`, `is_null`,
    `between` and `contains` - fifteen operators the IR cannot express. The only effect was
    to wave unknown operators through a check whose entire job is to refuse them: a gate
    that fails open, in the component built to fail closed. A second hand-written copy of a
    vocabulary is guaranteed to drift from the one it claims to describe.

    `get_type_hints` is required because the model uses `from __future__ import
    annotations`, so the raw field type is a string and `get_origin` would find nothing -
    which would quietly yield an EMPTY allowlist and refuse every comparison.
    """
    annotation = get_type_hints(cls).get(field_name)
    if get_origin(annotation) is not Literal:
        return frozenset()
    return frozenset(str(arg) for arg in get_args(annotation))


_COMPARISON_OPS = _literal_values(Comparison, "op")
_BOOL_OPS = _literal_values(BoolOp, "op")
_SET_OPS = _literal_values(SetOp, "op")
_SOURCE_STRATEGIES = _literal_values(SourceSelector, "strategy")
_EXPRESSION_FUNCTIONS = frozenset(FUNCTION_CONTRACTS)


def vocabulary() -> dict[str, frozenset[str]]:
    """Every vocabulary the preflight enforces, read from the model itself."""
    return {
        "comparison": _COMPARISON_OPS,
        "boolean": _BOOL_OPS,
        "set_op": _SET_OPS,
        "source_strategy": _SOURCE_STRATEGIES,
        "scalar_function": _EXPRESSION_FUNCTIONS,
    }


def _check_selector(node: Read) -> tuple[str, str] | None:
    """Source-level checks a renderer would otherwise have to guess at."""
    selector = node.selector
    if selector.name is not None and not selector.name.strip():
        return ("UNRESOLVED_SOURCE",
                f"source of {node.id!r} is blank; refusing to invent a table or index")
    if selector.confidence in ("unverified", "inferred") and selector.name is not None:
        return ("UNVERIFIED_SOURCE_REFERENCE",
                f"source of {node.id!r} is named {selector.name!r} at confidence "
                f"{selector.confidence!r}; it is not documented")
    if selector.strategy not in _SOURCE_STRATEGIES:
        return ("UNKNOWN_SOURCE_STRATEGY",
                f"source {node.id!r} uses unknown strategy {selector.strategy!r}")
    if selector.strategy == "accelerated" and not (selector.schema_id or "").strip():
        return ("ACCELERATED_SOURCE_WITHOUT_SCHEMA",
                f"source {node.id!r} is accelerated with no schema contract")
    return None


def resolve(ir: RuleIR, profile: TargetProfile) -> Resolution:
    """Decide whether `ir` can be lowered into `profile`.

    Whole-graph, default-deny, never partially resolvable. Raises only for a structurally
    invalid IR, which is a caller error rather than a capability question.
    """
    if not any(p == profile for p in PROFILES):
        # A caller-constructed profile can name a registered dialect and an arbitrary
        # version, which is a capability bypass the moment any emitter exists. Profiles
        # come from the catalog or they are not profiles.
        raise RuleIRValidationError(
            "UNREGISTERED_PROFILE",
            f"{profile.profile_id!r} is not in the profile catalog; a forged profile could "
            f"claim a registered dialect and a chosen target version", "profiles")

    # Target-aware validation. Without `target`, an unresolved source or an accelerated
    # source with no schema contract passes, and the refusal then has to invent a table or
    # index downstream - the one thing this project must never do.
    validate_ir(ir, target=profile.profile_id)

    for loss in ir.parse_diagnostics:
        if loss.severity == "must":
            # Our own parse gap. Reported as IR_UNSUPPORTED_CONSTRUCT, never as a vendor
            # limitation, because the analyst's next action is ours to fix.
            return Resolution(profile.profile_id, "refused", REFUSED,
                              "IR_UNSUPPORTED_CONSTRUCT", loss.message,
                              inferred_target=profile.inferred_target)

    if not profile.grants_execution:
        return Resolution(profile.profile_id, "refused", REFUSED,
                          "PROFILE_GRANTS_NO_EXECUTION",
                          f"{profile.product} {profile.artifact_kind} is an interchange "
                          f"format, not an executing engine",
                          inferred_target=profile.inferred_target)

    if ir.package is not None:
        package = ir.package
        # A bundle is a bundle whether or not an edge is drawn between its units. Resolving
        # one member while silently omitting its siblings would produce a rule that looks
        # like the bundle and is not, so any multi-unit package refuses.
        if len(package.units) > 1 or package.dependencies:
            return Resolution(profile.profile_id, "refused", REFUSED,
                              "BUNDLE_DEPENDENCY_NOT_EXPRESSIBLE",
                              f"this rule is one of {len(package.units)} units in a package "
                              f"with {len(package.dependencies)} dependency edge(s), and "
                              f"{profile.profile_id} has no registered emitter for a rule "
                              f"bundle. Emitting the member rules separately would drop the "
                              f"package's unit set and dependency ordering, so the package is "
                              f"refused rather than flattened.",
                              inferred_target=profile.inferred_target)

    semantic = _preflight_semantics(ir)
    if semantic is not None:
        return Resolution(profile.profile_id, "refused", REFUSED, semantic[0], semantic[1],
                          inferred_target=profile.inferred_target)

    unsupported: list[tuple[str, str]] = []
    exact_flags: list[bool] = []
    chosen: list[str] = []
    bindings: dict[str, Emitter] = {}
    for node in ir.nodes:
        primitive = primitive_of(node)
        if primitive is None:
            # Not a kernel node. Never resolve by class name: a lookalike class would
            # otherwise be treated as a real primitive and emitted.
            unsupported.append((type(node).__name__, "NOT_A_KERNEL_NODE"))
            continue
        if primitive not in OPERATORS:
            unsupported.append((primitive, "IR_UNSUPPORTED_CONSTRUCT"))
            continue
        candidates = emitters_for(profile.dialect, primitive, profile.version_range)
        matches = [e for e in candidates if e.accepts(node)]
        if not matches:
            if not candidates:
                unsupported.append((primitive, "IR_UNSUPPORTED_EMITTER"))
            else:
                # Name the parameter that was denied. "Unsupported parameter shape" without
                # saying WHICH shape sends the analyst hunting through our own source.
                denied = sorted({a for e in candidates for a in e.forbids
                                 if getattr(node, a, None) is not None})
                unsupported.append((primitive, "IR_UNSUPPORTED_PARAMETERS"
                                    if not denied else f"IR_UNSUPPORTED_PARAMETERS:{denied[0]}"))
            continue
        # Among applicable lowerings, the most native one is the one that would be used.
        best = max(matches, key=lambda e: e.exact)
        exact_flags.append(best.exact)
        chosen.append(best.emitter_id)
        bindings[node.id] = best

    if unsupported:
        detail = "; ".join(f"{p} ({why})" for p, why in unsupported)
        parameter_only = all(why.startswith("IR_UNSUPPORTED_PARAMETERS")
                             for _p, why in unsupported)
        if parameter_only:
            code = "IR_UNSUPPORTED_PARAMETERS"
            reason = (f"{profile.dialect} has a registered emitter for every primitive in this "
                      f"graph, but not for the parameter shape used here: {detail}. The target "
                      f"construct for that shape does not exist.")
        else:
            code = "IR_UNSUPPORTED_EMITTER"
            reason = (f"no registered {profile.dialect} emitter for: {detail}. "
                      f"A capability entry cannot substitute for a renderer that does "
                      f"not exist yet.")
        return Resolution(profile.profile_id, "refused", REFUSED, code, reason,
                          tuple(unsupported), profile.inferred_target)

    # Native only if EVERY lowering is native. An earlier draft said native if ANY node was
    # exact, which would have mislabelled a mixed graph the moment an equivalent emitter
    # landed.
    overall = NATIVE if all(exact_flags) else EQUIVALENT
    return Resolution(profile.profile_id, "resolvable", overall, None,
                      f"every primitive has a registered {profile.dialect} emitter",
                      (), profile.inferred_target, tuple(chosen), bindings)


def lower(ir: RuleIR, profile: TargetProfile) -> LoweredArtifact:
    """Actually produce target text by RUNNING the registered lowerings.

    This is the only function in the module that can return an artifact, and it is
    deliberately separate from `resolve()`. A capability table says what is possible; only
    running a renderer says what was produced. Keeping them apart is what stops a catalog
    row from asserting deployability on its own.

    Every emitter bound during resolution is invoked - the same emitter object, not a fresh
    lookup, so a registry swap between the two calls cannot change what runs or what the
    artifact's support claim is based on. An emitter that raises, or that returns text which
    is not a non-empty string, fails the whole lowering: a partially rendered rule is
    exactly the artifact that deploys and does not fire.
    """
    resolution = resolve(ir, profile)
    if not resolution.resolvable:
        raise RuleIRValidationError(
            resolution.refusal_code or "IR_UNSUPPORTED_EMITTER",
            resolution.reason or "the graph cannot be lowered into this profile", "lower")

    pieces: list[str] = []
    used: list[str] = []
    for node in ir.nodes:
        emitter = resolution.emitter_for(node)
        if emitter is None:
            raise RuleIRValidationError(
                "EMITTER_DISAPPEARED",
                f"no emitter was bound for node {node.id!r} during resolution", "lower")
        try:
            text = emitter.lowering(node)
        except RuleIRValidationError:
            raise
        except Exception as exc:
            # Renderer detail is redacted from the user-facing message: a renderer exception
            # can carry a file path, a fragment of source text, or a secret from a config.
            raise RuleIRValidationError(
                "EMITTER_FAILED",
                f"emitter {emitter.emitter_id!r} failed on node {node.id!r}",
                "lower") from exc
        if not isinstance(text, str) or not text.strip():
            raise RuleIRValidationError(
                "EMITTER_PRODUCED_NO_TEXT",
                f"emitter {emitter.emitter_id!r} produced no usable text for node "
                f"{node.id!r}; an empty artifact would deploy and never fire", "lower")
        pieces.append(text)
        used.append(emitter.emitter_id)

    body = "\n".join(pieces)
    if not body.strip():
        raise RuleIRValidationError("EMPTY_ARTIFACT",
                                    "lowering produced an empty artifact", "lower")
    return LoweredArtifact(profile.profile_id, body, resolution.support, tuple(used))


def resolve_for_product(ir: RuleIR, product: str) -> Resolution:
    """Resolve against a product's only artifact kind, refusing when ambiguous.

    Where a product has more than one artifact kind, picking one silently is how R4
    happened, so ambiguity refuses.
    """
    candidates = [p for p in PROFILES if p.product == product]
    if not candidates:
        return Resolution(f"{product}+*", "refused", REFUSED, "UNKNOWN_PRODUCT",
                          f"no profile is registered for {product}")
    if len(candidates) > 1:
        return Resolution(f"{product}+*", "refused", REFUSED, "ARTIFACT_KIND_AMBIGUOUS",
                          f"{product} has {len(candidates)} artifact kinds "
                          f"({', '.join(c.artifact_kind for c in candidates)}); the caller must "
                          f"say which one it wants, because a saved search and a detecting "
                          f"rule are not interchangeable")
    return resolve(ir, candidates[0])


# --------------------------------------------------------------------------
# Self-check: the catalogs must not contradict the kernel
# --------------------------------------------------------------------------


def audit() -> list[str]:
    """Return a list of inconsistencies between the catalogs and the kernel.

    A capability layer that disagrees with the model it describes is worse than no
    capability layer, so this is callable from a test rather than being a comment.

    It also checks the things an earlier draft missed, each of which had let a clean audit
    stand in for proof of honesty while the registry was returning false positives: every
    registered emitter must have a callable lowering, no planned emitter may have leaked
    into the registered set, and every enforced vocabulary must have been resolved from the
    model rather than silently coming back empty.
    """
    problems: list[str] = []
    for primitive in PRIMITIVE_NAMES:
        if primitive not in OPERATORS:
            problems.append(f"primitive {primitive} has no operator spec")
        if primitive not in NODE_TYPES:
            problems.append(f"primitive {primitive} has no concrete node class")
    for primitive in OPERATORS:
        if primitive not in PRIMITIVE_NAMES:
            problems.append(f"operator spec {primitive} is not a kernel primitive")

    for name, allowed in vocabulary().items():
        if not allowed:
            # An empty vocabulary means the model's Literal annotation failed to resolve.
            # Silently refusing every expression would look like a working strict check.
            problems.append(f"vocabulary {name!r} resolved EMPTY from the model; the preflight "
                            f"would refuse every value instead of every unknown one")
    if vocabulary()["comparison"] != frozenset({"=", "!=", "<", "<=", ">", ">=",
                                                "exists", "is_not_null"}):
        problems.append(f"the model's comparison vocabulary changed: "
                        f"{sorted(vocabulary()['comparison'])}")

    for emitter in EMITTERS:
        if not isinstance(emitter, Emitter):
            problems.append(f"registry contains a non-Emitter {type(emitter).__name__}; a "
                            f"planned row must never be registered as capability")
            continue
        if not callable(emitter.lowering):
            problems.append(f"registered emitter {emitter.emitter_id!r} has no callable "
                            f"lowering; it certifies capability that does not exist")
        if emitter.primitive not in NODE_TYPES:
            problems.append(f"registered emitter {emitter.emitter_id!r} targets unknown "
                            f"primitive {emitter.primitive!r}")
    planned_ids = {e.emitter_id for e in PLANNED_EMITTERS}
    for emitter in EMITTERS:
        if getattr(emitter, "emitter_id", None) in planned_ids:
            problems.append(f"emitter {emitter.emitter_id!r} is both planned and registered; "
                            f"a planned emitter must never grant capability")

    for profile in PROFILES:
        if profile.dialect in registered_dialects() and profile.grants_execution:
            declared = {e.primitive for e in EMITTERS
                        if isinstance(e, Emitter) and e.dialect == profile.dialect}
            for primitive in declared:
                if primitive not in PRIMITIVE_NAMES:
                    problems.append(f"{profile.profile_id} registers an emitter for "
                                    f"unknown primitive {primitive}")

    for product in ("wazuh", "qradar"):
        for profile in PROFILES:
            if profile.product == product and profile.grants_execution \
                    and not profile.inferred_target:
                problems.append(f"{profile.profile_id} must be inferred_target: {product} "
                                f"publishes no field schema")
    return problems
