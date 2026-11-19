"""Microsoft Sentinel / Log Analytics KQL.

The reference rule this dialect is built around, because it contains every
construct that makes KQL hard and none of them are optional:

    let LSASSAccess = SecurityEvent
        | where EventID == 10
        | project LSASSTime=TimeGenerated, Computer, Account, SourceImage;

    let LateralMovement = SecurityEvent
        | where EventID == 4624
        | project LoginTime=TimeGenerated, Computer, Account;

    LSASSAccess
    | join kind=inner (LateralMovement) on Computer, Account
    | where LoginTime between (LSASSTime .. LSASSTime + 10m)
    | summarize Hits=count(), FirstSeen=min(LSASSTime) by Computer, Account

Four things here are why a chain-of-stages model is not enough:

  1. `let` defines a named pipeline that is USED LATER, after both are defined.
     A linear stage chain cannot express "define two streams, then correlate".
  2. `join ... (Table) on K1, K2` -- the operand is a NAME, not a subquery, and
     the name was bound earlier.
  3. `| where LoginTime between (LSASSTime .. LSASSTime + 10m)` reads a field
     from the RIGHT row and a field from the LEFT row in one predicate.
  4. `summarize ... by` is an aggregate, and a `where` after it is a
     post-aggregate filter, which is a different operator from the `where`
     before it.
"""

from __future__ import annotations

import re

import dataclasses
from dataclasses import dataclass, field as dc_field
from decimal import Decimal
from typing import Any, Final

from ..ir import (
    Aggregate,
    Arith,
    Binding,
    BoolOp,
    Call,
    Comparison,
    Correlation,
    Derive,
    Distinct,
    Duration,
    Emit,
    FieldRef,
    Filter,
    Join,
    Limit,
    ListExpr,
    Literal,
    Measure,
    Not,
    Project,
    Read,
    Regex,
    Rule,
    Sort,
    Span,
    SubQuery,
    Window,
)
from ..ir import Annotations, render_expr
from ..validate import validate
from ..values import Capability, Duration as DurationValue, Refusal, duration_seconds
from .common import (
    plain_number,
    is_bare_identifier,
    C_LIKE_PRECEDENCE,
    Diagnostic,
    DialectSpec,
    Parser,
    Token,
    parse_annotation_header,
    render_annotation_header,
    split_top_level,
    strip_comments,
    tokenize,
    refuse_cross_row_predicate,
)

__all__ = ["DIALECT", "LANGUAGE", "SPEC", "Diagnostic", "lower_kql", "render_kql",
           "parse_kql", "ParsedKql"]

DIALECT: Final = "sentinel"
LANGUAGE: Final = "KQL"


# ---------------------------------------------------------------------------
# Spec
# ---------------------------------------------------------------------------

#: KQL's regex is RE2. RE2 has no backreferences and no lookaround, so it sits
#: much closer to POSIX ERE than to PCRE does, and modelling it as PCRE would
#: make this engine refuse vendor rules that are actually portable.
SPEC: Final = DialectSpec(
    key=DIALECT,
    language=LANGUAGE,
    precedence=dict(C_LIKE_PRECEDENCE),
    operators={
        "==": "==", "=": "==", "eq": "==",
        "!=": "!=", "<>": "!=",
        "and": "and", "or": "or",
        "=~": "matches", "!~": "!~",
        "in": "in", "in~": "in", "!in": "in", "!in~": "in",
        # `has_any` and `has_all` were mapped to THEMSELVES, and neither is in
        # `ir.COMPARISON_OPS` -- so `A has_any ("x","y")` raised
        # OPERATOR_UNKNOWN from the Comparison constructor. The spec emitted
        # an operator the model rejects, which the evaluator meanwhile
        # supported under a different name.
        #
        # Mapped onto `contains_any` / `contains_all`, which exist and mean
        # "any of these appears". That follows the `has` -> `contains`
        # precedent two lines down and carries its approximation: KQL's `has`
        # family matches whole TERMS and `contains` matches substrings, so the
        # local answer is slightly broader than Sentinel's for a term that is
        # a prefix of a longer word.
        "has_any": "contains_any", "has_all": "contains_all",
        # KQL's bare `has`, `contains`, `startswith` and `endswith` are
        # case-INSENSITIVE; the `_cs` forms are not. The engine's `contains`
        # IS case-sensitive, so mapping both spellings onto it made the two
        # indistinguishable: a round trip turned a case-insensitive test into
        # a case-sensitive one and the rule stopped matching `LSASS.EXE`.
        #
        # `_KqlParser.build_comparison` intercepts the bare spellings before
        # this map is consulted and folds them into a case-folding regex,
        # which is the only construct the engine has that carries the fold.
        # The entries here are the fallback, and they are the case-sensitive
        # ops so a spelling that somehow escapes the intercept narrows rather
        # than widens.
        "has": "contains", "contains": "contains",
        "hasprefix": "startswith", "startswith": "startswith",
        "hassuffix": "endswith", "endswith": "endswith",
        "has_cs": "contains", "contains_cs": "contains",
        "startswith_cs": "startswith", "endswith_cs": "endswith",
        "hasprefix_cs": "startswith", "hassuffix_cs": "endswith",
        "contains_any": "contains_any",
        "contains_all": "contains_all",
        "between": "between", "matches": "matches",
    },
    keywords=frozenset({
        "let", "where", "project", "project-away", "project-rename",
        "extend", "summarize", "join", "sort", "order", "top", "take",
        "limit", "distinct", "count", "countif", "dcount", "sum", "min",
        "max", "avg", "stdev", "make_set", "make_list", "make_bag",
        "make_array", "todynamic", "percentile", "arg_max", "arg_min",
        "by", "asc", "desc", "and", "or", "not", "in", "between", "on",
        "kind", "inner", "leftouter", "rightouter", "fullouter", "leftanti",
        "rightanti", "leftsemi", "rightsemi", "innerunique", "with",
        "hint", "to_string", "to_int", "to_long", "to_real", "to_bool",
        "to_lower", "to_upper", "strcat", "strlen", "substring", "split",
        "bin", "ago", "now", "datetime", "iff", "case", "regex", "nocase",
        "true", "false", "null", "print", "table", "evaluate", "invoke",
        "union", "sample", "top-nested", "consume", "range",
    }),
    # The keys are KQL's OWN spellings, which is the whole point of this map.
    # Several used to be the ENGINE's underscored names instead -- `to_lower`,
    # `to_string`, `to_int` -- which KQL does not have. A rule written
    # `tolower(Account)` therefore matched nothing in this map, passed through
    # lowering as a function called `tolower`, and the evaluator could not
    # resolve it: every row went UNDECIDED and the rule reported
    # `not_evaluated` rather than a verdict. The underscored forms are kept as
    # aliases so anything that previously parsed still does.
    functions={
        "ago": "ago", "now": "now", "datetime": "to_timestamp",
        "bin": "bin", "count": "count", "countif": "count_if",
        "dcount": "dcount", "dcountif": "dcount",
        "sum": "sum", "min": "min", "max": "max",
        "avg": "avg", "stdev": "stdev", "make_set": "make_set",
        "make_list": "make_list", "make_bag": "make_list",
        "make_array": "make_list", "todynamic": "make_list",
        "percentile": "percentile", "arg_max": "arg_max",
        "arg_min": "arg_min",
        # KQL's real spellings.
        "tostring": "to_string", "toint": "to_int", "tolong": "to_int",
        "toreal": "to_float", "todouble": "to_float", "tobool": "to_bool",
        "tolower": "lower", "toupper": "upper",
        # `isnull` maps to `is_null_or_absent`, NOT to the strict `is_null`.
        # KQL's schema is fixed -- every row carries every column -- so a
        # missing value there IS null, and the strict predicate (which Sigma
        # needs) left every such row UNDECIDED and the rule
        # `not_evaluated` on exactly the events it was written for.
        "isnull": "is_null_or_absent", "isnotnull": "is_present",
        "isempty": "is_empty", "isnotempty": "not_empty",
        "array_length": "length", "coalesce": "coalesce",
        "ipv4_is_in_range": "cidr_contains",
        # Aliases: the engine's own names, accepted so previously-parsing
        # input keeps parsing.
        "to_string": "to_string", "to_int": "to_int",
        "to_long": "to_int", "to_real": "to_float", "to_bool": "to_bool",
        "to_lower": "lower", "to_upper": "upper",
        "strcat": "strcat",
        "strlen": "strlen", "substring": "substring", "split": "split",
        "iff": "iff", "case": "case",
    },
    default_regex_dialect="posix_extended",
)

#: `!endswith`, `!has`, `!contains` and the rest of KQL's negated string
#: operators. The shared parser decides whether a word is an infix operator by
#: looking its BINDING POWER up in the spec, so each negated spelling needs an
#: entry or the expression stops at the operator. They map to the same engine
#: operator as their positive form; `_KqlParser.build_comparison` wraps the
#: result in `Not`, so `!has` and `not (... has ...)` cannot drift apart.
for _negated in ("has", "has_cs", "hasprefix", "hasprefix_cs", "hassuffix",
                 "hassuffix_cs", "contains", "contains_cs", "startswith",
                 "startswith_cs", "endswith", "endswith_cs", "in", "has_any",
                 "has_all", "between"):
    SPEC.operators["!" + _negated] = SPEC.operators[_negated]
del _negated

#: Aggregates KQL spells, mapped to what this engine computes.
AGGREGATES: Final[dict[str, tuple[str, bool]]] = {
    # name: (engine function, is_distinct)
    "count": ("count", False),
    "countif": ("count_if", False),
    "dcount": ("dcount", True),
    "distinctcount": ("dcount", True),
    "sum": ("sum", False),
    "min": ("min", False),
    "max": ("max", False),
    "avg": ("avg", False),
    "stdev": ("stdev", False),
    "make_set": ("make_set", True),
    "makelist": ("make_list", False),
    "make_list": ("make_list", False),
    "make_bag": ("make_list", False),
    "make_array": ("make_list", False),
    "todynamic": ("make_list", False),
    "arg_max": ("arg_max", False),
    "arg_min": ("arg_min", False),
    "percentile": ("percentile", False),
}

#: Aggregates that take an extra parameter, e.g. `percentile(x, 95)`.
PARAMETERISED: Final[frozenset[str]] = frozenset({"percentile"})

#: Join kinds, mapped to the model's.
JOIN_KINDS: Final[dict[str, str]] = {
    "inner": "inner",
    "innerunique": "inner",
    "leftouter": "left",
    "leftanti": "anti",
    "leftsemi": "left",
    "rightouter": "right",
    "rightanti": "anti",
    "rightsemi": "right",
    "fullouter": "full",
}

#: Columns a table may be joined on that are prefixed with the right-hand name.
UNSUPPORTED_OPERATORS: Final[dict[str, str]] = {
    "sample": "KQL's `sample` picks rows at RANDOM, so the rows it returns "
              "depend on a seed and cannot be reproduced. A rule built on it "
              "is not a rule.",
    "evaluate": "KQL's `evaluate` runs arbitrary plugin code on the cluster. "
                "There is nothing to model here and plenty to be careful about.",
    "invoke": "same problem as `evaluate`",
    "consume": "KQL's `consume` is a queue operation, not a filter",
    "range": "`range` generates rows rather than filtering them",
}


# ---------------------------------------------------------------------------
# Parsed shape
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ParsedStage:
    operator: str
    body: str
    options: dict[str, str] = dc_field(default_factory=dict)


@dataclass(slots=True)
class ParsedLet:
    name: str
    source: str
    stages: list[ParsedStage] = dc_field(default_factory=list)


@dataclass(slots=True)
class ParsedKql:
    lets: list[ParsedLet] = dc_field(default_factory=list)
    source: str = ""
    stages: list[ParsedStage] = dc_field(default_factory=list)
    raw: str = ""


def parse_kql(text: str) -> ParsedKql:
    """Split a KQL script into `let` bindings and the main pipeline.

    A SPLIT, not a parse. The expression grammar is the shared parser's job;
    what is dialect-specific is knowing that a `;` ends a `let` and a `|` ends a
    stage, and that a `;` inside a string or a bracket is not a separator.
    """
    cleaned = strip_comments(text or "")
    lets: list[ParsedLet] = []
    pieces = split_top_level(cleaned, ";")
    main = pieces[-1] if pieces else ""
    for piece in pieces[:-1]:
        piece = piece.strip()
        if not piece:
            continue
        lowered = piece.lower()
        if not lowered.startswith("let "):
            raise Refusal(
                "KQL_STATEMENT_UNKNOWN",
                f"`{piece[:60]}` does not start with `let`. A KQL script here is "
                f"a sequence of `let name = <pipeline>;` bindings followed by one "
                f"pipeline. Split the rule on a semicolon and check the first "
                f"word of each part.",
                "parse",
            )
        head, _, rest = piece.partition("=")
        name = head[4:].strip()
        if not name:
            raise Refusal(
                "KQL_LET_NAME_MISSING",
                f"`let = {rest[:40]}` has no name. A binding has to be named, "
                f"because the name is what a later stage joins against.",
                "parse",
            )
        source, stages = _split_pipeline(rest.strip())
        lets.append(ParsedLet(name=name, source=source, stages=stages))

    source, stages = _split_pipeline(main.strip())
    return ParsedKql(lets=lets, source=source, stages=stages, raw=cleaned)


def _split_pipeline(text: str) -> tuple[str, list[ParsedStage]]:
    """A source table, then `| op` stages."""
    parts = split_top_level(text, "|")
    source = parts[0].strip() if parts else ""
    stages: list[ParsedStage] = []
    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue
        head, _, body = part.partition(" ")
        stages.append(
            ParsedStage(operator=head.strip(), body=body.strip())
        )
    return source, stages


# ---------------------------------------------------------------------------
# Lower
# ---------------------------------------------------------------------------


def lower_kql(text: str, rule_id: str = "rule") -> tuple[Rule, list[Diagnostic]]:
    """KQL text to a Rule, plus what could not be represented.

    A `//` annotation header at the top is read back into `ir.Annotations`.
    This function used to build `Annotations(title="")` unconditionally, so a
    rule that round-tripped through KQL lost its title, severity and ATT&CK
    mapping even when the text in front of it said otherwise.
    """
    header, body = parse_annotation_header(text, "//")
    parsed = parse_kql(body if header else text)
    diagnostics: list[Diagnostic] = []
    diagnostics.extend(_check_unsupported(parsed))

    bindings: list[Binding] = []
    columns: dict[str, set[str]] = {}
    constants: dict[str, tuple[Any, ...]] = {}
    for let in parsed.lets:
        # A `let` whose right-hand side is a LIST OF CONSTANTS is an allowlist,
        # not a pipeline. Resolving it here is what makes `Account in (Admins)`
        # a membership test against two strings instead of against a column
        # that no event has.
        values = _constant_list(let.source)
        if values is not None:
            constants[let.name] = values
            diagnostics.append(Diagnostic(
                code="KQL_LET_LIST_RESOLVED",
                message=(
                    f"`let {let.name}` is a list of {len(values)} constant(s), "
                    f"so it has been substituted wherever it is used. The "
                    f"exported query spells the values out; a Sentinel "
                    f"`dynamic([...])` literal is not carried across as a name."
                ),
                severity="note",
                verified=True,
            ))
            continue
        nodes = _lower_stream(
            let.source, let.stages, f"let_{let.name}", diagnostics,
            bindings=bindings,
        )
        bindings.append(Binding(name=let.name, pipeline=tuple(nodes)))
        columns[let.name] = _declared_columns(nodes)


    main = _lower_stream(
        parsed.source, parsed.stages, "main", diagnostics, columns=columns,
        bindings=bindings,
    )

    # Every graph names its output stage, so what the rule RETURNS is stated
    # rather than implied. Appended rather than required, because KQL has no
    # syntax for it -- the output is simply whatever the last stage leaves.
    if not any(isinstance(n, Emit) for n in main):
        main = list(main) + [Emit(id=f"{prefix_of(main)}_out")]

    if constants:
        # Applied to the finished stages rather than threaded through the
        # parser, so a `let` name reaches every condition that uses it --
        # including the ones inside a `summarize` or a join predicate.
        main = [
            Filter(id=node.id,
                   condition=_resolve_constants(node.condition, constants))
            if isinstance(node, Filter) else node
            for node in main
        ]

    rule = Rule(
        rule_id=rule_id,
        pipeline=tuple(main),
        bindings=tuple(bindings),
        annotations=Annotations(**header) if header else Annotations(title=""),
        metadata={"dialect": DIALECT, "language": LANGUAGE, "artifact": "rule"},
    )
    validate(rule)
    return rule, diagnostics


def _constant_list(source: str) -> tuple[Any, ...] | None:
    """The literal values of `dynamic([...])` or `datatable(...)[...]`.

    These are how a Sentinel author writes an allowlist, and the NAME was
    lowered as if it were a column: `Account in (Admins)` became a membership
    test against a field called `Admins`, which no event has, so every row came
    back undecided. Nothing was refused and nothing was reported -- the rule
    simply stopped deciding anything.

    Returns None for anything that is not a flat list of constants, so a `let`
    that really is a pipeline is left alone.
    """
    text = source.strip()
    inner: str | None = None
    lowered = text.lower()
    if lowered.startswith("dynamic(") and text.endswith(")"):
        inner = text[len("dynamic("):-1].strip()
    elif lowered.startswith("datatable("):
        close = text.find(")")
        if close != -1:
            rest = text[close + 1:].strip()
            if rest:
                inner = rest
    if inner is None or not (inner.startswith("[") and inner.endswith("]")):
        return None
    values: list[Any] = []
    for token in _tokenise_kql(inner[1:-1]):
        if token.kind == "eof":
            continue
        if token.kind == "punct" and token.text == ",":
            continue
        if token.kind == "string":
            values.append(Literal(token.text))
        elif token.kind == "number":
            try:
                values.append(Literal(Decimal(token.text)))
            except Exception:  # noqa: BLE001 - a number this cannot read
                return None
        else:
            return None
    return tuple(values) if values else None


def _resolve_constants(expr: Any, constants: dict[str, tuple[Any, ...]]) -> Any:
    """Replace a `let` name used as a list with the list it names.

    Only a name standing ALONE in a list is replaced. `in (Admins, "x")` is
    left as it is, because expanding one member of a mixed list would silently
    change which of the other members the author meant.
    """
    if not constants or expr is None:
        return expr
    if isinstance(expr, ListExpr):
        items = tuple(_resolve_constants(item, constants) for item in expr.items)
        if len(items) == 1 and isinstance(items[0], FieldRef):
            named = constants.get(items[0].full)
            if named is not None:
                return ListExpr(named)
        return ListExpr(items) if items != expr.items else expr
    if isinstance(expr, Comparison):
        left = _resolve_constants(expr.left, constants)
        right = _resolve_constants(expr.right, constants)
        if left is expr.left and right is expr.right:
            return expr
        return Comparison(expr.op, left, right, negate=expr.negate,
                          nocase=expr.nocase)
    if isinstance(expr, BoolOp):
        operands = tuple(_resolve_constants(o, constants) for o in expr.operands)
        return expr if operands == expr.operands else BoolOp(expr.op, operands)
    if isinstance(expr, Not):
        inner = _resolve_constants(expr.operand, constants)
        return expr if inner is expr.operand else Not(inner)
    if isinstance(expr, Call):
        args = tuple(_resolve_constants(a, constants) for a in expr.args)
        return expr if args == expr.args else Call(
            expr.function, args, flags=expr.flags)
    if isinstance(expr, Span):
        return expr
    if isinstance(expr, Arith):
        left = _resolve_constants(expr.left, constants)
        right = _resolve_constants(expr.right, constants)
        if left is expr.left and right is expr.right:
            return expr
        return Arith(expr.op, left, right)
    return expr


def _declared_columns(nodes: list[Any]) -> set[str]:
    """The column names a pipeline hands to whatever comes next.

    Read off the stages, not guessed from the table name. A `project` states
    exactly what comes out; a `project-away` states it by subtraction; anything
    else passes the source columns through, which is unknown until an event
    arrives -- and is recorded as unknown rather than invented.
    """
    names: set[str] = set()
    open_ended = False
    for node in nodes:
        if isinstance(node, Project):
            names = set(node.output_names)
            if not names:
                if node.drops:
                    open_ended = True
                else:
                    names = set()
        elif isinstance(node, Derive):
            names.update(name for name, _ in node.assignments)
        elif isinstance(node, Aggregate):
            names = {m.name for m in node.measures}
            names.update(r.full for r in node.keys)
    return names


def prefix_of(nodes: list[Any]) -> str:
    if nodes and nodes[0].id:
        return nodes[0].id.split("_read")[0]
    return "rule"


def _check_unsupported(parsed: ParsedKql) -> list[Diagnostic]:
    out: list[Diagnostic] = []
    stages = list(parsed.stages)
    for let in parsed.lets:
        stages.extend(let.stages)
    for stage in stages:
        for name, reason in UNSUPPORTED_OPERATORS.items():
            if stage.operator.lower() == name:
                out.append(
                    Diagnostic(
                        "KQL_OPERATOR_UNSUPPORTED",
                        f"`{stage.operator}` is not lowered. {reason}",
                        severity="problem",
                        verified=True,
                        evidence=f"the {stage.operator} operator",
                    )
                )
    return out


def _lower_stream(
    source: str,
    stages: list[ParsedStage],
    prefix: str,
    diagnostics: list[Diagnostic],
    columns: dict[str, set[str]] | None = None,
    bindings: list[Binding] | None = None,
) -> list[Any]:
    """One `Table | op | op` chain into a list of nodes."""
    nodes: list[Any] = []
    table = source.strip()
    if table.startswith("(") and table.endswith(")"):
        table = table[1:-1].strip()
    if not table:
        raise Refusal(
            "KQL_NO_SOURCE",
            "a pipeline has no table to read from. A KQL stage list is a table "
            "name followed by `|` operators.",
            "parse",
        )
    # A bare binding name as the source means "use that binding", not "read a
    # table with that name". Distinguished because a join operand can be either.
    nodes.append(
        Read(
            id=f"{prefix}_read",
            table=table,
            selector="",
            time_field=_guess_time_field(table),
        )
    )

    index = 0
    #: Once a join has been seen, every later stage's bare column names are
    #: resolved through this map, because the two sides are now merged under
    #: prefixes. `summarize ... make_set(SourceIp)` after a join means the LEFT
    #: side's SourceIp; read unqualified it is a column called
    #: `L.SourceIp`, which exists under that name and no other, so the measure
    #: returns an empty list and the rule reports zero.
    active_scopes: dict[str, str] = {}

    while index < len(stages):
        stage = stages[index]
        node_id = f"{prefix}_{stage.operator.lower().replace('-', '_')}_{index}"
        lowered = _lower_stage(
            stage, node_id, table, diagnostics, active_scopes, bindings
        )
        index += 1
        if lowered is None:
            continue

        if isinstance(lowered, Join):
            lowered = dataclasses.replace(
                lowered, left=nodes[-1].id if nodes else node_id
            )
            left_columns = _columns_of(
                lowered.left, columns, nodes, source=source
            )
            right_columns = _columns_of(lowered.right, columns, nodes)
            field_scopes: dict[str, str] = {}
            for column in left_columns:
                field_scopes.setdefault(column, "left")
            for column in right_columns:
                field_scopes[column] = "right"

            while index < len(stages) and stages[index].operator.lower() == "where":
                after = _condition(
                    stages[index].body.strip(),
                    node_id,
                    default_scope="right",
                    field_scopes=field_scopes,
                )
                lowered = dataclasses.replace(
                    lowered,
                    predicate=(
                        after if lowered.predicate is None
                        else BoolOp("and", (lowered.predicate, after))
                    ),
                )
                index += 1

            # Everything after the join is reading the MERGED row, so the same
            # resolution applies to it.
            active_scopes = dict(field_scopes)

        nodes.append(lowered)
    return nodes


def _columns_of(
    name: str,
    columns: dict[str, set[str]] | None,
    nodes: list[Any],
    source: str = "",
) -> set[str]:
    """The columns a join side produces.

    Three cases, in order: the name is a binding, so use what that binding
    declares; the name is THIS stream's own read, so use the stream's source --
    which is frequently a binding too, and is how
    `LSASSAccess | join ... (LateralMovement)` gets a left-hand column set at
    all; otherwise fall back to the stages seen so far.
    """
    if columns and name in columns:
        return columns[name]
    if source and columns and source in columns:
        return columns[source]
    return _declared_columns(nodes)


def _guess_time_field(table: str) -> str:
    """The timestamp column, as a DECLARATION rather than a guess.

    Declared on the Read so the window logic has a column to work with. The
    alternative -- auto-selecting any column that looks like a timestamp -- once
    meant a rule silently windowed on `EventTimeCreated` when the author meant
    `TimeGenerated`, and produced a count for a window nobody asked for.
    """
    if table.lower() in ("securityevent", "syslog", "event", "signinlogs",
                         "auditlogs", "commonsecuritylog"):
        return "TimeGenerated"
    if table.lower().startswith("customtable"):
        return "TimeGenerated"
    return "TimeGenerated"


def _lower_stage(
    stage: ParsedStage,
    node_id: str,
    table: str,
    diagnostics: list[Diagnostic],
    field_scopes: dict[str, str] | None = None,
    bindings: list[Binding] | None = None,
) -> Any:
    operator = stage.operator.lower()
    body = stage.body.strip()

    if operator == "where":
        return Filter(
            id=node_id,
            condition=_condition(body, node_id, field_scopes=field_scopes),
        )

    if operator in ("project", "project-away", "project-rename"):
        return _lower_project(operator, body, node_id, field_scopes)

    if operator == "extend":
        return _lower_extend(body, node_id, field_scopes)

    if operator == "summarize":
        return _lower_summarize(body, node_id, diagnostics, field_scopes)

    if operator == "join":
        return _lower_join(body, node_id, diagnostics, bindings)

    if operator in ("sort", "order"):
        return _lower_sort(body, node_id)

    if operator in ("top", "take", "limit"):
        count, _ = _leading_count(body)
        return Limit(id=node_id, count=count)

    if operator == "distinct":
        keys = tuple(
            FieldRef.parse(part.strip())
            for part in split_top_level(body, ",")
            if part.strip()
        )
        return Distinct(id=node_id, keys=keys)

    if operator in UNSUPPORTED_OPERATORS:
        return None

    raise Refusal(
        "KQL_OPERATOR_UNKNOWN",
        f"`{stage.operator}` is not an operator this lowering knows. Everything "
        f"from here on was not read, so the stages after it have not been "
        f"checked either.",
        "lower",
    )


def _lower_project(
    operator: str,
    body: str,
    node_id: str,
    field_scopes: dict[str, str] | None = None,
) -> Any:
    # `project *` is what an identity output stage renders as, and re-reading it
    # as a PROJECTION would append a second output stage on every round trip --
    # the graph grows by one node each time the rule is written and re-read. It
    # is the output stage, because that is what it means.
    #
    # Checked BEFORE the item loop, because `*` would otherwise be taken as a
    # column name.
    if operator == "project" and body.strip() in ("*", "count(*)", ""):
        return Emit(id=node_id)

    renames: list[tuple[FieldRef, str]] = []
    keeps: list[FieldRef] = []
    drops: list[FieldRef] = []

    for part in split_top_level(body, ","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            target, _, source = part.partition("=")
            target = target.strip()
            source = source.strip()
            if not target or not source:
                raise Refusal(
                    "KQL_PROJECT_MALFORMED",
                    f"`{part}` is not a valid `project` item. It is either "
                    f"`Column` or `NewName = Expression`.",
                    "lower",
                )
            renames.append((FieldRef.parse(source), target))
        elif operator == "project-away":
            drops.append(_scoped(part, field_scopes))
        else:
            keeps.append(_scoped(part, field_scopes))


    # `project-away` removes columns. Otherwise a projection is a keeps-list,
    # and a rename is a rename. Getting this wrong is how a projection ends up
    # behaving as a pass-through, which renders correctly and silently does
    # nothing.
    if operator == "project-away":
        return Project(id=node_id, drops=tuple(drops))
    if renames and keeps:
        return Project(id=node_id, renames=tuple(renames), keeps=tuple(keeps))
    if renames:
        return Project(id=node_id, renames=tuple(renames))
    return Project(id=node_id, keeps=tuple(keeps))


def _scoped(name: str, field_scopes: dict[str, str] | None) -> FieldRef:
    """A column name, resolved through the post-join scope map when there is one."""
    ref = FieldRef.parse(name)
    if not field_scopes or ref.scope != "current":
        return ref
    resolved = field_scopes.get(ref.full)
    return FieldRef(ref.name, ref.path, resolved) if resolved else ref


def _lower_extend(
    body: str, node_id: str, field_scopes: dict[str, str] | None = None
) -> Derive:
    assignments: list[tuple[str, Any]] = []
    for part in split_top_level(body, ","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise Refusal(
                "KQL_EXTEND_MALFORMED",
                f"`{part}` is not a valid `extend` item. `extend` only ADDS or "
                f"REPLACES a column, so every item is `Name = Expression`. To "
                f"remove columns use `project-away`.",
                "lower",
            )
        target, _, source = part.partition("=")
        assignments.append(
            (
                target.strip(),
                _condition(source.strip(), node_id,
                           field_scopes=field_scopes),
            )
        )
    return Derive(id=node_id, assignments=tuple(assignments), kind="add")


def _lower_summarize(
    body: str,
    node_id: str,
    diagnostics: list[Diagnostic],
    field_scopes: dict[str, str] | None = None,
) -> Aggregate:
    measures_text, _, by_text = body.partition(" by ")
    measures: list[Measure] = []

    for part in split_top_level(measures_text, ","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            name, _, call = part.partition("=")
            name, call = name.strip(), call.strip()
        else:
            name, call = "", part
        measures.append(
            _lower_measure(name, call, node_id, diagnostics, field_scopes)
        )

    keys: list[FieldRef] = []
    window: Window | None = None
    if by_text.strip():
        for part in split_top_level(by_text, ","):
            part = part.strip()
            if not part:
                continue
            # `by bin(TimeGenerated, 5m)` groups into time buckets.
            if part.lower().startswith("bin("):
                # A `bin(` with no comma -- `bin(` on its own, or
                # `bin(TimeGenerated)` -- used to raise IndexError here, an
                # uncaught crash where every other unreadable input gets a
                # named refusal. `bin` takes a field AND a bucket size, and
                # guessing the size would invent the rule's resolution.
                if "," not in part:
                    raise Refusal(
                        "KQL_BIN_NEEDS_A_SIZE",
                        f"`{part}` has no bucket size. `bin()` takes a field "
                        f"and a span -- `bin(TimeGenerated, 5m)` -- and "
                        f"choosing a span here would invent the resolution "
                        f"the rule groups at.",
                        "lower",
                    )
                inner = part[4:].rsplit(",", 1)[0].strip()
                size_text = part.rsplit(",", 1)[1].rstrip(") ").strip()
                span = duration_seconds(size_text)
                if span is not None:
                    window = Window(
                        kind="tumbling", size=span, time_field=inner
                    )
                    keys.append(_scoped(inner, field_scopes))
                    continue
            keys.append(_scoped(part, field_scopes))

    return Aggregate(
        id=node_id, measures=tuple(measures), keys=tuple(keys), window=window
    )


def _lower_measure(
    name: str,
    call: str,
    node_id: str,
    diagnostics: list[Diagnostic],
    field_scopes: dict[str, str] | None = None,
) -> Measure:
    function, args, _ = _split_call(call)
    lowered = function.lower()

    if lowered not in AGGREGATES:
        raise Refusal(
            "KQL_AGGREGATE_UNKNOWN",
            f"`{function}()` is not an aggregate this lowering knows. Supported: "
            f"{', '.join(sorted(AGGREGATES))}. If it is a real KQL aggregate it "
            f"belongs in AGGREGATES with a stated meaning, not silently dropped "
            f"from a `summarize` that would then measure nothing.",
            "lower",
        )

    engine, distinct = AGGREGATES[lowered]

    if lowered == "count":
        if args:
            raise Refusal(
                "KQL_COUNT_OF_COLUMN_UNSUPPORTED",
                f"`count({args})` counts the values of a column, and this "
                f"lowering models `count()` as a count of ROWS. Those are "
                f"different numbers on any column with absent or null values, "
                f"and substituting one for the other silently changes an alert "
                f"threshold. Write `count()` to count rows, or "
                f"`dcount({args})` to count distinct values.",
                "lower",
            )
        return Measure(function="count", name=name or "count_")

    if not args:
        raise Refusal(
            "KQL_AGGREGATE_NEEDS_FIELD",
            f"`{lowered}()` aggregates a column, so it needs one. "
            f"`{call}` names none.",
            "lower",
        )

    # `countif(<predicate>)` counts the rows the PREDICATE is true for. Its one
    # argument is a condition, not a column: the code below would build
    # `FieldRef("EventID == 4625")` and look up a field literally named that,
    # which is absent in every row, so the count was always 0. A threshold
    # written as `countif(EventID == 4625) >= 10` therefore never fired and the
    # rule looked clean.
    if lowered == "countif":
        if len(args) != 1:
            raise Refusal(
                "KQL_COUNTIF_NEEDS_CONDITION",
                f"`{call}` takes exactly one argument, the condition to count. "
                f"It was given {len(args)}.",
                "lower",
            )
        condition = _condition(
            args[0].strip(), node_id, field_scopes=field_scopes
        )
        return Measure(
            function="count_if",
            name=name or "count_if",
            condition=condition,
        )

    # `arg_max(<sort column>, <returned column>)` returns a VALUE from the row
    # with the largest sort column. The model has one slot for a measure's
    # column, so the second argument used to be dropped and the measure became
    # "the largest sort column" -- a different number, reported as a success.
    if lowered in ("arg_max", "arg_min"):
        raise Refusal(
            "KQL_ARG_AGGREGATE_UNSUPPORTED",
            f"`{call}` returns `{args[1].strip() if len(args) > 1 else '?'}` "
            f"from the row with the "
            f"{'largest' if lowered == 'arg_max' else 'smallest'} "
            f"`{args[0].strip()}`. This model has one column per measure, so it "
            f"cannot say both which row to pick and which value to take, and "
            f"measuring `{args[0].strip()}` instead would answer a different "
            f"question. Use `max(...)`/`min(...)` if that is the number you "
            f"meant.",
            "lower",
        )

    field_text = args[0].strip()
    field = _scoped(field_text, field_scopes)
    param: Decimal | None = None
    if lowered in PARAMETERISED and len(args) > 1:
        try:
            param = Decimal(args[1].strip())
        except Exception as exc:  # noqa: BLE001
            raise Refusal(
                "KQL_AGGREGATE_PARAMETER_INVALID",
                f"`{call}` needs a number as its second argument.",
                "lower",
            ) from exc

    if lowered in ("make_set", "make_list", "make_bag", "make_array",
                   "todynamic"):
        # A LIST-valued aggregate. Collapsing it to a scalar loses exactly the
        # evidence a correlation rule correlates on: which source IPs, which
        # processes, which accounts.
        diagnostics.append(
            Diagnostic(
                "KQL_LIST_AGGREGATE",
                f"`{lowered}({field_text})` is kept as a collection, not "
                f"collapsed to one value. A rule that reports "
                f"`{name or field_text}` as a single value would lose every "
                f"element but one.",
                severity="note",
                verified=True,
                evidence=f"the {lowered} aggregate",
            )
        )

    return Measure(
        function=engine,
        name=name or field_text.replace(".", "_"),
        field=field,
        distinct=distinct,
        param=param,
    )


def _lower_join(
    body: str,
    node_id: str,
    diagnostics: list[Diagnostic],
    bindings: list[Binding] | None = None,
) -> Join:
    how = "inner"
    right = ""
    on_text = ""
    predicate_text = ""

    # `kind=inner (Table) on K1, K2` -- the kind is a modifier before the operand.
    options: dict[str, str] = {}
    rest = body
    while True:
        head, _, tail = rest.partition(" ")
        lowered = head.strip().lower()
        if "=" in head and lowered.split("=")[0] in ("kind", "hint"):
            options[lowered.split("=")[0]] = head.split("=", 1)[1].strip()
            rest = tail.strip()
            continue
        break

    kind = options.get("kind", "inner").lower()
    if kind not in JOIN_KINDS:
        raise Refusal(
            "KQL_JOIN_KIND_UNSUPPORTED",
            f"`kind={kind}` is not a join this engine implements. Supported: "
            f"{', '.join(sorted(JOIN_KINDS))}. Saying so is better than "
            f"substituting an inner join, which returns a different number of "
            f"rows than a left join on any input where a row fails to match.",
            "lower",
        )
    how = JOIN_KINDS[kind]

    # Split off the `on` clause, which is where the correlated predicate may live.
    lowered_rest = rest.lower()
    marker = lowered_rest.find(" on ")
    if marker == -1:
        raise Refusal(
            "KQL_JOIN_NO_ON",
            f"`{body}` has no `on` clause. Without one there is nothing to "
            f"match the two sides on, and a join with no condition is the "
            f"cartesian product of both inputs.",
            "lower",
        )
    operand = rest[:marker].strip()
    on_clause = rest[marker + 4:].strip()

    # A subsearch: `join (Table | where ... ) on K`.
    if operand.startswith("("):
        inner = operand[1:]
        if not inner.endswith(")"):
            raise Refusal(
                "KQL_JOIN_OPERAND_UNCLOSED",
                f"`{operand}` opens a sub-pipeline with `(` and never closes it.",
                "lower",
            )
        inner = inner[:-1].strip()
        source, stages = _split_pipeline(inner)
        if stages and bindings is not None:
            # CARRY the right-hand stages as a binding. They used to be parsed,
            # described in a note that said they were carried, and then thrown
            # away -- so `join kind=inner (AuditLogs | where ResultType == 0)
            # on UserPrincipalName` silently widened the join to the whole
            # unfiltered right table, which is a different rule and matches far
            # more than the one written.
            name = f"{node_id}_right"
            sub_nodes = _lower_stream(
                source, stages, name, diagnostics, bindings=bindings
            )
            bindings.append(Binding(name=name, pipeline=tuple(sub_nodes)))
            right = name
            diagnostics.append(
                Diagnostic(
                    "KQL_JOIN_SUBPIPELINE_CARRIED",
                    f"The joined operand's {len(stages)} stage(s) are carried as "
                    f"the binding `{name}`, so the filter inside the join is part "
                    f"of the rule rather than discarded.",
                    severity="note",
                    verified=True,
                    evidence=operand[:60],
                )
            )
        elif stages:
            raise Refusal(
                "KQL_JOIN_SUBPIPELINE_UNSUPPORTED",
                f"the joined operand has {len(stages)} stage(s) of its own and "
                f"this lowering has nowhere to put them, so carrying the table "
                f"alone would drop the filter inside the join and match more "
                f"events than the rule says.",
                "lower",
            )
        else:
            right = source
    else:
        right = operand

    if not right:
        raise Refusal(
            "KQL_JOIN_NO_OPERAND",
            f"`{body}` names no table to join to.",
            "lower",
        )

    # The `on` clause is `A, B` and MAY be followed by `and <condition>` --
    # that is where KQL puts a correlated predicate, and it is where the
    # cross-row comparison lives.
    key_part, _, predicate_part = on_clause.partition(" and ")
    on: list[tuple[FieldRef, FieldRef]] = []
    for part in split_top_level(key_part, ","):
        part = part.strip()
        if not part:
            continue
        # `on $left.A == $right.B` is how KQL writes a join whose key names
        # DIFFER, and `partition("=")` split it at the first `=` of `==`: the
        # left key became `$left.A ` and the right became `= $right.B`, which
        # re-rendered as `on $left.$left == $right.= $right`. Splitting on
        # `==` and stripping the scope prefixes is what the syntax means.
        spelling = "==" if "==" in part else "="
        left, _, right_name = part.partition(spelling)
        left = left.strip()
        right_name = right_name.strip()
        for scope_prefix in ("$left.", "$right."):
            if left.startswith(scope_prefix):
                left = left[len(scope_prefix):]
            if right_name.startswith(scope_prefix):
                right_name = right_name[len(scope_prefix):]
        if not right_name:
            # A bare key joins the column to ITSELF on the other side.
            ref = FieldRef.parse(left)
            on.append((ref, FieldRef(ref.name, ref.path, scope="right")))
            continue
        on.append(
            (
                FieldRef.parse(left),
                FieldRef.parse(right_name, scope="right"),
            )
        )

    if not on:
        raise Refusal(
            "KQL_JOIN_NO_KEYS",
            f"`on {on_clause}` names no join keys.",
            "lower",
        )

    predicate = None
    if predicate_part.strip():
        predicate = _correlation_predicate(predicate_part.strip(), node_id)

    return Join(
        id=node_id,
        left="",  # filled in by the caller: the previous stage
        right=right,
        how=how,
        on=tuple(on),
        predicate=predicate,
    )


def _correlation_predicate(text: str, node_id: str) -> Any:
    """Parse a `where` after a join, rewriting bare names onto the right side.

    In KQL, after a join the columns are FLATTENED into one namespace with no
    prefix, and the disambiguating convention is positional: the keys named in
    `on` are available unqualified, and anything else named after the join is
    read from the RIGHT row.

    That convention is a source of genuine ambiguity, and guessing wrong is the
    difference between a correlation that works and one that compares a field
    with itself. So only the keys are left unqualified, and every other
    unqualified field in the predicate is read from the right side -- and the
    ambiguity is reported rather than resolved silently.
    """
    return _condition(text, node_id, default_scope="right")


def _tokenise_kql(text: str) -> list[Token]:
    """Tokenize, then collapse KQL's bracket-quoted column names.

    `['Event Name']` is how KQL references a column whose name is not a bare
    identifier, and it is the normal case in Sentinel -- half the columns in
    `SecurityEvent` have spaces. The shared lexer sees `[`, a string and `]`,
    so the parser read it as a LIST, and `['Event Name'] == 'Logon'` lowered
    to a list compared with a string. Evaluated against an event that really
    did have `Event Name == "Logon"` it reported `no_match`: the rule silently
    never fired.

    Collapsed to one `ident` token here, which is what the parser already
    expects for a field, with the spaces kept as part of the name.
    """
    tokens = tokenize(text)
    out: list[Token] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        closing = tokens[index + 2] if index + 2 < len(tokens) else None
        if (
            token.kind == "punct" and token.text == "["
            and following is not None and following.kind == "string"
            and closing is not None and closing.kind == "punct"
            and closing.text == "]"
        ):
            out.append(Token("ident", following.text, token.at))
            index += 3
            continue
        out.append(token)
        index += 1
    return _merge_negated_operators(out)


#: KQL's negated string operators, spelled `!endswith` rather than `not (...)`
#: or `!~`. The lexer splits `!` from the name, so they never reached
#: `build_comparison` as one operator and `ServiceName !endswith "$"` was
#: refused with "stops making sense at `!`" -- a shape that appears in most
#: Kerberoasting and browser-tuning queries in Sentinel content.
_NEGATABLE: Final[frozenset[str]] = frozenset({
    "has", "has_cs", "hasprefix", "hasprefix_cs", "hassuffix",
    "hassuffix_cs", "contains", "contains_cs", "startswith", "startswith_cs",
    "endswith", "endswith_cs", "has_any", "has_all", "between",
})


def _merge_negated_operators(tokens: list[Token]) -> list[Token]:
    """Collapse `!` followed by a negatable operator into one `op` token."""
    out: list[Token] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if (
            token.kind == "op" and token.text == "!"
            and following is not None and following.kind == "ident"
            and following.text.lower() in _NEGATABLE
        ):
            # `ident`, not `op`: the shared parser resolves an operator's
            # binding power by looking a WORD up in the spec, so an `op` token
            # called `!endswith` had no precedence and the expression stopped
            # there. As an ident it takes the same path `endswith` does.
            out.append(Token("ident", "!" + following.text.lower(), token.at))
            index += 2
            continue
        out.append(token)
        index += 1
    return out


def _condition(
    text: str,
    node_id: str,
    default_scope: str = "current",
    field_scopes: dict[str, str] | None = None,
) -> Any:
    """Parse an expression body into the model's expression tree.

    `default_scope` and `field_scopes` together are how a post-join predicate
    resolves a name that the dialect spells without a prefix. `field_scopes`
    wins, because it is derived from the two streams' own declarations rather
    than from a convention.
    """
    if not text.strip():
        raise Refusal(
            "KQL_EMPTY_CONDITION",
            f"`{node_id}` has no condition. An empty condition is not a "
            f"condition; it would either match everything or nothing "
            f"depending on where it went.",
            "lower",
        )
    parser = _KqlParser(
        _tokenise_kql(text), SPEC, default_scope=default_scope,
        field_scopes=field_scopes,
    )
    parsed = parser.parse_expression(0)
    # EVERY token has to be consumed. A parser that stops early and returns
    # what it had read silently WIDENS the rule: `parse_json(InitiatedBy).user.
    # userPrincipalName == "admin@corp.com"` came back as the bare call
    # `parse_json(InitiatedBy)` -- the member path AND the comparison dropped --
    # so a filter that should have narrowed to one user matched (or, here,
    # could not be decided for) every row. Refusing names the token it could
    # not read.
    leftover = [t for t in parser.tokens[parser.index:] if t.kind != "eof"]
    if leftover:
        raise Refusal(
            "KQL_TRAILING_SYNTAX",
            f"`{node_id}` could not be read in full: the condition stops making "
            f"sense at `{leftover[0].text}`. Reading only the part before it "
            f"would silently widen the rule, so it is refused instead.",
            "lower",
        )
    return parsed


#: KQL's case-insensitive substring operators, and how each anchors.
#:
#: The engine has no case-insensitive `contains`, and `ilike` cannot express
#: which of the three a glob came from. A case-folding REGEX can: it is
#: unanchored by definition, so `contains` is the bare pattern, `startswith`
#: anchors at the front and `endswith` at the end.
_CASE_INSENSITIVE: Final[dict[str, tuple[str, str]]] = {
    "has": ("", ""),
    "contains": ("", ""),
    "hasprefix": ("^", ""),
    "startswith": ("^", ""),
    "hassuffix": ("", "$"),
    "endswith": ("", "$"),
}


#: A term boundary, spelled in the portable subset this engine can execute.
#:
#: KQL's `has` family matches whole alphanumeric TERMS: `CommandLine has "net"`
#: does not match `dotnet.exe`, because `net` there is part of the longer term.
#: The boundary is "start-or-non-word before, non-word-or-end after".
#:
#: Written as a plain group with an explicit character class rather than
#: `(?:...)` and `(?=...)`, because `_screen_portable` refuses every `(?` -- so a
#: lookahead version lowered fine and then could not be validated or run.
_TERM_BEFORE: Final = "(^|[^A-Za-z0-9_])"
_TERM_AFTER: Final = "([^A-Za-z0-9_]|$)"


def _term_pattern(value: str) -> str:
    """A whole-term match for `value`, in the portable regex subset."""
    return f"{_TERM_BEFORE}{re.escape(value)}{_TERM_AFTER}"


class _KqlParser(Parser):
    """The shared parser, plus KQL's case-insensitive substring operators.

    `DialectSpec.operators` maps a spelling to an engine operator and then
    forgets the spelling, so `contains` and `contains_cs` arrived at
    `build_comparison` indistinguishable. KQL's bare form ignores case and the
    engine's does not, so a rule reading `Image endswith "lsass.exe"` -- which
    matches `LSASS.EXE` in Sentinel -- lowered to a case-SENSITIVE test and
    stopped matching the events it was written for.

    `build_comparison` still receives the original token, which is the only
    place that distinction survives, so the fold happens here.
    """

    def parse_atom(self) -> Expr:
        """The shared atom, plus KQL's member access on a call result.

        `parse_json(InitiatedBy).user.userPrincipalName` is how an Entra ID
        detection reaches into a nested identity object, and the shared parser
        stopped at the `.`: `found '.' but needed ')'`. The member path is
        carried as `json_extract(base, "a.b")`, which the IR can hold, which
        the evaluator implements, and which the renderer writes back in dot
        form -- so the round trip is exact rather than approximate.
        """
        atom = super().parse_atom()
        if not isinstance(atom, Call):
            return atom
        path: list[str] = []
        while self.current.text == "." and self.current.kind == "punct":
            self.advance()
            if self.current.kind not in ("ident", "keyword"):
                break
            path.append(self.advance().text)
        if not path:
            return atom
        return Call("member_path", (atom, Literal(".".join(path))))

    def build_comparison(self, token: Token, left: Any, right: Any) -> Any:
        word = token.text.lower() if token.kind == "ident" else token.text

        # A negated string operator: `!endswith`, `!has`, `!contains`. KQL
        # spells negation as a `!` prefix on the operator, and the lexer splits
        # the two, so these never reached the tables below and were refused.
        # The positive form is built and then negated, so `!has` and
        # `not (... has ...)` cannot drift apart.
        if word.startswith("!") and word not in ("!=", "!~", "!in", "!in~"):
            positive = self.build_comparison(
                Token("ident", word[1:], token.at), left, right
            )
            return Not(positive)



        # `has_any` / `has_all` are case-INSENSITIVE in KQL, like the rest of
        # the `has` family. They were mapped onto the engine's
        # `contains_any` / `contains_all`, which are case-SENSITIVE, so
        #
        #     FileName has_any ("powershell.exe", "cmd.exe")
        #
        # -- the single most common shape in Sentinel content -- did not match
        # `PowerShell.EXE`. The SPEC comment for these two already records the
        # term-vs-substring approximation it accepts; the CASE difference was
        # missed, and unlike the substring approximation it makes the rule
        # miss events rather than match a few extra.
        #
        # Folded into the nocase regexes the single-valued `has` family
        # already becomes, so both spellings carry the same fold.
        if word in ("has_any", "has_all"):
            items = right.items if isinstance(right, ListExpr) else (right,)
            if not items:
                raise Refusal(
                    "KQL_HAS_EMPTY_LIST",
                    f"`{word}` has an empty list on the right, so it matches "
                    f"nothing at all.",
                    "lower",
                )
            tests: list[Any] = []
            for item in items:
                if not isinstance(item, Literal) or not isinstance(item.value, str):
                    raise Refusal(
                        "KQL_CASE_INSENSITIVE_NOT_LITERAL",
                        f"`{word}` folds case, so every member of its list has "
                        f"to be a constant string. `{render_expr(item)}` is not.",
                        "lower",
                    )
                # TERM-anchored, like `has` itself: `has_any ("net")` does not
                # match `dotnet.exe` in Sentinel. An unanchored pattern here
                # widened every `has_any` into a `contains_any`.
                #
                # Spelled with a plain capturing group and an explicit class
                # rather than `(?:...)` and a lookahead, because this engine's
                # portable subset refuses both -- and a pattern it refuses to
                # screen is a pattern it refuses to run.
                tests.append(Comparison(
                    "matches", left,
                    Regex(
                        _term_pattern(str(item.value)),
                        SPEC.default_regex_dialect,
                        nocase=True,
                    ),
                ))
            if len(tests) == 1:
                return tests[0]
            return BoolOp("or" if word == "has_any" else "and", tuple(tests))

        # `=~` and `!~` are case-insensitive EQUALITY in KQL. They were mapped
        # onto the engine's `matches`, which turned them into a case-SENSITIVE
        # SUBSTRING test -- wrong on both axes at once:
        #
        #   Account =~ "admin"   matched `administrator` and `xadminx`
        #                        and did NOT match `ADMIN`
        #
        # so the positive form silently widened to a substring search while
        # also missing the casing it exists to cover, and `!~` inverted the
        # same way: an exclusion list written `!~ "admin"` kept `ADMIN` rows
        # and dropped every `administrator`. Both are among the most common
        # operators in Sentinel content.
        #
        # Expanded into the anchored case-folding regex it means, which is the
        # only construct the model has that carries a fold.
        if word in ("=~", "!~"):
            if not isinstance(right, Literal) or not isinstance(right.value, str):
                raise Refusal(
                    "KQL_CASE_INSENSITIVE_NOT_LITERAL",
                    f"`{word}` folds case, so it needs a constant string on "
                    f"the right. `{render_expr(right)}` is not one, and there "
                    f"is no case-insensitive comparison between two fields in "
                    f"this model to fall back on.",
                    "lower",
                )
            exact = Comparison(
                "matches", left,
                Regex(
                    f"^{re.escape(str(right.value))}$",
                    SPEC.default_regex_dialect,
                    nocase=True,
                ),
            )
            return Not(exact) if word == "!~" else exact

        # `in~` and `!in~` fold case; `in` and `!in` do not. All four were
        # mapped onto the engine's case-SENSITIVE `in`, so the tilde was read
        # and discarded: `Account !in~ ("NT AUTHORITY\SYSTEM")` came back as
        # `!in`, and the exclusion stopped covering `nt authority\system`.
        # On a NEGATED membership test that is the dangerous direction -- an
        # exclusion that no longer excludes turns a filter into an alert
        # storm, and on the positive form the rule simply stops matching.
        #
        # There is no case-insensitive `in` in the model, so it is expanded
        # into the OR of case-folding equalities it means. That is exact
        # rather than approximate, and `_render_comparison` folds the shape
        # back to `in~` on the way out.
        if word in ("in~", "!in~"):
            items = right.items if isinstance(right, ListExpr) else (right,)
            if not items:
                raise Refusal(
                    "KQL_IN_EMPTY_LIST",
                    f"`{word}` has an empty list on the right, so it matches "
                    f"nothing at all. An empty exclusion list is almost "
                    f"always an editing mistake rather than a rule.",
                    "lower",
                )
            tests: list[Any] = []
            for item in items:
                if not isinstance(item, Literal) or not isinstance(item.value, str):
                    raise Refusal(
                        "KQL_CASE_INSENSITIVE_NOT_LITERAL",
                        f"`{word}` folds case, so every member of its list "
                        f"has to be a constant string. "
                        f"`{render_expr(item)}` is not.",
                        "lower",
                    )
                # Anchored and escaped: an unanchored pattern would turn a
                # membership test into a substring test, so `in~ ("ADMIN")`
                # would match `ADMINISTRATOR`.
                pattern = f"^{re.escape(str(item.value))}$"
                tests.append(Comparison(
                    "matches", left,
                    Regex(pattern, SPEC.default_regex_dialect, nocase=True),
                ))
            combined = tests[0] if len(tests) == 1 else BoolOp("or", tuple(tests))
            return Not(combined) if word.startswith("!") else combined

        # `has` and `has_cs` match a whole alphanumeric TERM, not a substring.
        # In Sentinel, `CommandLine has "net"` does NOT match
        # `C:\Program Files\dotnet\dotnet.exe`, because `net` there is part of
        # the longer term `dotnet`. Lowering it to a bare substring regex turned
        # every `has` into a `contains`, so the rule fired on text its author had
        # deliberately excluded -- silent widening on one of the most common
        # operators in Sentinel content.
        #
        # The term boundary is spelled "not preceded, and not followed, by a
        # word character", which is what KQL's tokenisation means.
        if word in ("has", "has_cs"):
            if not isinstance(right, Literal) or not isinstance(right.value, str):
                raise Refusal(
                    "KQL_CASE_INSENSITIVE_NOT_LITERAL",
                    f"`{word}` compares against something that is not a constant "
                    f"string, and a term boundary has to be applied to a known "
                    f"value.",
                    "lower",
                )
            term = re.escape(str(right.value))
            pattern = _term_pattern(str(right.value))
            return Comparison(
                "matches", left,
                Regex(pattern, SPEC.default_regex_dialect, nocase=word == "has"),
            )

        anchors = _CASE_INSENSITIVE.get(word)
        if anchors is None:
            return super().build_comparison(token, left, right)
        if not isinstance(right, Literal) or not isinstance(right.value, str):
            raise Refusal(
                "KQL_CASE_INSENSITIVE_NOT_LITERAL",
                f"`{word}` compares against something that is not a constant "
                f"string. KQL folds case for this operator, and the fold has "
                f"to be applied to a known value.",
                "lower",
            )
        prefix, suffix = anchors
        # Escaped, so a `.` in `lsass.exe` stays a literal dot rather than
        # becoming "any character" and matching `lsassXexe`.
        pattern = f"{prefix}{re.escape(str(right.value))}{suffix}"
        return Comparison(
            "matches", left,
            Regex(pattern, SPEC.default_regex_dialect, nocase=True),
        )


def _glob_shape(pattern: str) -> tuple[str, str] | None:
    """A LIKE glob back to the KQL operator that means it, or None.

    `%lsass%` is `contains lsass`, `lsass%` is `startswith`, `%lsass` is
    `endswith`. Only those three shapes are recognised: a glob with an
    INTERIOR wildcard is a real pattern with no substring spelling, and
    rendering it as `contains` would claim a looser match than it makes.

    Escaped wildcards are literal, so `100\\%` is a `contains` of `100%` and
    not a prefix test.
    """
    leading = pattern.startswith("%")
    trailing = pattern.endswith("%") and not pattern.endswith("\\%")
    body = pattern[1:] if leading else pattern
    if trailing:
        body = body[:-1]
    if not body:
        return None

    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body):
            out.append(body[index + 1])
            index += 2
            continue
        if char in "%_":
            # A live wildcard inside the body: a real glob, not a substring.
            return None
        out.append(char)
        index += 1
    text = "".join(out)

    if leading and trailing:
        return "contains", text
    if trailing:
        return "startswith", text
    if leading:
        return "endswith", text
    # No wildcards at all: an equality wearing a glob's clothes.
    return None


def _unfold_case_insensitive(pattern: str) -> tuple[str, str] | None:
    """A case-folding regex back to the KQL operator that means it.

    Only a pattern that is an escaped literal with the anchors this dialect
    adds is recognised. Anything else is a real regex and stays `matches
    regex`, because rendering it as a substring test would claim a looser
    match than the pattern makes.
    """
    body = pattern
    operator = "contains"
    if body.startswith("^"):
        operator, body = "startswith", body[1:]
    elif body.endswith("$") and not body.endswith("\\$"):
        operator, body = "endswith", body[:-1]

    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body):
            out.append(body[index + 1])
            index += 2
            continue
        if char in ".*+?[]{}()|^$":
            # A live metacharacter: a real pattern, not a quoted literal.
            return None
        out.append(char)
        index += 1
    text = "".join(out)
    if not text:
        return None
    if re.escape(text) != body:
        # Escaping it again must reproduce the pattern exactly, or the pattern
        # held something this function has misread.
        return None
    return operator, text


def _leading_count(text: str) -> tuple[int, str]:
    head, _, rest = text.strip().partition(" ")
    try:
        return int(head), rest.strip()
    except ValueError as exc:
        raise Refusal(
            "KQL_COUNT_NOT_A_NUMBER",
            f"`{head}` is not a row count. `top`, `take` and `limit` all take a "
            f"plain integer.",
            "lower",
        ) from exc


def _lower_sort(body: str, node_id: str) -> Sort:
    """`sort by A desc, B` as ordered keys.

    The leading `by` is CONSUMED here. The operator split hands this function
    everything after `sort`, which includes the keyword, and
    `FieldRef.parse("by A")` accepted it as a field name with a space in it.
    So `| sort by Time desc | take 5` sorted on a column called `by Time`,
    which no event has: the ordering was silently meaningless and the `take 5`
    that followed returned an arbitrary five rather than the five most recent.
    It also grew another `by` on every render/re-import cycle.
    """
    keys: list[tuple[FieldRef, bool]] = []
    text = body.strip()
    if text.lower() == "by":
        text = ""
    elif text.lower().startswith("by "):
        text = text[3:].strip()
    for part in split_top_level(text, ","):
        part = part.strip()
        if not part:
            continue
        # Reset per key. `descending` used to be declared once outside this
        # loop, so `sort by A desc, B` marked B descending as well -- KQL's
        # default is ASC, and the second key silently reversed.
        descending = False
        if part.lower().endswith(" desc"):
            descending = True
            part = part[:-5].strip()
        elif part.lower().endswith(" asc"):
            part = part[:-4].strip()
        if not part:
            raise Refusal(
                "KQL_SORT_KEY_EMPTY",
                "a sort key is empty, so the ordering names no column.",
                "lower",
            )
        keys.append((FieldRef.parse(part), descending))
    if not keys:
        raise Refusal(
            "KQL_SORT_NO_KEYS",
            "`sort` names no column to order by. An ordering that sorts on "
            "nothing makes any `take` after it return an arbitrary set of "
            "rows rather than the top ones.",
            "lower",
        )
    return Sort(id=node_id, keys=tuple(keys))


def _split_call(text: str) -> tuple[str, list[str], str]:
    """`name(a, b)` into (name, args, tail)."""
    name, _, rest = text.strip().partition("(")
    if not rest:
        return name.strip(), [], ""
    body, _, tail = rest.rpartition(")")
    args = split_top_level(body, ",") if body else []
    return name.strip(), args, tail.strip()


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def _kql_string(value: str) -> str:
    """A string constant as KQL.

    Escaped, because `render_expr` -- which this function replaced -- is
    DISPLAY text by its own docstring and was being used to produce executable
    query text. Two things followed from that. A value containing a backslash
    came out raw, so `endswith "\\lsass.exe"` re-read as `endswith
    "lsass.exe"` and the rule widened to match `maliciouslsass.exe`. And a
    value containing a quote came out as `"say "hi""`, which re-read as `say `
    -- the rest of the condition silently truncated.
    """
    body = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{body}"'


def _kql_literal(value: Any) -> str:
    if value is None:
        return "dynamic(null)"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Decimal):
        return plain_number(value)
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, Duration):
        return _kql_duration(value)
    return _kql_string(str(value))


def _kql_duration(duration: Duration) -> str:
    seconds = int(duration.seconds)
    for suffix, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size and seconds % size == 0:
            return f"{seconds // size}{suffix}"
    return f"{seconds}s"


#: Engine operator -> KQL spelling.
#:
#: `contains` maps to `contains_cs`, NOT to `contains`. KQL's bare `contains`
#: is case-INSENSITIVE and the engine's is not, so the obvious spelling would
#: widen every substring test in every rendered rule.
_RENDER_OPS: Final[dict[str, str]] = {
    "==": "==",
    "!=": "!=",
    "<": "<",
    "<=": "<=",
    ">": ">",
    ">=": ">=",
    "contains": "contains_cs",
    "startswith": "startswith_cs",
    "endswith": "endswith_cs",
    # Lowering maps KQL's `has_any`/`has_all` onto the engine's
    # `contains_any`/`contains_all` (see SPEC.operators), so those are the
    # names that reach a renderer. The table was keyed on `has_any`/`has_all`
    # instead -- ops that are not in `ir.COMPARISON_OPS` and so can never
    # appear -- which made the entries dead and left the real ops unmapped:
    # `FileName has_any ("a.exe","b.exe")` lowered fine and then refused with
    # KQL_RENDER_OPERATOR on the way back out.
    "contains_any": "has_any",
    "contains_all": "has_all",
}

#: Engine function -> the KQL spelling to write back.
#:
#: Seeded from the inverse of `SPEC.functions` so a function the parser
#: accepts cannot be unrenderable, then overridden where the mapping is
#: many-to-one and the preferred spelling matters. Hand-written, it was
#: missing every name that passes through lowering unchanged -- `isnull`,
#: `tostring`, `strlen` -- so a rule using one parsed cleanly and then refused
#: on the way out.
_RENDER_FUNCTIONS: Final[dict[str, str]] = {
    **{engine: spelled for spelled, engine in SPEC.functions.items()},
    "lower": "tolower",
    "upper": "toupper",
    "length": "strlen",
    "to_int": "toint",
    "to_string": "tostring",
    "to_float": "toreal",
    "to_bool": "tobool",
    "to_timestamp": "todatetime",
    "is_null": "isnull",
    "is_not_null": "isnotnull",
    "is_null_or_absent": "isnull",
    "is_present": "isnotnull",
    "is_empty": "isempty",
    "not_empty": "isnotempty",
    "make_list": "make_list",
    "make_set": "make_set",
    "count_if": "countif",
    "coalesce": "coalesce",
    "cidr_contains": "ipv4_is_in_range",
    "matches_regex": "matches regex",
}


def _exact_fold(expr: Any) -> tuple[FieldRef, str] | None:
    """A case-folding equality back to (field, value), or None.

    Recognises exactly what `build_comparison` emits for `in~`: a `matches`
    against a nocase regex anchored at BOTH ends whose body is an escaped
    literal. Anchoring at both ends is what makes it an equality rather than
    a substring test, so a pattern anchored at one end is not this shape.
    """
    if not isinstance(expr, Comparison) or expr.op != "matches" or expr.negate:
        return None
    if not isinstance(expr.left, FieldRef):
        return None
    pattern = expr.right
    if not isinstance(pattern, Regex) or not pattern.nocase:
        return None
    if pattern.dialect != SPEC.default_regex_dialect:
        return None
    body = pattern.pattern
    if not body.startswith("^") or not body.endswith("$"):
        return None
    if body.endswith("\\$"):
        return None
    body = body[1:-1]
    text = _unescape_literal(body)
    if text is None or re.escape(text) != body:
        return None
    return expr.left, text


def _unescape_literal(body: str) -> str | None:
    """An escaped-literal regex body back to its text, or None if it is a pattern."""
    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body):
            out.append(body[index + 1])
            index += 2
            continue
        if char in ".*+?[]{}()|^$":
            return None
        out.append(char)
        index += 1
    return "".join(out) if out else None


def _in_fold(expr: Any) -> tuple[FieldRef, list[str]] | None:
    """An OR of case-folding equalities on ONE field back to `in~`'s members.

    This is the inverse of the `in~` expansion in `build_comparison`. Without
    it a rule written `Account in~ ("a","b")` renders as a pile of `matches
    regex "(?i)^a$"` clauses -- correct, but unrecognisable to the analyst who
    wrote it, and it grows on every round trip.
    """
    single = _exact_fold(expr)
    if single is not None:
        return single[0], [single[1]]
    if not isinstance(expr, BoolOp) or expr.op != "or":
        return None
    field: FieldRef | None = None
    values: list[str] = []
    for operand in expr.operands:
        shape = _exact_fold(operand)
        if shape is None:
            return None
        if field is None:
            field = shape[0]
        elif shape[0].full != field.full:
            return None  # an OR across fields is not a membership test
        values.append(shape[1])
    if field is None or len(values) < 2:
        return None
    return field, values


def _substring_fold(expr: Any) -> tuple[FieldRef, str] | None:
    """An UNANCHORED case-folding containment test back to (field, value).

    The counterpart of `_exact_fold`. Anchoring is what separates the two: a
    pattern anchored at both ends came from `in~`/`=~` and is an equality,
    while an unanchored one came from the `has` family and is a containment.
    """
    if not isinstance(expr, Comparison) or expr.op != "matches" or expr.negate:
        return None
    if not isinstance(expr.left, FieldRef):
        return None
    pattern = expr.right
    if not isinstance(pattern, Regex) or not pattern.nocase:
        return None
    if pattern.dialect != SPEC.default_regex_dialect:
        return None
    body = pattern.pattern
    # A term-anchored body is the `has` family's spelling now: strip the
    # boundary first, so a round trip folds back to `has_any` / `has_all`
    # instead of growing a `matches regex` clause on every pass.
    if body.startswith(_TERM_BEFORE) and body.endswith(_TERM_AFTER):
        body = body[len(_TERM_BEFORE):-len(_TERM_AFTER)]
    if body.startswith("^") or body.endswith("$"):
        return None
    text = _unescape_literal(body)
    if text is None or re.escape(text) != body:
        return None
    return expr.left, text


def _has_fold(expr: Any) -> tuple[FieldRef, list[str], str] | None:
    """An OR/AND of case-folding containment tests on ONE field back to
    `has_any` / `has_all`, with the KQL spelling to use."""
    if not isinstance(expr, BoolOp) or expr.op not in ("or", "and"):
        return None
    field: FieldRef | None = None
    values: list[str] = []
    for operand in expr.operands:
        shape = _substring_fold(operand)
        if shape is None:
            return None
        if field is None:
            field = shape[0]
        elif shape[0].full != field.full:
            return None
        values.append(shape[1])
    if field is None or len(values) < 2:
        return None
    return field, values, "has_any" if expr.op == "or" else "has_all"


def _render_expression(expr: Any) -> str:
    """One expression as executable KQL.

    Every branch ends in a refusal. A silent `else` returns display text into
    a query, which is how `where` clauses came to contain things Sentinel
    cannot parse.
    """
    if isinstance(expr, Literal):
        return _kql_literal(expr.value)
    if isinstance(expr, FieldRef):
        # An irregular column is written in KQL's bracket form, which
        # `_tokenise_kql` reads back. This used to refuse, because the
        # bracket form was unreadable -- and before that it wrote the name
        # bare, which the ASCII-only tokenizer could not read at all.
        if not is_bare_identifier(expr.full):
            if '"' in expr.full or "'" in expr.full:
                raise Refusal(
                    "KQL_RENDER_FIELD_UNQUOTABLE",
                    f"`{expr.full}` contains a quote character, so it cannot "
                    f"be written in KQL's `['name']` form without inventing "
                    f"an escape KQL does not define. Map the field to a plain "
                    f"name first.",
                    "render",
                )
            return f"[{_kql_string(expr.full)}]"
        return expr.full
    if isinstance(expr, Regex):
        return _kql_string(expr.pattern)
    if isinstance(expr, Not):
        # `!in~` is written as itself rather than as `not (...)` around the
        # expansion, so a negated membership test survives a round trip in the
        # spelling the author used.
        folded = _in_fold(expr.operand)
        if folded is not None:
            field, values = folded
            members = ", ".join(_kql_string(v) for v in values)
            operator = "!in~" if len(values) > 1 else "!~"
            if operator == "!~":
                return f"{_render_expression(field)} !~ {members}"
            return f"{_render_expression(field)} !in~ ({members})"
        return f"not ({_render_expression(expr.operand)})"
    if isinstance(expr, BoolOp):
        folded = _in_fold(expr)
        if folded is not None:
            field, values = folded
            members = ", ".join(_kql_string(v) for v in values)
            return f"{_render_expression(field)} in~ ({members})"
        has = _has_fold(expr)
        if has is not None:
            field, values, spelling = has
            members = ", ".join(_kql_string(v) for v in values)
            return f"{_render_expression(field)} {spelling} ({members})"
        joiner = f" {expr.op} "
        return "(" + joiner.join(
            _render_expression(o) for o in expr.operands
        ) + ")"
    if isinstance(expr, ListExpr):
        return "(" + ", ".join(
            _render_expression(i) for i in expr.items
        ) + ")"
    if isinstance(expr, Span):
        low = _render_expression(expr.low)
        high = _render_expression(expr.high)
        return (
            f"{_render_expression(expr.value)} between ({low} .. {high})"
        )
    if isinstance(expr, Arith):
        return (
            f"({_render_expression(expr.left)} {expr.op} "
            f"{_render_expression(expr.right)})"
        )
    if isinstance(expr, Comparison):
        return _render_comparison(expr)
    if isinstance(expr, Call):
        return _render_call(expr)
    raise Refusal(
        "KQL_RENDER_EXPRESSION",
        f"`{render_expr(expr)}` has no KQL spelling, so writing this query out "
        f"would drop part of the condition.",
        "render",
    )


def _render_comparison(expr: Comparison) -> str:
    left = _render_expression(expr.left)

    if expr.op in ("matches", "=~", "!~"):
        pattern = expr.right
        if isinstance(pattern, Regex):
            if pattern.dialect in ("pcre", "pcre2", "os_regex", "java_regex"):
                raise Refusal(
                    "KQL_RENDER_REGEX_DIALECT",
                    f"this pattern is {pattern.dialect}, and KQL's `matches "
                    f"regex` is RE2-flavoured. Writing it out unchanged would "
                    f"hand Sentinel a pattern it reads differently.",
                    "render",
                )
            # A case-folding regex that is just a quoted literal came from
            # `contains`/`startswith`/`endswith`, so it goes back as that
            # operator. Rendered as `matches regex` it would still be correct
            # but unrecognisable to the analyst who wrote it.
            if pattern.nocase and not expr.negate and expr.op == "matches":
                # Anchored at both ends: a case-insensitive EQUALITY, which
                # KQL spells `=~`. Checked before the substring shapes below,
                # because `^x$` is not a prefix test.
                exact = _exact_fold(expr)
                if exact is not None:
                    return f"{left} =~ {_kql_string(exact[1])}"
                shape = _unfold_case_insensitive(pattern.pattern)
                if shape is not None:
                    operator, body = shape
                    return f"{left} {operator} {_kql_string(body)}"
            body = _kql_string(pattern.pattern)
            if pattern.nocase:
                body = _kql_string(f"(?i){pattern.pattern}")
        else:
            body = _render_expression(pattern)
        text = f"{left} matches regex {body}"
        negated = expr.negate != (expr.op == "!~")
        return f"not ({text})" if negated else text

    if expr.op == "in":
        items = expr.right
        rendered = (
            _render_expression(items) if isinstance(items, ListExpr)
            else f"({_render_expression(items)})"
        )
        return f"{left} {'!in' if expr.negate else 'in'} {rendered}"

    if expr.op in ("like", "ilike"):
        if not isinstance(expr.right, Literal) \
                or not isinstance(expr.right.value, str):
            raise Refusal(
                "KQL_RENDER_LIKE_NOT_LITERAL",
                "a wildcard match needs a constant pattern to translate.",
                "render",
            )
        pattern = str(expr.right.value)
        # A glob that is exactly a substring test comes back as the KQL
        # operator that means it, so `contains "p"` round-trips as itself
        # rather than as an anchored regex nobody would recognise.
        if expr.op == "ilike":
            shape = _glob_shape(pattern)
            if shape is not None:
                operator, body = shape
                # KQL's BARE `contains`/`startswith`/`endswith` ignore case,
                # which is exactly what `ilike` means -- so no flag is needed
                # and none is emitted.
                text = f"{left} {operator} {_kql_string(body)}"
                return f"not ({text})" if expr.negate else text
            # A case-insensitive glob with an INTERIOR wildcard has no
            # substring spelling, so it goes out as an anchored regex carrying
            # an inline `(?i)`.
            #
            # This used to refuse, with the reason that the engine's own
            # pattern screen rejected inline groups and the emitted rule could
            # not be read back. That reason no longer holds: a leading `(?i)`
            # is now read as a FLAG rather than screened as a group extension,
            # so the regex round-trips. Anchored, because an unanchored
            # pattern would widen a glob into a substring test.
            regex = f"(?i){_glob_to_regex(pattern)}"
            text = f"{left} matches regex {_kql_string(regex)}"
            return f"not ({text})" if expr.negate else text
        # KQL has no LIKE. The faithful translation of a case-SENSITIVE glob
        # is a regex anchored at both ends, because an unanchored one matches
        # a substring and widens the test.
        regex = _glob_to_regex(pattern)
        text = f"{left} matches regex {_kql_string(regex)}"
        return f"not ({text})" if expr.negate else text

    spelled = _RENDER_OPS.get(expr.op)
    if spelled is None:
        raise Refusal(
            "KQL_RENDER_OPERATOR",
            f"`{expr.op}` has no KQL spelling. Rendering it as equality would "
            f"change what the rule matches.",
            "render",
        )
    # KQL's `contains`/`startswith`/`endswith` are case-INSENSITIVE and the
    # `_cs` forms are the exact-case ones. The table above can name only one
    # of each pair, so the FOLD decides which. Without this, a Sigma
    # `|contains` (ignore-case by specification) came out as `contains_cs` and
    # every uppercase match was silently lost on export.
    if expr.nocase:
        spelled = {
            "contains_cs": "contains",
            "startswith_cs": "startswith",
            "endswith_cs": "endswith",
            # `==`/`!=` fold to KQL's `=~`/`!~`, which ARE case-insensitive
            # equality. Left as `==` the export was case-SENSITIVE, so a rule
            # that matched `ADMIN` locally stopped matching it in Sentinel --
            # the evaluator had learned to fold and the renderer had not.
            "==": "=~",
            "!=": "!~",
        }.get(spelled, spelled)
    right = _render_expression(expr.right)
    if expr.negate:
        flipped = {"==": "!=", "!=": "==", "<": ">=", ">=": "<",
                   ">": "<=", "<=": ">"}.get(spelled)
        if flipped:
            return f"{left} {flipped} {right}"
        return f"not ({left} {spelled} {right})"
    return f"{left} {spelled} {right}"


def _glob_to_regex(pattern: str) -> str:
    """A LIKE pattern as an ANCHORED regex.

    Anchored because `ILIKE 'lsass%'` must not match `not-lsass-helper.exe`:
    the wildcards in the pattern are the only source of looseness, which is
    the same rule `evaluate._glob_match` follows.
    """
    out = ["^"]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            out.append(re.escape(pattern[index + 1]))
            index += 2
            continue
        if char == "%":
            out.append(".*")
        elif char == "_":
            out.append(".")
        else:
            out.append(re.escape(char))
        index += 1
    out.append("$")
    return "".join(out)


def _render_call(call: Call) -> str:
    # `parse_json(X).user.name` is a MEMBER path, carried as a call so the IR
    # can hold it. Written back in dot form, which is the spelling an analyst
    # recognises and the one the parser reads.
    if call.function == "member_path" and len(call.args) == 2 \
            and isinstance(call.args[1], Literal) \
            and isinstance(call.args[1].value, str):
        return (
            f"{_render_expression(call.args[0])}.{call.args[1].value}"
        )
    spelled = _RENDER_FUNCTIONS.get(call.function)
    if spelled is None:
        raise Refusal(
            "KQL_RENDER_FUNCTION",
            f"`{call.function}()` has no KQL equivalent. Dropping it would "
            f"change what the expression computes.",
            "render",
        )
    arguments = ", ".join(_render_expression(a) for a in call.args)
    return f"{spelled}({arguments})"


def render_kql(rule: Rule) -> str:
    """Write a Rule back out as KQL.

    Every dispatch chain over stage types ends in a REFUSAL. A silent `else`
    here would drop a stage and produce a complete-looking query with the
    detection missing -- which is the defect that once made a Wazuh rule match
    every event while reporting success.

    The annotations are written as a `//` header. They used to be dropped
    entirely -- `sigma.py`'s docstring names this function as the origin of
    that defect -- so a Sigma rule converted to KQL arrived with no title, no
    severity and no ATT&CK mapping: a query a SOC cannot route or triage.
    `lower_kql` reads the header back, so the round trip is lossless rather
    than one-way.
    """
    lines: list[str] = list(render_annotation_header(rule.annotations, "//"))
    if lines:
        lines.append("")
    for binding in rule.bindings:
        body = _render_stream(binding.pipeline, binding.name)
        lines.append(f"let {binding.name} =\n{body};")
        lines.append("")
    lines.append(_render_stream(rule.pipeline, ""))
    return "\n".join(lines)


def _render_stream(nodes: tuple[Any, ...], indent: str) -> str:
    if not nodes:
        raise Refusal(
            "KQL_RENDER_EMPTY",
            "there is nothing to write: the pipeline is empty",
            "render",
        )
    head = _render_node(nodes[0])
    parts = [head]
    for node in nodes[1:]:
        parts.append("| " + _render_node(node))
        # A join's cross-row predicate is its OWN `| where`, because KQL's
        # `on` clause holds equality keys and nothing else. Folded into `on`
        # it was silently dropped on re-import -- see `_render_join`.
        if isinstance(node, Join) and node.predicate is not None:
            # A TEMPORAL window cannot be written here: KQL resolves a
            # post-join name by COLUMN, so two sides spelled the same collapse
            # onto one scope and the predicate stops reading both sides.
            refuse_cross_row_predicate(node, "KQL", "KQL_RENDER_JOIN_PREDICATE")
            parts.append("| where " + _render_expression(node.predicate))
    body = "\n".join(parts)
    if indent:
        return _indent(body, "    ")
    return body


def _indent(text: str, prefix: str) -> str:
    return "\n".join(prefix + line if line else line for line in text.splitlines())


def _render_node(node: Any) -> str:
    if isinstance(node, Read):
        return node.table
    if isinstance(node, Filter):
        return f"where {_render_expression(node.condition)}"
    if isinstance(node, Project):
        return _render_project(node)
    if isinstance(node, Derive):
        return _render_derive(node)
    if isinstance(node, Aggregate):
        return _render_aggregate(node)
    if isinstance(node, Join):
        return _render_join(node)
    if isinstance(node, Sort):
        keys = ", ".join(f"{r.full} desc" if d else r.full for r, d in node.keys)
        return f"sort by {keys}"
    if isinstance(node, Limit):
        return f"take {node.count}"
    if isinstance(node, Distinct):
        return "distinct " + ", ".join(r.full for r in node.keys)
    if isinstance(node, Correlation):
        return _render_correlation(node)
    if isinstance(node, Emit):
        if node.keeps:
            return "project " + ", ".join(r.full for r in node.keeps)
        return "project *"
    raise Refusal(
        "KQL_NODE_NOT_RENDERABLE",
        f"a {type(node).__name__} stage has no KQL spelling in this renderer. "
        f"It is refused rather than skipped, because skipping it writes a query "
        f"that is missing this stage -- and a query missing its `where` matches "
        f"everything.",
        "render",
    )


def _render_project(node: Project) -> str:
    if node.drops and not node.renames and not node.keeps:
        return "project-away " + ", ".join(r.full for r in node.drops)
    items: list[str] = []
    for source, target in node.renames:
        items.append(f"{target} = {source.full}")
    for ref in node.keeps:
        items.append(ref.full)
    if not items:
        # A projection with no items renders as `project *`, which is what the
        # node means: keep everything. It is spelled out rather than omitted,
        # because a renderer that omits the operator writes a different query.
        return "project *"
    return "project " + ", ".join(items)


def _render_derive(node: Derive) -> str:
    return "extend " + ", ".join(
        f"{name} = {_render_expression(expr)}" for name, expr in node.assignments
    )


def _render_aggregate(node: Aggregate) -> str:
    """`summarize`, including the time bucket its window describes.

    The WINDOW was dropped. `summarize c=count() by bin(TimeGenerated, 5m)`
    lowered with `Window(size=5m, time_field=TimeGenerated)` and rendered as
    `by TimeGenerated` -- so the bucketing vanished and the rule aggregated
    across the whole sample instead of per five minutes. A threshold built on
    that counts everything ever seen rather than a burst, which is the
    difference between an alert and a daily report.

    The bucket key is written in place of the bare time field rather than
    alongside it, because `by bin(T, 5m), T` groups by both the bucket and the
    exact timestamp -- which makes every row its own group and the count
    always one.
    """
    parts: list[str] = []
    for measure in node.measures:
        text = _render_measure(measure)
        parts.append(f"{measure.name} = {text}" if measure.name else text)
    body = ", ".join(parts)

    window = node.window
    bucket = ""
    if window is not None and window.size is not None:
        field = window.time_field or "TimeGenerated"
        bucket = f"bin({field}, {_kql_duration(window.size)})"

    if node.keys or bucket:
        names: list[str] = []
        if bucket:
            names.append(bucket)
        for ref in node.keys:
            if window is not None and ref.full == (window.time_field or ""):
                continue  # already carried by the bucket
            names.append(ref.full)
        body += " by " + ", ".join(names)
    return f"summarize {body}"


def _render_measure(measure: Measure) -> str:
    function = measure.function
    if measure.condition is not None:
        if function not in ("count", "count_if"):
            raise Refusal(
                "KQL_RENDER_CONDITIONAL_AGGREGATE",
                "only countif() has a faithful conditional aggregate spelling "
                "in KQL.",
                "render",
            )
        return f"countif({_render_expression(measure.condition)})"
    if function == "count":
        return "count()"
    supported = {
        "count_if", "dcount", "sum", "min", "max", "avg", "stdev",
        "make_set", "make_list", "percentile", "arg_max", "arg_min",
    }
    if function not in supported:
        raise Refusal(
            "KQL_RENDER_AGGREGATE",
            f"`{function}` has no supported KQL aggregate spelling. Rendering "
            f"it unchanged would produce a query this dialect cannot parse.",
            "render",
        )
    spelled = _SPELL_BACK.get(function, function)
    if measure.param is not None:
        return f"{spelled}({measure.field.full}, {measure.param})"
    return f"{spelled}({measure.field.full})"


_SPELL_BACK: Final[dict[str, str]] = {
    "count_if": "countif",
    "make_set": "make_set",
    "make_list": "make_list",
    "dcount": "dcount",
    "avg": "avg",
    "values": "make_set",
}


def _render_join(node: Join) -> str:
    """The `join` operator, keys only.

    KQL's `on` clause takes EQUALITY KEYS and nothing else. The cross-row
    predicate used to be appended to it with ` and `, producing

        on Computer = Computer, Account = Account and LoginTime between (...)

    which is not valid KQL and, re-read by this dialect's own parser, was
    swallowed into the key list: the temporal predicate vanished and the rule
    became "any LSASS access on a host that ever had an NTLM logon" rather
    than "within ten minutes". `_render_node` emits the predicate as the
    following `| where`, which is where the source rule had it.

    The key is written in KQL's shorthand when both sides spell it the same.
    `on Computer = Computer` is not KQL; the shorthand `on Computer` is, and
    the explicit form is `$left.A == $right.B`.
    """
    kind = {
        "inner": "inner",
        "left": "leftouter",
        "right": "rightouter",
        "full": "fullouter",
        "anti": "leftanti",
        "cross": "fullouter",
    }.get(node.how, "inner")
    keys = ", ".join(
        left.name if left.name == right.name
        else f"$left.{left.name} == $right.{right.name}"
        for left, right in node.on
    )
    return f"join kind={kind} ({node.right}) on {keys}"


def _render_correlation(node: Correlation) -> str:
    """KQL has no parent-rule threshold, so this is REFUSED, not commented out.

    It used to return `// correlation: 5 occurrences of ... within 300s`, which
    the pipeline writer turned into `| // correlation: ...` -- a syntax error in
    Sentinel that also deleted the threshold. The rule then matched every single
    event the filter caught, which is the opposite of what a threshold rule
    says. A comment is not a rule.
    """
    raise Refusal(
        "KQL_RENDER_CORRELATION",
        f"`{node.id}` fires when `{node.parent}` matches {node.frequency} times "
        f"within {int(node.timeframe.seconds)}s, and KQL has no way to say that. "
        f"Sentinel expresses it as a scheduled analytics rule with an "
        f"aggregation, not as a query, so writing this out as a comment would "
        f"delete the threshold and alert on every single event.",
        "render",
    )
