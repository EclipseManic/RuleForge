"""Splunk SPL -> RuleIR.

THE DESIGN DECISION THAT MATTERS HERE

`stats` and `tstats` look almost identical and are NOT the same command.

  `stats`   reads raw events. Its numbers can be reproduced from an event sample.
  `tstats`  reads tsidx, over INDEX-TIME fields, from an accelerated data model
            or a namespace. It is a report-generating command.

So a `tstats` rule is DECLARED faithfully -- every measure, key, span, FROM and
WHERE survives into the IR, and it renders back to correct SPL -- but local
evaluation is REFUSED by name, because there is no honest way to compute
indexed-field statistics from a handful of decoded events. Approximating it as
`stats` would report counts the agent never produces, which is the same false
claim as evaluating PCRE with Python's `re`.

The same refusal-by-name treatment applies to YARA-L's `pcre`, Wazuh's `pcre2`,
and a declared-only regex dialect. Consistency matters: a capability is either
reproducible from the inputs at hand or it is named as unavailable.
"""
from __future__ import annotations

from typing import Any

from ..engine.ir import (
    Aggregate,
    BoolOp,
    Call,
    Comparison,
    Duration,
    Emit,
    FieldExpr,
    FieldRef,
    Filter,
    Frame,
    Literal,
    Measure,
    Not,
    Read,
    RuleIR,
    SourceSelector,
    TimeRef,
)
from .spl import (
    DIALECT,
    SplCommand,
    SplParseError,
    SplTerm,
    parse_search_terms,
    parse_spl,
    parse_stats,
    walk_terms,
)

#: Commands that make a rule un-lowerable rather than merely unsupported. Each
#: one changes WHAT the rule detects, not just how it is written.
OPAQUE_COMMANDS = {
    "lookup": "an external CSV or lookup file, which RuleForge cannot read",
    "inputlookup": "an external lookup file, which RuleForge cannot read",
    "transaction": "Splunk's own multi-event grouping, which replaces the "
                   "event sequence rather than filtering it",
    "streamstats": "a windowed running aggregate, whose window is opened and "
                   "closed by events rather than by a fixed range",
    "timechart": "a time-bucketed report whose x-axis is a span, not a filter",
    "collector": "streaming collection output, not a predicate",
    "makeresults": "synthetic events, which match nothing real",
    "spath": "field extraction that changes the shape of every later term",
    "format": "rendering output, not filtering",
    "table": "a projection that drops the fields later terms would read",
    "rex": "in-place extraction, which rewrites the fields a later term reads",
}

#: `where` evaluates an eval expression; `search` evaluates search-language terms.
#: They are different languages and conflating them changes what matches.
_EVAL_FUNCTIONS = {
    "cidrmatch": "cidr_contains",
    "like": "contains",
    "match": "matches_regex",
    "true": None,
    "false": None,
}


def lower(text: str, rule_id: str = "spl",
          time_field: str = "_time") -> tuple[RuleIR, list[dict[str, Any]]]:
    """Lower an SPL search to a runnable graph, or refuse by name."""
    diagnostics: list[dict[str, Any]] = []
    search = parse_spl(text)

    for command in search.pipeline:
        if command.name in OPAQUE_COMMANDS:
            raise SplParseError(
                "SPL_COMMAND_NOT_LOWERABLE",
                f"`{command.name}` means {OPAQUE_COMMANDS[command.name]}. "
                f"Lowering it as a filter would change what the rule detects, "
                f"so it is named rather than approximated.", DIALECT)

    # `index=main sourcetype=X` ARE ANDed IN SPL, so they become ONE filter over
    # ONE read. An earlier version built a separate Read per selector, which
    # unions them -- every Windows event plus every Security event, rather than
    # the intersection. A guard then REFUSED the combination outright, which
    # fixed the union by rejecting the single most common opening line in SPL.
    # Both were wrong; the intersection is what the author wrote.
    # EVERY HEAD TERM IS LOWERED, NOT JUST THE SELECTORS. Only `index` and
    # `sourcetype` were read, so `index=windows EventCode=4625 | stats count by
    # host` quietly lost the `EventCode` filter: the analyst got a count over
    # ALL Security events instead of failed logons, `ok: true`, and no findings.
    # A search that was nothing but `EventCode=4625` rendered as an EMPTY query,
    # still `ok: true`. That is the most ordinary SPL there is, and losing its
    # filter inverts the rule's meaning while looking like success.
    # THE TERM TREE IS KEPT, NOT FLATTENED. `walk_terms` returned the leaf terms
    # and discarded the `("and"/"or", ...)` structure, then `_all_of` rejoined the
    # leaves with "and" unconditionally -- so `index=w a="1" OR b="2"` lowered to
    # `and(index=w, a="1", b="2")` and rendered as
    # `| search (a="1" AND b="2")`. For a single-valued field that is
    # unsatisfiable, so the rule could never fire, and for a multi-valued one it
    # matched a SUBSET. The `OR` was not merely lost: it was replaced with the
    # operator that changes what the rule detects. `_term_condition` already
    # handles the nested tree, so the tree is passed through whole.
    #
    # A NEGATED HEAD TERM IS REFUSED rather than dropped. `NOT user=admin` at the
    # head used to be filtered out by `not term.negate`, so the term vanished and
    # the rule got BROADER, with ok:true and no findings. The check walks the
    # FLATTENED view for this test only -- a negated term is nested inside the
    # tree, so inspecting the root alone would miss it -- while the tree itself
    # is carried into the lowering so the connectives survive.
    for leaf in walk_terms(search.terms):
        if isinstance(leaf, SplTerm) and leaf.negate:
            raise SplParseError(
                "SPL_NEGATED_HEAD_TERM",
                f"`NOT {leaf.field}` appears in the head of the search. A negated "
                f"term there is easy to drop, and widening the search is the "
                f"dangerous direction, so it is named. Write it as a `| where` "
                f"stage, which lowers exactly.", DIALECT)

    index_conditions = [
        _term_condition(term)
        for term in walk_terms(search.terms, keep_structure=True)
    ]
    index_conditions = [c for c in index_conditions if c is not None]

    nodes: list[Any] = [
        Read(id="read", selector=SourceSelector(name="events")),
    ]
    current = "read"

    # A BARE TERM IS AMBIGUOUS AND THE AMBIGUITY IS NOT RULEFORGE'S TO RESOLVE.
    # In Splunk, `index=main EventCode` asserts the field `EventCode` exists and
    # is non-empty -- but ONLY if the index has such a field. If it does not,
    # Splunk falls back to searching the raw event for that string, which matches
    # a superset. Which reading applies depends on the deployment's field
    # inventory, not on the rule text, so the field-existence reading is lowered
    # and the other is reported. Refusing instead would reject an ordinary search.
    bare_terms = [t for t in walk_terms(search.terms) if t.op is None]
    if bare_terms:
        diagnostics.append({
            "code": "SPL_BARE_TERM_MAY_BE_A_RAW_SEARCH",
            "severity": "info",
            "message": f"{', '.join(sorted({t.field for t in bare_terms}))} "
                       f"appear as bare terms. Lowered as 'this field exists and "
                       f"is not null'. If the index has no such field, Splunk "
                       f"instead searches the raw event for that string, which "
                       f"matches MORE. RuleForge cannot see your field inventory, "
                       f"so it cannot tell which applies.",
        })

    if index_conditions:
        nodes.append(Filter(id="selectors", input=current,
                            condition=_all_of(index_conditions)))
        current = "selectors"

    for position, command in enumerate(search.pipeline):
        if command.name == "search":
            condition = _all_of([_term_condition(t)
                                 for t in walk_terms((parse_search_terms(command.args),))])
            nodes.append(Filter(id=f"search_{position}", input=current,
                                condition=condition))
            current = f"search_{position}"
        elif command.name in ("stats", "tstats", "eventstats"):
            aggregate, following = _lower_aggregate(command, position, current,
                                                    time_field, diagnostics)
            nodes.append(aggregate)
            current = aggregate.id
            if following:
                nodes.append(following)
                current = following.id
        elif command.name == "where":
            nodes.append(Filter(id=f"where_{position}", input=current,
                                condition=_eval_condition(command.args)))
            current = f"where_{position}"
        elif command.name in ("head", "sort", "rename", "fields", "dedup",
                              "fillnull", "eval", "regex"):
            # BOTH HALVES OF THE OLD DIAGNOSTIC WERE FALSE, FOR ALL EIGHT.
            #
            # It said "`regex` does not change which events are selected" --
            # `| regex` is a FILTERING command in SPL, so
            # `index=main | regex CommandLine="mimikatz" | stats count BY host`
            # rendered as `index=main | stats count AS count BY host` and the
            # entire detection was deleted, with `ok=True` and severity `info`.
            #
            # It also said "It is preserved for rendering." Nothing preserved
            # anything: `render_spl` builds from `ir.nodes`, and no node is added
            # here, so there is nothing for it to render. `| head 10`,
            # `| dedup host` and `| fields host, user` all rendered as bare
            # `index=main`.
            #
            # The other seven are the same class and the review is right about
            # each: `dedup` collapses rows, `head` limits them, `fillnull` fills
            # empties so a LATER `where` matches rows it otherwise would not,
            # `rename` rewrites the very field a later term reads, `fields`
            # restricts the output, `eval` computes a column, `sort` orders.
            #
            # So this is refused by name, like the unknown-command branch below.
            # `info` is the wrong severity for a changed result set: a severity
            # band is a claim about how much this matters, and this is the
            # difference between a detection and no detection.
            raise SplParseError(
                "SPL_COMMAND_NOT_LOWERABLE",
                f"`{command.name}` changes which rows the search returns, and it "
                f"is not represented in the graph, so it would be dropped from "
                f"the rendered rule. Ignoring it produced an artifact that "
                f"silently returned a different set of events -- for `regex`, "
                f"the whole detection. Refused rather than approximated, "
                f"because an approximated command is a rule you did not write.",
                DIALECT)
        else:
            raise SplParseError(
                "SPL_COMMAND_UNKNOWN",
                f"`{command.name}` is not a command this lowering handles. An "
                f"unrecognised command in a detection rule is usually the part "
                f"carrying the detection, so it is named rather than ignored.",
                DIALECT)

    nodes.append(Emit(id="out", input=current))
    return RuleIR(rule_id=rule_id, nodes=tuple(nodes), output="out",
                  title=" ".join(search.text.split())[:200],
                  metadata={"dialect": DIALECT}), diagnostics


def _all_of(conditions: list[Any]) -> Any:
    usable = [c for c in conditions if c is not None]
    if not usable:
        raise SplParseError("SPL_NO_CONDITION",
                            "this stage has no condition at all", DIALECT)
    return usable[0] if len(usable) == 1 else BoolOp("and", tuple(usable))


def _term_condition(term: Any) -> Any:
    """One search-language term -> a boolean expression.

    THE OPERANDS ARE `term[1]`, NOT `term[1:]`. The parser builds
    `("and", (t1, t2, t3))` -- the operands are ONE element that happens to be a
    tuple -- so slicing from 1 yields `((t1, t2, t3),)`: a tuple containing the
    operand list, whose first element is a term rather than a connective, and it
    fell straight through to the assert. That never fired while the head terms
    were flattened, which is exactly why the bug survived until the tree was
    carried through whole.
    """
    if isinstance(term, tuple) and term and term[0] in ("and", "or"):
        operands = term[1] if len(term) == 2 and isinstance(term[1], tuple) \
            else term[1:]
        node = BoolOp(term[0], tuple(_term_condition(c) for c in operands))
        return node
    if isinstance(term, tuple) and term and term[0] == "not":
        inner = term[1]
        operand = inner[0] if isinstance(inner, tuple) and len(inner) == 1 \
            and isinstance(inner[0], (tuple, SplTerm)) else inner
        return Not(_term_condition(operand))

    assert isinstance(term, SplTerm)
    if term.op == "in":
        if not term.values:
            raise SplParseError("SPL_IN_EMPTY",
                                "an IN with no values can never match, and "
                                "Splunk treats it as an error, not a no-match",
                                DIALECT)
        subject = _field(term.field)
        if term.negate:
            return Not(Call(function="in_set", args=(subject, Literal(term.values))))
        return Call(function="in_set", args=(subject, Literal(term.values)))

    if term.op is None:
        # A bare field name in a search means "this field exists and is
        # non-empty". It is NOT a comparison to True. It is also a PRESENCE OP
        # on a Comparison, not a Call -- building `Call("is_not_null", ...)` was
        # refused with UNKNOWN_FUNCTION, so the same bare term was dropped on the
        # head line and raised on the `| search` line.
        return Comparison("is_not_null", _field(term.field), Literal(value=True))

    if term.op == "=":
        node: Any = Comparison("=", _field(term.field), Literal(term.value))
    else:
        node = Comparison(term.op, _field(term.field), Literal(term.value))
    return Not(node) if term.negate else node


def _field(name: str | None) -> FieldExpr:
    if not name:
        raise SplParseError("SPL_TERM_WITHOUT_FIELD", "a term has no field name",
                            DIALECT)
    parts = name.split(".")
    return FieldExpr(ref=FieldRef(parts[0], tuple(parts[1:])))


def _field_ref(name: str) -> FieldRef:
    parts = name.split(".")
    return FieldRef(parts[0], tuple(parts[1:]))


def _eval_condition(args: str) -> Any:
    """`where` uses the EVAL expression language, not search syntax."""
    text = args.strip()
    if not text:
        raise SplParseError("SPL_WHERE_EMPTY", "`where` has no expression", DIALECT)

    upper = text.upper()
    if upper == "TRUE":
        return Literal(value=True)
    if upper == "FALSE":
        return Literal(value=False)

    for splitter, op in ((" AND ", "and"), (" OR ", "or")):
        parts = text.split(splitter)
        if len(parts) > 1:
            return BoolOp(op, tuple(_eval_condition(p) for p in parts))

    negated = False
    body = text
    while body.upper().startswith("NOT "):
        negated = not negated
        body = body[4:].strip()

    node = _eval_comparison(body)
    return Not(node) if negated else node


def _eval_comparison(text: str) -> Any:
    body = text.strip()
    if body.startswith("(") and body.endswith(")"):
        return _eval_condition(body[1:-1])

    for operator in (">=", "<=", "!=", "=", ">", "<"):
        index = _find_operator(body, operator)
        if index < 0:
            continue
        left = body[:index].strip()
        right = body[index + len(operator):].strip()
        subject = _eval_operand(left)
        value = _literal(right)
        if operator == "=":
            return Comparison("=", subject, value)
        if operator == "!=":
            return Not(Comparison("=", subject, value))
        return Comparison(operator, subject, value)

    raise SplParseError(
        "SPL_WHERE_NOT_A_COMPARISON",
        f"{text!r} is not a comparison. `where` takes an expression, so a bare "
        f"word here means nothing; a rule that relied on it would match "
        f"everything.", DIALECT)


def _find_operator(text: str, operator: str) -> int:
    depth = 0
    in_quote = False
    for index, char in enumerate(text):
        if char == '"':
            in_quote = not in_quote
        elif not in_quote and char == "(":
            depth += 1
        elif not in_quote and char == ")":
            depth -= 1
        elif not in_quote and depth == 0 and text.startswith(operator, index):
            if operator == "=" and index > 0 and text[index - 1] in "!<>" \
                    and not text.startswith(operator + "=", index):
                continue
            return index
    return -1


def _eval_operand(text: str) -> Any:
    body = text.strip()
    if body.startswith('"') and body.endswith('"'):
        return Literal(value=body[1:-1])
    if body.isdigit():
        return Literal(value=int(body))
    return _field(body)


def _literal(text: str) -> Any:
    body = text.strip()
    if body.startswith('"') and body.endswith('"'):
        return Literal(value=body[1:-1])
    try:
        return Literal(value=int(body))
    except ValueError:
        return Literal(value=body)


def _lower_aggregate(command: SplCommand, position: int, source: str,
                     time_field: str,
                     diagnostics: list[dict[str, Any]]) -> tuple[Any, Any]:
    """`stats` / `tstats` -> Aggregate (+ the mandatory span Filter for _time)."""
    stats = parse_stats(command.args, command.name)
    node_id = f"agg_{position}"

    measures: list[Measure] = []
    for spec in stats.measures:
        name = spec.alias or _default_alias(spec.function, spec.field)
        if spec.function in ("count", "c") and not spec.field:
            measures.append(Measure(name=name, function="count", field=None))
            continue
        mapped = _MEASURE_FUNCTIONS.get(spec.function)
        if mapped is None:
            raise SplParseError(
                "SPL_MEASURE_NOT_LOWERABLE",
                f"`{spec.function}({spec.field})` has no IR measure equivalent "
                f"this lowering will guess at. Naming it is better than "
                f"substituting a different statistic.", DIALECT)
        measures.append(Measure(name=name, function=mapped,
                                field=_field_ref(spec.field) if spec.field else None))

    keys = tuple(_field_ref(k) for k in stats.keys)

    # `BY _time span=1h` IS A TIME BUCKET, AND span IS MANDATORY WITH IT. Without
    # a span every event lands in one bucket, which is a different report.
    if any(k.full == time_field for k in keys):
        if not stats.span:
            raise SplParseError(
                "SPL_TIME_BUCKET_WITHOUT_SPAN",
                f"the rule groups by {time_field} with no span=. Splunk requires "
                f"a span when grouping by time, and without one every event "
                f"collapses into a single bucket -- a different report from the "
                f"one the author asked for.", DIALECT)
        measures.append(Measure(name="__bucket__", function="count", field=None))
        keys = keys + (FieldRef("__bucket__"),)
        diagnostics.append({
            "code": "SPL_TIME_BUCKET_SYNTHESISED",
            "severity": "info",
            "message": f"BY {time_field} span={stats.span} is a tumbling time "
                       f"bucket, represented as a synthetic grouping key so the "
                       f"window is real rather than ignored.",
        })

    if stats.span:
        frame = Frame(kind="tumbling", size=Duration(_span_seconds(stats.span)),
                      time_ref=TimeRef(field_name=time_field))
    else:
        frame = Frame(kind="per_event")

    if command.name == "tstats":
        # REFUSED, NOT APPROXIMATED. See the module docstring.
        raise SplParseError(
            "TSTATS_NOT_EXECUTABLE_LOCALLY",
            "tstats reads INDEX-TIME fields from tsidx, over an accelerated "
            "data model or a namespace"
            + (f" ({stats.from_clause})" if stats.from_clause else "")
            + f", not raw events. Its {len(measures)} measures and "
            f"{len(keys)} keys are parsed and preserved, but no event sample can "
            f"reproduce indexed-field statistics, so this is not evaluated "
            f"locally rather than approximated as `stats`. To tune it, run it in "
            f"Splunk and bring the results back.", DIALECT)

    if stats.where:
        raise SplParseError(
            "SPL_STATS_WHERE_NOT_LOWERABLE",
            f"a WHERE clause inside {command.name} filters the aggregated table, "
            f"not the events, so it cannot be expressed as a filter before the "
            f"aggregate. Put it in a following `| where` and it lowers exactly.",
            DIALECT)

    aggregate = Aggregate(id=node_id, input=source, measures=tuple(measures),
                          keys=keys, frame=frame)

    following = None
    return aggregate, following


_MEASURE_FUNCTIONS = {
    "count": "count", "c": "count",
    "dc": "distinct_count", "distinct_count": "distinct_count",
    "avg": "avg", "min": "min", "max": "max", "sum": "sum",
    "values": "set", "list": "set",
    "first": "first", "last": "last",
}


def _default_alias(function: str, field: str | None) -> str:
    if function in ("count", "c") and not field:
        return "count"
    if function in ("dc", "distinct_count", "estdc"):
        return f"dc_{field}"
    return f"{function}_{field}"


def _span_seconds(span: str | None) -> int:
    if not span:
        return 3600
    text = span.strip().lower()
    units = (("s", 1), ("m", 60), ("h", 3600), ("d", 86400))
    for suffix, multiplier in units:
        if text.endswith(suffix):
            head = text[:-len(suffix)]
            if head.isdigit():
                return int(head) * multiplier
    raise SplParseError(
        "SPL_SPAN_NOT_A_TIMESPAN",
        f"span={span!r} is not a timespan like 1h, 30m or 7d", DIALECT)
