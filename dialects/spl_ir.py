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

import re
from typing import Any, Final

from engine.ir import (
    Aggregate,
    Arrange,
    BoolOp,
    Call,
    Comparison,
    Derive,
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
from dialects.spl import (
    DIALECT,
    SplCommand,
    SplParseError,
    SplTerm,
    parse_search_terms,
    parse_spl,
    parse_stats,
    walk_terms,
)

#: A plain field name, possibly dotted. Used to REFUSE a malformed
#: `fields` / `rename` / `sort` argument rather than guessing which column was
#: meant, because every one of those guesses returns a different set of events.
_FIELD_NAME: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")

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


def _parse_field_aliases(command: str, args: str, position: int,
                         dialect: str) -> tuple[tuple[str, Any], ...]:
    """`fields a, b` and `rename user as account` -> Derive assignments.

    `fields` keeps the named columns; `rename` reads one field and writes it
    under a new name. Both are `Derive`, and `projects` tells them apart.

    EVERY MALFORMED ARGUMENT LIST IS REFUSED RATHER THAN PARTLY HONOURED. A
    `fields` list that silently drops the one column it could not read narrows
    the output, and a `rename` that drops the pair leaves the rule reading a
    column the analyst renamed away. Both are the failure this project exists to
    prevent, so the whole list is rejected together.
    """
    assignments: list[tuple[str, Any]] = []
    for raw in (part.strip() for part in args.split(",")):
        if not raw:
            raise SplParseError(
                "SPL_FIELD_LIST_MALFORMED",
                f"`{command} {args}` has an empty entry. Refused rather than "
                f"skipped, because a dropped column changes what the rule "
                f"returns.", dialect)
        if command == "fields":
            if not _FIELD_NAME.fullmatch(raw):
                raise SplParseError(
                    "SPL_FIELD_LIST_MALFORMED",
                    f"`fields {raw}` is not a plain field name. RuleForge will "
                    f"not guess which column you meant.", dialect)
            assignments.append((raw, FieldExpr(ref=FieldRef(raw))))
            continue
        # `rename`: `<old> as <new>`, and Splunk also allows `as` to be omitted.
        if " as " in raw:
            old, _, new = raw.partition(" as ")
        else:
            old, new = raw, raw
        old, new = old.strip(), new.strip()
        if not (_FIELD_NAME.fullmatch(old) and _FIELD_NAME.fullmatch(new)):
            raise SplParseError(
                "SPL_RENAME_MALFORMED",
                f"`rename {raw}` is not `<field> as <field>`. Renaming to or "
                f"from something that is not a plain field name is refused, "
                f"because the later terms read the renamed field.", dialect)
        if old == new:
            raise SplParseError(
                "SPL_RENAME_NOOP",
                f"`rename {raw}` renames a field to itself. That is not an "
                f"error, but it changes nothing, so it is dropped rather than "
                f"emitted.", dialect)
        assignments.append((new, FieldExpr(ref=FieldRef(old))))
    if not assignments:
        raise SplParseError(
            f"SPL_{command.upper()}_NO_ARGUMENTS",
            f"`{command}` with no field list. Refused rather than rendered as a "
            f"no-op, because a stage that changes nothing and a stage that was "
            f"meant to change something look identical in the output.", dialect)
    return tuple(assignments)


def _parse_arrange_args(command: str, args: str, position: int,
                        dialect: str) -> tuple[tuple[tuple[FieldRef, str], ...],
                                               int | None]:
    """`sort -count` and `head 5 -_time` -> Arrange's order_by and limit.

    SPL's sign convention, from Splunk's `sort` documentation: a minus sign is
    DESCENDING and a plus sign is ASCENDING, with ascending the default. That is
    cited rather than remembered, because the previous version of this file
    asserted an SPL convention from memory and seven tests certified it -- and
    the syntax did not exist.

    `head` returns the first N in SEARCH order, so with no field it is a plain
    limit and no ordering is invented: inventing a sort would change which rows
    come back.
    """
    tokens = args.split()
    if not tokens:
        raise SplParseError(
            "SPL_ARRANGE_NO_ARGUMENTS",
            f"`{command}` with no arguments. Refused rather than rendered as a "
            f"no-op.", dialect)

    limit: int | None = None
    index = 0
    if command == "head":
        if not tokens[0].isascii() or not tokens[0].isdigit():
            raise SplParseError(
                "SPL_HEAD_LIMIT_NOT_AN_INTEGER",
                f"`head {tokens[0]}` -- the first argument to `head` is the "
                f"count, and it is not a plain number. Refused rather than "
                f"guessed, because the wrong count is a different rule.", dialect)
        limit = int(tokens[0])
        if limit <= 0:
            raise SplParseError(
                "SPL_HEAD_LIMIT_NOT_POSITIVE",
                f"`head {limit}` returns no events, so the rule could never "
                f"fire. Refused rather than rendered.", dialect)
        index = 1

    order: list[tuple[FieldRef, str]] = []
    while index < len(tokens):
        token = tokens[index]
        direction = "asc"
        if token.startswith("-"):
            direction, token = "desc", token[1:]
        elif token.startswith("+"):
            token = token[1:]
        # `sort 0 -field` is a count, not a field: 0 means "no limit".
        if token.isdigit():
            index += 1
            continue
        if not _FIELD_NAME.fullmatch(token):
            raise SplParseError(
                "SPL_SORT_FIELD_NOT_A_NAME",
                f"`{command} {token}` is not a plain field name. RuleForge will "
                f"not guess which column you meant, because sorting by a "
                f"different column returns a different set of events.", dialect)
        order.append((FieldRef(token), direction))
        index += 1

    if not order and limit is None:
        raise SplParseError(
            "SPL_ARRANGE_NO_MEANING",
            f"`{command} {args}` names no field and no count, so there is "
            f"nothing for it to do.", dialect)
    return tuple(order), limit


def _eval_expression(text: str) -> Any:
    """One `eval` right-hand side, which is a WIDER language than a condition.

    `_eval_condition` already parses comparisons, AND/OR, NOT, parentheses and
    function calls, and `| where` uses it. An `eval` assignment can also be a
    BARE FIELD REFERENCE -- `| eval copy=user` is the ordinary rename-by-eval
    form -- and a bare name is not a condition, so `_eval_condition` would reject
    it. Rather than a second parser, this handles the two forms a condition
    cannot be (a bare field, and a bare literal) and delegates everything else, so
    there is one implementation of each construct.
    """
    body = text.strip()
    if not body:
        raise SplParseError("SPL_EVAL_EMPTY", "`eval` has an empty expression",
                            DIALECT)

    if _FIELD_NAME.fullmatch(body):
        return FieldExpr(ref=FieldRef(body))

    try:
        return _eval_condition(body)
    except SplParseError:
        pass

    if (body[0] == body[-1] and body[0] in "'\"" and len(body) >= 2):
        return Literal(value=body[1:-1])
    if body.isascii() and body.lstrip("-").isdigit():
        return Literal(value=int(body))
    if body.isascii() and body.lstrip("-").replace(".", "", 1).isdigit():
        return Literal(value=float(body))
    raise SplParseError(
        "SPL_EVAL_EXPRESSION_NOT_LOWERABLE",
        f"`{body}` is not something this lowering can compute. RuleForge "
        f"evaluates a fixed set of expressions and will not approximate the "
        f"rest, because a computed column that is not the one the analyst meant "
        f"makes every later term read the wrong value.", DIALECT)


def _parse_eval_assignments(args: str) -> tuple[tuple[str, Any], ...]:
    """`eval a=1, b=user` -> Derive assignments.

    Split on commas that are not inside quotes or brackets, because
    `eval` arguments routinely contain both: `eval list="a,b"` is one
    assignment, not two. Splitting naively on every comma is how a single
    assignment becomes two broken ones.
    """
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    for char in args:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "'\"":
            quote = char
            current.append(char)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == "," and depth <= 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    if quote:
        raise SplParseError("SPL_EVAL_UNTERMINATED_QUOTE",
                            f"`eval {args}` has an unterminated quote.", DIALECT)

    assignments: list[tuple[str, Any]] = []
    seen: set[str] = set()
    for raw in (p.strip() for p in parts):
        if not raw:
            raise SplParseError("SPL_EVAL_EMPTY_ASSIGNMENT",
                                f"`eval {args}` has an empty assignment. "
                                f"Refused rather than skipped.", DIALECT)
        name, separator, expression = raw.partition("=")
        if not separator:
            raise SplParseError(
                "SPL_EVAL_NOT_AN_ASSIGNMENT",
                f"`eval {raw}` is not `<field>=<expression>`. A bare expression "
                f"in an `eval` stage computes nothing.", DIALECT)
        name = name.strip()
        if not _FIELD_NAME.fullmatch(name):
            raise SplParseError("SPL_EVAL_TARGET_NOT_A_FIELD",
                                f"`eval {raw}` does not assign to a plain field "
                                f"name.", DIALECT)
        if name in seen:
            raise SplParseError(
                "SPL_EVAL_DUPLICATE_FIELD",
                f"`eval` assigns {name!r} twice, and the second would silently "
                f"overwrite the first.", DIALECT)
        seen.add(name)
        assignments.append((name, _eval_expression(expression)))
    if not assignments:
        raise SplParseError("SPL_EVAL_EMPTY", "`eval` with no assignments.",
                            DIALECT)
    return tuple(assignments)


def _parse_regex_filter(args: str) -> Any:
    """`| regex Field="value"` -> ONE Filter.

    `regex` IS a filtering command -- the blanket refusal this replaces claimed
    it was not, and that claim is why `| regex CommandLine="mimikatz" | stats
    count by host` once rendered as a bare `stats`, deleting the whole detection
    with `ok=True`. It is a filter whose left side is a FIELD NAME, so
    `_eval_condition` already parses the comparison; the only thing added here
    is a refusal when the argument is not that shape, because guessing which
    field was meant is how a rule detects something else.
    """
    text = args.strip()
    if not text:
        raise SplParseError("SPL_REGEX_EMPTY", "`regex` has no pattern.",
                            DIALECT)
    if "=" not in text:
        raise SplParseError(
            "SPL_REGEX_NOT_A_FIELD_TEST",
            f"`regex {text}` is not `Field=\"pattern\"`. `regex` filters on a "
            f"named field, and RuleForge will not guess which one, because a "
            f"different field is a different rule.", DIALECT)
    return _eval_condition(text)


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
        elif command.name in ("fields", "rename", "sort", "head"):
            # FOUR OF THE EIGHT, LOWERED. These need no expression parser, so
            # they are structural and provable; `eval`, `regex`, `dedup` and
            # `fillnull` stay refused below with a message that says which.
            #
            # `fields` and `rename` are both `Derive`, distinguished by
            # `projects` -- TRUE restricts the output columns, FALSE rewrites one
            # field's name. That flag is data, not a name, and the renderer
            # already branches on it, so no new vocabulary is introduced here.
            #
            # `sort` and `head` are both `Arrange`, distinguished by `limit`:
            # a limit means "first N in this order", which Splunk spells as
            # `sort` then `head` -- the renderer emits exactly that.
            if command.name in ("fields", "rename"):
                pairs = _parse_field_aliases(command.name, command.args,
                                            position, DIALECT)
                nodes.append(Derive(
                    id=f"derive_{position}", input=current,
                    assignments=pairs,
                    projects=command.name == "fields",
                    kind=command.name))
                current = f"derive_{position}"
            else:
                order_by, limit = _parse_arrange_args(command.name,
                                                      command.args, position,
                                                      DIALECT)
                nodes.append(Arrange(id=f"arrange_{position}", input=current,
                                     order_by=order_by, limit=limit))
                current = f"arrange_{position}"
        elif command.name == "eval":
            nodes.append(Derive(id=f"derive_{position}", input=current,
                                assignments=_parse_eval_assignments(
                                    command.args),
                                projects=False,
                                kind="eval"))
            current = f"derive_{position}"
        elif command.name == "regex":
            nodes.append(Filter(id=f"regex_{position}", input=current,
                                condition=_parse_regex_filter(command.args)))
            current = f"regex_{position}"
        elif command.name in ("head", "sort", "rename", "fields", "dedup",
                              "fillnull"):
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
