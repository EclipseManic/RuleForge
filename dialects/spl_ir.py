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
        # `head` HAS NO FIELD ARGUMENT, AND EVERY ONE THAT FOLLOWED THE COUNT WAS
        # BEING REINTERPRETED AS A SORT.
        #
        #     | head 5 host   ->   | sort +host | head 5     ok=True, no finding
        #
        # Splunk's documented syntax is `head [keeplast] [while "<expr>"]
        # [<limit>]` -- no field, no sort-order argument, in SPL2 or in the older
        # `head <count> (<boolean-expression>)` form. The renderer in this same
        # package quotes that documentation at length, and a test asserted the
        # OPPOSITE of it, so the file contradicted itself about the same syntax.
        #
        # Why the reinterpretation is not a convenience: `head 5 host` and
        # `| sort host | head 5` return DIFFERENT EVENTS. The first takes the
        # first five in search order; the second reorders by host first and takes
        # five of those. A mistyped or mis-remembered argument would produce a
        # plausible, deployable, differently-behaving rule with nothing said --
        # which is the one outcome this project refuses everywhere else.
        #
        # So the two-stage form is spelled with SORT, which is where it belongs:
        # `| sort host | head 5`. `| head 5` alone stays valid and means "the
        # first 5 in search order", which is exactly what Splunk does with it.
        if index < len(tokens):
            raise SplParseError(
                "SPL_HEAD_TAKES_NO_FIELD",
                f"`head` takes a count and nothing else -- Splunk's syntax is "
                f"`head [keeplast] [while \"<expr>\"] [<limit>]`, with no field "
                f"and no sort-order argument. So `head {args}` is not valid SPL, "
                f"and it is refused rather than read as an ordering: sorting by "
                f"{tokens[index]} first and then taking {limit} returns "
                f"DIFFERENT events than the first {limit} in search order. Write "
                f"the two stages as `| sort {tokens[index]} | head {limit}`.",
                dialect)


    order: list[tuple[FieldRef, str]] = []

    while index < len(tokens):
        token = tokens[index]
        direction = "asc"
        if token.startswith("-"):
            direction, token = "desc", token[1:]
        elif token.startswith("+"):
            token = token[1:]
        # `sort [<count>] <fields>` -- THE COUNT WAS BEING PARSED AND DISCARDED.
        #
        # Splunk's syntax is `sort [<count>] [-|+]<field> [...]`, and the count
        # limits how many results come back. The digit branch below used to do
        # `index += 1; continue` -- it walked past the token and never read it --
        # so:
        #
        #     | sort 5 host   ->   Arrange(limit=None)   ->   | sort +host
        #
        # Five results requested, every result returned, `ok=True`, no finding.
        # The comment only ever justified the `0` case ("0 means no limit"), and
        # generalising it to non-zero counts is where the result set silently
        # widened. Now it is read, and `0` keeps meaning "no limit" because
        # Splunk says so.
        if token.isdigit():
            # `0` IS SPLUNK'S "NO LIMIT", SO IT BECOMES `None` AND NOT A CAP OF
            # ZERO. A cap of 0 would render as `head 0` and return nothing.
            if limit is None and int(token) > 0:
                limit = int(token)
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

    #: Set by the `dedup` branch and consumed AFTER the loop, because whether a
    #: `dedup` is the LAST pipeline stage is not knowable from inside the loop.
    _pending_dedupe_by: tuple[FieldRef, ...] | None = None
    _pending_dedupe_position: int = -1

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
        elif command.name == "dedup":
            # `dedup` COLLAPSES ROWS, which `Emit.dedupe_by` already models --
            # so this needs no new IR node. It does need the dedup to be the LAST
            # stage, because `Emit` is the graph's terminal: there is nowhere to
            # put a de-duplicating node in the middle of a chain. A `dedup`
            # followed by anything else is refused by name, with the reason,
            # rather than silently moving the dedup to the end -- which would
            # drop rows at a different point and return a different set.
            #
            # `_pending_dedupe_by` is checked after the loop, because whether
            # this is the last command is not knowable until the loop is done.
            if _pending_dedupe_by is not None:
                raise SplParseError(
                    "SPL_DEDUP_NOT_TERMINAL",
                    "two `dedup` stages. The second would collapse rows the "
                    "first had already decided to keep, in a different order, "
                    "so which rows survive is not something RuleForge will "
                    "guess.", DIALECT)
            fields = [f.strip() for f in command.args.split(",") if f.strip()]
            if not fields:
                raise SplParseError("SPL_DEDUP_NO_FIELDS",
                                    "`dedup` with no field list keeps every "
                                    "row, which is a no-op. Refused rather than "
                                    "rendered as one.", DIALECT)
            for name in fields:
                if not _FIELD_NAME.fullmatch(name):
                    raise SplParseError(
                        "SPL_DEDUP_FIELD_NOT_A_NAME",
                        f"`dedup {name}` is not a plain field name. "
                        f"De-duplicating by a different field keeps a different "
                        f"set of events.", DIALECT)
            _pending_dedupe_by = tuple(FieldRef(name) for name in fields)
            _pending_dedupe_position = position
        elif command.name == "fillnull":
            # REFUSED, AND THE REASON IS THE IR RATHER THAN THE PARSER. There is
            # no node for "fill an empty value": the vocabulary above is the
            # complete list, and nothing in it can express a default. `fillnull`
            # also changes which rows a LATER term matches -- filling an empty
            # field makes `where value=0` match a row that otherwise would not --
            # so dropping it would quietly widen the rule. Named here rather than
            # left to fall through to the generic unknown-command message,
            # because the reason is specific and actionable.
            raise SplParseError(
                "SPL_FILLNULL_NOT_LOWERABLE",
                f"`fillnull {command.args}` gives an empty field a value, and "
                f"there is no node in RuleForge's vocabulary for that. It is "
                f"also not safe to ignore: filling an empty field makes a LATER "
                f"`where` match rows that would otherwise not match, so dropping "
                f"it would quietly widen the rule. Rewrite the term to treat "
                f"the empty case explicitly, for example "
                f"`| where coalesce({command.args.split('=')[0].strip()}, 0) > 0`.",
                DIALECT)
        elif command.name in ("head", "sort", "rename", "fields"):
            # UNREACHABLE, AND THAT IS THE POINT. THE COMMENT THAT WAS HERE IS
            # GONE, AND THIS IS WHY.
            #
            # This arm carried 26 lines explaining why "regex" and "eval" were
            # refused, in a branch that CANNOT RUN: the branch above already
            # catches all four of these names, so control never arrives here. It
            # documented a diagnostic that no longer exists, on a path that never
            # executes, and a reader would reasonably have believed it described
            # live behaviour. A comment explaining dead code is a comment nobody
            # can act on; the history lives in the commit that changed the
            # behaviour and in tests/test_spl.py.
            #
            # IF YOU ARE HERE, either a name was added to the branch above
            # without being handled there, or that branch was changed. Both mean
            # this name needs handling up there. Until then, refusing is the
            # honest answer -- silently ignoring a command drops the detection.
            raise SplParseError(
                "SPL_COMMAND_NOT_LOWERABLE",
                f"`{command.name}` changes which rows the search returns, and it "
                f"is not represented in the graph, so it would be dropped from "
                f"the rendered rule. Ignoring a command that selects events once "
                f"produced an artifact that silently returned a different set -- "
                f"in one case the entire detection, with nothing said. Refused "
                f"rather than approximated, because an approximated command is a "
                f"rule you did not write.",
                DIALECT)

        else:
            raise SplParseError(
                "SPL_COMMAND_UNKNOWN",
                f"`{command.name}` is not a command this lowering handles. An "
                f"unrecognised command in a detection rule is usually the part "
                f"carrying the detection, so it is named rather than ignored.",
                DIALECT)

    # A TERMINAL `dedup` rides on the `Emit`, which is the graph's terminal node
    # and already carries `dedupe_by`. An empty tuple is a no-op rather than a
    # change, so nothing else about the Emit moves.
    #
    # TERMINAL IS CHECKED HERE, not in the branch, because the branch cannot know:
    # it runs while the loop is still going and later commands have not been seen
    # yet. Moving a mid-pipeline `dedup` to the end would collapse rows at a
    # different point in the pipeline and return a different set of events, so a
    # non-terminal one is refused rather than relocated.
    if (_pending_dedupe_by is not None
            and _pending_dedupe_position != len(search.pipeline) - 1):
        raise SplParseError(
            "SPL_DEDUP_NOT_TERMINAL",
            "`dedup` is not the last stage. RuleForge models de-duplication on "
            "the graph's terminal node, so a `dedup` in the middle would have to "
            "be moved to the end -- and collapsing rows at a different point in "
            "the pipeline returns a different set of events. Put `dedup` last.",
            DIALECT)
    nodes.append(Emit(id="out", input=current,
                      dedupe_by=_pending_dedupe_by or ()))
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


def _split_top_level(text: str, keyword: str) -> list[str]:
    """Split `text` on `keyword`, but ONLY at paren depth 0 and outside a string.

    The plain `text.split(" AND ")` this replaces was wrong three ways at once,
    and each one changes which rows a detection matches:

      - PRECEDENCE. The old loop tried `" AND "` FIRST and returned immediately,
        so AND ended up the OUTERMOST operator:
            a=1 OR b=2 AND c=3   ->   ((a=1 OR b=2) AND c=3)
        SPL, like SQL, binds AND tighter than OR, so that expression is
        `a=1 OR (b=2 AND c=3)`. The built tree MISSES a row where a=1 and
        nothing else holds -- a false NEGATIVE, which is the worst direction a
        detection rule can be wrong in.
      - PARENTHESES. `a=1 OR (b=2 AND c=3)` is correct SPL that the old code
        refused with "'(b=2' is not a comparison", blaming a bare word rather
        than the splitter's blindness.
      - QUOTED STRINGS. `msg="x AND y"` is one comparison whose VALUE contains
        the separator, and the old code split inside the quotes and refused on
        "'y\"' is not a comparison".

    Quote handling covers both `'` and `"`, with a backslash escape, because a
    value containing the other kind of quote is ordinary.
    """
    needle = keyword
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    start = 0
    index = 0
    while index < len(text):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and text.startswith(needle, index):
            before = text[index - 1] if index else " "
            after = text[index + len(needle):index + len(needle) + 1] or " "
            # A WHOLE WORD, and the boundary has to be outside the string too.
            # Without this, `ORANGE` would split on `OR` and the message the
            # analyst wrote about oranges would become a rule about a variable.
            if not before.isalnum() and not after.isalnum():
                parts.append(text[start:index])
                index += len(needle)
                start = index
                continue
        index += 1
    parts.append(text[start:])
    return [part for part in (p.strip() for p in parts) if part]


def _eval_condition(args: str) -> Any:
    """`where` uses the EVAL expression language, not search syntax.

    OR IS SPLIT FIRST, BECAUSE OR BINDS LOOSEST. SPL, like SQL, is
    `NOT` > `AND` > `OR`, so the loosest operator has to be the outermost node in
    the tree. Splitting AND first -- which is what this did, by trying the
    operator tuple in that order and returning on the first hit -- inverted every
    mixed expression and produced false negatives. See `_split_top_level`.
    """
    text = args.strip()
    if not text:
        raise SplParseError("SPL_WHERE_EMPTY", "`where` has no expression", DIALECT)

    upper = text.upper()
    if upper == "TRUE":
        return Literal(value=True)
    if upper == "FALSE":
        return Literal(value=False)

    for keyword, op in (("OR", "or"), ("AND", "and")):
        parts = _split_top_level(text, keyword)
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
    # `span=` ON `stats` IS NOT VALID SPL AT ALL, AND ACCEPTING IT PRODUCED A
    # RENDER THAT DISAGREED WITH THE DIAGNOSTIC BESIDE IT.
    #
    # `span` is a `timechart` argument. `stats` does not take one. The lowerer
    # accepted `| stats count by _time span=1h host`, synthesised a `__bucket__`
    # key, and emitted an INFO finding saying the window was "real rather than
    # ignored". Then the renderer dropped `span=`, kept a bogus `count AS
    # __bucket__` column, and returned ok=True:
    #
    #   in : index=main EventCode=4625 | stats count by _time span=1h host
    #   out: index=main | search EventCode="4625"
    #        | stats count AS count, count AS __bucket__ by _time, host
    #
    # One row per host instead of one row per host per hour, a column that means
    # nothing, and a diagnostic asserting the opposite of what shipped. The
    # renderer had no way to say so: `Frame` is in the IR, but there is no SPL
    # `stats` spelling of a tumbling window to render it into.
    #
    # So the refusal is HERE, where the invalid syntax is read, rather than at
    # render time. `timechart` is the command that buckets time; it also FILLS
    # gaps with zero, which is not what `stats` does, so translating one into the
    # other would silently change the report. Naming it is the honest answer.
    # GATED ON `stats` SO `tstats` STILL GETS ITS OWN, MORE SPECIFIC REFUSAL.
    # The `tstats` example in the docs carries `span=1h`, and `tstats` is
    # refused at line 855 for the stronger reason that it reads index-time
    # fields no sample can reproduce. Letting the span check fire first replaced
    # that with a message about syntax, which is a worse answer to a worse
    # question. The most specific true refusal wins.
    if stats.span and command.name == "stats":
        raise SplParseError(
            "SPL_STATS_SPAN_NOT_VALID",
            f"`span=` is a `timechart` argument, not a `stats` one, so this is "
            f"not valid SPL. It is refused rather than approximated: the "
            f"tumbling window it describes has no `stats` spelling, and "
            f"`timechart` -- which does -- also fills gaps with zero, so "
            f"translating would quietly change which rows come back. Write the "
            f"bucketed query as `| timechart span={stats.span} count by ...`, or "
            f"bucket the time field yourself before the `stats`.",
            DIALECT)
    # a span every event lands in one bucket, which is a different report.
    if any(k.full == time_field for k in keys):
        raise SplParseError(
            "SPL_TIME_BUCKET_WITHOUT_SPAN",
            f"the rule groups by {time_field} with no span=. Splunk requires "
            f"a span when grouping by time, and without one every event "
            f"collapses into a single bucket -- a different report from the "
            f"one the author asked for.", DIALECT)


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

    if stats.from_clause:
        # THE `stats` SPELLING OF THE SAME CONSTRUCT `tstats` IS REFUSED FOR.
        #
        #     index=main | stats count FROM my_datamodel
        #     ->  index=main | stats count AS count          ok=True, findings=[]
        #
        # A data model is a saved query, not a table. RuleForge evaluates against
        # the events it was given, so reading one is not reproducible from a
        # sample -- which is the whole thesis of this module's docstring, and the
        # reason `tstats` gets named at line 855. The `stats` spelling of the very
        # same clause was accepted and dropped, so the rule silently ran against a
        # different dataset than the analyst wrote.
        #
        # `from_clause` used to be read by the parser and then referenced ONLY
        # inside the `tstats` error message. So the construct was understood well
        # enough to explain it in one command and not in the other.
        raise SplParseError(
            "SPL_STATS_FROM_NOT_LOWERABLE",
            f"a data model is a saved query, not a table, so `stats ... FROM "
            f"{stats.from_clause}` cannot be evaluated against the events "
            f"RuleForge was given -- the rule would run against a different "
            f"dataset than the one written. Refused by name, the same way "
            f"`tstats` is. Run it in Splunk, or point the rule at the underlying "
            f"fields.", DIALECT)
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
