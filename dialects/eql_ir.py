"""Lower EQL slice 1 onto the IR: `[ category where condition ]` is a filter.

The category becomes the read's `SourceSelector` -- it says which events are
searched, the way an index does -- and the condition becomes a `Filter`. No new
nodes, no approximations. `sequence` and `sample` never reach here; they are
refused in `dialects/eql.py` with the construct named.

The condition language here is the honest subset: comparisons, `and`/`or`/`not`
with NOT > AND > OR precedence, parentheses, quoted strings, numbers, dotted
field names, and `true`. Everything else -- the `:` wildcard operator, `like`,
`in (...)`, and every function (`stringContains`, `startsWith`, ...) -- is
refused BY NAME, because each of those changes which rows match and guessing at
any of them is a different rule.

The boolean structure mirrors `dialects/spl_ir.py::_split_top_level`, and that
is stated rather than hidden: two precedence-aware, quote-aware, paren-aware
splitters for two languages with different leaf syntax. If a third appears, that
is the moment to share one.
"""

from __future__ import annotations

from typing import Any

from dialects.eql import DIALECT, EqlQuery
from engine.ir import (
    BoolOp,
    Comparison,
    Duration,
    Emit,
    FieldExpr,
    FieldRef,
    Filter,
    Literal,
    Not,
    Pattern,
    Read,
    RuleIR,
    SourceSelector,
)
from engine.values import Refusal


def lower(query: EqlQuery, rule_id: str = "rule") -> tuple[RuleIR, list[dict]]:
    """A single event -> `Read` -> `Filter` -> `Emit`; a sequence or a sample
    -> `Pattern`."""
    if query.sequence is not None:
        return _lower_sequence(query.sequence, rule_id)
    if query.sample is not None:
        return _lower_sample(query.sample, rule_id)
    event = query.event
    assert event is not None
    condition = _condition(event.condition)
    nodes = (
        Read(id="read", selector=SourceSelector(name=event.category)),
        Filter(id="filter", input="read", condition=condition),
        Emit(id="out", input="filter"),
    )
    return (RuleIR(rule_id=rule_id, nodes=nodes, output="out",
                   title=f"[{event.category} where ...]",
                   metadata={"dialect": DIALECT}), [])


def _lower_sequence(sequence, rule_id: str) -> tuple[RuleIR, list[dict]]:
    """`sequence` onto the IR's `Pattern` node.

    The mapping, construct by construct:
      steps            -> `stages`, each step's condition parsed as one stage
      `with maxspan=`  -> `within`, measured from the first event
      `sequence by`    -> `key`, the shared join keys
      `until`          -> `until` with `until_scope="between"`, which is EQL's
                          rule: an expiry between matches expires the sequence,
                          one after it does not
      ordering         -> `ordered=True` with `time_field="@timestamp"`, which
                          is Elasticsearch's implicit event time rather than a
                          guess -- it is what the engine stamps every event with
    """
    if sequence.maxspan is None:
        # NO UNBOUNDED SPELLING EXISTS. `Pattern.within` is required, and using
        # 0 for "no bound" would mean "same timestamp", which is a different
        # rule. EQL allows a sequence with no `maxspan`; the IR cannot express
        # one yet, so it is refused rather than bounded silently.
        raise Refusal(
            "EQL_SEQUENCE_NEEDS_MAXSPAN",
            "`sequence` with no `with maxspan=` has no time bound, and "
            "`Pattern.within` is required -- there is no unbounded spelling. "
            "Add `with maxspan=<duration>`; without one the window is "
            "undefined and any bound RuleForge invented would be a different "
            "rule.", DIALECT)
    stages = tuple((_stage_condition(step),) for step in sequence.steps)
    key = tuple(FieldRef(name) for name in sequence.by)
    until = None
    if sequence.until is not None:
        # The category is folded in here too, for the same reason as the
        # stages: rendering `until [any where ...]` for an `until [process
        # where ...]` would silently widen the expiry.
        until = _stage_condition(sequence.until)
    # A TRAILING `![ ... ]` IS THE `until` VETO, AND THE WINDOW SCOPE IS RIGHT.
    # "A process event happened and no exit event followed, inside maxspan" is
    # the same claim as `until`, expressed as a step: no row in the window may
    # satisfy the condition. So the trailing negative step lowers onto the same
    # mechanism, and `until_scope` is the WINDOW scope rather than EQL's
    # "between" -- the veto genuinely ranges over the whole window, which is the
    # point of a missing-event step. A "between" scope would let an exit event
    # after the sequence completed pass straight through, which is the opposite
    # of what `![ ... ]` means.
    #
    # A NEGATIVE STEP ANYWHERE ELSE IS REFUSED, and the reason is structural: a
    # negative step in the MIDDLE would need a window anchored at the preceding
    # positive step, and `Pattern` has one window for the whole pattern. Emitting
    # a veto over the wrong range would match MORE than the analyst wrote.
    negatives = [index for index, step in enumerate(sequence.steps)
                 if step.negative]
    negative_stages: tuple[int, ...] = ()
    if negatives:
        last = len(sequence.steps) - 1
        if negatives != [last]:
            raise Refusal(
                "EQL_MISSING_EVENT_MUST_BE_LAST",
                f"a `![ ... ]` step must be the LAST step of a sequence. One at "
                f"position {negatives[0]} would need its own time window, "
                f"anchored at the step before it, and this rule has a single "
                f"`maxspan` for the whole pattern -- so a middle `!` would be "
                f"checked over the wrong range and would match events the "
                f"analyst never excluded. Refused rather than widened.", DIALECT)
        if until is not None:
            raise Refusal(
                "EQL_MISSING_EVENT_AND_UNTIL_BOTH",
                "this sequence has both a trailing `![ ... ]` and an `until "
                "[...]`. Both veto, over the same window, and the rule does not "
                "say which wins when they disagree. Refused rather than "
                "picking one -- dropping either changes which rows match.",
                DIALECT)
        if negatives[0] == 0:
            raise Refusal(
                "EQL_MISSING_EVENT_CANT_BE_FIRST",
                "a sequence cannot START with `![ ... ]`: there would be "
                "nothing for the missing event to be missing FROM. Refused "
                "rather than matched, which would invert the rule.", DIALECT)
        until = _stage_condition(sequence.steps[last])
        # THE STAGE STAYS IN `stages`, marked negative. Removing it would leave
        # one stage, which `Pattern` refuses (`PATTERN_NEEDS_TWO_STAGES`) --
        # correctly, since "a process happened and no exit followed" is a
        # two-part rule. Keeping it and marking its polarity gives the stage its
        # place in the sequence's shape without requiring it to occur.
        negative_stages = (last,)
    nodes = (
        Read(id="read", selector=SourceSelector(name="any")),
        Pattern(id="pattern", input="read", stages=stages,
                within=Duration(_span_seconds(sequence.maxspan)),
                key=key, until=until,
                until_scope="window" if negatives else "between",
                ordered=True, time_field="@timestamp",
                negative_stages=negative_stages,
                # `runs=N` -> `Pattern.runs`, which the evaluator READS. The
                # absent clause is `None` here and 1 on the node, so a rule with
                # no `runs` gets the identical default YARA-L always had.
                runs=1 if sequence.runs is None else sequence.runs),
        Emit(id="out", input="pattern"),
    )
    return (RuleIR(rule_id=rule_id, nodes=nodes, output="out",
                   title=f"sequence of {len(stages)} events",
                   metadata={"dialect": DIALECT}), [])


def _lower_sample(sample, rule_id: str) -> tuple[RuleIR, list[dict]]:
    """`sample by keys steps...` onto `Pattern` with `ordered=False`.

    The mapping: stages from the steps (categories folded in, exactly as for
    sequences), `key` from `by`, `ordered=False`, `within=None` (no time bound
    -- EQL samples can run on data with no timestamp at all), and no `until`
    (EQL does not allow one on `sample`). `time_field` stays unset because an
    unordered pattern needs none, and guessing one would order the match by an
    unrelated column.
    """
    stages = tuple((_stage_condition(step),) for step in sample.steps)
    key = tuple(FieldRef(name) for name in sample.by)
    nodes = (
        Read(id="read", selector=SourceSelector(name="any")),
        Pattern(id="pattern", input="read", stages=stages, within=None,
                key=key, until=None, ordered=False),
        Emit(id="out", input="pattern"),
    )
    return (RuleIR(rule_id=rule_id, nodes=nodes, output="out",
                   title=f"sample of {len(stages)} events by "
                         f"{', '.join(sample.by)}",
                   metadata={"dialect": DIALECT}), [])


def _stage_condition(step) -> Any:
    """A sequence step's condition, WITH its category folded in.

    `[ file where X ]` means "a file event satisfying X". Every ECS event
    carries `event.category`, so the category IS a condition on that field --
    not metadata about the query, and not something the renderer may drop.
    Rendering the step back reads it back out, so the round trip is exact and
    `any` never silently widens a rule that named a category.
    """
    condition = _condition(step.condition)
    if step.category == "any":
        return condition
    return BoolOp("and", (Comparison("=", FieldExpr(FieldRef("event.category")),
                                     Literal(step.category)),
                          condition))


def _span_seconds(span: str) -> int:
    """`30s`, `15m`, `1h`, `7d` -> seconds. Anything else is refused, because a
    guessed unit is a guessed window."""
    match = span.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if len(match) >= 2 and match[-1] in units and match[:-1].isdigit():
        return int(match[:-1]) * units[match[-1]]
    raise Refusal("EQL_MAXSPAN_NOT_A_DURATION",
                  f"`{span}` is not a duration like `30s`, `15m`, `1h` or "
                  f"`7d`. Refused rather than guessed, because the wrong unit "
                  f"is a different window.", DIALECT)


def _condition(text: str) -> Any:
    """Parse an EQL boolean condition with NOT > AND > OR precedence."""
    or_parts = _split_top_level(text, "or")
    if len(or_parts) > 1:
        return BoolOp("or", tuple(_condition(p) for p in or_parts))
    and_parts = _split_top_level(text, "and")
    if len(and_parts) > 1:
        return BoolOp("and", tuple(_condition(p) for p in and_parts))
    body = text.strip()
    negated = False
    while body.lower().startswith("not "):
        negated = not negated
        body = body[4:].strip()
    node = _comparison(body)
    return Not(node) if negated else node


def _split_top_level(text: str, keyword: str) -> list[str]:
    """Split on `keyword` only at paren depth 0, outside strings, whole words.

    `ORANGE` contains `or`; a message about oranges must not become a rule
    about a variable. `msg="x and y"` is one comparison whose value contains
    the word. Both are asserted, because both have happened in this codebase
    before -- in SPL, where the same splitter shape was built for the same
    reasons.
    """
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
        elif depth == 0 and text[index:index + len(keyword)].lower() == keyword:
            before = text[index - 1] if index else " "
            after = text[index + len(keyword):index + len(keyword) + 1] or " "
            if not before.isalnum() and before != "." \
                    and not after.isalnum() and after != ".":
                parts.append(text[start:index])
                index += len(keyword)
                start = index
                continue
        index += 1
    parts.append(text[start:])
    return [p for p in (part.strip() for part in parts) if p]


def _comparison(text: str) -> Any:
    """One `field op value`, or `true`, or a parenthesised condition."""
    body = text.strip()
    if not body:
        raise Refusal("EQL_EMPTY_CONDITION", "`where` has no expression",
                      DIALECT)
    if body.lower() == "true":
        return Literal(value=True)
    if body.startswith("(") and body.endswith(")"):
        return _condition(body[1:-1])
    # Refused by name, because each changes which rows match:
    for marker, code, what in (
            (":", "EQL_WILDCARD_NOT_LOWERED",
             "the `:` wildcard operator matches substrings and globs"),
            (" like ", "EQL_LIKE_NOT_LOWERED",
             "`like` matches `*` and `?` globs"),
            (" in ", "EQL_IN_NOT_LOWERED",
             "`in (...)` tests membership in a list"),
            ("(", "EQL_FUNCTION_NOT_LOWERED",
             "function calls such as `stringContains(...)`")):
        if marker == "(":
            if "(" in body:
                raise Refusal(code,
                              f"{what}, which is not in the lowered subset. "
                              f"Refused rather than approximated.", DIALECT)
        elif marker in body:
            # The `:` check must not fire on `://` inside a string; the splitter
            # already proved quote-awareness is needed, so strip strings first.
            bare = _without_strings(body)
            if marker.strip() in bare or (marker == ":" and ":" in bare):
                raise Refusal(code,
                              f"{what}, which is not in the lowered subset. "
                              f"Refused rather than approximated.", DIALECT)
    for op in ("==", "!=", ">=", "<=", ">", "<"):
        left, sep, right = body.partition(op)
        if sep:
            field = left.strip()
            if not field or not all(
                    part.isidentifier() for part in field.split(".")):
                raise Refusal(
                    "EQL_FIELD_NOT_A_NAME",
                    f"`{field}` is not a plain dotted field name. Refused "
                    f"rather than guessed.", DIALECT)
            return Comparison("=" if op == "==" else op,
                              FieldExpr(FieldRef(field)),
                              _literal(right.strip()))
    raise Refusal(
        "EQL_NOT_A_COMPARISON",
        f"{body[:60]!r} is not a comparison this lowering handles. `where` "
        f"takes `field op value`, `true`, or a parenthesised expression.",
        DIALECT)


def _without_strings(body: str) -> str:
    """`body` with quoted regions blanked, so operator detection cannot fire
    inside a value."""
    out: list[str] = []
    quote: str | None = None
    escaped = False
    for char in body:
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            out.append(" ")
        elif char in ("'", '"'):
            quote = char
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)


def _literal(text: str) -> Any:
    """A quoted string, a number, or `true`."""
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return Literal(value=text[1:-1])
    if text.lower() == "true":
        return Literal(value=True)
    try:
        return Literal(value=int(text))
    except ValueError:
        pass
    try:
        return Literal(value=float(text))
    except ValueError:
        pass
    raise Refusal("EQL_LITERAL_NOT_A_VALUE",
                  f"{text[:40]!r} is not a quoted string, a number, or `true`. "
                  f"Refused rather than guessed.", DIALECT)
