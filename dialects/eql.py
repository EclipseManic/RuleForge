"""Elastic EQL, slice 1: a single event query, honestly.

A single `[ category where condition ]` is genuinely just a filter, and lowers
onto nodes that already exist: `Read` -> `Filter` -> `Emit`. That is the whole
of this file's ambition, and it is stated up front because the value of EQL is
overwhelmingly its sequences -- every real detection written in it is a
`sequence` or a `sample` -- so parsing one event while refusing the rest is the
easy 5% and must say so.

`sequence`, `sample`, `join`, `pipe` (`|`) and `until` are recognised HERE, at
parse time, and refused by name with the reason and the missing piece, rather
than falling through to a generic "unknown syntax" message. The IR already has
`Pattern` (stages, within, key, ordered, until with `until_scope`), so these
refusals are "not yet lowered", not "cannot be expressed" -- except `runs=N`
and the `!` missing-event clause, which have no node at all. See
`docs/eql-design.md` for the construct-by-construct mapping.
"""

from __future__ import annotations

from dataclasses import dataclass

from engine.values import Refusal

DIALECT = "eql"
LANGUAGE = "Elastic EQL"


@dataclass(frozen=True, slots=True)
class EqlEvent:
    """One `[ category where condition ]`."""
    category: str
    condition: str


@dataclass(frozen=True, slots=True)
class EqlSequenceStep:
    """One `[ category where condition ] [by ...]` inside a sequence."""
    category: str
    condition: str
    by: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EqlSequence:
    """A `sequence [by ...] [with maxspan=...|with runs=...] steps... [until ...]`."""
    by: tuple[str, ...]
    maxspan: str | None
    steps: tuple[EqlSequenceStep, ...]
    until: EqlSequenceStep | None
    #: `with runs=N`. Only `1` lowers -- one run IS the pattern, so there is
    #: nothing to repeat. Anything higher needs a repeat count `Pattern` does
    #: not have, and is refused where it is parsed.
    runs: int | None = None


@dataclass(frozen=True, slots=True)
class EqlSample:
    """A `sample by k1, k2 steps...` -- unordered events sharing join keys.

    At least one `by` key (EQL requires it) and at most five filters (EQL caps
    it). No `maxspan`, no `until`, no `runs`: `sample` takes none of those, so
    any of them here is a syntax error rather than a refused feature.
    """
    by: tuple[str, ...]
    steps: tuple[EqlSequenceStep, ...]


@dataclass(frozen=True, slots=True)
class EqlQuery:
    """Slice 1 parses single events; slice 2 adds sequences; sample is here."""
    event: EqlEvent | None = None
    sequence: EqlSequence | None = None
    sample: EqlSample | None = None


def _parse_sample(text: str) -> EqlSample:
    """Parse `sample by k1, k2 [cat where cond] ...`.

    `sample` shares the step syntax with `sequence` -- categories, conditions,
    the 5-filter cap -- but not the window machinery. There is deliberately no
    `maxspan`/`until`/`runs` handling here: EQL does not allow them on `sample`,
    so accepting any would be inventing syntax, not lowering it.
    """
    rest = text[len("sample"):].strip()
    if not rest.lower().startswith("by "):
        raise Refusal(
            "EQL_SAMPLE_NEEDS_BY",
            "`sample` requires at least one `by` join key -- without shared "
            "keys it is just unrelated events, which is a no-op disguised as "
            "a rule. Refused rather than rendered as one.", DIALECT)
    segment, _, rest = rest.partition("[")
    by = tuple(f.strip() for f in segment[3:].split(",") if f.strip())
    if not by:
        raise Refusal("EQL_SAMPLE_BY_EMPTY",
                      "`sample by` with no fields joins on nothing.", DIALECT)
    for name in by:
        if not all(part.isidentifier() for part in name.split(".")):
            raise Refusal("EQL_JOIN_KEY_NOT_A_NAME",
                          f"`{name}` is not a plain dotted field name.",
                          DIALECT)
    rest = "[" + rest
    steps = _parse_steps(rest)
    if not steps:
        raise Refusal("EQL_SAMPLE_NO_STEPS",
                      "`sample` with no event steps matches nothing.", DIALECT)
    if len(steps) > 5:
        raise Refusal(
            "EQL_SAMPLE_TOO_MANY_FILTERS",
            f"`sample` takes at most 5 filters and this has {len(steps)}. The "
            f"6th would silently not filter, so it is refused rather than "
            f"truncated.", DIALECT)
    return EqlSample(by=by, steps=tuple(steps))


#: The event categories Elastic documents. `any` matches every category.
CATEGORIES = frozenset({
    "file", "process", "network", "authentication", "library",
    "registry", "dns", "any",
})


def parse_eql(text: str) -> EqlQuery:
    """Parse a single-event EQL query, or refuse by name."""
    stripped = text.strip()
    if not stripped:
        raise Refusal("EQL_EMPTY", "nothing to parse", DIALECT)

    head = stripped.split(None, 1)
    keyword = head[0].lower() if head else ""
    # `sequence`, `sample` and friends are RECOGNISED, not unknown. Each refusal
    # names the construct and the missing piece, because "not yet lowered" and
    # "cannot be expressed" are different answers and the analyst is owed the
    # true one.
    if keyword == "sequence":
        return EqlQuery(sequence=_parse_sequence(stripped))
    if keyword == "sample":
        return EqlQuery(sample=_parse_sample(stripped))

    # A `|` ANYWHERE at the top level is pipe syntax, not just a first word
    # literally reading "pipe". `[file where true] | head 5` starts with `[`,
    # so the keyword check above never fires and it fell through to the generic
    # "not a single event" message. Same for a leading `until`, which is a
    # sequence tail without its sequence. Both are recognised here because the
    # module docstring already claims they are -- and a docstring claiming a
    # refusal exists when it does not is the same false-claim class as
    # everything else this project deletes.
    if _has_top_level_pipe(stripped):
        raise Refusal(
            "EQL_PIPE_NOT_LOWERED",
            "this uses `|` pipes, which chain commands the way SPL does. Only "
            "single events and `sequence` lower today. Refused by name rather "
            "than read as either half.", DIALECT)
    if keyword == "until":
        raise Refusal(
            "EQL_UNTIL_WITHOUT_SEQUENCE",
            "`until [...]` is a sequence tail without its sequence. It expires "
            "a sequence that is not here, so there is nothing to attach it to. "
            "Write the full `sequence ... until ...`.", DIALECT)
    if keyword in ("join", "pipe"):
        raise Refusal(
            "EQL_JOIN_NOT_LOWERED",
            f"`{keyword}` correlates queries across indices, which has no IR "
            f"node at all -- not `Join` as it exists, which joins two inputs of "
            f"one rule. Refused rather than approximated.", DIALECT)

    if not (stripped.startswith("[") and stripped.endswith("]")):
        raise Refusal(
            "EQL_NOT_A_SINGLE_EVENT",
            "slice 1 parses one `[ category where condition ]` and nothing "
            "else. This does not start with `[` and end with `]`, so it is a "
            "larger query -- most likely a `sequence` or `sample`, which are "
            "refused by name above.", DIALECT)

    inner = stripped[1:-1].strip()
    parts = inner.split(None, 2)
    if len(parts) < 3 or parts[1].lower() != "where":
        raise Refusal(
            "EQL_EVENT_NOT_A_WHERE",
            f"an event is `[ category where condition ]`, so the second word "
            f"must be `where`. Got {inner[:60]!r}.", DIALECT)
    category, condition = parts[0].lower(), parts[2].strip()
    if category not in CATEGORIES:
        raise Refusal(
            "EQL_UNKNOWN_CATEGORY",
            f"`{parts[0]}` is not one of the documented event categories "
            f"({', '.join(sorted(CATEGORIES))}). Refused rather than treated "
            f"as `any`, because matching every category is a different rule.",
            DIALECT)
    if not condition:
        raise Refusal("EQL_EMPTY_CONDITION",
                      "`where` with no condition matches everything, which is "
                      "a no-op disguised as a rule. Refused rather than "
                      "rendered as one.", DIALECT)
    return EqlQuery(event=EqlEvent(category=category, condition=condition))


def _has_top_level_pipe(text: str) -> bool:
    """True if `|` appears at bracket depth 0 outside strings.

    A `|` inside a quoted value (`name == "a|b"`) or inside brackets is data,
    not a pipe. Only the top-level one chains commands.
    """
    depth = 0
    quote: str | None = None
    for char in text:
        if quote is not None:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        elif char == "|" and depth == 0:
            return True
    return False


def _split_with_clauses(segment: str) -> list[str]:
    """`with maxspan=15m with runs=1` -> `["maxspan=15m", "runs=1"]`.

    Each clause starts at a top-level `with` (outside strings). Without this,
    the whole segment reads as one clause and `maxspan` becomes the literal
    string "15m with runs=1", which fails duration parsing with a message
    about a duration the analyst never wrote.
    """
    clauses: list[str] = []
    depth = 0
    quote: str | None = None
    start = 0
    index = 0
    lowered = segment.lower()
    while index < len(segment):
        char = segment[index]
        if quote is not None:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        elif depth == 0 and lowered.startswith("with ", index) \
                and (index == 0 or not segment[index - 1].isalnum()):
            if index > start:
                clauses.append(segment[start:index].strip())
            start = index + len("with ")
            index += len("with ")
            continue
        index += 1
    tail = segment[start:].strip()
    if tail:
        clauses.append(tail)
    return [c for c in clauses if c]


def _parse_sequence(text: str) -> EqlSequence:
    """Parse `sequence [by ...] [with maxspan=...|with runs=...] steps [until ...]`.

    `with runs=N`, `!` missing-event steps, and per-step `by` are recognised and
    refused HERE with the construct named, because each changes which sequences
    match and none has a `Pattern` spelling yet. What remains lowers onto
    `Pattern` in `dialects/eql_ir.py`.
    """
    rest = text[len("sequence"):].strip()
    by: tuple[str, ...] = ()
    maxspan: str | None = None
    runs: int | None = None

    # `sequence by f1, f2` -- shared join keys. Consumed before `with`, because
    # Elastic's grammar puts `by` first and a `by` after `with` belongs to a step.
    if rest.lower().startswith("by "):
        # `by` ends at `with`, at `[`, or at the end -- whichever comes first.
        # Taking everything up to `[` swallowed `with maxspan=...` into the
        # join keys, so `sequence by user.name with maxspan=15m` joined on a
        # field literally named "user.name with maxspan=15m".
        segment, _, rest = rest.partition("[")
        with_at = _find_top_level(segment, "with")
        if with_at >= 0:
            # The `with` clause stays in `rest` for the branch below, which
            # re-adds the `[` itself. Prepending one here as well would produce
            # `[with maxspan=...`, which is how a whole afternoon went missing.
            segment, rest = segment[:with_at], segment[with_at:] + "[" + rest
        else:
            rest = "[" + rest
        by = tuple(f.strip() for f in segment[3:].split(",") if f.strip())
        if not by:
            raise Refusal("EQL_SEQUENCE_BY_EMPTY",
                          "`sequence by` with no fields joins on nothing, which "
                          "is a no-op disguised as a rule.", DIALECT)
        for name in by:
            if not all(part.isidentifier() for part in name.split(".")):
                raise Refusal("EQL_JOIN_KEY_NOT_A_NAME",
                              f"`{name}` is not a plain dotted field name. "
                              f"Joining on a different field joins different "
                              f"events.", DIALECT)

    # `with maxspan=...` and/or `with runs=...`, in either order. EQL allows
    # both on one sequence, and they arrive in ONE segment (everything up to
    # the first `[`), so the segment is split into clauses first -- otherwise
    # `maxspan=15m with runs=1` reads as a duration literally named
    # "15m with runs=1".
    while rest.lower().startswith("with "):
        segment, _, rest = rest.partition("[")
        for clause in _split_with_clauses(segment):
            if clause.lower().startswith("maxspan="):
                if maxspan is not None:
                    raise Refusal("EQL_MAXSPAN_TWICE",
                                  "`with maxspan=` twice joins nothing new; the "
                                  "second is refused rather than silently kept "
                                  "alongside the first.", DIALECT)
                maxspan = clause[len("maxspan="):].strip()
                if not maxspan:
                    raise Refusal("EQL_MAXSPAN_EMPTY",
                                  "`with maxspan=` with no duration bounds "
                                  "nothing.", DIALECT)
            elif clause.lower().startswith("runs="):
                # `with runs=1` MEANS "MATCH ONCE", WHICH IS THE PATTERN ITSELF.
                #
                # `runs=N` requires N consecutive repeats, and `Pattern` has no
                # repeat count -- but `runs=1` requires exactly one run, which is
                # what a plain sequence already is. So 1 is accepted and carried
                # through (the lowerer ignores it, because one run needs no extra
                # semantics), and only 2+ is refused. A non-integer is refused too,
                # because a repeat count that is not a number is not a count.
                raw = clause[len("runs="):].strip()
                if not raw.isdigit() or int(raw) < 1:
                    raise Refusal(
                        "EQL_RUNS_NOT_A_COUNT",
                        f"`with runs={raw}` is not a positive integer, so it "
                        f"cannot count repeats. Refused rather than guessed.",
                        DIALECT)
                if int(raw) > 1:
                    raise Refusal(
                        "EQL_RUNS_NOT_LOWERED",
                        f"`with runs={raw}` requires {raw} consecutive repeats "
                        f"of the pattern, and `Pattern` has no repeat count. "
                        f"Refused rather than matched once.", DIALECT)
                runs = 1
            else:
                raise Refusal("EQL_WITH_UNKNOWN",
                              f"`with {clause}` is not `maxspan=` or `runs=`. "
                              f"Refused rather than guessed.", DIALECT)
        rest = "[" + rest

    # `until [...]` trails the steps. Split it off before parsing steps so a
    # `]` inside the until condition cannot confuse the step splitter.
    until: EqlSequenceStep | None = None
    until_at = _find_top_level(rest, "until")
    if until_at >= 0:
        steps_text, until_text = (rest[:until_at],
                                  rest[until_at + len("until"):])
        until = _parse_step(until_text.strip(), allow_bang=False,
                            context="until")
        rest = steps_text

    steps = _parse_steps(rest)
    if not steps:
        raise Refusal("EQL_SEQUENCE_NO_STEPS",
                      "`sequence` with no event steps matches nothing.",
                      DIALECT)
    return EqlSequence(by=by, maxspan=maxspan, steps=tuple(steps), until=until,
                       runs=runs)


def _find_top_level(text: str, keyword: str) -> int:
    """Index of `keyword` at bracket depth 0 outside strings, or -1."""
    depth = 0
    quote: str | None = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote is not None:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        elif depth == 0 and text[index:index + len(keyword)].lower() == keyword:
            before = text[index - 1] if index else " "
            after = text[index + len(keyword):index + len(keyword) + 1] or " "
            if not before.isalnum() and not after.isalnum():
                return index
        index += 1
    return -1


def _parse_steps(text: str) -> list:
    """Split top-level `[...]` blocks into steps, KEEPING what is around them.

    A `!` before a `[` and a `by ...` after a `]` are OUTSIDE the brackets, so
    a splitter that only looks inside `[...]` drops them silently -- and a
    dropped `!` inverts the rule while a dropped `by` un-joins it. The text
    before each `[` and after each `]` is therefore carried into `_parse_step`,
    which refuses both by name.
    """
    steps: list = []
    depth = 0
    quote: str | None = None
    start = -1
    segment_start = 0
    for index, char in enumerate(text):
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "[":
            if depth == 0:
                start = index
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0 and start >= 0:
                # The segment runs from the end of the previous step (or the
                # start of the text) to the end of this block, so a leading
                # `!` and a trailing `by ...` survive to be refused by name.
                # Pure whitespace between steps is fine and ignored.
                segment = text[segment_start:index + 1]
                steps.append(_parse_step(segment, allow_bang=True,
                                         context="sequence"))
                segment_start = index + 1
                start = -1
    trailing = text[segment_start:].strip()
    if depth != 0 or trailing:
        raise Refusal("EQL_SEQUENCE_MALFORMED",
                      "the sequence steps do not parse as `[...]` blocks.",
                      DIALECT)
    if not steps and text.strip():
        raise Refusal("EQL_SEQUENCE_MALFORMED",
                      "the sequence steps do not parse as `[...]` blocks.",
                      DIALECT)
    return steps



def _find_step_close(body: str) -> int:
    """Index of the `[`-matching `]`, skipping quoted regions.

    The step splitter that calls this is quote-aware when FINDING blocks, but
    this used to take `body.index("]")` -- the first one, even inside a string.
    So `[file where name == "]" ]` truncated the condition at the string's
    bracket and misread the rest as a `by` trailer, refusing with
    EQL_PER_STEP_BY_NOT_LOWERED for a rule with no `by` in it. Same bug, one
    layer down from the splitter that was already fixed.
    """
    quote: str | None = None
    escaped = False
    for index, char in enumerate(body):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "]":
            return index
    return -1


def _parse_step(text: str, allow_bang: bool, context: str):
    """One `[ category where condition ] [by ...]`, or a refused `![ ... ]`."""
    body = text.strip()
    if body.lower().startswith("by "):
        # A per-step `by` that the splitter left dangling: it follows a `]`,
        # so it arrives here as its own segment rather than as a trailer. Same
        # refusal as the trailer form, because it is the same construct -- the
        # reason is at the trailer site, where the fields are in hand.
        raise Refusal(
            "EQL_PER_STEP_BY_NOT_LOWERED",
            "per-step `by` joins values that may live in DIFFERENT fields "
            "between consecutive steps, while `Pattern.key` is one global list "
            "of field names compared by name and so can only express a shared "
            "key. Using it here would join on the wrong fields and over-match. "
            f"Write `{body.strip()}` on the step it belongs to, or use "
            "`sequence by ...` for a shared key.", DIALECT)
    if body.startswith("!"):
        if not allow_bang:
            raise Refusal("EQL_UNTIL_MISSING_EVENT",
                          "`until ![ ... ]` negates the expiry, which the IR "
                          "cannot express. Refused rather than dropped.",
                          DIALECT)
        raise Refusal(
            "EQL_MISSING_EVENT_NOT_LOWERED",
            "`![ ... ]` matches the ABSENCE of an event, and `Pattern` has no "
            "negative step -- nor does it have anywhere to put the mandatory "
            "`maxspan` that comes with one. Refused rather than dropped, "
            "because dropping a negative step inverts the rule.", DIALECT)
    if not (body.startswith("[") and "]" in body):
        raise Refusal("EQL_STEP_MALFORMED",
                      f"a {context} step is `[ category where condition ]`.",
                      DIALECT)
    close = _find_step_close(body)
    if close < 0:
        raise Refusal("EQL_STEP_MALFORMED",
                      f"a {context} step is `[ category where condition ]`.",
                      DIALECT)
    inner, trailer = body[1:close].strip(), body[close + 1:].strip()
    parts = inner.split(None, 2)
    if len(parts) < 3 or parts[1].lower() != "where":
        raise Refusal("EQL_EVENT_NOT_A_WHERE",
                      "an event is `[ category where condition ]`.", DIALECT)
    category = parts[0].lower()
    if category not in CATEGORIES:
        raise Refusal(
            "EQL_UNKNOWN_CATEGORY",
            f"`{parts[0]}` is not one of the documented event categories.",
            DIALECT)
    if trailer:
        # PER-STEP `by` HAS NO `Pattern` SPELLING, AND THE VENDOR SAYS WHY.
        # Elastic's EQL reference: "Use the `by` keyword in a sequence query to
        # only match events that share the same values, EVEN IF THOSE VALUES ARE
        # IN DIFFERENT FIELDS. These shared values are called join keys." So
        # `[a where ...] by user.name [b where ...] by user.id` joins the FIRST
        # step's `user.name` to the SECOND's `user.id` -- two DIFFERENT field
        # names, matched pairwise by POSITION.
        #
        # `Pattern.key` is `tuple[FieldRef, ...]`, a single global list compared
        # by field NAME, so it can only ever express "same name in every step".
        # Faking the per-step case with a global key would join on the wrong
        # fields: the two would agree only when both steps happen to name the
        # same field, and would silently over-match in every other case.
        #
        # The IR would need a per-stage key list (a list of PAIRS, or a list of
        # per-stage field tuples) before this is honest -- and a half-measure
        # here is worse than the refusal, because a rule that joins on the wrong
        # field is a rule that matches things nobody asked it to match.
        raise Refusal(
            "EQL_PER_STEP_BY_NOT_LOWERED",
            "per-step `by` matches shared values even when they are in "
            "DIFFERENT fields (Elastic's own words: \"even if those values are "
            "in different fields\"), so this step joins "
            f"{trailer.split()[1:]} by POSITION against the previous step's "
            "fields. `Pattern.key` is one global list of field names compared "
            "by name, which can only express a shared key -- using it here "
            "would join on the wrong fields and over-match. Use "
            "`sequence by ...` for a shared key, or a single `by` naming the "
            "same field on every step.", DIALECT)
    return EqlSequenceStep(category=category, condition=parts[2].strip())
