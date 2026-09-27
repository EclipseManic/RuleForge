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
class EqlQuery:
    """Slice 1 only parses single events. Anything else is refused."""
    event: EqlEvent


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
        raise Refusal(
            "EQL_SEQUENCE_NOT_LOWERED",
            "`sequence` matches an ordered series of events, which lowers onto "
            "the IR's `Pattern` node -- but that lowering is not written yet. "
            "`Pattern` has stages, within, key, ordered and until, so the "
            "mapping exists; only the code does not. A single "
            "`[ category where condition ]` does lower today.", DIALECT)
    if keyword == "sample":
        raise Refusal(
            "EQL_SAMPLE_NOT_LOWERED",
            "`sample` matches an unordered set of events sharing join keys, "
            "which is `Pattern` with `ordered=False` -- but that lowering is "
            "not written yet. A single `[ category where condition ]` does "
            "lower today.", DIALECT)
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
