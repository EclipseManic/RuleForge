"""CrowdStrike FQL, slice 1: a flat API filter, honestly.

FQL is the API filter syntax: `<property>:[operator]<value>`, with `+` for AND,
`,` for OR, and `(...)` for grouping. It lowers to a single `Filter` and
nothing else -- it cannot be half-done, because it is either a filter or a
refusal.

THIS IS NOT CQL. The pipeline language (`field = "value"`, `| table`, `AND` as
a word) is a different grammar with different operators, and the two must never
be accepted by one parser: a string valid in neither would pass, and a string
valid in one would be misread as the other. So anything shaped like CQL is
refused HERE with the confusion named, not left to fail mysteriously later.
"""

from __future__ import annotations

from dataclasses import dataclass

from engine.values import Refusal

DIALECT = "fql"
LANGUAGE = "CrowdStrike FQL"


@dataclass(frozen=True, slots=True)
class FqlTerm:
    """One `property:[operator]value`."""
    prop: str
    operator: str
    value: str


@dataclass(frozen=True, slots=True)
class FqlQuery:
    """Slice 1 parses a flat boolean filter and nothing else."""
    text: str


def parse_fql(text: str) -> FqlQuery:
    """Accept an FQL filter, or refuse -- including CQL shaped input, by name."""
    stripped = text.strip()
    if not stripped:
        raise Refusal("FQL_EMPTY", "nothing to parse", DIALECT)
    # THE TWO LANGUAGES MUST NOT MIX. CQL's `field = "value"`, its pipes, and
    # its word operators are all refused here with the confusion named, because
    # a combined grammar would accept strings valid in neither language.
    lowered = stripped.lower()
    if "|" in stripped:
        raise Refusal(
            "FQL_NOT_CQL",
            "this contains `|`, which is CQL pipeline syntax, not FQL. FQL is "
            "`property:[operator]value` with `+` for AND and `,` for OR. "
            "Refused rather than read as either.", DIALECT)
    if " and " in f" {lowered} " or " or " in f" {lowered} ":
        raise Refusal(
            "FQL_NOT_CQL",
            "this contains `AND`/`OR` as words, which is CQL syntax, not FQL. "
            "FQL uses `+` for AND and `,` for OR. Refused rather than read as "
            "either.", DIALECT)
    if "=" in stripped and ":" not in stripped:
        raise Refusal(
            "FQL_NOT_CQL",
            "this contains `=` without `:`, which is CQL comparison syntax, "
            "not FQL. FQL comparisons are `property:[operator]value`. Refused "
            "rather than read as either.", DIALECT)
    return FqlQuery(text=stripped)
