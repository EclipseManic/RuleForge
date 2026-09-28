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
    #
    # THE CHECKS RUN ON THE TEXT WITH QUOTED REGIONS BLANKED. FQL values are
    # single-quoted and may contain anything -- `hostname:'a and b'` is one
    # term whose VALUE contains the word, and refusing it as CQL made valid
    # values unrepresentable. The lowerer's own splitter is quote-aware for the
    # same reason; the gate in front of it has to be too, or the gate is
    # stricter than the grammar it guards.
    bare = _without_quotes(stripped)
    lowered = bare.lower()
    if "|" in bare:
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
    if "=" in bare and ":" not in bare:
        raise Refusal(
            "FQL_NOT_CQL",
            "this contains `=` without `:`, which is CQL comparison syntax, "
            "not FQL. FQL comparisons are `property:[operator]value`. Refused "
            "rather than read as either.", DIALECT)
    return FqlQuery(text=stripped)


def _without_quotes(text: str) -> str:
    """`text` with single-quoted regions blanked, so the CQL-shape checks
    cannot fire inside a value. A backslash escapes the next character, so an
    escaped quote does not end the region early."""
    out: list[str] = []
    quote = False
    escaped = False
    for char in text:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "'":
                quote = False
            out.append(" ")
        elif char == "'":
            quote = True
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)
