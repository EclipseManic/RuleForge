"""CrowdStrike CQL (LogScale), slice 1: a filter plus `| table`, honestly.

CQL is a PIPELINE language: `filter | table a, b`. The filter uses `=`/`!=`
comparisons with `AND`/`OR`/`NOT`, `#tag` fields (indexed), `@meta` fields
(`@timestamp`), and bare event fields. This slice lowers the filter onto one
`Filter` and `| table a, b` onto `Derive(kind="fields")` -- both existing
nodes, no approximations.

THIS IS NOT FQL, and the two must never share a parser. FQL is
`property:[operator]value` with `+`/`,`; CQL is `field = "value"` with pipes
and word operators. Each refuses the other's shape by name: a combined grammar
would accept strings valid in neither language.

Refused by name in this slice: wildcards in values, regex (`/re/` and
`regex()`), functions, `in()`, `:=` assignment, `field = *` exists-checks, and
every pipe except `table`. Each changes which rows match or needs a node not
yet wired, so each is named rather than approximated.
"""

from __future__ import annotations

from dataclasses import dataclass

from engine.values import Refusal

DIALECT = "cql"
LANGUAGE = "CrowdStrike CQL"


@dataclass(frozen=True, slots=True)
class CqlQuery:
    """A CQL filter with zero or more pipes. Slice 1 allows only `table`."""
    filt: str
    table: tuple[str, ...] = ()


def parse_cql(text: str) -> CqlQuery:
    """Split a CQL query into its filter and its pipes."""
    stripped = text.strip()
    if not stripped:
        raise Refusal("CQL_EMPTY", "nothing to parse", DIALECT)
    # FQL SHAPES ARE REFUSED AS FQL, NOT AS BROKEN CQL. `a:'b'` with a colon
    # and no `=` is FQL's `property:value`, and `a+b` is FQL's AND. Reading
    # either as CQL would misparse a valid rule from the other language.
    bare = _without_quotes(stripped)
    if ":" in bare and "=" not in bare.replace("==", "").replace("!=", "") \
            .replace("<=", "").replace(">=", ""):
        raise Refusal(
            "CQL_NOT_FQL",
            "this looks like FQL (`property:value`), not CQL (`field = "
            "\"value\"`). The two languages share a name and nothing else; "
            "this is refused rather than read as either.", DIALECT)
    segments = _split_pipes(stripped)
    filt = segments[0].strip()
    if not filt:
        raise Refusal("CQL_EMPTY_FILTER",
                      "a query starting with `|` has no filter, which matches "
                      "everything -- a no-op disguised as a rule.", DIALECT)
    table: tuple[str, ...] = ()
    for pipe in segments[1:]:
        name, _, args = pipe.strip().partition(" ")
        name, args = name.lower(), args.strip()
        if name == "table":
            if table:
                raise Refusal("CQL_TABLE_TWICE",
                              "two `| table` stages join nothing new; the "
                              "second is refused rather than silently kept.",
                              DIALECT)
            table = tuple(f.strip() for f in args.split(",") if f.strip())
            if not table:
                raise Refusal("CQL_TABLE_EMPTY",
                              "`| table` with no columns projects nothing.",
                              DIALECT)
            for column in table:
                if not all(part.isidentifier()
                           for part in column.replace("#", "").replace(
                               "@", "").split(".")):
                    raise Refusal(
                        "CQL_COLUMN_NOT_A_NAME",
                        f"`{column}` is not a plain field name. Refused "
                        f"rather than guessed.", DIALECT)
        else:
            raise Refusal(
                "CQL_PIPE_NOT_LOWERED",
                f"`| {name}` is a real CQL command, but only `| table` lowers "
                f"today. Refused by name rather than dropped -- dropping a "
                f"pipe stage silently changes which rows come back.", DIALECT)
    return CqlQuery(filt=filt, table=table)


def _split_pipes(text: str) -> list[str]:
    """Split on `|` at bracket depth 0 outside strings.

    A `|` inside a quoted value (`name == "a|b"`) or inside parens is data,
    not a pipe. Splitting there would break the value and then refuse on the
    pieces.
    """
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    start = 0
    for index, char in enumerate(text):
        if quote is not None:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def _without_quotes(text: str) -> str:
    """`text` with quoted regions blanked, so shape checks cannot fire inside
    a value."""
    out: list[str] = []
    quote: str | None = None
    for char in text:
        if quote is not None:
            if char == quote:
                quote = None
            out.append(" ")
        elif char in ("'", '"'):
            quote = char
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)
