"""Lower FQL slice 1: a flat `property:[operator]value` filter onto one `Filter`.

The boolean structure is `+` (AND), `,` (OR), `(...)` (grouping), with AND
binding tighter than OR -- the same precedence every other dialect in this
project uses, and the splitter is quote-aware for the same reason the SPL and
EQL ones are: a value may contain the separator characters.

Values by type, per the FQL documentation:
  strings   -- single-quoted (`hostname:'g*'`, with `*` as wildcard)
  exact     -- square-bracketed (`hostname:['exact']`, case-sensitive)
  dates     -- single-quoted UTC (`last_seen:<='2021-08-31T12:00:00Z'`)
  booleans  -- lowercase unquoted (`featured:true`)
  integers  -- unquoted (`posts.count:>10`)

Operators: default (equal), `!` not-equal, `>` `>=` `<` `<=`, `~` text-match,
`!~` not-text-match, `*` wildcard. The text-match operators tokenise and ignore
case -- the IR's `matches_regex` does neither, so they are refused rather than
mapped onto it. A different matcher is not the same matcher.

At most 20 properties per statement, enforced by the API. passthrough: the
lowerer counts terms and refuses past 20 with the limit named, because the 21st
term would silently not filter server-side.
"""

from __future__ import annotations

from typing import Any

from dialects.fql import DIALECT, FqlQuery
from engine.ir import (
    BoolOp,
    Comparison,
    Emit,
    FieldExpr,
    FieldRef,
    Filter,
    Literal,
    Read,
    RuleIR,
    SourceSelector,
)
from engine.values import Refusal

MAX_PROPERTIES = 20


def lower(query: FqlQuery, rule_id: str = "rule") -> tuple[RuleIR, list[dict]]:
    """An FQL filter -> `Read` -> `Filter` -> `Emit`."""
    # The API allows at most 20 properties per statement, and the 21st would
    # silently not filter server-side. Counted on the raw text before lowering,
    # because after lowering the terms are a tree and the count is harder to
    # audit. Refused rather than truncated.
    if count_terms(query.text) > MAX_PROPERTIES:
        raise Refusal(
            "FQL_TOO_MANY_PROPERTIES",
            f"this filter has more than {MAX_PROPERTIES} properties, which is "
            f"the most the API accepts. The rest would silently not filter, so "
            f"it is refused rather than truncated.", DIALECT)
    condition = _filter(query.text)
    nodes = (
        Read(id="read", selector=SourceSelector(name="any")),
        Filter(id="filter", input="read", condition=condition),
        Emit(id="out", input="filter"),
    )
    return (RuleIR(rule_id=rule_id, nodes=nodes, output="out",
                   title="FQL filter", metadata={"dialect": DIALECT}), [])


def _filter(text: str) -> Any:
    """Top level: `,` (OR) binds loosest, so it splits first."""
    parts = _split_top_level(text, ",")
    if len(parts) > 1:
        return BoolOp("or", tuple(_filter(p) for p in parts))
    parts = _split_top_level(text, "+")
    if len(parts) > 1:
        return BoolOp("and", tuple(_filter(p) for p in parts))
    body = text.strip()
    if body.startswith("(") and body.endswith(")"):
        return _filter(body[1:-1])
    return _term(body)


def _split_top_level(text: str, sep: str) -> list[str]:
    """Split on `sep` only at paren depth 0 and outside single quotes.

    Values are single-quoted and may contain `+`, `,` and parens
    (`hostname:'a+b'` is one term), so a plain split would break the value and
    then refuse on the pieces.
    """
    parts: list[str] = []
    depth = 0
    quote = False
    start = 0
    for index, char in enumerate(text):
        if char == "'" and (index == 0 or text[index - 1] != "\\"):
            quote = not quote
        elif not quote:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == sep and depth == 0:
                parts.append(text[start:index])
                start = index + 1
    parts.append(text[start:])
    return [p for p in (part.strip() for part in parts) if p]


def _term(text: str) -> Any:
    """One `property:[operator]value`."""
    body = text.strip()
    if not body:
        raise Refusal("FQL_EMPTY_TERM", "an empty filter term matches "
                      "everything, which is a no-op.", DIALECT)
    prop, colon, rest = body.partition(":")
    if not colon:
        raise Refusal("FQL_TERM_NOT_A_FILTER",
                      f"{body[:50]!r} is not `property:[operator]value`.",
                      DIALECT)
    prop = prop.strip()
    if not prop or not prop[0].isalpha() or not all(
            c.isalnum() or c in ("_", ".") for c in prop):
        raise Refusal(
            "FQL_PROPERTY_NOT_A_NAME",
            f"`{prop}` is not a property name: alphanumeric and underscore, "
            f"starting with a letter. Refused rather than guessed.", DIALECT)
    operator = "="
    value = rest.strip()
    for prefix, op in (("!~", "not_text_match"), ("~", "text_match"),
                       ("!", "!="), (">=", ">="), ("<=", "<="),
                       (">", ">"), ("<", "<")):
        if value.startswith(prefix):
            operator, value = op, value[len(prefix):].strip()
            break
    if operator in ("text_match", "not_text_match"):
        # `~` tokenises the string and ignores case and punctuation. The IR's
        # `matches_regex` does neither, so mapping one onto the other would
        # match a different set of rows. There is no text-match node yet.
        raise Refusal(
            "FQL_TEXT_MATCH_NOT_LOWERED",
            f"`{prop}:{'!~' if operator == 'not_text_match' else '~'}{value}` "
            f"is a tokenising, case-insensitive text match, which the IR "
            f"cannot express yet. Refused rather than rendered as a regex.",
            DIALECT)
    return Comparison("=" if operator == "=" else operator,
                      FieldExpr(FieldRef(prop.lower())),
                      _value(value, prop))


def _value(text: str, prop: str) -> Any:
    """An FQL value by its shape."""
    if not text:
        raise Refusal("FQL_VALUE_MISSING",
                      f"`{prop}:` with no value matches nothing testable.",
                      DIALECT)
    # Exact match: `[ 'value' ]`, case-sensitive. Lowered as a plain equality
    # -- which IS case-sensitive here -- with the exactness noted, because the
    # IR has no separate "exact" marker and inventing one would be a new node
    # for no behavioural difference.
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if len(inner) >= 2 and inner[0] == inner[-1] == "'":
            return Literal(value=inner[1:-1])
        raise Refusal("FQL_EXACT_MALFORMED",
                      f"`{prop}:{text}` is not `[ 'value' ]`.", DIALECT)
    if len(text) >= 2 and text[0] == text[-1] == "'":
        inner = text[1:-1]
        # A `*` inside a quoted value is a wildcard (one or more chars). The
        # IR has no wildcard node, so this is the one value shape refused
        # rather than lowered -- lowering it as a literal equality would miss
        # every row the wildcard was meant to catch.
        if "*" in inner:
            raise Refusal(
                "FQL_WILDCARD_NOT_LOWERED",
                f"`{prop}:'{inner}'` contains a `*` wildcard, which matches "
                f"one or more characters. There is no wildcard node yet, so "
                f"this is refused rather than read as a literal equality that "
                f"would match almost nothing.", DIALECT)
        return Literal(value=inner)
    if text == "true":
        return Literal(value=True)
    if text == "false":
        return Literal(value=False)
    if text == "null":
        # `null` is a real FQL value and the IR distinguishes ABSENT from NULL,
        # so equality against null lowers exactly.
        return Literal(value=None)
    try:
        return Literal(value=int(text))
    except ValueError:
        pass
    raise Refusal("FQL_VALUE_NOT_A_VALUE",
                  f"`{prop}:{text}` is not a quoted string, `true`/`false`, "
                  f"`null`, or an integer. Refused rather than guessed.",
                  DIALECT)


def count_terms(text: str) -> int:
    """Leaf `property:...` terms, splitting `,` then `+` at the top level.

    Parenthesised groups recurse naturally: `(a+b),(c+d)` is two OR-branches
    holding two terms each, for four total.
    """
    total = 0
    for or_branch in _split_top_level(text, ","):
        branch = or_branch.strip()
        if branch.startswith("(") and branch.endswith(")"):
            total += count_terms(branch[1:-1])
        else:
            total += max(1, len(_split_top_level(branch, "+")))
    return total
