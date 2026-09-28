"""Lower CQL slice 1: a filter onto one `Filter`, `| table` onto `fields`.

The filter language here is comparisons, `AND`/`OR`/`NOT` with NOT > AND > OR
precedence, parentheses, quoted strings, numbers, dotted fields, `#tag` and
`@meta` prefixes, and `true`. Everything else -- wildcards, regex, functions,
`in()`, `:=`, `field = *` -- is refused BY NAME, because each changes which
rows match.

A LEADING `#` IS A PERFORMANCE HINT, NOT PART OF THE NAME. `#event_simpleName`
and `event_simpleName` match the same rows; the `#` tells LogScale the field
is indexed. So it is stripped at lowering and not rendered back -- which is
semantically identical, the way normalising whitespace is. A leading `@` IS
part of the name (`@timestamp` is the field), so it is kept verbatim.
"""

from __future__ import annotations

from typing import Any

from dialects.cql import CqlQuery, DIALECT
from engine.ir import (
    BoolOp,
    Comparison,
    Derive,
    Emit,
    FieldExpr,
    FieldRef,
    Filter,
    Literal,
    Not,
    Read,
    RuleIR,
    SourceSelector,
)
from engine.values import Refusal


def lower(query: CqlQuery, rule_id: str = "rule") -> tuple[RuleIR, list[dict]]:
    """A CQL filter -> `Read` -> `Filter` (+ `Derive` for `table`) -> `Emit`."""
    condition = _condition(query.filt)
    nodes: list[Any] = [
        Read(id="read", selector=SourceSelector(name="any")),
        Filter(id="filter", input="read", condition=condition),
    ]
    current = "filter"
    if query.table:
        nodes.append(Derive(id="derive", input=current,
                            assignments=tuple(
                                (column, FieldExpr(FieldRef(column)))
                                for column in query.table),
                            projects=True, kind="fields"))
        current = "derive"
    nodes.append(Emit(id="out", input=current))
    return (RuleIR(rule_id=rule_id, nodes=tuple(nodes), output="out",
                   title="CQL filter", metadata={"dialect": DIALECT}), [])


def _condition(text: str) -> Any:
    """A CQL boolean condition with NOT > AND > OR precedence."""
    or_parts = _split_top_level(text, "OR")
    if len(or_parts) > 1:
        return BoolOp("or", tuple(_condition(p) for p in or_parts))
    and_parts = _split_top_level(text, "AND")
    if len(and_parts) > 1:
        return BoolOp("and", tuple(_condition(p) for p in and_parts))
    body = text.strip()
    negated = False
    while body[:4].upper() == "NOT ":
        negated = not negated
        body = body[4:].strip()
    if body.startswith("!") and not body.startswith("!="):
        negated = not negated
        body = body[1:].strip()
    node = _comparison(body)
    return Not(node) if negated else node


def _split_top_level(text: str, keyword: str) -> list[str]:
    """Split on `keyword` only at paren depth 0, outside strings, whole words.

    `UserName = "and"` is one comparison whose value contains the word, and
    `ORANGE = 1` contains `OR`. Both are asserted, because both have happened
    in this codebase before -- in SPL and EQL, where the same splitter shape
    was built for the same reasons. Third copy of the shape; if a fourth
    appears, that is the moment to share one.
    """
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    start = 0
    index = 0
    upper_keyword = keyword.upper()
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
        elif depth == 0 and text[index:index + len(keyword)].upper() \
                == upper_keyword:
            before = text[index - 1] if index else " "
            after = text[index + len(keyword):index + len(keyword) + 1] or " "
            if not before.isalnum() and before not in (".", "_") \
                    and not after.isalnum() and after not in (".", "_"):
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
        raise Refusal("CQL_EMPTY_CONDITION", "an empty filter matches "
                      "everything, which is a no-op.", DIALECT)
    if body.lower() == "true":
        return Literal(value=True)
    if body.startswith("(") and body.endswith(")"):
        return _condition(body[1:-1])
    bare = _without_strings(body)
    # Refused by name, because each changes which rows match:
    if "/" in bare and _looks_like_regex(body):
        raise Refusal("CQL_REGEX_NOT_LOWERED",
                      "regex (`/pattern/` and `regex()`) is not in the lowered "
                      "subset. Refused rather than approximated.", DIALECT)
    if " in(" in bare.lower() or bare.lower().startswith("in("):
        raise Refusal("CQL_IN_NOT_LOWERED",
                      "`in(field, [...])` tests membership in a list, which "
                      "has no node yet. Refused rather than approximated.",
                      DIALECT)
    if ":=" in bare:
        raise Refusal("CQL_ASSIGN_NOT_LOWERED",
                      "`:=` creates a new field, which needs a `Derive` the "
                      "filter lowering does not build. Refused rather than "
                      "dropped.", DIALECT)
    for op in ("!=", ">=", "<=", "=", ">", "<"):
        left, sep, right = body.partition(op)
        # `!=` must win over `=`; partition finds the FIRST occurrence, so try
        # two-char operators before one-char ones. `==` is not CQL -- a double
        # equals here means the value starts with `=`, which is refused below
        # as not-a-value rather than misread.
        if sep:
            return _comparison_op(left.strip(), op, right.strip(), body)
    raise Refusal(
        "CQL_NOT_A_COMPARISON",
        f"{body[:60]!r} is not a comparison this lowering handles.",
        DIALECT)


def _looks_like_regex(body: str) -> bool:
    """A `/` outside strings that opens a `/pattern/` or `regex(` call."""
    bare = _without_strings(body)
    return "/" in bare


def _without_strings(body: str) -> str:
    """`body` with quoted regions blanked."""
    out: list[str] = []
    quote: str | None = None
    for char in body:
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


def _comparison_op(field: str, op: str, value: str, body: str) -> Any:
    """Build the comparison, or refuse what is not in the subset."""
    if not field:
        raise Refusal("CQL_FIELD_MISSING",
                      f"{body[:50]!r} has an operator with no field.",
                      DIALECT)
    # Strip the `#` tag marker: performance hint, not part of the name. `@`
    # stays -- it IS part of names like `@timestamp`.
    bare_field = field[1:] if field.startswith("#") else field
    if not bare_field or not all(
            part.isidentifier() or part.replace("_", "").isalnum()
            for part in bare_field.replace("@", "").split(".")):
        raise Refusal(
            "CQL_FIELD_NOT_A_NAME",
            f"`{field}` is not a plain field name. Refused rather than "
            f"guessed.", DIALECT)
    if not value:
        raise Refusal("CQL_VALUE_MISSING",
                      f"`{field} {op}` with no value matches nothing "
                      f"testable.", DIALECT)
    # `field = *` is an existence check, which the engine has -- but wiring it
    # here would need a presence node this lowering does not build. Refused by
    # name rather than read as equality against a literal star.
    if value == "*":
        raise Refusal(
            "CQL_EXISTS_NOT_LOWERED",
            f"`{field} = *` tests existence, not equality against `*`. There "
            f"is no presence node in this lowering yet. Refused rather than "
            f"read as a literal star that would match almost nothing.",
            DIALECT)
    if "*" in value.strip("'\""):
        raise Refusal(
            "CQL_WILDCARD_NOT_LOWERED",
            f"`{field} {op} {value}` contains a `*` wildcard, which matches "
            f"one or more characters. There is no wildcard node yet. Refused "
            f"rather than read as a literal.", DIALECT)
    if op == "=" and value.startswith("="):
        raise Refusal(
            "CQL_DOUBLE_EQUALS",
            f"`{body[:50]!r}` uses `==`, which is not CQL -- CQL equality is "
            f"a single `=`. Refused rather than read as equality against a "
            f"value starting with `=`.", DIALECT)
    return Comparison("=" if op == "=" else op,
                      FieldExpr(FieldRef(bare_field)),
                      _literal(value))


def _literal(text: str) -> Any:
    """A quoted string, a number, `true`, or a bare word.

    CQL values are very often unquoted (`#event_simpleName=ProcessRollup2`),
    so a bare word is a string value, not a syntax error. It must still be a
    single token -- anything with spaces in it that is not quoted is refused,
    because an unquoted multi-word value is two things the analyst may have
    meant as one.
    """
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
    if text and " " not in text:
        return Literal(value=text)
    raise Refusal("CQL_LITERAL_NOT_A_VALUE",
                  f"{text[:40]!r} is not a quoted string, a number, or a bare "
                  f"word. Refused rather than guessed.", DIALECT)
