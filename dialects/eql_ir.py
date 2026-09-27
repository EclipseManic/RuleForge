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


def lower(query: EqlQuery, rule_id: str = "rule") -> tuple[RuleIR, list[dict]]:
    """`[ category where condition ]` -> `Read` -> `Filter` -> `Emit`."""
    condition = _condition(query.event.condition)
    nodes = (
        Read(id="read", selector=SourceSelector(name=query.event.category)),
        Filter(id="filter", input="read", condition=condition),
        Emit(id="out", input="filter"),
    )
    return (RuleIR(rule_id=rule_id, nodes=nodes, output="out",
                   title=f"[{query.event.category} where ...]",
                   metadata={"dialect": DIALECT}), [])


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
