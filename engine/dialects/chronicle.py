"""Google SecOps YARA-L 2.0: the dialect where `=` is three different things.

A YARA-L rule is a block of named sections, and the sections do different
jobs with the same syntax:

    rule suspicious_lsass_access {
      meta:
        author = "soc"
        severity = "HIGH"
      events:
        $e.metadata.event_type = "PROCESS_OPEN"
        $e.target.process.file.full_path = /lsass\\.exe$/ nocase
        $e.principal.hostname = $host
      match:
        $host over 5m
      condition:
        $e and #e > 5
    }

**`=` is equality, a regex test, or a VARIABLE BINDING, depending on the right
side.** This is the defect this module exists to prevent. The first line above
is a comparison. The second is a pattern match. The third declares `$host` and
binds it to the hostname -- it is not a test at all, and it filters nothing.
Lowering it as a comparison asks whether `principal.hostname` equals a field
called `host`, which does not exist: the comparison is ABSENT against a value,
goes UNDECIDED, and takes the whole conjunction with it. The rule then matches
nothing and reports a clean no_match. `_is_placeholder` is the one-line check
that keeps the three apart, and `EqualsIsThreeDifferentThings` is the test
class that holds it down.

**`#e` is a COUNT, not a field.** `#e > 5` means "more than five events
matched `$e`". Read as a field reference it becomes a comparison against an
absent column called `e`, and the threshold silently stops applying.

**`#e > 5` is STRICT and `ir.Correlation.frequency` is not.** The engine fires
at `>= frequency`, so `> 5` has to lower to a frequency of SIX. Copying the
five across makes the rule fire one event early, which is the kind of
off-by-one that looks like a tuning problem for months.

**`match:` is what makes a threshold meaningful.** It names the fields the
count is grouped on. `ir.Correlation` refuses an empty `group_by` because a
count with nothing to group on is "anywhere in the log", and a rule written to
catch five failures against ONE host becomes one that fires on five failures
across the estate.

**Regex is RE2, and it does execute here.** Unlike PCRE and Java, RE2 has no
backreferences and no lookaround at all, so it is strictly less expressive
than the portable core `evaluate.py` already screens for. A pattern that
survives that screen denotes the same language in RE2 and in Python's `re`
for the only question asked of it -- whether the subject matches -- so running
it is a faithful answer rather than a guess. That is the difference from
`pcre` and `java_regex`, which are refused.

**`meta:` round-trips.** It is the one vendor metadata block that maps cleanly
onto `ir.Annotations`, so a rule imported from YARA-L and written back out
keeps its author, description, severity and ATT&CK mapping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from decimal import Decimal
from typing import Any, Final

from ..ir import (
    Aggregate,
    Annotations,
    Arith,
    Binding,
    BoolOp,
    Call,
    Comparison,
    Correlation,
    Emit,
    Expr,
    FieldRef,
    Filter,
    Join,
    ListExpr,
    Literal,
    Measure,
    Node,
    Not,
    Read,
    Regex,
    Rule,
    Span,
    render_expr,
)
from ..validate import validate
from ..values import Duration, Refusal
from .common import plain_number, Diagnostic, is_bare_identifier, split_top_level

__all__ = [
    "DIALECT",
    "LANGUAGE",
    "REGEX_DIALECT",
    "DEFAULT_TABLE",
    "SECTIONS",
    "OUTCOME_FUNCTIONS",
    "FUNCTIONS",
    "ParsedYaraL",
    "parse_chronicle",
    "lower_chronicle",
    "render_chronicle",
]

DIALECT: Final = "chronicle"
LANGUAGE: Final = "YARA-L 2.0"

#: RE2. Executable here -- see the module docstring for why it differs from
#: `pcre` and `java_regex`.
REGEX_DIALECT: Final = "re2"

#: YARA-L runs over the UDM event stream; the rule text names no table.
DEFAULT_TABLE: Final = "udm_events"

#: The sections of a rule, in the order YARA-L writes them.
SECTIONS: Final[tuple[str, ...]] = (
    "meta", "events", "match", "outcome", "condition", "options",
)

#: `meta:` key -> the `ir.Annotations` field it round-trips through.
META_FIELDS: Final[dict[str, str]] = {
    "author": "author",
    "description": "description",
    "severity": "severity",
    "rule_name": "title",
    "name": "title",
    "title": "title",
}

#: YARA-L function -> the engine's. Everything not here is refused by name.
FUNCTIONS: Final[dict[str, str]] = {
    "re.regex": "matches_regex",
    "net.ip_in_range_cidr": "cidr_contains",
    "strings.contains": "contains",
    "strings.starts_with": "starts_with",
    "strings.ends_with": "ends_with",
    "strings.to_lower": "lower",
    "strings.to_upper": "upper",
    "strings.length": "length",
    "strings.coalesce": "coalesce",
    "math.abs": "abs",
    "timestamp.current_seconds": "now",
}

#: `outcome:` aggregate -> the engine's measure function.
OUTCOME_FUNCTIONS: Final[dict[str, tuple[str, bool]]] = {
    "count": ("count", False),
    "count_distinct": ("dcount", True),
    "max": ("max", False),
    "min": ("min", False),
    "sum": ("sum", False),
    "avg": ("avg", False),
    "array_distinct": ("values", True),
    "array": ("make_list", False),
}

_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_RULE_HEAD = re.compile(r"^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", re.M)
_SECTION = re.compile(
    r"^[ \t]*(" + "|".join(SECTIONS) + r")[ \t]*:[ \t]*$", re.M
)

#: The same section words, WITHOUT requiring the line to end after the colon.
#:
#: YARA-L is whitespace-insensitive, so `rule x { events: $e.a = "1"
#: condition: $e }` is a legal rule -- and `_SECTION` anchors to `$`, so it
#: found no sections at all and the rule was refused with "this rule body has
#: no `events:`, `condition:` or any other section" about a body that plainly
#: had both. Used only when the strict pass finds nothing, so a conventional
#: multi-line rule still splits on its own line breaks and a field called
#: `options` inside a condition cannot be mistaken for a section header.
_SECTION_INLINE = re.compile(
    r"(?:^|\s)(" + "|".join(SECTIONS) + r")[ \t]*:", re.M
)
_DURATION = re.compile(r"^(\d+)\s*([smhd])$", re.I)
_PLACEHOLDER = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")
_EVENT_FIELD = re.compile(
    r"^\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_.]*)$"
)
_COUNT_REF = re.compile(r"^#([A-Za-z_][A-Za-z0-9_]*)$")

_UNITS: Final[dict[str, int]] = {"s": 1, "m": 60, "h": 3600, "d": 86400}


@dataclass(frozen=True, slots=True)
class ParsedYaraL:
    """A YARA-L rule split into its sections, with nothing interpreted."""

    name: str = ""
    meta: dict[str, str] = dc_field(default_factory=dict)
    events: tuple[str, ...] = ()
    match: str = ""
    outcome: tuple[str, ...] = ()
    condition: str = ""
    options: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------


def _strip_comments(text: str) -> str:
    """Remove comments, preserving newlines so line structure survives.

    A regex literal can contain `//`, so slashes inside `/.../` are protected
    before the comment pass. Without that, `$e.url = /https:\\/\\/evil/` lost
    everything from the first slash pair and the predicate silently changed.
    """
    out: list[str] = []
    index = 0
    in_regex = False
    in_string = False
    while index < len(text):
        char = text[index]
        if in_string:
            if char == "\\" and index + 1 < len(text):
                out.append(text[index:index + 2])
                index += 2
                continue
            if char == '"':
                in_string = False
            out.append(char)
            index += 1
            continue
        if in_regex:
            if char == "\\" and index + 1 < len(text):
                out.append(text[index:index + 2])
                index += 2
                continue
            if char == "/":
                in_regex = False
            out.append(char)
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if text.startswith("//", index):
            while index < len(text) and text[index] != "\n":
                index += 1
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            stop = len(text) if end < 0 else end + 2
            out.append("\n" * text.count("\n", index, stop))
            index = stop
            continue
        if char == "/":
            # The opening slash of a regex literal. A division operator would
            # be ambiguous here, but YARA-L has no arithmetic in `events:`.
            in_regex = True
            out.append(char)
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _split_sections(body: str) -> dict[str, list[str]]:
    marks = list(_SECTION.finditer(body))
    inline = False
    if not marks:
        # A one-line rule. See `_SECTION_INLINE`: the strict pattern requires
        # the line to end after the colon, so `rule x { events: ... condition:
        # ... }` reported having no sections at all.
        marks = list(_SECTION_INLINE.finditer(body))
        inline = bool(marks)
    if not marks:
        raise Refusal(
            "YARAL_NO_SECTIONS",
            "this rule body has no `events:`, `condition:` or any other "
            "section. Nothing has been interpreted.",
            "parse",
        )
    sections: dict[str, list[str]] = {}
    for position, mark in enumerate(marks):
        name = mark.group(1)
        start = mark.end()
        end = marks[position + 1].start() if position + 1 < len(marks) \
            else len(body)
        if name in sections:
            raise Refusal(
                "YARAL_SECTION_REPEATED",
                f"`{name}:` appears more than once. Which one applies is a "
                f"guess, and guessing changes what the rule matches.",
                "parse",
            )
        chunk = body[start:end]
        if inline:
            # One-line form: the predicates are separated by whitespace rather
            # than newlines, and each section holds exactly one of them.
            # Split on nothing -- the whole chunk IS the single entry -- so a
            # value containing a space is not cut in half.
            text = chunk.strip()
            sections[name] = [text] if text else []
        else:
            sections[name] = [
                line.strip()
                for line in chunk.splitlines()
                if line.strip()
            ]
    return sections


def parse_chronicle(text: str) -> ParsedYaraL:
    """YARA-L text to its sections, with nothing interpreted."""
    cleaned = _strip_comments(text).strip()
    if not cleaned:
        raise Refusal(
            "YARAL_EMPTY", "there is no rule text to read.", "parse"
        )

    head = _RULE_HEAD.search(cleaned)
    if head is None:
        raise Refusal(
            "YARAL_NO_RULE_BLOCK",
            "this text has no `rule <name> {` block. A YARA-L rule is a named "
            "block, and reading a bare list of predicates as one would invent "
            "a name the rule never had.",
            "parse",
        )
    if _RULE_HEAD.search(cleaned, head.end()):
        raise Refusal(
            "YARAL_MULTIPLE_RULES",
            "this text holds more than one rule. Lowering only the first "
            "would silently discard the rest, so pass one rule at a time.",
            "parse",
        )

    closing = cleaned.rfind("}")
    if closing < head.end():
        raise Refusal(
            "YARAL_UNCLOSED_RULE",
            f"the block for `{head.group(1)}` is never closed, so the rest of "
            f"the rule could not be read.",
            "parse",
        )

    sections = _split_sections(cleaned[head.end():closing])

    meta: dict[str, str] = {}
    for line in sections.get("meta", []):
        key, found, value = line.partition("=")
        if not found:
            raise Refusal(
                "YARAL_META_NOT_A_PAIR",
                f"`{line}` in `meta:` is not a `key = \"value\"` pair.",
                "parse",
            )
        meta[key.strip()] = _meta_value(value)

    return ParsedYaraL(
        name=head.group(1),
        meta=meta,
        events=tuple(sections.get("events", [])),
        match=" ".join(sections.get("match", [])),
        outcome=tuple(sections.get("outcome", [])),
        condition=" ".join(sections.get("condition", [])),
        options=tuple(sections.get("options", [])),
    )


# ---------------------------------------------------------------------------
# Lower: expressions
# ---------------------------------------------------------------------------


def _is_placeholder(text: str) -> bool:
    """True for `$host`, false for `$e.principal.hostname`.

    The whole dialect turns on this. A bare `$name` on the right of `=` is a
    variable being DECLARED and bound to the left-hand field -- it is not a
    comparison and filters nothing. A `$e.field.path` is an event field and
    the comparison is real.
    """
    return bool(_PLACEHOLDER.match(text)) and "." not in text


def _duration(text: str) -> Duration:
    match = _DURATION.match(text.strip())
    if match is None:
        raise Refusal(
            "YARAL_DURATION_UNREADABLE",
            f"`{text.strip()}` is not a YARA-L duration. They are written "
            f"like `5m`, `1h` or `30s`.",
            "lower",
        )
    return Duration(Decimal(int(match.group(1)) * _UNITS[match.group(2).lower()]))


def _field(
    text: str, event_vars: set[str], seen: set[str] | None = None
) -> FieldRef:
    """`$e.principal.hostname` as a FieldRef.

    `seen` records which EVENT VARIABLE the reference mentioned. The variable
    is not part of FieldRef (the IR has no streams), but a multi-variable
    YARA-L rule is a join and needs to know which stream each predicate
    belongs to -- so it is captured here, where the prefix is still visible.
    """
    match = _EVENT_FIELD.match(text.strip())
    if match is None:
        raise Refusal(
            "YARAL_NOT_A_FIELD",
            f"`{text.strip()}` is not a UDM field reference. They are written "
            f"`$<event>.<path>`, for example `$e.principal.hostname`.",
            "lower",
        )
    event_vars.add(match.group(1))
    if seen is not None:
        seen.add(match.group(1))
    parts = match.group(2).split(".")
    return FieldRef(name=parts[0], path=tuple(parts[1:]))


def _value(text: str) -> Expr:
    """A literal, a regex, or a list."""
    body = text.strip()
    if body.startswith("/"):
        closing = body.rfind("/")
        if closing <= 0:
            raise Refusal(
                "YARAL_REGEX_UNTERMINATED",
                f"the pattern `{body}` is never closed.",
                "lower",
            )
        pattern = body[1:closing]
        modifiers = body[closing + 1:].strip().lower()
        nocase = "nocase" in modifiers or modifiers == "i"
        return Regex(pattern, REGEX_DIALECT, nocase)
    if body.startswith('"') and body.endswith('"') and len(body) >= 2:
        return Literal(body[1:-1])
    if body.startswith("[") and body.endswith("]"):
        return ListExpr(tuple(
            _value(part) for part in split_top_level(body[1:-1], ",")
            if part.strip()
        ))
    lowered = body.lower()
    if lowered == "true":
        return Literal(True)
    if lowered == "false":
        return Literal(False)
    try:
        return Literal(Decimal(body))
    except Exception:
        raise Refusal(
            "YARAL_VALUE_UNREADABLE",
            f"`{body}` is not a string, number, list or pattern. An unquoted "
            f"word is not a value in YARA-L, and reading it as one would "
            f"compare against text the rule never wrote.",
            "lower",
        ) from None


def _call(text: str, event_vars: set[str]) -> Expr | None:
    """A function call predicate, or None when this is not one."""
    body = text.strip()
    open_paren = body.find("(")
    if open_paren < 0 or not body.endswith(")"):
        return None
    name = body[:open_paren].strip()
    if name not in FUNCTIONS:
        if "." in name and not name.startswith("$"):
            raise Refusal(
                "YARAL_FUNCTION_UNKNOWN",
                f"`{name}()` is not a YARA-L function this tool models. "
                f"Dropping it would change what the rule matches, and "
                f"guessing at it would be worse.",
                "lower",
            )
        return None

    mapped = FUNCTIONS[name]
    arguments = [
        part.strip()
        for part in split_top_level(body[open_paren + 1:-1], ",")
        if part.strip()
    ]
    parsed: list[Expr] = []
    for argument in arguments:
        if _EVENT_FIELD.match(argument):
            parsed.append(_field(argument, event_vars))
        else:
            parsed.append(_value(argument))

    if mapped == "matches_regex" and len(parsed) == 2:
        # `re.regex($e.f, "p")` is a pattern test, and the pattern is RE2
        # whether it was written as a string or between slashes.
        pattern = parsed[1]
        if isinstance(pattern, Literal) and isinstance(pattern.value, str):
            return Comparison(
                "matches", parsed[0], Regex(pattern.value, REGEX_DIALECT, False)
            )
    if mapped in ("contains", "starts_with", "ends_with") and len(parsed) == 2:
        operator = {
            "contains": "contains",
            "starts_with": "startswith",
            "ends_with": "endswith",
        }[mapped]
        return Comparison(operator, parsed[0], parsed[1])
    return Call(mapped, tuple(parsed))


#: Longest first, so `!=` and `>=` are not read as `=` and `>`.
#: Longest first, so `!=` and `>=` are not read as `=` and `>`.
#:
#: ` in ` is here because `render_chronicle` writes a membership test as
#: `$e.F in ["a", "b"]`, and without it the line had no recognisable operator
#: and was refused as "neither a comparison nor a function call" -- the
#: renderer emitting text its own parser rejected. Spelled with surrounding
#: spaces so a field called `b.instance` does not split on the `in` inside it.
_OPERATORS: Final[tuple[tuple[str, str], ...]] = (
    ("!=", "!="),
    (">=", ">="),
    ("<=", "<="),
    (" in ", "in"),
    ("=", "=="),
    (">", ">"),
    ("<", "<"),
)


def _split_operator(text: str) -> tuple[str, str, str] | None:
    """Split a predicate on its top-level operator.

    Bracket and quote depth are tracked, because a `=` inside a regex or a
    string is not the predicate's operator and splitting on it cuts the
    pattern in half.
    """
    depth = 0
    in_string = False
    in_regex = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and (in_string or in_regex):
            index += 2
            continue
        if in_string:
            if char == '"':
                in_string = False
            index += 1
            continue
        if in_regex:
            if char == "/":
                in_regex = False
            index += 1
            continue
        if char == '"':
            in_string = True
            index += 1
            continue
        if char == "/" and depth == 0:
            in_regex = True
            index += 1
            continue
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif depth == 0:
            for spelling, mapped in _OPERATORS:
                if text.startswith(spelling, index):
                    return (
                        text[:index].strip(),
                        mapped,
                        text[index + len(spelling):].strip(),
                    )
        index += 1
    return None


def _closes_at_end(body: str) -> bool:
    """True when the opening bracket is closed by the LAST character.

    `(a or b)` groups the whole line; `(a) or (b)` does not, and treating the
    second as a group would strip the outer brackets and lose the `or`.
    """
    depth = 0
    in_string = False
    in_regex = False
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and (in_string or in_regex):
            # Advance PAST the escaped character, not just past the backslash.
            # This loop used to `continue` without moving on, so an escaped `/`
            # inside a pattern still ENDED the pattern: `/\/dev\/tcp\//` was
            # read as regex, then not-regex, then regex again, and the closing
            # `)` was swallowed as pattern text. The group was never recognised,
            # so the whole predicate was refused as unreadable -- which is how
            # the `linux-reverse-shell` Sigma rule rendered Chronicle text that
            # Chronicle itself could not read back.
            index += 2
            continue
        if in_string:
            if char == '"':
                in_string = False
            index += 1
            continue
        if in_regex:
            if char == "/":
                in_regex = False
            index += 1
            continue
        if char == '"':
            in_string = True
        elif char == "/":
            in_regex = True
        elif char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
            if depth == 0:
                return index == len(body) - 1
        index += 1
    return False



def _split_top(body: str, joiner: str) -> list[str]:
    """Split on `joiner` at bracket depth zero, case-insensitively.

    Quote and regex aware, because ` or ` inside a string or a pattern is text
    and splitting there would cut the value in half.
    """
    parts: list[str] = []
    depth = 0
    in_string = False
    in_regex = False
    start = 0
    index = 0
    lowered = body.lower()
    while index < len(body):
        char = body[index]
        if char == "\\" and (in_string or in_regex):
            index += 2
            continue
        if in_string:
            if char == '"':
                in_string = False
            index += 1
            continue
        if in_regex:
            if char == "/":
                in_regex = False
            index += 1
            continue
        if char == '"':
            in_string = True
            index += 1
            continue
        if char == "/":
            in_regex = True
            index += 1
            continue
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif depth == 0 and lowered.startswith(joiner, index):
            parts.append(body[start:index])
            index += len(joiner)
            start = index
            continue
        index += 1
    parts.append(body[start:])
    return [p for p in parts if p.strip()]


def _predicate(
    line: str,
    event_vars: set[str],
    placeholders: dict[str, FieldRef],
    seen: set[str] | None = None,
) -> Expr | None:
    """One `events:` line.

    Returns None when the line DECLARES a placeholder rather than testing
    anything, which is the case `_is_placeholder` exists for.
    """
    body = line.strip().rstrip(",")
    if not body:
        return None

    negate = False
    while body.lower().startswith("not "):
        negate = not negate
        body = body[4:].strip()

    # A parenthesised group, and a disjunction inside one.
    #
    # `render_chronicle` writes an OR as `($e.A = 1 or $e.B = 2)` and this
    # function could not read it back: the whole line went to
    # `_split_operator`, which found no top-level operator inside the
    # brackets and refused with "neither a comparison nor a function call".
    # The renderer was emitting text its own parser rejected, and nothing
    # noticed because nothing re-read the output.
    if body.startswith("(") and _closes_at_end(body):
        inner = _predicate(body[1:-1], event_vars, placeholders, seen)
        if inner is None:
            raise Refusal(
                "YARAL_GROUP_EMPTY",
                f"`{body}` groups nothing. An empty group is not a test, and "
                f"reading it as one would pass every event.",
                "lower",
            )
        return Not(inner) if negate else inner

    disjuncts = _split_top(body, " or ")
    if len(disjuncts) > 1:
        operands = []
        for part in disjuncts:
            parsed = _predicate(part, event_vars, placeholders, seen)
            if parsed is None:
                raise Refusal(
                    "YARAL_DISJUNCT_IS_A_BINDING",
                    f"`{part.strip()}` is one side of an `or` and it binds a "
                    f"variable rather than testing anything. A binding inside "
                    f"a disjunction would make the whole branch true for "
                    f"every event.",
                    "lower",
                )
            operands.append(parsed)
        joined: Expr = BoolOp("or", tuple(operands))
        return Not(joined) if negate else joined

    conjuncts = _split_top(body, " and ")
    if len(conjuncts) > 1:
        operands = []
        for part in conjuncts:
            parsed = _predicate(part, event_vars, placeholders, seen)
            if parsed is not None:
                operands.append(parsed)
        if not operands:
            return None
        joined = operands[0] if len(operands) == 1 else BoolOp(
            "and", tuple(operands)
        )
        return Not(joined) if negate else joined

    call = _call(body, event_vars)
    if call is not None:
        return Not(call) if negate else call

    split = _split_operator(body)
    if split is None:
        raise Refusal(
            "YARAL_PREDICATE_UNREADABLE",
            f"`{body}` in `events:` is neither a comparison nor a function "
            f"call. A bare field name is not a test, and reading it as one "
            f"would pass every event where the field merely exists.",
            "lower",
        )

    left, operator, right = split

    if _is_placeholder(right):
        # A BINDING, not a test. See `_is_placeholder`.
        if operator != "==":
            raise Refusal(
                "YARAL_PLACEHOLDER_COMPARISON",
                f"`{body}` compares a field with the variable `{right}` using "
                f"`{operator}`. A placeholder is bound with `=` and nothing "
                f"else; any other operator would be a test against a value "
                f"that has not been decided yet.",
                "lower",
            )
        reference = _field(left, event_vars, seen)
        existing = placeholders.get(right)
        if existing is not None and existing != reference:
            # The same variable bound to two different fields is a JOIN
            # between them. Keeping only one silently drops the other half.
            return Comparison("==", reference, existing)
        placeholders[right] = reference
        return None

    if _is_placeholder(left):
        raise Refusal(
            "YARAL_PLACEHOLDER_ON_THE_LEFT",
            f"`{body}` puts the variable on the left. YARA-L binds with "
            f"`<field> = $var`, and the reversed form would read as a test "
            f"against a variable that is not bound yet.",
            "lower",
        )

    # Function predicates can appear on the left of a comparison, for example
    # `strings.to_lower($e.user.name) = "admin"`.  Treating the whole call as a
    # field made the renderer's own output fail to parse on the next pass and
    # silently turned a supported expression into a refusal.
    reference = _call(left, event_vars)
    if reference is None:
        reference = _field(left, event_vars, seen)
    value = _value(right)

    if isinstance(value, Regex):
        return Comparison("matches", reference, value, negate=negate)
    if isinstance(value, ListExpr):
        return Comparison("in", reference, value, negate=negate)
    return Comparison(operator, reference, value, negate=negate)


# ---------------------------------------------------------------------------
# Lower: sections
# ---------------------------------------------------------------------------


def _lower_match(
    text: str, placeholders: dict[str, FieldRef]
) -> tuple[list[FieldRef], Duration | None]:
    """`match: $host, $user over 5m` as group keys and a window."""
    body = text.strip()
    if not body:
        return [], None
    window: Duration | None = None
    lowered = body.lower()
    if " over " in lowered:
        cut = lowered.rindex(" over ")
        window = _duration(body[cut + 6:])
        body = body[:cut]
    keys: list[FieldRef] = []
    for part in split_top_level(body, ","):
        name = part.strip()
        if not name:
            continue
        reference = placeholders.get(name)
        if reference is None:
            raise Refusal(
                "YARAL_MATCH_UNBOUND",
                f"`match:` groups on `{name}`, which no line in `events:` "
                f"binds. Grouping on a variable that was never assigned means "
                f"grouping on nothing, and a threshold with nothing to group "
                f"on counts across the whole estate.",
                "lower",
            )
        keys.append(reference)
    return keys, window


@dataclass(frozen=True, slots=True)
class _Threshold:
    variable: str
    minimum: int
    strict: bool


@dataclass(frozen=True, slots=True)
class _OutcomeTest:
    """One `$name <op> <number>` from `condition:`.

    `condition:` constrains the `outcome:` aggregates as well as the event
    count, and only the count was ever read. `condition: #e >= 5 and $cnt >= 3`
    lowered with no diagnostics and no filter after the aggregate, so a
    password-spray rule written to require three distinct source IPs fired on
    one -- the exported YARA-L would do the same in SecOps.
    """

    variable: str
    operator: str
    value: Decimal


#: The comparisons an `outcome:` test may use. All six are plain orderings or
#: equalities, so no inversion is needed and nothing has to be rewritten.
_OUTCOME_OPERATORS: Final[frozenset[str]] = frozenset(
    (">", ">=", "<", "<=", "==", "!=")
)


def _lower_condition(
    text: str, outcome_names: frozenset[str] = frozenset()
) -> tuple[_Threshold | None, tuple[_OutcomeTest, ...]]:
    """`condition:` split into the event-count threshold and the outcome tests.

    `#e` is a COUNT. Read as a field reference it becomes a comparison against
    an absent column and the threshold stops applying. `$name` is an `outcome:`
    aggregate, and it was not read AT ALL: the old version returned on the first
    `#e` it found, so every `$name` test after it disappeared without a word.
    """
    body = text.strip()
    if not body:
        raise Refusal(
            "YARAL_NO_CONDITION",
            "this rule has no `condition:`. YARA-L requires one, and assuming "
            "`$e` would invent a condition the author did not write.",
            "lower",
        )
    threshold: _Threshold | None = None
    outcome_tests: list[_OutcomeTest] = []
    for part in re.split(r"\band\b", body, flags=re.I):
        piece = part.strip().strip("()").strip()
        split = _split_operator(piece)
        if split is None:
            continue
        left, operator, right = split
        count = _COUNT_REF.match(left.strip())
        if count is None:
            # An `outcome:` aggregate test. A `$e`-style event reference has no
            # operator of its own and never reaches here; anything else keeps
            # the old behaviour rather than inventing a meaning for it.
            name = left.strip()
            if name.startswith("$") and name[1:] in outcome_names:
                outcome_tests.append(
                    _outcome_test(piece, name[1:], operator, right)
                )
            continue
        if threshold is not None:
            raise Refusal(
                "YARAL_THRESHOLD_REPEATED",
                f"`condition:` thresholds the event count more than once "
                f"(`{piece}`). Only one count can be the threshold, and "
                f"picking one of them silently would drop the other.",
                "lower",
            )
        if operator not in (">", ">="):
            raise Refusal(
                "YARAL_THRESHOLD_DIRECTION",
                f"`{piece}` thresholds the event count with `{operator}`. The "
                f"model expresses a threshold as a minimum, so an upper bound "
                f"or an equality would have to be inverted -- and inverting it "
                f"silently would change which events fire the rule.",
                "lower",
            )
        try:
            minimum = int(Decimal(right.strip()))
        except Exception:
            raise Refusal(
                "YARAL_THRESHOLD_NOT_A_NUMBER",
                f"`{piece}` compares the event count with `{right.strip()}`, "
                f"which is not a number.",
                "lower",
            ) from None
        threshold = _Threshold(
            variable=count.group(1), minimum=minimum, strict=operator == ">"
        )
    return threshold, tuple(outcome_tests)


def _outcome_test(
    piece: str, variable: str, operator: str, right: str
) -> _OutcomeTest:
    """One validated `$name <op> <number>`."""
    if operator not in _OUTCOME_OPERATORS:
        raise Refusal(
            "YARAL_OUTCOME_TEST_OPERATOR",
            f"`{piece}` tests the outcome `{variable}` with `{operator}`. "
            f"YARA-L's `condition:` compares an outcome with > >= < <= == or "
            f"!=, and anything else is not a test this model can write back.",
            "lower",
        )
    try:
        value = Decimal(right.strip())
    except Exception:
        raise Refusal(
            "YARAL_OUTCOME_TEST_NOT_A_NUMBER",
            f"`{piece}` compares the outcome `{variable}` with "
            f"`{right.strip()}`, which is not a number.",
            "lower",
        ) from None
    return _OutcomeTest(variable=variable, operator=operator, value=value)


def _outcome_condition(tests: tuple[_OutcomeTest, ...]) -> Expr:
    """The post-aggregate filter the outcome tests describe."""
    comparisons: list[Expr] = [
        Comparison(
            test.operator,
            FieldRef(name=test.variable),
            Literal(test.value),
        )
        for test in tests
    ]
    if len(comparisons) == 1:
        return comparisons[0]
    return BoolOp("and", tuple(comparisons))



def _lower_outcome(
    lines: tuple[str, ...], event_vars: set[str]
) -> list[Measure]:
    measures: list[Measure] = []
    for line in lines:
        body = line.strip().rstrip(",")
        if not body:
            continue
        name, found, expression = body.partition("=")
        if not found:
            raise Refusal(
                "YARAL_OUTCOME_NOT_AN_ASSIGNMENT",
                f"`{body}` in `outcome:` is not a `$name = aggregate(...)` "
                f"assignment.",
                "lower",
            )
        name = name.strip().lstrip("$")
        expression = expression.strip()
        open_paren = expression.find("(")
        if open_paren < 0 or not expression.endswith(")"):
            raise Refusal(
                "YARAL_OUTCOME_NOT_AN_AGGREGATE",
                f"`{expression}` is not an aggregate call. An `outcome:` entry "
                f"summarises the matched events, so a plain value there would "
                f"be a column the rule never computed.",
                "lower",
            )
        function = expression[:open_paren].strip().lower()
        spec = OUTCOME_FUNCTIONS.get(function)
        if spec is None:
            raise Refusal(
                "YARAL_OUTCOME_FUNCTION_UNKNOWN",
                f"`{function}()` is not an aggregate this tool models. "
                f"Reporting a different number than the rule asked for is "
                f"worse than refusing.",
                "lower",
            )
        mapped, distinct = spec
        argument = expression[open_paren + 1:-1].strip()
        reference: FieldRef | None = None
        if argument and argument != "*":
            if _EVENT_FIELD.match(argument):
                reference = _field(argument, event_vars)
            else:
                raise Refusal(
                    "YARAL_OUTCOME_ARGUMENT",
                    f"`{argument}` is not a UDM field, so there is nothing to "
                    f"aggregate over.",
                    "lower",
                )
        measures.append(Measure(
            function=mapped, name=name, field=reference, distinct=distinct
        ))
    return measures


def _annotations(
    meta: dict[str, str], fallback: str
) -> tuple[Annotations, set[str]]:
    """`meta:` as Annotations, plus the keys that were consumed.

    The consumed set matters: a key folded into `Annotations` must NOT also be
    kept in `Rule.metadata`, or rendering writes it twice and the round-tripped
    rule grows a duplicate `mitre_attack_tactic` line every pass.
    """
    values: dict[str, Any] = {
        "title": fallback,
        "description": "",
        "severity": "",
        "author": "",
    }
    consumed: set[str] = set()
    techniques: list[str] = []
    tactics: list[str] = []
    references: list[str] = []
    for key, value in meta.items():
        lowered = key.lower()
        mapped = META_FIELDS.get(lowered)
        if mapped:
            values[mapped] = value
            consumed.add(key)
        elif "technique" in lowered:
            techniques.extend(p.strip() for p in value.split(",") if p.strip())
            consumed.add(key)
        elif "tactic" in lowered:
            tactics.extend(p.strip() for p in value.split(",") if p.strip())
            consumed.add(key)
        elif "reference" in lowered or lowered in ("url", "docs"):
            references.append(value)
            consumed.add(key)
    attack: tuple[tuple[str, tuple[str, ...]], ...] = ()
    if tactics or techniques:
        attack = tuple(
            (tactic, tuple(techniques)) for tactic in (tactics or [""])
        )
    return (
        Annotations(
            title=values["title"],
            description=values["description"],
            severity=values["severity"],
            author=values["author"],
            mitre_attack=attack,
            references=tuple(references),
        ),
        consumed,
    )


def _owner(
    predicate: Expr, before: set[str], after: set[str]
) -> str | None:
    """Which event variable a predicate tests.

    The variable is whichever `$name.` prefix the predicate's fields carry.
    `before`/`after` catch the case where this line was the FIRST mention of a
    variable, so the predicate itself has no field to inspect.
    """
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, FieldRef) and node.name in after:
            found.add(node.name)
        elif isinstance(node, BoolOp):
            for operand in node.operands:
                walk(operand)
        elif isinstance(node, Not):
            walk(node.operand)
        elif isinstance(node, (Comparison, Arith)):
            walk(node.left)
            walk(node.right)
        elif isinstance(node, Call):
            for argument in node.args:
                walk(argument)
        elif isinstance(node, ListExpr):
            for item in node.items:
                walk(item)
        elif isinstance(node, Span):
            walk(node.value)

    walk(predicate)
    if len(found) == 1:
        return next(iter(found))
    if not found:
        introduced = after - before
        if len(introduced) == 1:
            return next(iter(introduced))
    return None


def _lower_join(
    parsed: ParsedYaraL,
    rule_id: str,
    predicates: list[Expr],
    owners: list[str | None],
    event_vars: set[str],
    placeholders: dict[str, FieldRef],
    diagnostics: list[Diagnostic],
) -> tuple[Rule, list[Diagnostic]]:
    """A multi-variable YARA-L rule as a real Join between streams.

    `$lsass` and `$login` are two streams; flattening them into one predicate
    tests both sets of conditions against the SAME event, which matches
    almost nothing. Each variable becomes a Binding with its own Read and
    Filter, the first becomes the main stream, and a Join matches the rest on
    the variables they share.
    """
    variables = sorted(event_vars)

    grouped: dict[str, list[Expr]] = {name: [] for name in variables}
    unowned: list[Expr] = []
    for predicate, owner in zip(predicates, owners):
        if owner is None:
            unowned.append(predicate)
        else:
            grouped.setdefault(owner, []).append(predicate)

    if unowned:
        raise Refusal(
            "YARAL_PREDICATE_SPANS_EVENTS",
            f"{len(unowned)} predicate(s) mix fields from more than one event "
            f"variable. That is not a correlation between events; it tests one "
            f"event as though it were both, and no stream can satisfy it.",
            "lower",
        )

    if set(variables) != set(grouped):
        raise Refusal(
            "YARAL_EVENT_VARIABLE_UNUSED",
            "an event variable in this rule is bound but never tested.",
            "lower",
        )

    for name in variables:
        if not grouped[name]:
            raise Refusal(
                "YARAL_EVENT_VARIABLE_UNEMPTY",
                f"event variable `${name}` is never narrowed by a predicate. A "
                f"stream with no filter joins on every event it sees, which "
                f"turns the correlation into an unconditional cross product.",
                "lower",
            )

    keys, window = _lower_match(parsed.match, placeholders)

    # A shared placeholder IS the join condition. `$lsass.principal.hostname
    # = $host` and `$login.principal.hostname = $host` say the two events must
    # agree on the host -- the common shape in real YARA-L correlation rules,
    # which usually carries no `match:` section at all. Dropping that would
    # join every LSASS event to every logon.
    if not keys:
        keys = _shared_placeholder_keys(parsed, variables)

    if not keys:
        raise Refusal(
            "YARAL_JOIN_WITHOUT_MATCH",
            "this rule correlates "
            f"{len(variables)} event variables but `match:` names no field to "
            "join them on. Without a key the two streams are related only by "
            "time, which is not a correlation an analyst wrote.",
            "lower",
        )

    time_field = "metadata.event_timestamp"
    main_name, *rest = variables

    bindings: list[Binding] = []
    for index, name in enumerate(variables):
        conditions = grouped[name]
        condition = conditions[0] if len(conditions) == 1 \
            else BoolOp("and", tuple(conditions))
        bindings.append(Binding(
            name=f"stream_{name}",
            pipeline=(
                Read(
                    id=f"read_{name}",
                    table=DEFAULT_TABLE,
                    time_field=time_field,
                ),
                Filter(id=f"filter_{name}", condition=condition),
                Emit(id=f"emit_{name}"),
            ),
        ))

    # The window, as a REAL predicate on the join. Carrying it only in metadata
    # meant the evaluated rule was an unbounded all-time join: two events ten
    # days apart on the same host satisfied a rule that said `over 10m`. The
    # span is symmetric because YARA-L's `over` bounds the whole match window,
    # so either event may come first -- which is also why the ordering caveat
    # below is about ORDER, not about the window.
    window_predicate: Expr | None = None
    if window is not None:
        left_time = FieldRef(name="metadata", path=("event_timestamp",),
                             scope="left")
        right_time = FieldRef(name="metadata", path=("event_timestamp",),
                              scope="right")
        window_predicate = Span(
            left_time,
            Arith("-", right_time, Literal(window.seconds)),
            Arith("+", right_time, Literal(window.seconds)),
        )

    nodes: list[Node] = [
        Read(
            id="source",
            table=f"stream_{main_name}",
            time_field=time_field,
        ),
    ]
    for name in rest:
        nodes.append(Join(
            id=f"join_{name}",
            left="source" if len(nodes) == 1 or not _has_join(nodes) else
            _last_join(nodes),
            right=f"stream_{name}",
            how="inner",
            on=tuple(
                (key, FieldRef(name=key.name, path=key.path, scope="right"))
                for key in keys
            ),
            predicate=window_predicate,
        ))



    nodes.append(Emit(id="out"))

    annotations, consumed = _annotations(parsed.meta, parsed.name)
    metadata = {
        "dialect": DIALECT,
        "language": LANGUAGE,
        "artifact": "rule",
        "chronicle.rule_name": parsed.name,
        "chronicle.event_vars": ",".join(variables),
        "chronicle.match_vars": ",".join(
            name for name, reference in placeholders.items()
            if reference in keys
        ),
    }
    if window is not None:
        # `match: $host over 10m` bounds the correlation, and it was parsed
        # and then dropped on the floor: the rendered rule lost its `over`
        # clause and became an all-time join. It is carried here so the
        # renderer writes it back out.
        metadata["chronicle.window"] = f"{int(window.seconds)}s"

    for key, value in parsed.meta.items():
        if key not in consumed:
            metadata[f"chronicle.meta.{key}"] = value

    diagnostics.append(Diagnostic(
        code="YARAL_EVENT_ORDER_UNCONSTRAINED",
        message=(
            "the two event streams are joined on their shared fields"
            + (
                f" and bounded by `over {int(window.seconds)}s`, which IS "
                f"applied to your sample"
                if window is not None
                else ""
            )
            + ", but YARA-L's ORDERING (`$lsass.metadata.event_timestamp <= "
            "$login.metadata.event_timestamp`) is not modelled here: the window "
            "is symmetric, so either event may come first. Add the directional "
            "clause in the target SIEM if the rule needs one."
        ),
        severity="caution",
        verified=True,
    ))

    rule = Rule(
        rule_id=rule_id,
        pipeline=tuple(nodes),
        bindings=tuple(bindings),
        annotations=annotations,
        metadata=metadata,
    )
    validate(rule)
    return rule, diagnostics


_BINDING_LINE = re.compile(
    r"^\s*(?P<field>\$[\w.]+)\s*=\s*(?P<var>\$[A-Za-z_]\w*)\s*$"
)


def _shared_placeholder_keys(
    parsed: ParsedYaraL, variables: list[str]
) -> list[FieldRef]:
    """Fields that two event variables both bind to the same `$placeholder`.

    Reads the raw `events:` lines because the placeholder map keeps only the
    LAST field bound to a name -- the second binding is what makes it a join,
    and by the time `_predicate` has seen it the first is gone.

    Returns one field per shared binding. A variable that binds a placeholder
    another variable does not share contributes nothing: that is a filter on
    that stream's own field, already expressed by the predicate.
    """
    binds: dict[str, list[tuple[str, str]]] = {}
    for line in parsed.events:
        match = _BINDING_LINE.match(line.strip().rstrip(","))
        if match is None:
            continue
        field = match.group("field")
        variable = match.group("var").lstrip("$")
        event = _EVENT_FIELD.match(field)
        if event is None:
            continue
        binds.setdefault(variable, []).append((event.group(1), event.group(2)))

    # Group by the VARIABLE (the shared `$host`), then by the UDM path. Two
    # streams binding `$host` to `principal.hostname` agree on the host even
    # though each spells it with its own event prefix -- the prefix names the
    # stream, not the field.
    shared: dict[str, dict[str, set[str]]] = {}
    for variable, fields in binds.items():
        for event_name, path in fields:
            shared.setdefault(variable, {}).setdefault(path, set()).add(
                event_name
            )

    keys: list[FieldRef] = []
    seen: set[str] = set()
    for variable, paths in shared.items():
        for path, events in paths.items():
            if len(events) < 2 or path in seen:
                continue
            seen.add(path)
            parts = path.split(".")
            keys.append(FieldRef(name=parts[0], path=tuple(parts[1:])))
    return keys


def _has_join(nodes: list[Node]) -> bool:
    return any(isinstance(node, Join) for node in nodes)


def _last_join(nodes: list[Node]) -> str:
    return next(
        node.id for node in reversed(nodes) if isinstance(node, Join)
    )


def lower_chronicle(
    text: str, rule_id: str = "rule"
) -> tuple[Rule, list[Diagnostic]]:
    """YARA-L text to a Rule, plus what could not be represented."""
    parsed = parse_chronicle(text)
    diagnostics: list[Diagnostic] = []

    event_vars: set[str] = set()
    placeholders: dict[str, FieldRef] = {}
    predicates: list[Expr] = []
    #: Which event variable each predicate belongs to.
    #:
    #: A multi-variable rule is a JOIN between streams, and the join is what
    #: makes it a correlation search rather than a filter. Keeping the owner
    #: per predicate is what lets each variable lower to its own Binding.
    owners: list[str | None] = []

    for line in parsed.events:
        mentioned: set[str] = set()
        predicate = _predicate(line, event_vars, placeholders, mentioned)
        if predicate is not None:
            predicates.append(predicate)
            owners.append(
                next(iter(mentioned)) if len(mentioned) == 1 else None
            )

    if len(event_vars) > 1:
        return _lower_join(
            parsed, rule_id, predicates, owners, event_vars, placeholders,
            diagnostics,
        )

    if not predicates:
        # An aggregate with a grouping key has no per-event test to state: the
        # detection IS the count. The IR holds that shape (a Read, an
        # Aggregate and a post-aggregate Filter), so refusing to read it back
        # made the renderer's own output unparseable. It is allowed only with
        # BOTH an `outcome:` and a `match:` -- without them the rule really
        # would count every event in the stream with nothing to group on --
        # and it is reported rather than passed quietly.
        if parsed.outcome and parsed.match:
            diagnostics.append(Diagnostic(
                code="YARAL_NO_EVENT_PREDICATE",
                message=(
                    "`events:` names no test, so this rule counts EVERY event "
                    "in the stream and groups the count by `match:`. That is "
                    "what a bare `outcome:` aggregate means; add a predicate to "
                    "`events:` if the count should be narrower."
                ),
                severity="caution",
                verified=True,
            ))
        else:
            raise Refusal(
                "YARAL_NO_PREDICATES",
                "this rule's `events:` section tests nothing: every line binds a "
                "variable. A rule with no test matches every event in the stream.",
                "lower",
            )

    if parsed.options:
        diagnostics.append(Diagnostic(
            code="YARAL_OPTIONS_DROPPED",
            message=(
                f"`options:` ({'; '.join(parsed.options)}) tunes how SecOps "
                f"runs the rule rather than what it matches, so it is not "
                f"modelled. The detection logic is kept."
            ),
            severity="note",
            verified=True,
        ))

    keys, window = _lower_match(parsed.match, placeholders)
    measures = _lower_outcome(parsed.outcome, event_vars)
    threshold, outcome_tests = _lower_condition(
        parsed.condition, frozenset(m.name for m in measures)
    )

    nodes: list[Node] = [
        Read(
            id="source",
            table=DEFAULT_TABLE,
            # The timestamp is declared ONLY when the rule actually depends on
            # time. Declaring it unconditionally made every single-event rule
            # report `not_evaluated` against any sample without a
            # `metadata.event_timestamp`, because the engine correctly warns
            # that it cannot place rows in a window -- a true statement about a
            # window this rule does not have. A rule with no `over` clause
            # needs no clock, and saying otherwise buries the real caveats.
            time_field=(
                "metadata.event_timestamp" if window is not None else ""
            ),
        ),
    ]
    if predicates:
        # An aggregate-only rule has no per-event test at all, and inventing an
        # always-true Filter for it is refused by `BoolOp`. Its detection IS
        # the count, which the Aggregate and the outcome test below express.
        nodes.append(Filter(
            id="events",
            condition=predicates[0] if len(predicates) == 1
            else BoolOp("and", tuple(predicates)),
        ))

    if threshold is not None:
        if not keys:
            raise Refusal(
                "YARAL_THRESHOLD_WITHOUT_MATCH",
                f"`#{threshold.variable} > {threshold.minimum}` counts events "
                f"but `match:` names nothing to group them by. A count with "
                f"nothing to group on is 'anywhere in the log', so a rule "
                f"written to catch repeats against ONE host would fire on "
                f"repeats spread across the estate.",
                "lower",
            )
        if window is None:
            raise Refusal(
                "YARAL_THRESHOLD_WITHOUT_WINDOW",
                f"`#{threshold.variable} > {threshold.minimum}` counts events "
                f"but `match:` gives no `over <duration>`. A threshold with no "
                f"window counts over all time, which fires on slow background "
                f"noise rather than on a burst.",
                "lower",
            )
        # `> N` is STRICT and `Correlation.frequency` fires at `>=`. Copying
        # the number across makes the rule fire one event early.
        frequency = threshold.minimum + 1 if threshold.strict \
            else threshold.minimum
        nodes.append(Correlation(
            id="threshold",
            parent="events",
            frequency=frequency,
            timeframe=window,
            group_by=tuple(keys),
        ))

    if measures:
        nodes.append(Aggregate(
            id="outcome", measures=tuple(measures), keys=tuple(keys)
        ))
        if outcome_tests:
            # `$cnt >= 3` is a test on the OUTCOME, so it runs after the
            # aggregate. Dropping it let a rule written to need three distinct
            # source IPs fire on one, with no diagnostic to say so.
            nodes.append(Filter(
                id="outcome_test",
                condition=_outcome_condition(outcome_tests),
            ))
    elif outcome_tests:
        raise Refusal(
            "YARAL_OUTCOME_TEST_WITHOUT_OUTCOME",
            f"`condition:` tests `{'$' + outcome_tests[0].variable}`, but "
            f"there is no `outcome:` section that computes it. Testing a value "
            f"the rule never calculates would compare against nothing and pass "
            f"every event.",
            "lower",
        )
    elif keys and threshold is None:
        diagnostics.append(Diagnostic(
            code="YARAL_MATCH_WITHOUT_THRESHOLD",
            message=(
                "`match:` groups the events but the condition sets no count, "
                "so the grouping narrows nothing. The rule fires on a single "
                "matching event."
            ),
            severity="caution",
            verified=True,
        ))

    nodes.append(Emit(id="out"))

    annotations, consumed = _annotations(parsed.meta, parsed.name)

    metadata = {
        "dialect": DIALECT,
        "language": LANGUAGE,
        "artifact": "rule",
        "chronicle.rule_name": parsed.name,
    }
    # The analyst's own variable names. Derived names are stable but not the
    # ones they wrote, and a round trip that renames `$host` to `$hostname`
    # makes a save look like an edit.
    if keys:
        metadata["chronicle.match_vars"] = ",".join(
            name for name, reference in placeholders.items()
            if reference in keys
        )
    for key, value in parsed.meta.items():
        if key not in consumed:
            metadata[f"chronicle.meta.{key}"] = value

    rule = Rule(
        rule_id=rule_id,
        pipeline=tuple(nodes),
        bindings=(),
        annotations=annotations,
        metadata=metadata,
    )
    validate(rule)
    return rule, diagnostics


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def _render_value(value: Any) -> str:
    if value is None:
        return '""'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Decimal):
        return plain_number(value)
    if isinstance(value, (int, float)):
        return str(value)
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _render_outcome_test(expr: Expr) -> str:
    """A post-aggregate filter as a `condition:` test on an outcome name.

    `condition:` is the only place YARA-L can test an `outcome:` value, so a
    Filter that sits after the Aggregate has to be written back there. Putting
    it in `events:` would apply it per event -- the opposite of what it says.
    """
    tests: list[Expr]
    if isinstance(expr, BoolOp) and expr.op == "and":
        tests = list(expr.operands)
    else:
        tests = [expr]
    parts: list[str] = []
    for test in tests:
        if not isinstance(test, Comparison) or test.negate:
            raise Refusal(
                "YARAL_RENDER_OUTCOME_TEST",
                f"`{render_expr(test)}` runs after the aggregate but is not a "
                f"plain comparison against an outcome. YARA-L can only write "
                f"`$name <op> <number>` there, and writing this as something "
                f"else would change which events fire the rule.",
                "render",
            )
        if not isinstance(test.left, FieldRef) or not isinstance(
            test.right, Literal
        ):
            raise Refusal(
                "YARAL_RENDER_OUTCOME_TEST",
                f"`{render_expr(test)}` compares something other than an "
                f"outcome name with a constant. `condition:` cannot express "
                f"that, and dropping it would delete the test.",
                "render",
            )
        if test.op not in _OUTCOME_OPERATORS:
            raise Refusal(
                "YARAL_RENDER_OUTCOME_TEST",
                f"`{render_expr(test)}` uses `{test.op}`, which is not one of "
                f"the comparisons `condition:` allows on an outcome.",
                "render",
            )
        parts.append(
            f"${test.left.full} {test.op} {_render_value(test.right.value)}"
        )
    return " and ".join(parts)


def _render_field(ref: FieldRef, event: str) -> str:
    """A UDM field path.

    YARA-L has NO quoting syntax for a path segment, so an irregular name
    cannot be written at all -- `_EVENT_FIELD` requires ASCII and refused the
    renderer's own output with YARAL_NOT_A_FIELD.
    """
    path = ".".join((ref.name,) + tuple(ref.path))
    if not is_bare_identifier(path):
        raise Refusal(
            "YARAL_RENDER_FIELD_NOT_AN_IDENTIFIER",
            f"`{path}` is not a UDM field path: those are ASCII letters, "
            f"digits and underscores separated by dots. YARA-L has no way to "
            f"quote an irregular name, so there is nothing to write -- map "
            f"the field onto a UDM path first.",
            "render",
        )
    return f"${event}.{path}"


_RENDER_OPS: Final[dict[str, str]] = {
    "==": "=", "!=": "!=", ">": ">", ">=": ">=", "<": "<", "<=": "<=",
}

_RENDER_FUNCTIONS: Final[dict[str, str]] = {
    "cidr_contains": "net.ip_in_range_cidr",
    "lower": "strings.to_lower",
    "upper": "strings.to_upper",
    "length": "strings.length",
    "coalesce": "strings.coalesce",
    "abs": "math.abs",
    "now": "timestamp.current_seconds",
    "matches_regex": "re.regex",
}


def _render_expression(expr: Expr, event: str, lines: list[str]) -> None:
    """One predicate as an `events:` line.

    `events:` lines are implicitly ANDed, so a conjunction becomes several
    lines rather than one. Every branch ends in a refusal: a silent `else`
    drops a line, and a rule with a line missing matches more events than the
    author wrote.
    """
    if isinstance(expr, BoolOp) and expr.op == "and":
        for operand in expr.operands:
            _render_expression(operand, event, lines)
        return
    lines.append(_render_inline(expr, event))


def _render_inline(expr: Expr, event: str) -> str:
    if isinstance(expr, BoolOp):
        joiner = " or " if expr.op == "or" else " and "
        return "(" + joiner.join(
            _render_inline(o, event) for o in expr.operands
        ) + ")"
    if isinstance(expr, Not):
        return "not " + _render_inline(expr.operand, event)
    if isinstance(expr, Comparison):
        return _render_comparison(expr, event)
    if isinstance(expr, Call):
        return _render_call(expr, event)
    raise Refusal(
        "YARAL_RENDER_EXPRESSION",
        f"`{render_expr(expr)}` has no YARA-L spelling, so writing this rule "
        f"out would drop part of the condition.",
        "render",
    )


def _render_operand(expr: Expr, event: str) -> str:
    if isinstance(expr, FieldRef):
        return _render_field(expr, event)
    if isinstance(expr, Literal):
        return _render_value(expr.value)
    if isinstance(expr, Call):
        return _render_call(expr, event)
    raise Refusal(
        "YARAL_RENDER_OPERAND",
        f"`{render_expr(expr)}` cannot appear as an operand in YARA-L.",
        "render",
    )


#: Characters RE2 reads as syntax, so a literal containing one has to be
#: escaped before it can be written as a pattern.
#:
#: `/` is here because a YARA-L pattern is written BETWEEN SLASHES: an
#: unescaped `/` closes the literal early, and a leading one -- `/all` from
#: `CommandLine|contains: '/all'` -- produced `//all/`, which YARA-L reads as
#: a COMMENT. The rule then lost its predicate entirely and matched every
#: event. That broke seven Sigma rules in the cross-dialect corpus
#: (bitsadmin-download, mshta-remote, net-user-add, net-group-admin,
#: nltest-recon, linux-sudo-shadow, linux-reverse-shell).
_REGEX_META: Final = frozenset("\\^$.*+?()[]{}|/")


def _escape_regex(value: Any) -> str:
    """A literal as an RE2 pattern that matches that literal and nothing else."""
    return "".join(
        "\\" + char if char in _REGEX_META else char for char in str(value)
    )



def _render_comparison(expr: Comparison, event: str) -> str:
    left = _render_operand(expr.left, event)

    if isinstance(expr.right, Regex):
        if expr.right.dialect != REGEX_DIALECT:
            raise Refusal(
                "YARAL_RENDER_REGEX_DIALECT",
                f"this pattern is {expr.right.dialect} and YARA-L uses RE2. "
                f"Writing it out unchanged would hand SecOps a pattern in a "
                f"syntax it reads differently.",
                "render",
            )
        suffix = " nocase" if expr.right.nocase else ""
        text = f"{left} = /{expr.right.pattern}/{suffix}"
        return f"not {text}" if expr.negate else text

    if expr.op == "in":
        if not isinstance(expr.right, ListExpr):
            raise Refusal(
                "YARAL_RENDER_IN_NOT_A_LIST",
                "a membership test needs a list of values.",
                "render",
            )
        items = ", ".join(
            _render_operand(item, event) for item in expr.right.items
        )
        text = f"{left} in [{items}]"
        return f"not {text}" if expr.negate else text

    if expr.op in ("contains", "startswith", "endswith"):
        if expr.nocase:
            # `strings.contains` is case-SENSITIVE, and YARA-L has no folded
            # variant by name. A regex with the `nocase` modifier is the
            # documented way to say it, and it round-trips through the parser.
            if not isinstance(expr.right, Literal) \
                    or not isinstance(expr.right.value, str):
                raise Refusal(
                    "YARAL_RENDER_NOCASE_NOT_LITERAL",
                    f"`{expr.op}` ignoring case needs a constant to fold, and "
                    f"`{render_expr(expr.right)}` is not one.",
                    "render",
                )
            body = _escape_regex(expr.right.value)
            # PREFIX and SUFFIX, not one anchor. `endswith` was written with
            # the `$` at the FRONT (`/$whoami\.exe/`), which is an end-of-input
            # assertion followed by text -- a pattern that cannot match
            # anything at all. The rule compiled, rendered and never fired.
            prefix, suffix = {
                "contains": ("", ""),
                "startswith": ("^", ""),
                "endswith": ("", "$"),
            }[expr.op]
            text = f"{left} = /{prefix}{body}{suffix}/ nocase"
            return f"not {text}" if expr.negate else text
        spelled = {
            "contains": "strings.contains",
            "startswith": "strings.starts_with",
            "endswith": "strings.ends_with",
        }[expr.op]
        text = f"{spelled}({left}, {_render_operand(expr.right, event)})"
        return f"not {text}" if expr.negate else text

    if expr.nocase and expr.op in ("==", "!="):
        # YARA-L's `nocase` modifier is the documented way to fold an
        # equality, and the parser reads it back as `Comparison.nocase`. Left
        # as a bare `=` the export was case-SENSITIVE, so `Image = "/bin/sh"`
        # missed `/BIN/SH` in SecOps while matching it locally.
        if not isinstance(expr.right, Literal) \
                or not isinstance(expr.right.value, str):
            raise Refusal(
                "YARAL_RENDER_NOCASE_NOT_LITERAL",
                f"`{expr.op}` ignoring case needs a constant to fold, and "
                f"`{render_expr(expr.right)}` is not one.",
                "render",
            )
        spelled = "=" if expr.op == "==" else "!="
        text = (f"{left} {spelled} {_render_operand(expr.right, event)} "
                f"nocase")
        return f"not ({text})" if expr.negate else text

    spelled = _RENDER_OPS.get(expr.op)
    if spelled is None:
        raise Refusal(
            "YARAL_RENDER_OPERATOR",
            f"`{expr.op}` has no YARA-L spelling. Rendering it as equality "
            f"would change what the rule matches.",
            "render",
        )
    text = f"{left} {spelled} {_render_operand(expr.right, event)}"
    return f"not ({text})" if expr.negate else text


def _render_call(call: Call, event: str) -> str:
    spelled = _RENDER_FUNCTIONS.get(call.function)
    if spelled is None:
        raise Refusal(
            "YARAL_RENDER_FUNCTION",
            f"`{call.function}()` has no YARA-L equivalent. Dropping it would "
            f"change what the expression computes.",
            "render",
        )
    arguments = ", ".join(_render_operand(a, event) for a in call.args)
    return f"{spelled}({arguments})"


def _render_measure(measure: Measure, event: str) -> str:
    inverse = {
        "count": "count", "dcount": "count_distinct", "max": "max",
        "min": "min", "sum": "sum", "avg": "avg", "values": "array_distinct",
        "make_list": "array",
    }
    name = inverse.get(measure.function.lower())
    if name is None:
        raise Refusal(
            "YARAL_RENDER_MEASURE",
            f"`{measure.function}` is not a YARA-L outcome aggregate. "
            f"Reporting a different number than the rule asked for is worse "
            f"than refusing.",
            "render",
        )
    if measure.field is None:
        # `count(1)` used to be emitted here, and `_lower_outcome` refuses it:
        # "`1` is not a UDM field". The renderer produced a rule its own
        # parser rejects, and nothing noticed because nothing re-read the
        # output.
        #
        # YARA-L's outcome aggregates all take a UDM field. A bare row count
        # has a different spelling entirely -- `#e` in `condition:` -- which
        # needs a threshold to compare against, and an aggregate with no
        # threshold has nothing to put there. So it is refused, with the
        # spelling named.
        #
        # NOTE: mapping it to `count($e.metadata.event_type)` was tried and
        # reverted. It renders, but the round trip then merges the two Filters
        # of a threshold rule into one, and
        # `test_fidelity.RenderedOutputCanBeReadBack` rejects the change of
        # stage shape. That mismatch is a decision about how much shape the
        # round trip must preserve, not something to paper over here.
        raise Refusal(
            "YARAL_RENDER_COUNT_WITHOUT_A_FIELD",
            f"`{measure.name}` counts rows rather than values, and every "
            f"YARA-L outcome aggregate takes a UDM field. The row count is "
            f"spelled `#{event}` in `condition:`, which needs a threshold to "
            f"compare against -- this aggregation states none, so there is "
            f"nothing to write. Give the count a field, or give the rule a "
            f"threshold.",
            "render",
        )
    return f"    ${measure.name} = {name}({_render_field(measure.field, event)})"


def _render_duration(duration: Duration) -> str:
    seconds = int(duration.seconds)
    for suffix, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0 and seconds >= size:
            return f"{seconds // size}{suffix}"
    return f"{seconds}s"


def _rule_name(raw: str) -> str:
    """A YARA-L rule name, which must be an identifier.

    A Wazuh rule whose id is `100` rendered as `rule 100 {`, and
    `parse_chronicle` then refused the result with "this text has no
    `rule <name> {` block" -- because `_RULE_HEAD` requires a leading letter
    or underscore, as YARA-L does. The renderer was emitting a block its own
    parser could not find.

    Prefixed rather than renamed, so the original id stays readable in the
    output instead of being replaced by a counter.
    """
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", raw.strip()) or "rule"
    if not re.match(r"^[A-Za-z_]", cleaned):
        cleaned = f"rule_{cleaned}"
    return cleaned


def render_chronicle(rule: Rule) -> str:
    """Write a Rule back out as a YARA-L rule block.

    A stage that cannot be placed is refused rather than skipped: a YARA-L
    rule missing its `match:` or its count still compiles in SecOps, runs, and
    fires on a single event where the author asked for a burst.
    """
    meta = rule.metadata
    event = "e"

    joins = [node for node in rule.pipeline if isinstance(node, Join)]
    if joins:
        return _render_join(rule, meta)

    condition_lines: list[str] = []
    correlation: Correlation | None = None
    aggregate: Aggregate | None = None
    outcome_tests: list[str] = []

    for node in rule.pipeline:
        if isinstance(node, Read):
            continue
        if isinstance(node, Filter):
            if aggregate is None:
                _render_expression(node.condition, event, condition_lines)
            else:
                # It runs AFTER the aggregate, so it tests an outcome rather
                # than an event. Writing it into `events:` would apply it per
                # event, which is the opposite of what it says.
                outcome_tests.append(_render_outcome_test(node.condition))
            continue
        if isinstance(node, Correlation):
            correlation = node
            continue
        if isinstance(node, Aggregate):
            aggregate = node
            continue
        if isinstance(node, Emit):
            continue
        raise Refusal(
            "YARAL_RENDER_STAGE",
            f"a `{type(node).__name__}` stage has no YARA-L section. Writing "
            f"the rule without it would produce one that compiles and matches "
            f"a different set of events.",
            "render",
        )

    if rule.bindings:
        raise Refusal(
            "YARAL_RENDER_BINDINGS",
            "YARA-L has no named sub-queries. Writing only the main stream "
            "would drop whatever the bindings constrained.",
            "render",
        )

    # `events:` is filled either by the event predicates or, when a rule is
    # purely an AGGREGATE, by the `match:` key bindings inserted further down.
    # Refusing on an empty `condition_lines` alone rejected a valid
    # `stats dc(user) by src` rule, whose only test runs after the aggregate.
    #
    # Deliberately NOT relaxed for a bare Correlation: `Read -> Correlation ->
    # Emit` has no event test to write, so rendering it produced YARA-L with an
    # `events:` section holding nothing but a binding -- text this parser then
    # refused, which turned an honest "I cannot write this" into a broken
    # round trip.
    aggregate_keys = aggregate.keys if aggregate is not None else ()
    if not condition_lines and not aggregate_keys:
        raise Refusal(
            "YARAL_RENDER_NO_EVENTS",
            "this rule has no filter stage, so its `events:` section would be "
            "empty -- and a YARA-L rule with no predicate matches every event "
            "in the stream.",
            "render",
        )


    name = _rule_name(
        meta.get("chronicle.rule_name") or rule.rule_id or "rule"
    )
    out: list[str] = [f"rule {name} {{"]

    annotations = rule.annotations
    meta_lines: list[str] = []
    if annotations.author:
        meta_lines.append(f'    author = "{annotations.author}"')
    if annotations.description:
        meta_lines.append(f'    description = "{annotations.description}"')
    if annotations.severity:
        meta_lines.append(f'    severity = "{annotations.severity}"')
    for tactic, techniques in annotations.mitre_attack:
        if tactic:
            meta_lines.append(f'    mitre_attack_tactic = "{tactic}"')
        if techniques:
            meta_lines.append(
                f'    mitre_attack_technique = "{", ".join(techniques)}"'
            )
    for reference in annotations.references:
        meta_lines.append(f'    reference = "{reference}"')
    for key, value in meta.items():
        if key.startswith("chronicle.meta."):
            meta_lines.append(
                f'    {key[len("chronicle.meta."):]} = "{value}"'
            )
    if meta_lines:
        out.append("  meta:")
        out.extend(meta_lines)

    out.append("  events:")
    out.extend(f"    {line}" for line in condition_lines)

    keys = correlation.group_by if correlation else (
        aggregate.keys if aggregate else ()
    )
    if keys:
        # The placeholders are re-declared in `events:`, because `match:` can
        # only group on a variable something bound. The analyst's own names are
        # used when the rule carries them, so a round trip does not rename
        # `$host` to `$hostname` and make a save look like an edit.
        saved = [
            part for part in
            (meta.get("chronicle.match_vars") or "").split(",") if part
        ]
        names = [
            saved[index].lstrip("$") if index < len(saved)
            else _placeholder_name(key)
            for index, key in enumerate(keys)
        ]
        bindings = [
            f"    {_render_field(key, event)} = ${name}"
            for key, name in zip(keys, names)
        ]
        out[out.index("  events:") + 1:out.index("  events:") + 1] = bindings
        window = (
            f" over {_render_duration(correlation.timeframe)}"
            if correlation else ""
        )
        out.append("  match:")
        out.append(f"    {', '.join('$' + n for n in names)}{window}")

    if aggregate and aggregate.measures:
        out.append("  outcome:")
        out.extend(_render_measure(m, event) for m in aggregate.measures)

    out.append("  condition:")
    if correlation:
        # `frequency` is a minimum and YARA-L's `>` is strict, so the number
        # comes back one lower. Writing `frequency` straight out would make
        # the rendered rule fire one event LATER than the one it came from.
        head = f"${event} and #{event} > {correlation.frequency - 1}"
    else:
        head = f"${event}"
    for test in outcome_tests:
        head += f" and {test}"
    out.append(f"    {head}")
    out.append("}")
    return "\n".join(out)


def _render_join(rule: Rule, meta: dict[str, str]) -> str:
    """A rule whose pipeline joins streams, written back as event variables.

    The shape `lower_chronicle` produces is one Binding per YARA-L event
    variable; this is its inverse. Rendering only the main stream would drop
    every predicate the join's right-hand binding carried -- the exact silent
    widening this module refuses elsewhere.
    """
    streams: dict[str, Expr] = {}
    for binding in rule.bindings:
        conditions = [
            node.condition for node in binding.pipeline
            if isinstance(node, Filter)
        ]
        if not conditions:
            raise Refusal(
                "YARAL_RENDER_STREAM_NO_FILTER",
                f"stream `{binding.name}` has no filter, so its YARA-L event "
                f"variable would test nothing and match every event.",
                "render",
            )
        streams[binding.name] = (
            conditions[0] if len(conditions) == 1
            else BoolOp("and", tuple(conditions))
        )

    keys: list[FieldRef] = []
    ordered: list[str] = []
    for node in rule.pipeline:
        if isinstance(node, Read):
            if node.table.startswith("stream_") and node.table not in ordered:
                ordered.append(node.table)
            continue
        if isinstance(node, Emit):
            continue
        if not isinstance(node, Join):
            raise Refusal(
                "YARAL_RENDER_STAGE",
                f"a `{type(node).__name__}` stage has no YARA-L section. "
                f"Writing the rule without it would produce one that matches "
                f"a different set of events.",
                "render",
            )
        if node.how != "inner":
            raise Refusal(
                "YARAL_RENDER_JOIN_KIND",
                f"`{node.how}` join has no YARA-L spelling: its streams are "
                f"related only by the condition, and YARA-L has no outer or "
                f"anti join. Writing it as inner would change the matches.",
                "render",
            )
        if node.right not in ordered:
            ordered.append(node.right)
        for left, _right in node.on:
            if left not in keys:
                keys.append(left)

    if not ordered:
        raise Refusal(
            "YARAL_RENDER_NO_STREAM",
            "this rule joins streams but its pipeline never reads one.",
            "render",
        )

    # Every stream the main pipeline reads must have a binding; a bare table
    # name here would mean a stream whose filter was never written out.
    for name in ordered:
        if name not in streams:
            raise Refusal(
                "YARAL_RENDER_STREAM_UNKNOWN",
                f"the pipeline reads `{name}`, which is not one of this rule's "
                f"bindings. Writing the main stream alone would drop whatever "
                f"it constrained.",
                "render",
            )

    saved_vars = [
        part for part in (meta.get("chronicle.event_vars") or "").split(",")
        if part
    ]
    variables: list[str] = []
    for index, _name in enumerate(ordered):
        variables.append(
            saved_vars[index].lstrip("$") if index < len(saved_vars)
            else _placeholder_name(FieldRef(name=_name))
        )

    condition_lines: list[str] = []
    for name, variable in zip(ordered, variables):
        _render_expression(streams[name], variable, condition_lines)

    # A shared placeholder is how YARA-L says "these events agree on this
    # field". Emitting the join keys as bare comparisons would be the
    # difference between a correlation and a rule that matches every LSASS
    # event and every logon independently.
    saved_vars_for_keys = [
        part for part in
        (meta.get("chronicle.match_vars") or "").split(",") if part
    ]
    key_names = [
        saved_vars_for_keys[index].lstrip("$")
        if index < len(saved_vars_for_keys)
        else _placeholder_name(key)
        for index, key in enumerate(keys)
    ]
    key_lines = [
        f"    {_render_field(key, variable)} = ${name}"
        for key, name in zip(keys, key_names)
        for variable in variables
    ]

    name = _rule_name(
        meta.get("chronicle.rule_name") or rule.rule_id or "rule"
    )
    out: list[str] = [f"rule {name} {{"]

    annotations = rule.annotations
    meta_lines: list[str] = []
    if annotations.author:
        meta_lines.append(f'    author = "{_meta_text(annotations.author)}"')
    if annotations.description:
        meta_lines.append(
            f'    description = "{_meta_text(annotations.description)}"'
        )
    if annotations.severity:
        meta_lines.append(f'    severity = "{_meta_text(annotations.severity)}"')
    for tactic, techniques in annotations.mitre_attack:
        if tactic:
            meta_lines.append(
                f'    mitre_attack_tactic = "{_meta_text(tactic)}"'
            )
        if techniques:
            meta_lines.append(
                f'    mitre_attack_technique = '
                f'"{_meta_text(", ".join(techniques))}"'
            )
    for reference in annotations.references:
        meta_lines.append(f'    reference = "{_meta_text(reference)}"')
    for key, value in meta.items():
        if key.startswith("chronicle.meta."):
            meta_lines.append(
                f'    {key[len("chronicle.meta."):]} = "{_meta_text(value)}"'
            )
    if meta_lines:
        out.append("  meta:")
        out.extend(meta_lines)

    out.append("  events:")
    out.extend(key_lines)
    out.extend(f"    {line}" for line in condition_lines)

    if keys:
        out.append("  match:")
        match_line = ", ".join('$' + n for n in key_names)
        # The `over <window>` clause belongs to this line. Without it a
        # 10-minute correlation was written back out as an unbounded join.
        saved_window = meta.get("chronicle.window")
        if saved_window:
            match_line += f" over {saved_window}"
        out.append(f"    {match_line}")

    out.append("  condition:")
    out.append(f"    {' and '.join('$' + v for v in variables)}")
    out.append("}")
    return "\n".join(out)


def _meta_value(raw: str) -> str:
    """A `meta:` value read back, with its escapes undone.

    The inverse of `_meta_text`. Without it a rule that was written out with a
    quoted description and read back in kept the backslashes, so every round
    trip added another layer and the two texts never compared equal.
    """
    body = raw.strip()
    if len(body) >= 2 and body.startswith('"') and body.endswith('"'):
        body = body[1:-1]
    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body):
            following = body[index + 1]
            out.append({"n": "\n", "r": "\r", "t": "\t"}.get(following, following))
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _meta_text(value: str) -> str:
    """A `meta:` value with the characters that end the string escaped.

    A description containing `"` closed the YARA-L string literal early and the
    rest of the value became syntax -- a rule that does not parse, from a rule
    that was fine. Backslash goes first so an existing `\\` is not doubled.
    """
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _placeholder_name(ref: FieldRef) -> str:
    """A stable variable name for a group key.

    Derived from the field rather than numbered, so the same rule rendered
    twice produces the same text and a save does not look like a change.
    """
    parts = (ref.name,) + tuple(ref.path)
    return parts[-1].lower()
