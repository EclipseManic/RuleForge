"""YARA-L 2.0.

The cleanest of the five dialects for this engine, because YARA-L's `match`
section is a window over a grouping key -- which is what `Pattern` plus `Frame`
already are. Most of this module is careful refusal rather than clever mapping.

VERIFIED SEMANTICS (Google's documentation, not inferred):

  rule <Name> { meta: ... events: ... match: ... outcome: ... condition: ... }

  events:     named event variables, `$var.field.path = value`
  match:      `$a, $b over 10m` groups by those placeholders over a window.
              `over <n><m|h|d>`, minimum 1m, maximum 48h.
              `by <n><m|h|d>` is a TUMBLING bucket instead of a rolling window.
              `after $e1` makes the window pivot-relative.
  regex:      `/pattern/` literals with an optional `nocase` modifier;
              `re.regex(field, `pattern`)` is the function form.
  condition:  event variables combined with and/or/not and `#e > 10` counts.

WHAT IS REFUSED, AND WHY

  `after $e1`        a pivot-relative window is not a step grid over all rows.
                     Refused rather than approximated: a tumbling approximation
                     of a sliding window is the exact defect this tool was built
                     to avoid, and it is already documented once in the engine.

  `not`              the engine has a `Not` node now, so this IS representable --
                     see the lowering. Kept as an explicit branch so an
                     unrepresentable variant is named rather than guessed.

  `nocase` on a     there is no case-insensitive COMPARISON operator in the
  comparison        engine. `contains` folds case, but "starts with, ignoring
                    case" is a different test from "contains, ignoring case", and
                    using `contains` for it would widen the rule. Refused.

  `#e > 10` with     a Pattern produces no count column, so a count has nothing
  a pattern         to count. Refused rather than inventing one.

  bucket with no     a `by 10m` with no metric is a grouping, not an aggregate,
  metric            and this IR requires an aggregate to hold measures. Refused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from typing import Any, Final

from ..dialects.aql import Diagnostic
from ..engine import (
    Refusal,
)

DIALECT: Final = "yaral"
LANGUAGE: Final = "YARA-L 2.0"

#: `over` accepts 1m to 48h. Bounds are the platform's, not a preference.
MIN_WINDOW: Final = 60
MAX_WINDOW: Final = 48 * 3600

_SECTIONS: Final = ("meta", "events", "match", "outcome", "condition", "options")

_FIELD_PATH_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*$")
_PLACEHOLDER_RE: Final = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")
_REGEX_LITERAL_RE: Final = re.compile(r"^/(?P<body>.*)/(?P<mods>(?:\s+[a-z]+)*)$",
                                      re.DOTALL)

_UNIT_RE: Final = re.compile(r"^(\d+)([smhd])$")


@dataclass(frozen=True, slots=True)
class YaraEvent:
    """One `$var.field = value` line in the events section."""

    var: str
    field: str
    operator: str
    value: Any
    nocase: bool = False
    is_regex: bool = False
    is_placeholder: bool = False


@dataclass(frozen=True, slots=True)
class YaraMatch:
    keys: tuple[str, ...] = ()
    window_seconds: int | None = None
    bucket_seconds: int | None = None
    pivot: str | None = None


@dataclass(frozen=True, slots=True)
class YaraCondition:
    op: str
    operands: tuple[Any, ...]


@dataclass
class ParsedYaraL:
    name: str = ""
    meta: dict[str, str] = dc_field(default_factory=dict)
    events: list[YaraEvent] = dc_field(default_factory=list)
    #: var -> the placeholder fields it binds, e.g. $host -> principal.hostname
    placeholders: dict[str, list[str]] = dc_field(default_factory=dict)
    match: YaraMatch = dc_field(default_factory=YaraMatch)
    outcome: dict[str, str] = dc_field(default_factory=dict)
    condition: Any = None
    cross_event_order: list[tuple[str, str, str]] = dc_field(default_factory=list)
    diagnostics: list[Diagnostic] = dc_field(default_factory=list)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_yaral(text: str) -> ParsedYaraL:
    """Parse a YARA-L 2.0 rule into a structured form with diagnostics."""
    parsed = ParsedYaraL()
    parsed.name = _find_rule_header(text)

    # Sections are found by their own headers rather than by walking lines and
    # tracking a "current section" variable. The earlier version tracked state
    # while joining wrapped lines, and because a wrapped comparison left the
    # joiner mid-statement, every section header was swallowed into the previous
    # buffer: the rule parsed as having zero events and zero metadata, and
    # produced a diagnostic that blamed the analyst's rule for a parser bug.
    for section, body in _split_sections(text):
        if section == "meta":
            for line in body:
                # YARA-L meta entries are `key = value`, NOT `key: value`. An
                # earlier version split on a colon, so every meta entry was
                # silently dropped and the rule rendered with no author.
                key, sep, value = line.partition("=")
                if sep:
                    parsed.meta[key.strip()] = _unquote(value.strip())
        elif section == "events":
            for line in body:
                _parse_event(line, parsed)
        elif section == "match":
            if body:
                parsed.match = _parse_match(body[0])
        elif section == "outcome":
            for line in body:
                key, _, value = line.partition("=")
                parsed.outcome[key.strip()] = value.strip()
        elif section == "condition":
            for line in body:
                parsed.condition = _parse_condition(line.strip(), parsed)
        elif section == "options":
            continue

    _classify_references(parsed)
    _check_diagnostics(parsed)
    return parsed


def _classify_references(parsed: ParsedYaraL) -> None:
    """Decide, after parsing, which `$reference` right-hand sides are BINDINGS
    and which are CROSS-EVENT COMPARISONS.

    Both look identical on the line:

        $lsass.principal.hostname = $host          <- a binding
        $lsass.metadata.event_timestamp <= $login.metadata.event_timestamp

    A `$name` on the right is a GROUPING KEY when the match section names it, and
    an EVENT REFERENCE when another declared event variable owns it. Only the
    second is a comparison between two different events.

    This has to run after the whole rule is read. An earlier version decided
    during line parsing, comparing the right-hand name to the left-hand variable
    -- which classified `$lsass.principal.hostname = $host` as cross-event,
    reported the rule as ordering events against each other when it only groups
    them, and would have made the honest "this compares two events" warning fire
    on a rule that does no such thing. A warning that cries wolf is worse than no
    warning, because it trains the reader to skip it.
    """
    event_vars = {e.var for e in parsed.events if not e.is_placeholder}
    match_keys = set(parsed.match.keys)

    # Iterate a COPY. Removing from `parsed.events` while iterating it skips
    # elements, so the cross-event line was left in the list on one pass and
    # removed on the next -- a rule that parsed differently depending on how many
    # cross-event references it had.
    cross: list[tuple[str, str, str]] = []
    for event in list(parsed.events):
        if not event.is_placeholder:
            continue
        target = str(event.value)
        head = f"${target.lstrip('$').split('.', 1)[0]}"
        if head in match_keys:
            continue                                   # a grouping key
        if head in event_vars and head != event.var:
            cross.append((f"{event.var}.{event.field}", target, event.operator))
            parsed.events.remove(event)
    parsed.cross_event_order.extend(cross)


def _split_sections(text: str) -> list[tuple[str, list[str]]]:
    """Return [(section_name, joined_lines)] for a YARA-L rule body.

    Comments and braces are removed, then each section header starts a new
    section. Within a section, a line that ENDS WITH AN OPERATOR is joined to the
    next one -- which is how YARA-L wraps a long comparison:

        $lsass.metadata.event_timestamp <=
          $login.metadata.event_timestamp

    Joining is driven by the trailing operator rather than by brace counting,
    because brace counting cannot tell "a wrapped comparison" from "the start of
    the next section" and guessed wrong on both.
    """
    body_lines: list[str] = []
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line or line in ("{", "}"):
            continue
        body_lines.append(line)

    sections: list[tuple[str, list[str]]] = []
    current_name = ""
    current: list[str] = []
    for line in body_lines:
        header = line.rstrip(":").strip().lower()
        if header in _SECTIONS and line.endswith(":"):
            if current_name:
                sections.append((current_name, current))
            current_name = header
            current = []
            continue
        if current_name:
            if current and _ends_with_operator(current[-1]):
                current[-1] = f"{current[-1]} {line}"
            else:
                current.append(line)
    if current_name:
        sections.append((current_name, current))
    return sections


def _ends_with_operator(line: str) -> bool:
    return line.rstrip().endswith(("<=", ">=", "!=", "==", "=", "<", ">"))


def _find_rule_header(text: str) -> str:
    for raw in text.splitlines():
        stripped = raw.split("//", 1)[0].strip()
        if stripped.startswith("rule "):
            name = stripped[len("rule "):].split("{", 1)[0].strip()
            if not name:
                raise Refusal("YARAL_RULE_UNNAMED",
                              "a rule needs a name", "YARA-L")
            return name
    raise Refusal(
        "YARAL_NO_RULE_HEADER",
        "no `rule <Name> {` line was found. This does not parse as YARA-L, and "
        "guessing at the intended structure would be worse than saying so.",
        "YARA-L")


def _parse_event(line: str, parsed: ParsedYaraL) -> None:
    """Parse one `events:` entry and record it."""
    expression = line.strip()
    if ":" in expression and expression.lstrip().startswith("$"):
        var, _, rest = expression.partition(":")
        var = var.strip()
        expression = rest.strip()
    else:
        var = None

    operator_match = re.search(r"(==|!=|<=|>=|=|<|>)", expression)
    if operator_match is None:
        raise Refusal(
            "YARAL_EVENT_NO_COMPARISON",
            f"{expression!r} is not a comparison. Every events entry must state a "
            f"field and a value; a bare field would match every event that has it.",
            "YARA-L")

    # Partition on the COMPARISON OPERATOR, not on a bare `=`. The user's rule
    # wraps `$lsass.metadata.event_timestamp <= $login...` across two lines, and
    # splitting on `=` first chopped the `<=` in half, leaving a field path of
    # `metadata.event_timestamp <` -- a parser bug that surfaced as a refusal
    # blaming the analyst's field name.
    left = expression[:operator_match.start()].strip()
    right = expression[operator_match.end():].strip()
    operator = operator_match.group(0)

    if var is None:
        var, left = _split_var_and_field(left)
    if not _PLACEHOLDER_RE.match(var):
        raise Refusal("YARAL_VAR_NAME_INVALID",
                      f"{var!r} is not a $variable name", "YARA-L")
    if not _FIELD_PATH_RE.match(left):
        raise Refusal("YARAL_FIELD_PATH_INVALID",
                      f"{left!r} is not a UDM field path. Field paths are passed "
                      f"through byte-for-byte; this one is not valid.", "YARA-L")

    nocase = False
    modifier = re.search(r"\s+nocase\s*$", right)
    if modifier:
        nocase = True
        right = right[:modifier.start()].strip()

    is_regex = False
    literal = re.match(_REGEX_LITERAL_RE, right)
    if literal:
        is_regex = True
        right = literal.group("body")
        mods = (literal.group("mods") or "").split()
        if any(m == "nocase" or m == "i" for m in mods):
            nocase = True
    elif right.startswith("`") and right.endswith("`"):
        right = right[1:-1]
        is_regex = True
        if re.search(r"\(\?i\)", right):
            nocase = True
            right = re.sub(r"\(\?i\)", "", right)

    is_placeholder = bool(_PLACEHOLDER_RE.match(right)) or \
        bool(re.match(r"^\$[A-Za-z_][A-Za-z0-9_]*(\..+)?$", right))

    if is_placeholder:
        parsed.placeholders.setdefault(var, []).append(left)

    parsed.events.append(YaraEvent(
        var=var, field=left, operator=operator, value=_unquote(right),
        nocase=nocase, is_regex=is_regex, is_placeholder=is_placeholder))


def _unquote(value: str) -> str:
    """Strip one layer of surrounding double quotes.

    YARA-L writes `event_type = "PROCESS_ACCESS"`. Keeping the quotes would put a
    literal `"` at both ends of the value, so an equality test would compare
    `PROCESS_ACCESS` against `"PROCESS_ACCESS"` and never match. The quotes are
    YARA-L syntax, not data.
    """
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('\\"', '"')
    return value


def _split_var_and_field(left: str) -> tuple[str, str]:
    """`$e.metadata.event_type` -> ('$e', 'metadata.event_type')."""
    stripped = left.lstrip()
    if not stripped.startswith("$"):
        raise Refusal("YARAL_EVENT_NO_VARIABLE",
                      f"{left!r} does not start with a $variable", "YARA-L")
    body = stripped[1:]
    dot = body.find(".")
    if dot < 0:
        raise Refusal(
            "YARAL_EVENT_NO_FIELD",
            f"{left!r} names a variable but no field. A variable with no field is "
            f"a placeholder binding, which belongs in the match section.", "YARA-L")
    return f"${body[:dot]}", body[dot + 1:]


def _parse_duration(text: str) -> int:
    match = _UNIT_RE.match(text.strip().lower())
    if not match:
        raise Refusal(
            "YARAL_WINDOW_UNPARSEABLE",
            f"{text!r} is not a window. Expected a number and a unit, like 10m, 2h "
            f"or 1d.", "YARA-L")
    value = int(match.group(1))
    unit = match.group(2)
    seconds = value * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    if not (MIN_WINDOW <= seconds <= MAX_WINDOW):
        raise Refusal(
            "YARAL_WINDOW_OUT_OF_RANGE",
            f"a {text} window is {seconds}s. YARA-L accepts 1m to 48h; outside "
            f"that range the platform would reject the rule, so this tool will "
            f"not build one.", "YARA-L")
    return seconds


def _parse_match(line: str) -> YaraMatch:
    body = line.strip()
    if ":" in body:
        body = body.partition(":")[2].strip()
    body = body.replace("match", "", 1).strip() if body.lower().startswith(
        "match") else body

    pivot: str | None = None
    if " after " in body:
        body, _, after = body.partition(" after ")
        pivot = after.strip()
        if not _PLACEHOLDER_RE.match(pivot):
            raise Refusal("YARAL_PIVOT_INVALID",
                          f"{pivot!r} is not a $variable", "YARA-L")

    lowered = body.lower()
    bucket = None
    window = None
    # `s` is accepted by the DURATION pattern on purpose, even though YARA-L's
    # minimum is 1m. Accepting it here means `over 30s` is reported as
    # YARAL_WINDOW_OUT_OF_RANGE -- "YARA-L accepts 1m to 48h" -- instead of
    # leaving `30s` in the key list and producing a confusing "invalid match key"
    # about a string the author never wrote as a key.
    if re.search(r"\bby\s+\d+[mhsd]\s*$", lowered):
        match = re.search(r"\bby\s+(\d+[mhsd])\s*$", lowered)
        assert match is not None
        bucket = _parse_duration(match.group(1))
        body = body[:match.start()].strip()
    elif re.search(r"\bover\s+\d+[mhsd]\s*$", lowered):
        match = re.search(r"\bover\s+(\d+[mhsd])\s*$", lowered)
        assert match is not None
        window = _parse_duration(match.group(1))
        body = body[:match.start()].strip()

    keys = tuple(k.strip() for k in body.replace("and", ",").split(",") if k.strip())
    for key in keys:
        if not _PLACEHOLDER_RE.match(key):
            raise Refusal("YARAL_MATCH_KEY_INVALID",
                          f"{key!r} is not a $placeholder", "YARA-L")
    return YaraMatch(keys=keys, window_seconds=window, bucket_seconds=bucket,
                     pivot=pivot)


_COMPARISONS: Final = ("<=", ">=", "==", "!=", "<", ">", "=")


def _parse_condition(text: str, parsed: ParsedYaraL) -> Any:
    """Parse the condition section into a small boolean tree."""
    expression = text.strip().rstrip(";").strip()

    count_match = re.fullmatch(r"#([A-Za-z_][A-Za-z0-9_]*)\s*"
                               r"(>=|<=|>|<|=|==|!=)\s*(\d+)", expression)
    if count_match:
        return YaraCondition("count", (count_match.group(1), count_match.group(2),
                                       int(count_match.group(3))))

    for joiner, op in ((" and ", "and"), (" or ", "or")):
        if joiner in expression:
            parts = expression.split(joiner)
            return YaraCondition(op, tuple(_parse_condition(p.strip(), parsed)
                                           for p in parts))

    stripped = expression.strip()
    if stripped.lower().startswith("not "):
        return YaraCondition("not", (_parse_condition(stripped[4:], parsed),))

    for operator in _COMPARISONS:
        if operator in expression:
            left, _, right = expression.partition(operator)
            left = left.strip()
            right = right.strip()
            if _PLACEHOLDER_RE.match(left) and _PLACEHOLDER_RE.match(right):
                parsed.cross_event_order.append((left, right, operator))
            return YaraCondition("cmp", (left, operator, right))

    if _PLACEHOLDER_RE.match(stripped):
        return YaraCondition("exists", (stripped,))

    raise Refusal(
        "YARAL_CONDITION_UNPARSEABLE",
        f"{expression!r} is not a condition this parser understands. Conditions "
        f"combine event variables with and/or/not and compare counts like "
        f"`#e > 10`; anything else is refused rather than approximated.", "YARA-L")


def _check_diagnostics(parsed: ParsedYaraL) -> None:
    if not parsed.events:
        parsed.diagnostics.append(Diagnostic(
            "YARAL_NO_EVENTS",
            "the rule declares no events, so there is nothing to match.", "refusal"))
    if parsed.condition is None:
        parsed.diagnostics.append(Diagnostic(
            "YARAL_NO_CONDITION",
            "the rule has no condition section, so it states nothing about when it "
            "fires. YARA-L requires one.", "refusal"))
    if parsed.match.pivot is not None:
        parsed.diagnostics.append(Diagnostic(
            "YARAL_UNSUPPORTED_SLIDING_PIVOT",
            f"`after {parsed.match.pivot}` makes the window relative to a pivot "
            f"event rather than a fixed grid. This engine's windows are grids over "
            f"the whole group, so approximating one with a grid would change which "
            f"events fall inside the window. Refused rather than approximated.",
            "refusal"))
