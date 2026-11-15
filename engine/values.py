"""Value types and three-valued logic.

The rule this module exists to enforce:

    ABSENT   the field is not in the row
    NULL     the field is present and its value is null
    ""       the field is present and its value is the empty string

Those are three different things and a great deal of real detection breakage is a
rule quietly treating a missing field as an empty string. So the third value,
UNDECIDED, is a first-class citizen: a comparison that cannot be decided is
UNDECIDED, never False. `NOT UNDECIDED` is UNDECIDED.

Everything numeric goes through Decimal. Floats are coerced via Decimal(str(v))
so 0.1 + 0.2 does not become 0.30000000000000004 and quietly fail an equality
test against a value the analyst typed.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Final

__all__ = [
    "ABSENT",
    "Absent",
    "UNDECIDED",
    "Undecided",
    "Duration",
    "Refusal",
    "Seq",
    "is_absent",
    "is_undecided",
    "has_value",
    "as_number",
    "compare",
    "not_",
    "and_",
    "or_",
    "coalesce",
    "duration_seconds",
    "truthy",
    "type_name",
]


# ---------------------------------------------------------------------------
# ABSENT
# ---------------------------------------------------------------------------


class Absent:
    """The field is not in the row at all.

    A singleton with a cached __new__, so `is ABSENT` is the identity test and
    there is exactly one instance in the process. Falsy as a convenience only --
    code that needs to tell ABSENT from "" must test `is ABSENT`, never truth.
    """

    __slots__ = ()
    _instance: "Absent | None" = None

    def __new__(cls) -> "Absent":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "ABSENT"

    def __bool__(self) -> bool:
        return False

    def __reduce__(self) -> tuple[Any, ...]:
        return (Absent, ())

    def __eq__(self, other: object) -> bool:
        return other is self

    def __hash__(self) -> int:
        return hash("ruleforge.absent")


ABSENT: Final[Absent] = Absent()


def is_absent(value: Any) -> bool:
    return value is ABSENT


# ---------------------------------------------------------------------------
# UNDECIDED
# ---------------------------------------------------------------------------


class Undecided:
    """A comparison that cannot be decided from the data given.

    Single-member enum by construction, with a module-level singleton. Falsy, for
    the same reason ABSENT is: a bare truth test almost never means what the
    author wanted. Code that genuinely needs the third case tests
    `is UNDECIDED` explicitly.
    """

    __slots__ = ()
    _instance: "Undecided | None" = None

    def __new__(cls) -> "Undecided":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNDECIDED"

    def __bool__(self) -> bool:
        return False

    def __reduce__(self) -> tuple[Any, ...]:
        return (Undecided, ())


UNDECIDED: Final[Undecided] = Undecided()


def is_undecided(value: Any) -> bool:
    return value is UNDECIDED


# ---------------------------------------------------------------------------
# Duration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Duration:
    """A span of time, held as a number of seconds.

    Kept as a distinct type rather than collapsed to a float, because `ago(10m)`
    and `3600` are different things in a rule and a renderer has to be able to
    write the author's spelling back out.
    """

    seconds: Decimal

    def __post_init__(self) -> None:
        if not isinstance(self.seconds, Decimal):
            object.__setattr__(self, "seconds", Decimal(str(self.seconds)))

    def __repr__(self) -> str:
        return f"Duration({self.seconds}s)"


_DURATION_RE: Final = re.compile(
    r"^\s*(?P<value>\d+(?:\.\d+)?)\s*"
    r"(?P<unit>ms|milliseconds?|s|secs?|seconds?|m|mins?|minutes?|h|hrs?|hours?|"
    r"d|days?|w|weeks?)\s*$",
    re.IGNORECASE,
)

_UNIT_SECONDS: Final[dict[str, Decimal]] = {
    "ms": Decimal("0.001"),
    "millisecond": Decimal("0.001"),
    "milliseconds": Decimal("0.001"),
    "s": Decimal(1),
    "sec": Decimal(1),
    "secs": Decimal(1),
    "second": Decimal(1),
    "seconds": Decimal(1),
    "m": Decimal(60),
    "min": Decimal(60),
    "mins": Decimal(60),
    "minute": Decimal(60),
    "minutes": Decimal(60),
    "h": Decimal(3600),
    "hr": Decimal(3600),
    "hrs": Decimal(3600),
    "hour": Decimal(3600),
    "hours": Decimal(3600),
    "d": Decimal(86400),
    "day": Decimal(86400),
    "days": Decimal(86400),
    "w": Decimal(604800),
    "week": Decimal(604800),
    "weeks": Decimal(604800),
}


def duration_seconds(text: str) -> Duration | None:
    """Parse `10m`, `300 seconds`, `1h30m` is refused rather than guessed."""
    match = _DURATION_RE.match(text or "")
    if match is None:
        return None
    unit = match.group("unit").lower()
    factor = _UNIT_SECONDS.get(unit)
    if factor is None:
        return None
    return Duration(Decimal(match.group("value")) * factor)


# ---------------------------------------------------------------------------
# Seq -- list-valued results
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Seq:
    """An ordered collection, as a VALUE rather than as a row.

    Enterprise rules collect values rather than collapsing them: Splunk
    `values(field)`, KQL `make_set(field)`, YARA-L `output(...)`. A first-class
    sequence type is what lets those aggregate honestly instead of keeping only
    the last one or refusing.

    Distinct is a separate flag rather than a constructor argument because
    `values()` de-duplicates and `make_set()` does not, and that difference is
    load-bearing in a correlation rule.
    """

    items: tuple[Any, ...]
    distinct: bool = False

    def __repr__(self) -> str:
        body = ", ".join(repr(i) for i in self.items)
        return f"Seq([{body}]{', distinct' if self.distinct else ''})"

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self) -> Any:
        return iter(self.items)

    def __contains__(self, needle: Any) -> bool:
        return needle in self.items


# ---------------------------------------------------------------------------
# Refusal
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class Refusal(Exception):
    """The one error type this tool raises on purpose.

    `code` is for machines and grouping. `message` is for the analyst and always
    names the construct and the reason -- never apologises, never says "invalid
    input". `where` is a human breadcrumb and is genuinely a mixed bag across the
    codebase (a dialect name in one place, a node class in another), which is why
    nothing parses it and everything displays it.
    """

    code: str
    message: str
    where: str = ""

    def __post_init__(self) -> None:
        Exception.__init__(self, self.message)

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return f"Refusal({self.code!r}, {self.message!r}, {self.where!r})"

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message, "where": self.where}


# ---------------------------------------------------------------------------
# Predicates
# ---------------------------------------------------------------------------


def has_value(value: Any) -> bool:
    """True when the value is real data, not absence, null, or indecision.

    Note what passes: 0, "", False. Those are values. A field that is present and
    empty IS present, and a rule that treats `field = 0` as "field is missing" is
    the bug this whole module exists to prevent.
    """
    if value is ABSENT or value is UNDECIDED or value is None:
        return False
    if isinstance(value, Seq):
        return len(value) > 0
    return True


def truthy(value: Any) -> bool:
    """Kleene AND/OR helpers refuse to coerce. A bare truth test is a bug."""
    if value is UNDECIDED:
        return False
    if value is ABSENT or value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float, Decimal)):
        return value != 0
    if isinstance(value, str):
        return value != ""
    return True


def type_name(value: Any) -> str:
    """For a message the analyst reads. Never the class name."""
    if value is ABSENT:
        return "absent"
    if value is UNDECIDED:
        return "undecided"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, Decimal):
        return "number"
    if isinstance(value, int):
        return "number"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Duration):
        return "duration"
    if isinstance(value, Seq):
        return "list"
    return type(value).__name__


# ---------------------------------------------------------------------------
# Numbers
# ---------------------------------------------------------------------------


def as_number(value: Any) -> Decimal | None:
    """Coerce to Decimal, or None if it is not a number.

    Numeric STRINGS are coerced deliberately: SIEM payloads carry
    `"EventID": "4624"` as often as `4624`, and a rule that compares
    `EventID = 4624` should not silently fail on the string spelling. The trace
    records that the coercion happened, so the analyst is never surprised.

    bool is rejected. `bool` is an `int` subclass in Python, so without this
    `True == 1` and a boolean field would satisfy a numeric threshold.
    """
    if value is None or value is ABSENT or value is UNDECIDED:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return Decimal(text)
        except InvalidOperation:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return Decimal(str(parsed.timestamp()))
    if isinstance(value, Duration):
        return value.seconds
    return None


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

COMPARISON_OPS: Final[frozenset[str]] = frozenset(
    {"==", "!=", "<", "<=", ">", ">=", "=~", "!~", "contains", "in", "contains_any",
     "contains_all", "startswith", "endswith", "matches", "like", "ilike"}
)


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    """A comparison outcome plus WHY, when it could not be decided.

    The reason string is not decoration. "the field was absent on 4 of 5 rows"
    tells the analyst where to look; a bare False tells them nothing and is
    indistinguishable from a rule that correctly did not match.
    """

    value: bool | Undecided
    reason: str = ""

    def __bool__(self) -> bool:
        return self.value is True


def _comparable_pair(left: Any, right: Any) -> tuple[Any, Any] | None:
    """A pair that may be ordered, or None.

    Only like-for-like. num/num, str/str, bool/bool. Mixed kinds are refused here
    rather than coerced, because Python will happily order a str against an int
    by raising, and every vendor dialect disagrees about what that means anyway.
    """
    lb, rb = as_number(left), as_number(right)
    if lb is not None and rb is not None:
        return lb, rb
    if isinstance(left, bool) and isinstance(right, bool):
        return left, right
    if isinstance(left, str) and isinstance(right, str):
        return left, right
    if isinstance(left, (list, Seq)) and isinstance(right, (list, Seq)):
        return list(left), list(right)
    return None


def _ordering(left: Any, right: Any) -> int | Undecided:
    pair = _comparable_pair(left, right)
    if pair is None:
        return UNDECIDED
    a, b = pair
    try:
        if a < b:
            return -1
        if a > b:
            return 1
    except TypeError:
        return UNDECIDED
    return 0


def compare(left: Any, op: str, right: Any) -> ComparisonResult:
    """Compare two values under one operator, three-valuedly.

    The order of the checks is the design. UNDECIDED first, then unknown
    operator, then ABSENT, then NULL -- so the reason a comparison could not be
    decided always names the actual cause rather than a generic failure.
    """
    if left is UNDECIDED or right is UNDECIDED:
        return ComparisonResult(UNDECIDED, "an operand was already undecided")
    if op not in COMPARISON_OPS:
        return ComparisonResult(UNDECIDED, f"`{op}` is not a comparison operator")

    if left is ABSENT:
        return ComparisonResult(UNDECIDED, "the left field is absent from the row")
    if right is ABSENT:
        return ComparisonResult(UNDECIDED, "the right field is absent from the row")

    # null == null is a DECIDED yes. It is the one place null is comparable,
    # because "this field is null" is a statement a rule is allowed to make
    # about null. Comparing null to a VALUE stays undecided: `field == null` in
    # most dialects is a mistake, and treating it as false is how a rule quietly
    # matches every row that has the field.
    if left is None and right is None:
        if op in ("==", "in"):
            return ComparisonResult(True)
        if op in ("!=",):
            return ComparisonResult(False)
        return ComparisonResult(UNDECIDED, "null cannot be ordered")

    if left is None:
        return ComparisonResult(UNDECIDED, "the left value is null")
    if right is None:
        return ComparisonResult(UNDECIDED, "the right value is null")

    if op in ("==", "!="):
        equal = _equals(left, right)
        if equal is UNDECIDED:
            return ComparisonResult(UNDECIDED, "the two values are not comparable")
        decided = equal if op == "==" else not equal
        return ComparisonResult(decided)

    if op in ("<", "<=", ">", ">="):
        order = _ordering(left, right)
        if order is UNDECIDED:
            return ComparisonResult(
                UNDECIDED,
                f"a {type_name(left)} and a {type_name(right)} cannot be ordered",
            )
        if op == "<":
            return ComparisonResult(order < 0)
        if op == "<=":
            return ComparisonResult(order <= 0)
        if op == ">":
            return ComparisonResult(order > 0)
        return ComparisonResult(order >= 0)

    return ComparisonResult(UNDECIDED, f"`{op}` is not evaluated here")


def _equals(left: Any, right: Any) -> bool | Undecided:
    if isinstance(left, (list, Seq)) or isinstance(right, (list, Seq)):
        return _seq_equals(left, right)
    if isinstance(left, Duration) and isinstance(right, Duration):
        return left.seconds == right.seconds
    pair = _comparable_pair(left, right)
    if pair is None:
        return UNDECIDED
    a, b = pair
    return a == b


def _seq_equals(left: Any, right: Any) -> bool | Undecided:
    a = list(left) if isinstance(left, (list, Seq)) else [left]
    b = list(right) if isinstance(right, (list, Seq)) else [right]
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        result = _equals(x, y)
        if result is not UNDECIDED and not result:
            return False
    return True


# ---------------------------------------------------------------------------
# Kleene logic
# ---------------------------------------------------------------------------


def not_(value: bool | Undecided) -> bool | Undecided:
    """NOT UNDECIDED is UNDECIDED. This is the whole point."""
    if value is UNDECIDED:
        return UNDECIDED
    return not value


def and_(*values: bool | Undecided) -> bool | Undecided:
    """False dominates. An undecided AND false is false, and that is correct:
    the answer is settled even though one side of it was not."""
    result: bool | Undecided = True
    for value in values:
        if value is False:
            return False
        if value is UNDECIDED:
            result = UNDECIDED
    return result


def or_(*values: bool | Undecided) -> bool | Undecided:
    """True dominates, for the same reason."""
    result: bool | Undecided = False
    for value in values:
        if value is True:
            return True
        if value is UNDECIDED:
            result = UNDECIDED
    return result


def coalesce(*values: Any) -> Any:
    """First value that is not ABSENT and not NULL.

    Never invents a default. `coalesce(a, b)` with both absent returns ABSENT,
    because returning `None` there would be a rule that quietly matches something.
    """
    for value in values:
        if value is not ABSENT and value is not None:
            return value
    return ABSENT


class Capability(str, Enum):
    """How honestly a node can be executed here.

    This replaces the older "refuse anything you cannot run" posture, which was
    right for a validator and useless for an authoring tool: an enterprise rule
    is mostly things a laptop cannot execute (appliance functions, index-time
    fields, PCRE), and refusing them meant refusing the rule.

    EVALUATED     ran locally; the answer is trustworthy.
    DECLARED_ONLY modelled faithfully and renders correctly, but only the
                  vendor's engine can run it. Rendered with a marker so the
                  limitation travels with the artifact.
    """

    EVALUATED = "evaluated"
    DECLARED_ONLY = "declared_only"
