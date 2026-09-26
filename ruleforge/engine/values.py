"""Value model for RuleForge.

THE ONE PROPERTY THIS FILE EXISTS TO GUARANTEE:

    An undecidable comparison is never a `False`.

Detection rules are evaluated against rows that frequently lack the field the rule
mentions. That is not an edge case, it is the normal case: a Sysmon rule keyed on
`win.eventdata.grantedAccess` meets every event from a source that never produced
that field. A tool that reports "did not match" for those rows is asserting a
negative it never established, and an analyst who reads that output has been told
something false about their own data.

So there are three outcomes, not two:

    TRUE      the comparison was decided, and it held
    FALSE     the comparison was decided, and it did not hold
    UNDECIDED at least one operand was absent or null, so the
              comparison has no answer

UNDECIDED is not an error state and it is not False. It propagates: `NOT UNDECIDED`
is UNDECIDED, not TRUE. Once a value is undecided it cannot be recovered by
downstream logic, because every consumer of a comparison wants a yes/no and will
happily take UNDECIDED as a no if we let it.

THREE STATES, NOT TWO, FOR VALUES:

    ABSENT   the field is not present in this row
    NULL     the field is present and its value is null
    ""       the field is present and its value is the empty string

Collapsing these is how a missing field becomes an empty match. `destination_ip`
absent and `destination_ip` empty are different facts about a network connection,
and a rule that treats them alike will fire on rows it was never written for.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Final


class _Absent:
    """Sentinel for a field the row does not carry.

    A distinct type rather than None, because None is a legitimate value meaning
    "present and null". Using None for both would make them indistinguishable, and
    that confusion is the root of the whole class of bug this file prevents.
    """

    __slots__ = ()
    _instance: "_Absent | None" = None

    def __new__(cls) -> "_Absent":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "ABSENT"

    def __bool__(self) -> bool:
        # Deliberately falsy so a stray `if value:` treats it like "nothing here",
        # but every comparison in this module checks for ABSENT explicitly before
        # reaching a truthiness test. This is a convenience, not a decision.
        return False

    def __reduce__(self) -> str:
        return "ABSENT"


ABSENT: Final = _Absent()


class Undecided(Enum):
    """The third logical value. Not True, not False, not an error."""

    UNDECIDED = "undecided"

    def __repr__(self) -> str:
        return "UNDECIDED"

    def __bool__(self) -> bool:
        # Falsy, because a caller that does not check for it must not accidentally
        # treat it as a match. Code that genuinely needs the third case has to
        # test `is UNDECIDED` explicitly; there is no way to make this safe by
        # default, only safe by explicit handling.
        return False


UNDECIDED: Final = Undecided.UNDECIDED


class Refusal(Exception):
    """A named, reasoned refusal.

    Raised when the tool cannot do something honestly. Carries a code so the UI
    can group and the analyst can search, and a message that says what is missing
    rather than apologising for it.
    """

    def __init__(self, code: str, message: str, where: str = "") -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.where = where

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message, "where": self.where}


def is_undecided(value: Any) -> bool:
    return value is UNDECIDED


def has_value(value: Any) -> bool:
    """True when the value carries information.

    ABSENT and NULL and UNDECIDED all fail. `0`, `""` and `False` all pass, which
    is the entire reason this function exists: every one of those three falsy
    values is a real, meaningful value that a naive `if not value` would discard.
    An event with `bytes_sent=0` is not an event with no bytes field.
    """
    return value is not ABSENT and value is not None and value is not UNDECIDED


def coalesce(*values: Any) -> Any:
    """First value that carries information, else UNDECIDED.

    Never returns a default the caller did not supply, because inventing a
    substitute for a missing field is the failure this tool exists to avoid.
    """
    for value in values:
        if has_value(value):
            return value
    return UNDECIDED


def _duration_seconds(value: Any) -> Decimal | None:
    """A Duration's seconds, or None if this is not a Duration.

    A DURATION IS A NUMBER OF SECONDS FOR COMPARISON AND ARITHMETIC. A KQL rule
    saying `LoginTime <= LSASSTime + 10m` lowers to a comparison and an addition
    whose operand is a span. Without this, both went UNDECIDED, the rule matched
    nothing, and it looked perfectly well formed.

    The import is INSIDE the function on purpose. `Duration` lives in `ir.py`,
    which imports this module, so a module-level import would be circular. By the
    time this is called `ir` is fully loaded. A module-level `from .ir import
    Duration` here would break every import of this package.
    """
    from .ir import Duration

    return value.seconds if isinstance(value, Duration) else None


def as_number(value: Any) -> Decimal | None:
    """Decimal for numeric values, None when not numeric.

    Decimal rather than float throughout. Detection thresholds are compared
    against counts and byte totals where 0.1 + 0.2 != 0.3 would produce a wrong
    bucket, and a wrong bucket is a wrong alert.
    """
    if isinstance(value, bool):
        # bool is a subclass of int. Treating True as 1 would let `port = true`
        # pass a numeric range check it has no business passing.
        return None
    seconds = _duration_seconds(value)
    if seconds is not None:
        return seconds
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, str):
        # Numeric strings are common in SIEM data and are genuinely comparable
        # after coercion, but the coercion is visible in the trace so a reader can
        # see that a string was compared as a number.
        try:
            return Decimal(value)
        except (InvalidOperation, ValueError):
            return None
    return None


def comparable_pair(left: Any, right: Any) -> tuple[Any, Any] | None:
    """Return both operands coerced to a comparable pair, or None.

    None means "these two cannot be compared at all", which the caller must
    report as UNDECIDED rather than resolving in either direction.
    """
    left_num, right_num = as_number(left), as_number(right)
    if left_num is not None and right_num is not None:
        return left_num, right_num
    if isinstance(left, str) and isinstance(right, str):
        return left, right
    if isinstance(left, bool) and isinstance(right, bool):
        return left, right
    return None


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    """Outcome of one comparison, with the reason it came out that way.

    `reason` is not decoration. When a rule does not fire, the analyst's first
    question is why, and "the field was absent on 4 of 5 rows" is the answer that
    saves them an hour. A bare False sends them looking in the wrong place.
    """

    value: bool | Undecided
    left: Any = None
    right: Any = None
    reason: str = ""

    @property
    def decided(self) -> bool:
        return not isinstance(self.value, Undecided)

    def __bool__(self) -> bool:
        # Falsy for UNDECIDED so an unhandled case cannot accidentally read as a
        # match. Callers that care about the third case test `.decided`.
        return self.value is True

    def as_dict(self) -> dict[str, Any]:
        return {
            "value": self.value.value if isinstance(self.value, Undecided)
            else self.value,
            "decided": self.decided,
            "left": _describe(self.left),
            "right": _describe(self.right),
            "reason": self.reason,
        }


def _describe(value: Any) -> Any:
    if value is ABSENT:
        return "<absent>"
    if value is None:
        return "<null>"
    if value is UNDECIDED:
        return "<undecided>"
    return value


ORDERING: Final = {
    "=": lambda c: c == 0,
    "!=": lambda c: c != 0,
    "<": lambda c: c < 0,
    "<=": lambda c: c <= 0,
    ">": lambda c: c > 0,
    ">=": lambda c: c >= 0,
}


def compare(left: Any, right: Any, op: str) -> ComparisonResult:
    """Compare two field values under an ordering operator.

    Order of checks matters and is deliberate:

      1. UNDECIDED on either side propagates immediately.
      2. ABSENT and NULL never satisfy an ordering test. An absent field is not
         less than 5; it is not comparable to 5. Resolving it either way asserts
         a fact about the data that does not exist.
      3. Only then is coercion attempted, and only between like kinds.
    """
    if left is UNDECIDED or right is UNDECIDED:
        return ComparisonResult(UNDECIDED, left, right, "an operand was undecided")

    if op not in ORDERING:
        return ComparisonResult(UNDECIDED, left, right, f"unknown operator {op!r}")

    # ABSENT and NULL: present-but-null is an explicit statement in the data.
    # Absent is the absence of any statement. Neither answers an ordering
    # question, so both are undecided. This is the rule that stops a missing
    # field from being reported as "below the threshold".
    if left is ABSENT or right is ABSENT:
        return ComparisonResult(UNDECIDED, left, right,
                                "a field was absent, so it cannot be ordered")
    if left is None or right is None:
        return ComparisonResult(UNDECIDED, left, right,
                                "a value was null, so it cannot be ordered")

    pair = comparable_pair(left, right)
    if pair is None:
        kinds = f"{type(left).__name__} vs {type(right).__name__}"
        return ComparisonResult(UNDECIDED, left, right,
                                f"values are not comparable ({kinds})")

    left_c, right_c = pair
    if isinstance(left_c, str) != isinstance(right_c, str):
        return ComparisonResult(UNDECIDED, left, right, "mixed string and numeric")
    if isinstance(left_c, bool) != isinstance(right_c, bool):
        return ComparisonResult(UNDECIDED, left, right, "mixed boolean and non-boolean")

    try:
        if left_c < right_c:
            cmp_value = -1
        elif left_c > right_c:
            cmp_value = 1
        else:
            cmp_value = 0
    except TypeError as exc:
        return ComparisonResult(UNDECIDED, left, right, f"comparison failed: {exc}")

    return ComparisonResult(ORDERING[op](cmp_value), left, right, "")


def presence(field_value: Any, op: str) -> ComparisonResult:
    """Answer a presence question: `exists` or `is_not_null`.

    Two distinct questions that must not be merged:

      exists(a)      the field is in the row at all
      is_not_null(a) the field is in the row AND is not null

    A row where `a` is present and null satisfies is_not_null but not exists is
    irrelevant to it. Collapsing the two is how a null field becomes a confident
    "the field was there and had a value", which is the specific false statement
    that makes tuning a rule against sparse data go wrong.
    """
    if op == "exists":
        held = field_value is not ABSENT
        return ComparisonResult(held, field_value, True,
                                "" if held else "field is absent")
    if op == "is_not_null":
        if field_value is ABSENT:
            return ComparisonResult(False, field_value, True, "field is absent")
        held = field_value is not None
        return ComparisonResult(held, field_value, True,
                                "" if held else "field is present but null")
    return ComparisonResult(UNDECIDED, field_value, None, f"unknown presence op {op!r}")


def not_(value: bool | Undecided) -> bool | Undecided:
    """Negation, three-valued.

    NOT UNDECIDED is UNDECIDED. It is never True. A rule that has not been
    decided to match has also not been decided not to match, and the second
    reading is exactly the false negative this tool must not produce.
    """
    if isinstance(value, Undecided):
        return UNDECIDED
    return not value


def and_(*values: bool | Undecided) -> bool | Undecided:
    """Conjunction, three-valued.

    False dominates: one decided False is enough to decide the whole thing,
    because AND with a False is False regardless of what the rest was. UNDECIDED
    is only returned when nothing decided it.
    """
    seen_undecided = False
    for value in values:
        if value is False:
            return False
        if isinstance(value, Undecided):
            seen_undecided = True
    return UNDECIDED if seen_undecided else True


def or_(*values: bool | Undecided) -> bool | Undecided:
    """Disjunction, three-valued. True dominates, symmetrically."""
    seen_undecided = False
    for value in values:
        if value is True:
            return True
        if isinstance(value, Undecided):
            seen_undecided = True
    return UNDECIDED if seen_undecided else False
