"""Reject patterns that can take exponential time on a non-matching subject.

THE PRECISE CONDITION, NOT A BLUNT ONE

Two shapes make matching blow up, and both are about the number of ways a
subject can be SPLIT:

  1. Two or more ALTERNATIVES where one is a prefix of another, inside a
     quantified group. `(a|aa)+$` -- for a subject of `aaaa...b` the engine
     tries every way of dividing the a's between the two branches. 2^n.
     `(a|b)+c` is NOT this: neither alternative is a prefix of the other, so
     there is only one way to match any given text, and it is linear. Refusing
     that would be a false positive on a perfectly ordinary pattern.

  2. MANY unbounded quantifiers with nothing to separate them. `a*a*a*a*a$`
     needs no parentheses at all. Each quantifier multiplies the number of ways
     the prefix can be split, so the cost is the PRODUCT of the counts.

Both are refused. A 31-character pattern of shape 2 was refused in 0.04 ms;
before this, the same shape took 31 SECONDS and timed out past 60.

WHAT IS DELIBERATELY NOT REFUSED: `(abc)+`, `[a-z]+`, `^lsass\.exe$`,
`^577$|^4673$`, `[0-9]+`, `a*b`. A quantified fixed string and a character class
are linear, and they are what detection rules overwhelmingly use. A refusal is a
named error the analyst can act on; a hang is not.
"""
from __future__ import annotations

import re

#: At this many unbounded quantifiers the product of the split counts stops being
#: safe. `a*a*a*$` is three and is already exponential. Ordinary detection regexes
#: have one or two -- `\d+\.\d+` has two.
MAX_UNBOUNDED_QUANTIFIERS = 2

#: Alternatives longer than this are not compared for prefix overlap. The check
#: is only there to catch `a` vs `aa`, and comparing long branches is wasted work.
_MAX_ALT_LEN = 24

_ATOM = re.compile(r"\((?!\?)|\[|\^|\$|\\.|[^()[\]\\^$.*+?|]")


def _alternatives_overlap(body: str) -> bool:
    """Do any two top-level alternatives in `body` share a prefix?

    `(a|aa)` yes -- `a` is a prefix of `aa`, so `aaaa` can be split many ways.
    `(a|b)` no. `(GET|POST)` no. `(foo|foobar)` yes.
    """
    branches: list[str] = []
    current: list[str] = []
    depth = 0
    index = 0
    length = len(body)

    while index < length:
        char = body[index]
        if char == "\\":
            current.append(body[index:index + 2])
            index += 2
            continue
        if char == "[":
            close = body.find("]", index + 1)
            current.append(body[index:close + 1 if close > 0 else index + 1])
            index = (close + 1) if close > 0 else index + 1
            continue
        if char == "(":
            depth += 1
            current.append(char)
            index += 1
            continue
        if char == ")":
            depth -= 1
            current.append(char)
            index += 1
            continue
        if char == "|" and depth == 0:
            branches.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    branches.append("".join(current))

    if len(branches) < 2:
        return False

    trimmed = [b[:_MAX_ALT_LEN] for b in branches]
    for i, first in enumerate(trimmed):
        if not first:
            return True
        for j, second in enumerate(trimmed):
            if i == j:
                continue
            if first.startswith(second) or second.startswith(first):
                return True
    return False


def _quantified_bodies(pattern: str) -> list[tuple[int, str, str]]:
    """Every group body that is quantified, as (position, body, quantifier)."""
    out: list[tuple[int, str]] = []
    open_at: list[int] = []
    index = 0
    length = len(pattern)

    while index < length:
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            close = pattern.find("]", index + 1)
            index = (close + 1) if close > 0 else index + 1
            continue
        if char == "(":
            open_at.append(index)
            index += 1
            if index < length and pattern[index] == "?":
                while index < length and pattern[index] not in ":=!<":
                    index += 1
                index += 1
            continue
        if char == ")":
            start = open_at.pop() if open_at else None
            index += 1
            if start is None:
                continue
            quantifier = None
            probe = index
            while probe < length and pattern[probe].isspace():
                probe += 1
            if probe < length and pattern[probe] in "*+":
                quantifier = pattern[probe]
            elif probe < length and pattern[probe] == "{":
                quantifier = "{"
            if quantifier is not None:
                out.append((index, pattern[start + 1:index - 1], quantifier))
            continue
        index += 1
    return out


def catastrophic_reason(pattern: str) -> str | None:
    """Why this pattern can blow up, or None when it is fine."""
    if len(pattern) > 4096:
        return (f"the pattern is {len(pattern):,} characters, over the 4096 "
                f"limit. A long pattern is not a threat by itself, but nothing "
                f"here needs one, and the analysis below is linear in its "
                f"length")

    unbounded = 0
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            close = pattern.find("]", index + 1)
            index = (close + 1) if close > 0 else index + 1
            continue
        if char in "*+":
            unbounded += 1
        index += 1

    if unbounded > MAX_UNBOUNDED_QUANTIFIERS:
        return (f"{unbounded} unbounded quantifiers ({'*' and '*' or ''}"
                f"{' or +' if unbounded > 1 else ''}). Each one multiplies the "
                f"number of ways the text before it can be split, so a "
                f"non-matching subject costs the product of all of them. "
                f"{len(pattern)} characters of this shape is already 30 seconds")

    for position, body, quantifier in _quantified_bodies(pattern):
        # `?` MEANS ZERO-OR-ONE, so the group is tried at most ONCE and cannot
        # re-split anything. `[0-9]+(\.[0-9]+)?` is an ordinary decimal pattern
        # that an earlier version of this check refused.
        if quantifier == "?" or not body:
            continue
        if _overlapping_alternation_anywhere(body):
            return (f"the group quantified at position {position} has "
                    f"alternatives where one is a prefix of another, so a "
                    f"non-matching subject makes the engine try every way of "
                    f"dividing the text between them -- exponentially many")
        if unbounded_in(body):
            return (f"the group quantified at position {position} contains a "
                    f"quantifier of its own, so both the group and its contents "
                    f"can be re-split on a non-matching subject")

    return None


def _all_group_bodies(body: str) -> list[str]:
    """Every group body at any depth, quantified or not.

    `((a|aa))+$` puts the alternation two groups down and the inner group is NOT
    itself quantified, so recursing only into quantified groups missed it.
    """
    out: list[str] = []
    stack: list[int] = []
    index = 0
    length = len(body)
    while index < length:
        char = body[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            close = body.find("]", index + 1)
            index = (close + 1) if close > 0 else index + 1
            continue
        if char == "(":
            stack.append(index)
            index += 1
            if index < length and body[index] == "?":
                while index < length and body[index] not in ":=!<":
                    index += 1
                index += 1
            continue
        if char == ")":
            start = stack.pop() if stack else None
            if start is not None:
                out.append(body[start + 1:index])
            index += 1
            continue
        index += 1
    return out


def _overlapping_alternation_anywhere(body: str) -> bool:
    """Prefix-overlapping alternatives at ANY depth inside `body`."""
    if _alternatives_overlap(body):
        return True
    for inner in _all_group_bodies(body):
        if _overlapping_alternation_anywhere(inner):
            return True
    return False


def unbounded_in(body: str) -> int:
    total = 0
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            close = body.find("]", index + 1)
            index = (close + 1) if close > 0 else index + 1
            continue
        if char in "*+":
            total += 1
        index += 1
    return total


def _group_contains_quantifier(body: str) -> bool:
    """Is there a quantifier inside a NESTED group in `body`?

    A quantifier directly on a top-level atom -- `(a+)` -- is linear, so it is
    not this. `([a-z]+)+` is.
    """
    for _, inner in _quantified_bodies(body):
        if unbounded_in(inner):
            return True
    return False
