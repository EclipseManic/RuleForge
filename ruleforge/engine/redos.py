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

# The analysis recurses into nested group bodies. That recursion is bounded so
# a pattern cannot make the ANALYSIS expensive -- an unbounded analysis is a
# denial-of-service vector wearing the costume of a security control.
_MAX_ANALYSIS_DEPTH = 64

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

    # STRING PREFIX IS NOT THE ONLY WAY TWO BRANCHES AMBIGUOUSLY SHARE TEXT.
    # `([a-c][a-c]|[b-d][b-d])+$` is 23 characters, neither branch is a prefix
    # of the other, and it took 19.73 seconds at n=50: every position is a
    # choice between two branches that both match, so there are 2^(n/2) ways to
    # divide the text. Comparing branch STRINGS cannot see that; comparing the
    # characters each position can match can.
    #
    # This must not fire on `GET|POST|PUT`, which also shares a first letter
    # (P) but diverges at the second character -- O(1) choices per position, not
    # exponential. That is why this compares EVERY position, not the first.
    shapes = [_char_shape(branch) for branch in trimmed]
    for i, first in enumerate(shapes):
        if first is None:
            continue
        for j, second in enumerate(shapes):
            if i == j or second is None or len(first) != len(second):
                continue
            if all(a & b for a, b in zip(first, second)):
                return True
    return False


def _char_shape(branch: str) -> list[set[str]] | None:
    """The set of characters each position of `branch` can match.

    None when a position can match more than one character (`.*`, an escaped
    multi-character sequence, a nested group) -- unknown, so this declines to
    claim either overlap or safety.
    """
    out: list[set[str]] = []
    for atom, quantifier, fset in _items(branch):
        if quantifier or fset is None or atom.startswith("("):
            return None
        out.append(fset)
    return out or None


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


def _first_set(atom: str) -> set[str] | None:
    """Characters `atom` can match, or None when that is "anything".

    None means UNKNOWN, and unknown is treated as overlapping with everything.
    A control that assumes two atoms are disjoint when it has not proved it is
    the same class of bug as the one this module exists to prevent.
    """
    if not atom:
        return None
    char = atom[0]
    if char == "\\":
        if len(atom) == 1:
            return None
        return {atom[1]}
    if char == "[":
        close = atom.find("]")
        if close < 0:
            return None
        if atom[1:2] == "^":
            return None
        out: set[str] = set()
        index = 1
        while index < close:
            if atom[index] == "\\":
                out.add(atom[index + 1])
                index += 2
                continue
            if (index + 2 < close and atom[index + 1] == "-"
                    and atom[index + 2] != "]"):
                # RANGES MUST BE EXPANDED, not reduced to their endpoints.
                # Returning only `a` and `c` for `[a-c]` makes `[a-c]` and
                # `[b-d]` look DISJOINT when they share `b` and `c` -- which is
                # how `([a-c][a-c]|[b-d][b-d])+$`, 19.73 seconds at n=50, walked
                # straight through. A range too wide to enumerate is reported as
                # unknown, and unknown is treated as overlapping.
                low, high = ord(atom[index]), ord(atom[index + 2])
                if high - low > 64:
                    return None
                out.update(chr(code) for code in range(low, high + 1))
                index += 3
                continue
            out.add(atom[index])
            index += 1
        return out
    if char == ".":
        return None
    if char == "(":
        return _first_set(_group_body(atom))
    return {char}


def _group_body(atom: str) -> str:
    """The inside of a `(...)` atom, or '' when there is none."""
    if not atom.startswith("("):
        return ""
    depth = 0
    for index, char in enumerate(atom):
        if char == "\\":
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return atom[index + 1:-1]
    return ""


def _items(pattern: str) -> list[tuple[str, str, set[str] | None]]:
    """Split into (atom, quantifier, first_set) triples.

    `quantifier` is '', '?', '*', '+' or '{...}'. An `X{2,4}` counts as
    UNBOUNDED, because a wide upper bound is a wide ambiguity.
    """
    out: list[tuple[str, str, set[str] | None]] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\":
            atom, index = pattern[index:index + 2], index + 2
        elif char == "[":
            close = pattern.find("]", index + 1)
            if close < 0:
                atom, index = pattern[index:], length
            else:
                # A `]` first in the class is a literal, not the terminator.
                probe = close
                if close == index + 1:
                    probe = pattern.find("]", index + 2)
                    if probe < 0:
                        probe = close
                atom, index = pattern[index:probe + 1], probe + 1
        elif char == "(":
            depth = 0
            probe = index
            while probe < length:
                if pattern[probe] == "\\":
                    probe += 2
                    continue
                if pattern[probe] == "(":
                    depth += 1
                elif pattern[probe] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                probe += 1
            atom, index = pattern[index:probe + 1], min(probe + 1, length)
        elif char in "*+?":
            # A bare quantifier with nothing to quantify. `*?` and `+?` are the
            # LAZY forms, so the `?` belongs to the quantifier before it and is
            # not a second quantifier. Treating it as one is what let
            # `"a?" * 24 + "$"` through at 4.85 seconds.
            if out and out[-1][1] in ("*", "+"):
                out[-1] = (out[-1][0], out[-1][1] + "?", out[-1][2])
            index += 1
            continue
        elif char == "{":
            close = pattern.find("}", index)
            body = pattern[index + 1:close] if close > 0 else ""
            # `{2,}`, `{1,}` and `{0,3}` ARE quantifiers. Treating the brace as
            # an ordinary ATOM meant `a{1,}` was seen as the literal text `{1,}`
            # with nothing quantified, so `(a{1,})+$` -- exponential -- was
            # accepted. Python's own interval grammar: `m` is a digit run and `n`
            # is either a digit run or empty.
            interval = re.fullmatch(r"\d*(?:,\d*)?", body) is not None
            if interval and out:
                quantifier = pattern[index:close + 1]
                out[-1] = (out[-1][0], quantifier, out[-1][2])
                index = close + 1
                continue
            atom, index = char, index + 1
        else:
            atom, index = char, index + 1
        quantifier = ""
        if index < length and pattern[index] in "*+?":
            quantifier = pattern[index]
            index += 1
            if index < length and pattern[index] == "?":
                quantifier += "?"
                index += 1
        out.append((atom, quantifier, _first_set(atom)))
    return out


def _is_unbounded(quantifier: str) -> bool:
    """Can this quantifier consume an unbounded number of characters?

    `{2,4}` CANNOT, and treating it as though it could refused
    `[a-z]{2,4}\\d*` -- a shape that reads as a bounded word followed by digits.
    Only `{2,}` and `{1,}` are open-ended; `{4}` is a fixed count.
    """
    if not quantifier:
        return False
    head = quantifier[0]
    if head in "*+":
        return True
    if head != "{":
        return False
    return "," not in quantifier[:-1] or quantifier[:-1].endswith(",")


def _open_after(items: list[tuple[str, str, set[str] | None]]) -> bool:
    """Does this sequence end with an unbounded quantifier still 'open'?

    Open means: the last thing that could consume text is an unbounded
    quantifier and nothing after it PROVED it cannot consume the same text.
    `[a-z]+\\.` is closed -- the dot is a mandatory separator. `[a-z]+` and
    `[a-z]+[a-z]` are open.
    """
    pending: set[str] | None = None
    open_ = False
    for atom, quantifier, fset in items:
        if _is_unbounded(quantifier):
            pending = fset
            open_ = True
        elif quantifier == "?":
            # Zero-or-one is tried once, so it cannot re-split anything.
            continue
        else:
            if pending is not None and fset is not None and not (fset & pending):
                pending = None
                open_ = False
            # A fset of None overlaps everything, so `open_` stays as it was.
    return open_


def _adjacent_ambiguity(pattern: str) -> str | None:
    """Two unbounded quantifiers with nothing provable between them.

    `a*a*b$` is six characters and took 6.07 seconds at n=3000. The old check
    counted quantifiers GLOBALLY, so two of them passed a limit of two --
    while its own comment justified that limit with `\\d+\\.\\d+`, which is only
    safe because a LITERAL separates the two quantifiers. The count was never
    the property that mattered; the separator is.
    """
    pending: set[str] | None = None
    pending_at = -1
    for position, (atom, quantifier, fset) in enumerate(_items(pattern)):
        if _is_unbounded(quantifier):
            if pending is not None:
                return (f"two unbounded quantifiers at positions "
                        f"{pending_at} and {position} with nothing between them "
                        f"that the first one could not have consumed, so a "
                        f"non-matching subject costs the product of every way "
                        f"of splitting the text between them")
            pending = fset
            pending_at = position
        elif quantifier == "?":
            continue
        elif pending is not None and fset is not None and not (fset & pending):
            pending = None
    return None


def catastrophic_reason(pattern: str) -> str | None:
    """Why this pattern can blow up, or None when it is fine."""
    if len(pattern) > 4096:
        return (f"the pattern is {len(pattern):,} characters, over the 4096 "
                f"limit. A long pattern is not a threat by itself, but nothing "
                f"here needs one, and the analysis below is linear in its "
                f"length")

    # COUNT `?` AND NOTHING ELSE HERE. This used to count every `*` and `+`
    # against a limit of two, on the reasoning that each one multiplies the
    # number of ways the text can be split. That reasoning is wrong about its
    # own examples: the comment justifying the limit cited `\d+\.\d+`, which is
    # safe ONLY because a literal separates the two quantifiers -- and the check
    # could not see the separator. So it refused `[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`
    # (every IPv4 regex), `^[0-9]+:[0-9]+:[0-9]+$` (every timestamp) and
    # `\w+@\w+\.\w+` (every email), while `--adjacent-ambiguity--` below passes
    # all three. `_adjacent_ambiguity` now decides the `*`/`+` case from the
    # separator, which is the property that actually mattered.
    #
    # `?` still needs a count, because zero-or-one is deliberately exempt from
    # the adjacency check (it is tried once and cannot re-split anything), and
    # `"a?" * 24 + "$"` is 4.85 seconds of pure multiplication with no `*` or
    # `+` anywhere for the adjacency check to see.
    optional = sum(1 for _, quantifier, _ in _items(pattern)
                   if quantifier and quantifier[0] == "?")
    if optional > MAX_UNBOUNDED_QUANTIFIERS:
        return (f"{optional} optional groups (?). Each one multiplies the number "
                f"of ways the text before it can be split, so a non-matching "
                f"subject costs the product of all of them. "
                f"{len(pattern)} characters of this shape is already 30 seconds")

    ambiguity = _adjacent_ambiguity(pattern)
    if ambiguity:
        return ambiguity

    for position, body, quantifier in _quantified_bodies(pattern):
        # `?` MEANS ZERO-OR-ONE, so the group is tried at most ONCE and cannot
        # re-split anything. `[0-9]+(\.[0-9]+)?` is an ordinary decimal pattern
        # that an earlier version of this check refused.
        if quantifier == "?" or not body:
            continue
        if _overlapping_alternation_anywhere(body):
            return (f"the group quantified at position {position} has "
                    f"alternatives that can match the same text, so a "
                    f"non-matching subject makes the engine try every way of "
                    f"dividing the text between them -- exponentially many")
        if _open_after(_items(body)):
            return (f"the group quantified at position {position} ends with an "
                    f"unbounded quantifier that nothing after it rules out, so "
                    f"both the group and its contents can be re-split on a "
                    f"non-matching subject")
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


def _overlapping_alternation_anywhere(body: str, _seen: set[str] | None = None) -> bool:
    """Ambiguous alternatives at ANY depth inside `body`.

    THE RECURSION USED TO BE 2^depth, AND THAT MADE THE CONTROL A DoS VECTOR.
    `_all_group_bodies` returns every group body at every depth, so the
    innermost one was re-analysed once per group that encloses it: `"("*24 +
    "a" + ")"*24 + "+$"` is 51 characters and took 15.28 seconds in THIS
    function, reachable from `POST /api/tune` with a single event. A guard that
    can be made to hang is worse than no guard, because it reads as protection.

    Two fixes, because either alone is insufficient. `_seen` makes each
    distinct body text cost one analysis, which is what actually removes the
    blowup -- a pure nesting chain has `depth` distinct bodies, not 2^depth.
    The depth cap is the backstop for the case memoisation cannot help: many
    distinct nested bodies. ReDoS needs the alternation inside a QUANTIFIED
    group, and `re.compile` rejects nesting past ~200 deep on its own, so 64 is
    far past any pattern that could match.
    """
    if _seen is None:
        _seen = set()
    if body in _seen:
        return False
    if len(body) > _MAX_ANALYSIS_DEPTH:
        return False
    _seen.add(body)
    if _alternatives_overlap(body):
        return True
    for inner in _all_group_bodies(body):
        if _overlapping_alternation_anywhere(inner, _seen):
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
