r"""Reject patterns that can take exponential time on a non-matching subject.

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
import string

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

#: `\d` and `\w`, as the SETS THEY MATCH rather than the names they are spelled.
#: Every other escape is either a literal (handled inline) or unknown, and
#: unknown is the safe answer. See `_first_set` for why direction matters more
#: than completeness here.
_CLASS_ESCAPES: dict[str, frozenset[str]] = {
    "d": frozenset(string.digits),
    "w": frozenset(string.ascii_letters + string.digits + "_"),
}

#: Control-character escapes, which ARE literals -- unlike `\b`, which is not a
#: literal and was being reported as the letter `b`.
_CONTROL_ESCAPES: dict[str, str] = {
    "n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v",
    "a": "\a", "0": "\0",
}

# `_ATOM` USED TO BE DEFINED HERE AND WAS CALLED BY NOTHING. It was an atom
# pattern for a tokeniser this module no longer has -- `catastrophic_reason`
# works on quantifier counts, prefix overlap and alternation structure, not on a
# token stream. It had zero references in the whole tree, so it was not a
# fallback or a re-export; it was the remains of the round-3 control that this
# module replaced.


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


def _body_start_after_prefix(text: str, paren: int) -> int:
    """Index just past a group-opening `(` and any prefix that follows it.

    SHARED BY `_group_body_start` AND `_group_inner` ON PURPOSE. Those two
    callers need the same knowledge -- which characters after `(` are a group
    prefix rather than body -- and when the alternation check and the quantifier
    check each carried their own copy of these rules, they disagreed, and the
    disagreement was the bug: `((a|aa))+$` was refused because the alternation
    path descended correctly while the quantifier path did not. One
    implementation, two callers, cannot drift.
    """
    length = len(text)
    after = paren + 1
    if after >= length or text[after] != "?":
        return after

    marker = text[after + 1:after + 2]
    if marker == "P" and text[after + 2:after + 3] == "<":
        close = text.find(">", after + 3)
        return (close + 1) if close != -1 else after + 1
    if marker == "<":
        return after + 3
    if marker in (":", "=", "!"):
        return after + 2
    if marker == "#":
        close = text.find(")", after + 2)
        return len(text) if close == -1 else close + 1
    index = after + 1
    while index < length and text[index] not in "):":
        index += 1
    return (index + 1) if index < length and text[index] == ":" else index


def _group_body_start(pattern: str, paren: int) -> int:
    """Index of the first character INSIDE the group opened at `paren`.

    THE BUG THIS FIXES IS A WHOLE CLASS OF BYPASS, NOT ONE PATTERN.

    The old code scanned forward from `(` looking for one of `:=!<` and then
    skipped exactly one more character, on the assumption that a group prefix is
    two characters. That is true for `(?:` and false for everything else:

        (?:a|aa)+      body read as "?"      -> no alternation seen -> ACCEPTED
        (?P<w>a|aa)+   body read as "?P<"    -> no alternation seen -> ACCEPTED
        (?<=a|aa)      correct by luck, because < is in the stop set

    And then the body was sliced as `pattern[start + 1:...]` where `start` was
    the index of `(` -- so for EVERY prefixed group the slice began at the `?`
    and the real body was never examined at all. `(?:` is a non-capturing group:
    its body is `a|aa`, two prefix-overlapping alternatives under a `+`, which is
    the exact shape the alternation check exists to catch. It measured 0.6-1.0s
    at n=32 and was accepted, while the identical `(a|aa)+$` was refused. Same
    language, different verdict, decided by a prefix nobody thought about.

    So the prefix is now parsed rather than guessed. Every construct Python's
    `re` allows after `(` is listed, and an unknown one returns `paren + 1` --
    the old behaviour -- rather than something clever that could be wrong in a
    new way. A group whose prefix is not understood is measured as if it had no
    prefix, which is the same shape the bypass had, so that case is refused
    rather than waved through: an unparsed prefix is a reason to be suspicious,
    not a reason to assume the body is clean.
    """
    return _body_start_after_prefix(pattern, paren)


def _quantified_bodies(pattern: str) -> list[tuple[int, str, str]]:
    """Every group body that is quantified, as (position, body, quantifier)."""
    out: list[tuple[int, str]] = []
    #: The index where each open group's BODY begins -- not where its `(` is.
    #: Those differ for every prefixed group, and using the paren index is what
    #: let `(?:a|aa)+` through. See `_group_body_start`.
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
            open_at.append(_group_body_start(pattern, index))
            index += 1
            continue
        if char == ")":
            body_start = open_at.pop() if open_at else None
            index += 1
            if body_start is None:
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
                out.append((index, pattern[body_start:index - 1], quantifier))
            continue
        index += 1
    return out


def _first_set(atom: str) -> set[str] | None:
    r"""Characters `atom` can match, or None when that is "anything".

    None means UNKNOWN, and unknown is treated as overlapping with everything.
    A control that assumes two atoms are disjoint when it has not proved it is
    the same class of bug as this module exists to prevent.

    THE ESCAPE BRANCH USED TO BE `{atom[1]}`, AND THAT MADE THE WHOLE
    CONVENTION A LIE. For a word escape that is `{'w'}` -- the name of the
    class, as a literal letter. So that escape and `a` were "proved" disjoint,
    the pattern below was accepted, and it grows 8.71x per character added:
    measured 0.0022s at n=20 and 12.5s at n=38. The unwrapped equivalent
    `(aa|a)+$` is refused.

    The error is one of DIRECTION, not of detail. Every consumer of this
    function needs an UPPER bound on what an atom can match, because it uses the
    result to prove two atoms CANNOT collide. A one-character set is a LOWER
    bound. A lower bound used as an upper bound proves the opposite of what is
    true, which is why the docstring above could name the exact invariant and
    the code still break it: `\d` became `{'d'}`, `\s` became `{'s'}`, `\b`
    became `{'b'}`, and a backreference `\1` became `{'1'}`.

    So each escape is classified by what it MEANS, not by what it is spelled:

      `\\d`      the ten ASCII digits -- a complete, exact, small set
      `\\w`      ASCII letters, digits and underscore. Python's `\\w` is Unicode
                 aware for str patterns, so this is not the whole truth; it is
                 a superset of what matters for collision detection on real
                 event fields, and it is deliberately on the LARGE side because
                 finding a collision is the safe direction.
      `\\s`      None. Whitespace under `re.UNICODE` is not a small set, and a
                 short approximation here is a lower bound again.
      `\\D \\W \\S`  None. These are NEGATIONS -- "anything except" -- and the
                 whole point is that they are not enumerable.
      `\\b \\B \\A \\Z \\z \\G`  None. Zero-width assertions match the EMPTY
                 string, not a character. Reporting them as their own name made
                 `\\b` look like the letter `b`.
      `\\1`..`\\99`  None. A backreference matches whatever the group captured,
                 which is unknowable without executing the pattern -- and this
                 function must not execute anything.
      `\\n \\t \\r \\f \\v \\a \\0`  the real control characters. These ARE
                 literals, and reporting them as the letter `n` was wrong.
      punctuation  `\\.` `\\\\` `\\+` ... all single characters, and a single
                 character IS the complete answer. These stay exact.
    """
    if not atom:
        return None
    char = atom[0]
    if char == "\\":
        if len(atom) == 1:
            return None
        kind = atom[1]
        if kind in _CLASS_ESCAPES:
            return _CLASS_ESCAPES[kind]
        # Negated classes and zero-width assertions. `\b` matching the letter
        # `b` is how a boundary assertion turned into a literal, and a literal
        # here is a false proof of disjointness.
        if kind in "sSbBAZGzgWDS":
            return None
        if kind.isdigit():
            # A backreference. Unknowable without running the pattern.
            return None
        if kind in _CONTROL_ESCAPES:
            return {_CONTROL_ESCAPES[kind]}
        # Anything else is escaped PUNCTUATION, which is a literal in both
        # Python flavours, so one character is the complete answer.
        return {kind}
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
                escaped = atom[index + 1]
                if escaped in _CLASS_ESCAPES:
                    out |= _CLASS_ESCAPES[escaped]
                elif escaped in "sSbBAZGzgWDS" or escaped.isdigit():
                    # Same reasoning as above, and it bites here too: `[\d]`
                    # used to contribute the letter `d`.
                    return None
                elif escaped in _CONTROL_ESCAPES:
                    out.add(_CONTROL_ESCAPES[escaped])
                else:
                    out.add(escaped)
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

    AND A NESTED GROUP IS NOT AN ATOM, IT IS A BODY. It used to be treated as
    one: `((a+))+$` gives a single item, the atom `(a+)` with quantifier `''`, so
    nothing in this loop ever saw the `+` and the group looked closed. The
    pattern was accepted, and it grows 4.00x per character added -- 0.022s at
    n=18, 1.40s at n=24 -- while the unwrapped `(a+)+$` is refused.

    That is the same language with one pair of parentheses around it, and the
    ONLY reason it behaved differently is that the alternation check descends
    into nested bodies and this one did not. The asymmetry was the bug:
    `((a|aa))+$` was always refused, `((a+))+$` never was, and nothing in the
    module said those two should differ.

    So a group atom is now expanded and recursed into. The body is located with
    the SAME `_body_start_after_prefix` the quantified-body scan uses, so the two
    paths cannot disagree about where a body starts -- which is precisely how
    they came to disagree in the first place.

    RECURSION IS BOUNDED, NOT ASSUMED. A group whose inner call is already
    deeper than `_MAX_ANALYSIS_DEPTH` stops descending and is reported as OPEN,
    which is the refusing answer. An unbounded search here would be a
    denial-of-service vector in the middle of a denial-of-service screen, which
    is not a trade anyone needs to make.
    """
    return _open_after_at_depth(items, 0)


def _open_after_at_depth(items: list[tuple[str, str, set[str] | None]],
                         depth: int) -> bool:
    pending: set[str] | None = None
    open_ = False
    for atom, quantifier, fset in items:
        if atom.startswith("(") and atom.endswith(")"):
            if depth >= _MAX_ANALYSIS_DEPTH:
                return True
            inner = atom[_body_start_after_prefix(atom, 0):-1]
            if inner and _open_after_at_depth(_items(inner), depth + 1):
                # The nested body is itself open, so this group is open: the
                # outer quantifier can hand the same text to the inner one in
                # more than one way.
                return True
        if _is_unbounded(quantifier):
            pending = fset
            open_ = True
        elif quantifier == "?":
            # `?` IS EXEMPT AT THE TOP LEVEL -- it is tried once and cannot
            # re-split anything, which is why `[0-9]+(\.[0-9]+)?` compiles. But
            # INSIDE a group that is itself quantified it is a multiplier, and
            # `(a?a?)+$` is twelve characters that hang: each `a?` can match or
            # skip, so the ways to divide the text multiply. Skipping `?` here
            # is what let that through.
            pending = fset
            open_ = True
        else:
            if pending is not None and fset is not None and not (fset & pending):
                pending = None
                open_ = False
            # A fset of None overlaps everything, so `open_` stays as it was.
    return open_


def _adjacent_ambiguity(pattern: str) -> str | None:
    """Two unbounded quantifiers with NOTHING at all between them.

    `a*a*b$` is six characters and took 6.07 seconds at n=3000. The old check
    counted quantifiers GLOBALLY, so two of them passed a limit of two -- while
    its own comment justified that limit with `\\d+\\.\\d+`, which is only safe
    because a literal separates the two quantifiers. The count was never the
    property that mattered.

    THE TEST IS NOW ADJACENCY, NOT "NOTHING PROVABLY DISJOINT" -- AND THAT IS A
    CORRECTNESS FIX, NOT A LOOSENING. The previous version refused any pair whose
    intervening atoms the first quantifier could also match, which made it
    reject `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$`: the standard
    email regex, in sentinel, YARA-L and Wazuh. A legitimate SOC rule could no
    longer be authored. That pattern is QUADRATIC, not exponential -- one
    ambiguous separator, two quantifiers, no nesting -- and refusing a merely
    quadratic pattern is over-strict in the direction that does real harm.

    The exponential families are all still caught, by the other two checks:
    a quantifier under a quantifier and an ambiguous alternation both live in
    `_open_after` and `_alternatives_overlap`, and neither depends on this one.
    """
    previous_unbounded = False
    for position, (atom, quantifier, fset) in enumerate(_items(pattern)):
        if _is_unbounded(quantifier):
            # A QUANTIFIED GROUP IS ONLY "UNBOUNDED" FOR THIS PURPOSE IF ITS BODY
            # ENDS OPEN. `([a-z]+\.)+[a-z]+` is an FQDN pattern: the body ends
            # with a literal dot, so each label has exactly one possible length
            # and there is nothing to re-split. Treating the group as an
            # unbounded atom anyway refused it, and the two quantifiers in that
            # pattern are separated by a mandatory character in every reading.
            # `_open_after` is the same test the nested-quantifier check uses, so
            # both agree on what "open" means.
            if atom.startswith("(") and not _open_after(_items(_group_body(atom))):
                previous_unbounded = False
                continue
            if previous_unbounded:
                return (f"two unbounded quantifiers in a row at positions "
                        f"{position - 1} and {position}, with nothing between "
                        f"them, so a non-matching subject costs the product of "
                        f"every way of splitting the text between them")
            previous_unbounded = True
            continue
        if quantifier == "?":
            # Zero-or-one is tried once. It does not re-split anything, and it
            # breaks adjacency, so `a*a?` is not this shape.
            previous_unbounded = False
            continue
        # ANY atom between the two quantifiers ends the run. That atom may be
        # matchable by the quantifier before it -- which is the quadratic case
        # above -- but it is still a mandatory character, so the engine is not
        # choosing between exponentially many readings of the same text.
        previous_unbounded = False
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


def _overlapping_alternation_anywhere(body: str, _seen: set[str] | None = None,
                                      _depth: int = 0) -> bool:
    """Ambiguous alternatives at ANY depth inside `body`.

    THE DEPTH BOUND MUST COUNT DEPTH, NOT CHARACTERS.

    The round-4 fix bounded this with `len(body) > 64`, because the recursion was
    `2^depth` and had to stop somewhere. But a LENGTH cap is not a DEPTH cap, and
    the alternation-overlap check is the one that exists for exactly this pattern
    family -- so every quantified group body longer than 64 characters skipped it
    entirely. The cap added to kill the analysis blowup is what created the
    bypass: `([a-c][a-c]|[b-d][b-d])+$` at 21 characters is refused (19.7s at
    n=24), and the same alternation repeated to 109 characters is ACCEPTED and
    hangs at n=2. A 17-byte `<field>` reached it end to end, because a `<field>`
    with no `type` attribute defaults to `os_regex`, which this engine executes.

    So: `_depth` counts recursion, and `_seen` on the body text is what actually
    removes the blowup -- a pure nesting chain has `depth` distinct bodies, not
    2^depth. 64 levels of nesting is far past anything `re.compile` will accept.
    """
    if _seen is None:
        _seen = set()
    # A BUDGET ON DISTINCT BODIES, NOT JUST ON DEPTH. `_all_group_bodies`
    # returns every group body at EVERY depth in one call, so the recursion is
    # one level deep and wide rather than deep: a depth cap alone never fires,
    # and memoisation leaves the cost at O(n^2) in the pattern length. Depth 900
    # took 744ms and depth 1500 took 3.7s -- the analysis was a DoS vector again,
    # one round after it stopped being one. 512 distinct bodies is far more
    # alternation than any real detection has.
    if body in _seen or _depth > _MAX_ANALYSIS_DEPTH or len(_seen) > 512:
        return False
    _seen.add(body)
    if _alternatives_overlap(body):
        return True
    for inner in _all_group_bodies(body):
        if _overlapping_alternation_anywhere(inner, _seen, _depth + 1):
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
