"""Regex dialects, and an honest account of what can be executed.

THE PROBLEM

`matches_regex` needs a declared dialect because the dialects disagree on real
analyst input: `\d`, `[[:digit:]]`, `\b`, inline flags, intervals and lazy
quantifiers all behave differently. A rule written for one engine and run on
another does not degrade gracefully -- it matches a different set of rows,
silently.

WHAT THIS MODULE DOES

An ALLOWLIST, not a blocklist. Only constructs whose meaning is identical in
every supported dialect may be executed. Everything else is refused by name.

The earlier version of this file used a blocklist with a `_DIALECT_SPECIFIC`
table, and an independent review found nine patterns it classified as portable
whose meaning actually differs in the declared dialect -- including POSIX BRE,
where `+ ? { | ( )` are LITERALS rather than operators, so a translation that
passed them through turned "literal a+b" into "one or more a, then b". Both
directions were wrong: a pattern that should match reported no-match, which on a
credential-access rule is a missed detection.

A blocklist cannot establish portability. Only an allowlist can. So:

  * Only the constructs below are executable.
  * `posix_basic` is NOT executable. Translating BRE faithfully means
    re-escaping its literal metacharacters, and a half-correct translation is
    worse than no translation because it returns confidently wrong booleans.
    It remains DECLARABLE so an analyst's intent is recorded without loss.
  * `pcre` is NOT executable either. Python's `re` is not PCRE.
"""

from __future__ import annotations

import re
from typing import Callable, Final

from .values import Refusal

#: The only dialects this module can run.
#:
#: Kept as a single definition here and re-exported by `ir.py`, because two
#: copies of this set is precisely how a guard and a capability claim drift apart.
EXECUTABLE_DIALECTS: Final = frozenset({"posix_extended"})

#: Dialects an author may DECLARE, whether or not they can be executed.
DECLARABLE_DIALECTS: Final = frozenset({"pcre", "posix_extended", "posix_basic"})

#: Tokens permitted in an executable pattern, matched literally.
#:
#: Letters, digits, space, and the class delimiters. Note what is ABSENT: no
#: backslash. Every backslash escape is dialect-sensitive (`\d` is a class in ERE
#: but backspace in BRE), so an executable pattern may not contain one. That is a
#: severe restriction and it is stated plainly rather than discovered later.
_ALLOWED_LITERALS: Final = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " _-.,:;/@#%&*+?|^~"
)

#: Structural tokens that mean the same thing in every supported dialect, mapped
#: to what they are. Anything not in here and not a literal is refused.
_ALLOWED_SYNTAX: Final[dict[str, str]] = {
    ".": "any character",
    "^": "start anchor",
    "$": "end anchor",
    "*": "zero or more",
    "+": "one or more",
    "?": "zero or one",
    "|": "alternation",
    "(": "group",
    ")": "group close",
    "[": "character class",
    "]": "character class close",
}

#: Constructs refused, and the reason, so the message names the problem.
#: This is documentation and message quality -- it is NOT what makes a pattern
#: executable. The allowlist above is what makes it executable.
_REFUSED_WITH_REASON: Final[dict[str, str]] = {
    "\\": "backslash escapes are dialect-specific (`\\d` is a digit class in ERE "
          "but a backspace in BRE), so an executable pattern may not contain one",
    "{": "interval quantifiers such as {2,4} are ERE syntax and literals in BRE",
    "(?": "group extensions (inline flags, lookaround, named groups) are PCRE-only",
    "[[": "POSIX named character classes such as [[:digit:]] are not supported by "
          "this engine and would return a wrong answer rather than an error",
}


def _scan(pattern: str) -> str | None:
    """Return a refusal reason, or None when the pattern is fully understood."""
    index = 0
    while index < len(pattern):
        char = pattern[index]

        if char == "\\":
            # AN ESCAPED LITERAL IS NOT DIALECT-SPECIFIC. Refusing every
            # backslash was defensible but too broad: `\.` is a literal dot in
            # ERE and in BRE alike, and so are `\+`, `\(`, `\$`, `\\` and the
            # rest. Wazuh's own shipped rule 60000 is `\.+`, so the refusal made
            # a real ruleset unexecutable over a character with exactly one
            # meaning.
            #
            # The line is drawn at ALPHANUMERICS. `\d`, `\w`, `\s`, `\b` and `\1`
            # are character classes, anchors and backreferences, and those DO
            # differ between engines -- `\b` is a word boundary in ERE but a
            # backspace in BRE. Those stay refused, because evaluating them here
            # would return a wrong answer rather than an error.
            following = pattern[index + 1:index + 2]
            if not following:
                return ("a trailing backslash is not a pattern")
            if following.isalnum():
                return _REFUSED_WITH_REASON["\\"]
            index += 2
            continue

        if char == "(" and pattern[index:index + 2] == "(?":
            return _REFUSED_WITH_REASON["(?"]

        if char == "[":
            rest = pattern[index + 1:index + 3]
            if rest.startswith(":"):
                return _REFUSED_WITH_REASON["[["]
            if rest.startswith("."):
                return (f"collating symbol {pattern[index:index + 4]!r} is not "
                        f"supported and would compile with a warning and a wrong "
                        f"answer")

        if char in _ALLOWED_SYNTAX:
            index += 1
            continue

        if char in _ALLOWED_LITERALS:
            index += 1
            continue

        return (f"the character {char!r} is not in the set this engine can execute "
                f"with a guarantee of identical meaning")

    return None


def _nested_quantifier(pattern: str) -> str | None:
    """The first quantified group that can blow up, or None.

    TWO SHAPES, both refused:

      1. A quantifier INSIDE a quantified group -- `([a-z]+)+`. Tracked with a
         depth stack and a per-level "is this group already quantified" flag.

      2. An ALTERNATION inside a quantified group -- `(a|aa)+$`. There is no
         quantifier to find here, but the alternatives overlap in their prefix,
         so a non-matching subject makes the engine try exponentially many
         splits: 2^n. Detecting that precisely needs real analysis, so the rule
         is the conservative one: a quantified group carries no top-level `|`.

    Both are conservative. A quantified group that is a plain fixed string --
    `(abc)+` -- is fine and still allowed, because that is what detection rules
    overwhelmingly use. Being refused a pattern is a named error the analyst can
    act on; hanging is not.
    """
    depth = 0
    quantified: list[bool] = []
    alternation: list[bool] = []
    #: Consecutive unbounded quantifiers at the SAME level, with no group between
    #: them. `a*a*a*a*a*a*a*a*$` needs no parentheses at all to be catastrophic:
    #: a 12-character pattern took 31 seconds and timed out past 60. The first
    #: version of this check only looked INSIDE groups, so that whole class walked
    #: straight through it -- which is exactly the threat this control exists for,
    #: since the attacker picks the pattern and not the data.
    run = 0
    pending: tuple[bool, bool] | None = None
    index = 0
    length = len(pattern)

    #: Two in a row is ordinary (`\d+\.\d+` is separated, but `a*b` is not
    #: ambiguous); three is the point where the split count turns exponential.
    MAX_CONSECUTIVE_QUANTIFIERS = 2

    while index < length:
        char = pattern[index]

        if char == "\\":
            index += 2
            continue
        if char == "[":
            close = pattern.find("]", index + 1)
            index = length if close < 0 else close + 1
            continue
        if char == "(":
            quantified.append(False)
            alternation.append(False)
            pending = None
            depth += 1
            index += 1
            # A `?` STRAIGHT AFTER `(` IS A GROUP MODIFIER, not a quantifier:
            # `(?i)`, `(?=x)`, `(?<=a)`, `(?:x)` all start with one. Treating it
            # as a quantifier made every lookaround look like a nested-quantifier
            # pattern, so it was refused for catastrophic backtracking instead of
            # for being PCRE-only -- and the mutation check caught that the
            # `(?` refusal had become untested.
            if index < length and pattern[index] == "?":
                index += 1
            continue
        if char == ")":
            depth = max(0, depth - 1)
            inner_quantified = quantified.pop() if quantified else False
            inner_alternation = alternation.pop() if alternation else False
            if inner_quantified:
                return f"the group ending at position {index}"
            pending = (False, inner_alternation)
            index += 1
            continue
        if char == "|":
            if alternation:
                alternation[-1] = True
            index += 1
            continue
        if char in "*+?":
            if depth and quantified and quantified[-1]:
                return f"the quantifier at position {index}"
            if depth and quantified:
                quantified[-1] = True
            elif pending is not None and depth == 0:
                # A quantifier closing a group from outside: `(a|aa)+`.
                if pending[1]:
                    return (f"the group quantified at position {index}: its "
                            f"alternatives overlap, so a non-matching subject "
                            f"makes the engine try exponentially many splits")
                pending = None
                run = 0
            else:
                # AT THE TOP LEVEL, WITH NO GROUP INVOLVED. Three in a row is
                # the catastrophic shape and needs no parentheses to reach it.
                run += 1
                if run > MAX_CONSECUTIVE_QUANTIFIERS:
                    return (f"{run} unbounded quantifiers in a row at position "
                            f"{index}, with nothing between them. A subject that "
                            f"does not match makes the engine try every way of "
                            f"splitting it, which is exponential -- a "
                            f"{len(pattern)}-character pattern of this shape "
                            f"already takes 30 seconds")
            index += 1
            continue
        if char == "{" and index + 1 < length and pattern[index + 1].isdigit():
            if depth and quantified and quantified[-1]:
                return f"the interval at position {index}"
            if depth and quantified:
                quantified[-1] = True
            elif pending is not None and depth == 0:
                if pending[1]:
                    return (f"the group quantified at position {index}: its "
                            f"alternatives overlap")
                pending = None
            index += 1
            continue
        if not char.isspace():
            pending = None
            run = 0
        index += 1
    return None


def compile_pattern(dialect: str, pattern: str) -> Callable[..., bool]:
    """Compile `pattern` for `dialect`, or refuse with the reason.

    Refusal codes:
        REGEX_NOT_EXECUTABLE    the dialect has no engine here at all
        REGEX_DIALECT_SPECIFIC  the pattern uses a construct whose meaning this
                                engine cannot guarantee for that dialect
        REGEX_INVALID           the pattern does not compile

    The returned callable takes `(value, case_insensitive=False)`. Case folding
    is applied to BOTH sides rather than by rewriting the pattern with `(?i)`,
    because rewriting would change the analyst's bytes and break the render
    round-trip -- and because `(?i)` is precisely the inline-flag construct this
    module refuses elsewhere on portability grounds.
    """
    if dialect not in EXECUTABLE_DIALECTS:
        raise Refusal(
            "REGEX_NOT_EXECUTABLE",
            f"no regex engine is implemented for dialect {dialect!r}. Python's `re` "
            f"is neither PCRE nor POSIX BRE, so evaluating with it and calling the "
            f"result {dialect!r} would be a false claim about a security control. "
            f"Executable: {sorted(EXECUTABLE_DIALECTS)}.", "Call")

    if not pattern:
        raise Refusal("REGEX_EMPTY", "the pattern is empty", "Call")

    reason = _scan(pattern)
    if reason is not None:
        raise Refusal(
            "REGEX_DIALECT_SPECIFIC",
            f"this pattern cannot be executed as {dialect} because it uses {reason}. "
            f"A match or a non-match computed here would not be what {dialect} does, "
            f"so refusing is the only honest answer.", "Call")

    from .redos import catastrophic_reason
    reason = catastrophic_reason(pattern)
    if reason is not None:
        # A QUANTIFIER UNDER A QUANTIFIER, AN OVERLAPPING ALTERNATION, OR A PILE
        # OF UNBOUNDED QUANTIFIERS. The allowlist permits `( ) * + ?`, which is
        # the shape catastrophic backtracking needs. The PATTERN is refused, not
        # the subject, because the attacker picks the pattern and a time limit
        # would still let one row burn the whole budget.
        raise Refusal(
            "REGEX_CATASTROPHIC_BACKTRACKING",
            f"this pattern can take exponential time on a subject that does not "
            f"match: {reason}. Refused rather than given a time limit, because a "
            f"limit would still let one row exhaust the budget. Rewrite it with "
            f"a character class, a bounded length, or fewer quantifiers.",
            "Call")

    # THE ANALYSIS MUST COME FIRST. It did not: `re.compile` ran seven lines
    # above this one, so `"(" * 900 + "a" + ")" * 900` raised a bare
    # `RecursionError` out of `compile_pattern` -- not a `Refusal`. The catch-all
    # then reported INPUT_TOO_DEEP, "the pasted events are nested too deeply",
    # which is the opposite of the truth: the cause was the rule's regex, not
    # the events. Any refusal that escapes as a non-Refusal is a crash, and a
    # crash that misattributes blame is worse than the crash alone.
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise Refusal(
            "REGEX_INVALID",
            f"the pattern does not compile: {exc}", "Call") from exc
    except RecursionError as exc:
        raise Refusal(
            "REGEX_NESTING_TOO_DEEP",
            "this pattern nests parentheses or groups too deeply for the regex "
            "engine to parse. That is a property of the pattern, not of the "
            "events. Flatten it -- a character class instead of nested groups.",
            "Call") from exc
    except (MemoryError, OverflowError, ValueError) as exc:
        raise Refusal(
            "REGEX_RESOURCE_EXHAUSTED",
            f"this pattern is too large or too deeply nested to compile: "
            f"{type(exc).__name__}. Flatten it and try again.", "Call") from exc

    def evaluate(value: str, case_insensitive: bool = False,
                 _c: re.Pattern[str] = compiled) -> bool:
        if case_insensitive:
            return _c.search(value.casefold()) is not None
        return _c.search(value) is not None
    return evaluate


def describe_dialect(dialect: str) -> str:
    """Human-readable status, for the Understand view.

    Every sentence here is a claim the analyst will act on, so each one is checked
    against `EXECUTABLE_DIALECTS` rather than written from memory. An earlier
    version of this function told the analyst that portable PCRE patterns "are
    accepted" while the code refused every PCRE pattern before reading it.
    """
    if dialect in EXECUTABLE_DIALECTS:
        return (f"{dialect} is executable, restricted to: literals, `.`, anchors "
                f"^ and $, character classes, alternation, groups, and the simple "
                f"greedy quantifiers * + ?. Backslash escapes, interval "
                f"quantifiers, lookaround and POSIX named classes are refused by "
                f"name, because this engine cannot guarantee they mean the same "
                f"thing here as in {dialect}.")
    if dialect == "pcre":
        return ("PCRE is DECLARABLE but NOT executable. Every PCRE pattern is "
                "refused with REGEX_NOT_EXECUTABLE, including ones made only of "
                "portable constructs, because this engine implements no PCRE "
                "engine at all.")
    if dialect == "posix_basic":
        return ("POSIX BRE is DECLARABLE but NOT executable. In BRE the characters "
                "+ ? { | ( ) are LITERALS rather than operators, so evaluating a "
                "BRE pattern requires re-escaping them. A partial translation "
                "returns confidently wrong booleans, which is worse than a "
                "refusal, so none is attempted.")
    return f"{dialect} is not a recognised dialect."
