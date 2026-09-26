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
            return _REFUSED_WITH_REASON["\\"]

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


def compile_pattern(dialect: str, pattern: str) -> Callable[[str], bool]:
    """Compile `pattern` for `dialect`, or refuse with the reason.

    Refusal codes:
        REGEX_NOT_EXECUTABLE    the dialect has no engine here at all
        REGEX_DIALECT_SPECIFIC  the pattern uses a construct whose meaning this
                                engine cannot guarantee for that dialect
        REGEX_INVALID           the pattern does not compile
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

    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise Refusal(
            "REGEX_INVALID",
            f"the pattern does not compile: {exc}", "Call") from exc

    def evaluate(value: str, _c: re.Pattern[str] = compiled) -> bool:
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
