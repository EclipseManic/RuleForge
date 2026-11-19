"""Shared parsing machinery for the dialects.

Eight vendor languages, one tokenizer and one expression parser. The
differences between them are small and DATA, not code: an operator precedence
table, a keyword set, a string-literal style, a comment style. Writing that as
eight hand-rolled parsers is how a tool ends up with eight subtly different
readings of `a and b or c` -- and a precedence difference is invisible in review
and produces a rule that matches a different set of events than the author
wrote.

So: one parser, driven by a `DialectSpec`. The spec is where a vendor's
peculiarities live, which means the peculiarities are DATA and can be asserted
about rather than rediscovered in eight places.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field, replace as dc_replace
from decimal import Decimal
from typing import Any, Callable, Final, Iterable, Sequence

from ..ir import (
    Arith,
    BoolOp,
    Call,
    Comparison,
    Expr,
    FieldRef,
    ListExpr,
    Literal,
    Not,
    Regex,
    Span,
)
from ..values import Duration, Refusal, duration_seconds

__all__ = [
    "Token",
    "Diagnostic",
    "DialectSpec",
    "Parser",
    "C_LIKE_PRECEDENCE",
    "tokenize",
    "split_top_level",
    "split_statements",
    "plain_number",
    "strip_comments",
    "BARE_IDENTIFIER",
    "is_bare_identifier",
    "ANNOTATION_LABELS",
    "render_annotation_header",
    "parse_annotation_header",
    "qualified_name",
    "TOKEN_RE",
    "cross_row_predicate",
    "refuse_cross_row_predicate",
    "escape_for_string_literal",
]


# ---------------------------------------------------------------------------
# Escaping a rendered pattern for the string-literal layer
# ---------------------------------------------------------------------------


def escape_for_string_literal(pattern: str) -> str:
    """Double the backslashes in a LIKE/glob pattern for the STRING layer.

    A LIKE pattern escapes its own metacharacters with a backslash, and the
    dialect's string literal escapes a backslash AGAIN on the way back in. A
    renderer that emitted only the glob layer lost it on re-import.

    The value `NT AUTHORITY\\` went out as `"nt authority\\\\%"` -- the glob
    layer's two backslashes, un-doubled for the literal -- the tokenizer
    collapsed them to one, and `\\%` then meant an ESCAPED percent sign rather
    than "a literal backslash, then any run of characters". A `startswith`
    benign-filter stopped matching its own value, so its NEGATION matched every
    `NT AUTHORITY\\SYSTEM` event: a false positive on the most common exclusion
    in Windows detection content, in three dialects at once.
    """
    return pattern.replace("\\", "\\\\")


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """Something the analyst should know that is not a refusal.

    `verified` distinguishes "I checked this against the text" from "this is a
    reading of the rule". The UI shows the difference, because a caveat that
    looks measured but is not is worse than no caveat.

    Shared by every dialect rather than redefined per dialect. Eight private
    `Diagnostic` classes would be eight shapes arriving at one UI, and the
    caller would have to know which vendor produced a message before it could
    read it.
    """

    code: str
    message: str
    severity: str = "caution"  # problem | caution | note
    verified: bool = True
    evidence: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "verified": self.verified,
            "evidence": self.evidence,
        }



# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Token:
    kind: str  # ident | number | string | op | punct | eof
    text: str
    at: int = 0

    def is_op(self, *texts: str) -> bool:
        return self.kind in ("op", "punct") and self.text in texts

    def is_word(self, *texts: str) -> bool:
        return self.kind == "ident" and self.text.lower() in texts

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Token({self.kind}, {self.text!r})"


#: Ordered alternation. The string forms come first because a quote inside an
#: identifier position would otherwise start an identifier.
#:
#: `opword` holds the operator spellings that are made of word characters and
#: so would otherwise be split. `!in` was missing from it while `!in~` was
#: present, so `A !in ("x")` tokenised as `!` followed by the keyword `in`:
#: the parser saw a lone field, and the rule was refused as
#: CONDITION_IS_A_FIELD. The renderer emits `!in` for a negated `in`, so this
#: dialect could not read back text it had just written. The alternation is
#: ordered longest-first because `!in~` must not be read as `!in` plus a
#: stray `~`, and the trailing guard stops `!integer` becoming `!in` + `teger`.
TOKEN_RE: Final = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<lcomment>//[^\n]* | --[^\n]*)
    | (?P<bcomment>/\*.*?\*/)
    | (?P<vstring>@"(?:[^"]|"")*")
    | (?P<btstring>@`(?:[^`]|``)*`)
    | (?P<string>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")
    | (?P<opword>!in~|in~|!in(?![A-Za-z0-9_~]))
    | (?P<duration>\d+(?:\.\d+)?[ \t]*(?:ms|milliseconds?|s|secs?|seconds?|m|mins?|minutes?|h|hrs?|hours?|d|days?)(?![A-Za-z_]))
    | (?P<hex>0[xX][0-9A-Fa-f]+)
    | (?P<number>\d+\.\d+(?:[eE][+-]?\d+)?|\.\d+|\d+(?:[eE][+-]?\d+)?)
    | (?P<dotted>[A-Za-z_@#$][A-Za-z0-9_@#$]*(?:\.[A-Za-z0-9_@#$]+)*)
    | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    | (?P<op>\.\.|\.\.<|!in~|in~|!~|~=|<=|>=|==|!=|<>|=~|\|\||[-+*/%<>=!~^&|])
    | (?P<punct>[()\[\]{},;:?.])
    """,
    re.VERBOSE | re.DOTALL,
)

_ESCAPES: Final[dict[str, str]] = {
    "n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"',
    "0": "\0", "a": "\a", "b": "\b", "f": "\f", "v": "\v",
}


def tokenize(text: str) -> list[Token]:
    """Lex, or refuse with the position.

    A parse error that says "unexpected token" and nothing else costs an analyst
    twenty minutes of guessing. Every refusal here names what was found and
    roughly where.
    """
    out: list[Token] = []
    index = 0
    length = len(text)
    while index < length:
        match = TOKEN_RE.match(text, index)
        if match is None:
            raise Refusal(
                "TOKEN_UNKNOWN",
                f"`{text[index]!r}` at character {index + 1} is not something "
                f"this parser recognises. The text around it is: "
                f"{_excerpt(text, index)}",
                "parse",
            )
        index = match.end()
        kind = match.lastgroup or ""
        if kind in ("ws", "lcomment", "bcomment"):
            continue
        value = match.group()
        if kind == "vstring":
            # `value[2:-1]`, not `[2:-2]`. The opening delimiter is `@"` (two
            # characters) and the closing one is `"` (one), so slicing two from
            # each end silently eats the last character of every verbatim
            # string -- `@"\lsass.exe"` came back as `\lsass.ex`.
            out.append(Token("string", value[2:-1].replace('""', '"'), match.start()))
        elif kind == "btstring":
            out.append(Token("string", value[2:-1].replace("``", "`"), match.start()))
        elif kind == "string":
            out.append(Token("string", _unescape(value[1:-1]), match.start()))
        elif kind == "duration":
            # A duration is ONE token, not a number followed by a field called
            # `m`. Lexing `10m` as `10` and `m` makes `| where T > ago(10m)` parse
            # as a comparison against a column named `m`, which is a rule that
            # silently matches nothing.
            out.append(Token("duration", value, match.start()))
        elif kind == "opword":
            # `in~` is a case-INSENSITIVE membership test: one token, matched
            # before the identifier rule. As `in` followed by `~`, the `~` is
            # left unconsumed and the whole condition after it goes unread.
            out.append(Token("op", value, match.start()))
        elif kind == "number":
            out.append(Token("number", value, match.start()))
        elif kind == "dotted":
            out.append(Token("ident", value, match.start()))
        else:
            out.append(Token(kind, value, match.start()))
    out.append(Token("eof", "", length))
    return out


def _unescape(body: str) -> str:
    """Resolve escapes, keeping the backslash of one that means nothing.

    An UNKNOWN escape keeps both characters. `\\l` is not an escape in any of
    these dialects, and dropping the backslash turned
    `endswith "\\lsass.exe"` into `endswith "lsass.exe"` -- which widens the
    rule from "a file called lsass.exe in some directory" to "any path ending
    in that text", so `maliciouslsass.exe` matches. Windows paths are most of
    what these rules test, so this was not an edge case; it silently changed
    the meaning of the most common literal in the corpus.
    """
    if "\\" not in body:
        return body
    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\" or index + 1 >= len(body):
            out.append(char)
            index += 1
            continue
        following = body[index + 1]
        if following in _ESCAPES:
            out.append(_ESCAPES[following])
            index += 2
        elif following == "u" and index + 5 < len(body) + 1:
            try:
                out.append(chr(int(body[index + 2:index + 6], 16)))
                index += 6
                continue
            except ValueError:
                out.append(char)
                index += 1
        else:
            out.append(char)
            out.append(following)
            index += 2
    return "".join(out)


def _excerpt(text: str, index: int, width: int = 40) -> str:
    start = max(0, index - width // 2)
    end = min(len(text), index + width // 2)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{text[start:end]!r}{suffix}"


# ---------------------------------------------------------------------------
# Annotation headers
# ---------------------------------------------------------------------------

#: The `meta:` of the dialects that have no `meta:`.
#:
#: KQL, SPL, AQL and EQL are query languages: they carry a condition and
#: nothing else. `ir.Annotations` therefore had nowhere to go, and five of the
#: eight dialects rendered a rule's title, severity, author and ATT&CK mapping
#: as NOTHING. A Sigma rule converted to KQL came out as a bare query, which
#: is the single most common conversion this tool will be asked for and the
#: one whose output a SOC cannot triage: no name to alert on, no severity to
#: route by, no technique to attribute to.
#:
#: Written as a comment header, which every one of those languages supports,
#: and read back by `parse_annotation_header` so the round trip is lossless
#: rather than one-way. The keys are spelled out here rather than derived from
#: the dataclass, because a field rename must not silently change the on-disk
#: spelling of a header somebody already has in a repository.
ANNOTATION_LABELS: Final[tuple[tuple[str, str], ...]] = (
    ("title", "title"),
    ("description", "description"),
    ("severity", "severity"),
    ("author", "author"),
)


def render_annotation_header(
    annotations: Any, opener: str, closer: str = ""
) -> list[str]:
    """`ir.Annotations` as comment lines, or an empty list when it is empty.

    Empty in means empty out: a header of blank fields is noise, and noise at
    the top of every rendered rule is what teaches an analyst to skip the top
    of rendered rules.
    """
    def line(key: str, value: str) -> str:
        body = f"{opener} {key}: {value}"
        return f"{body} {closer}" if closer else body

    out: list[str] = []
    for attribute, label in ANNOTATION_LABELS:
        value = getattr(annotations, attribute, "")
        if value:
            out.append(line(label, str(value).replace("\n", " ")))
    for tactic, techniques in getattr(annotations, "mitre_attack", ()):
        joined = ", ".join(techniques)
        if tactic and joined:
            out.append(line("attack", f"{tactic}: {joined}"))
        elif tactic:
            out.append(line("attack", tactic))
        elif joined:
            out.append(line("attack", joined))
    for reference in getattr(annotations, "references", ()):
        out.append(line("reference", reference))
    for positive in getattr(annotations, "false_positives", ()):
        out.append(line("false-positive", positive))
    return out


def parse_annotation_header(
    text: str, opener: str, closer: str = ""
) -> tuple[dict[str, Any], str]:
    """Read a header back, returning the fields and the REMAINING text.

    Only a run of header lines at the very top is consumed, and only lines
    whose comment body is `<known key>: value`. An ordinary comment an analyst
    wrote is left alone: swallowing it would delete their note, and treating
    it as metadata would put their prose in the rule's title.
    """
    fields: dict[str, Any] = {
        "title": "", "description": "", "severity": "", "author": "",
    }
    attack: list[tuple[str, tuple[str, ...]]] = []
    references: list[str] = []
    false_positives: list[str] = []
    known = {label for _attribute, label in ANNOTATION_LABELS}

    lines = text.splitlines()
    consumed = 0
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            consumed += 1
            continue
        if not stripped.startswith(opener):
            break
        body = stripped[len(opener):]
        if closer and body.rstrip().endswith(closer):
            body = body.rstrip()[: -len(closer)]
        body = body.strip()
        key, found, value = body.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not found or not value:
            break
        if key in known:
            fields[key] = value
        elif key == "attack":
            tactic, _sep, techniques = value.partition(":")
            attack.append((
                tactic.strip(),
                tuple(p.strip() for p in techniques.split(",") if p.strip()),
            ))
        elif key == "reference":
            references.append(value)
        elif key == "false-positive":
            false_positives.append(value)
        else:
            break
        consumed += 1

    if not any((fields["title"], fields["description"], fields["severity"],
                fields["author"], attack, references, false_positives)):
        # Nothing recognisable, so nothing is consumed. Returning the text
        # unchanged matters: a dialect that trimmed lines here would lose the
        # first line of any rule beginning with an ordinary comment.
        return {}, text

    fields["mitre_attack"] = tuple(attack)
    fields["references"] = tuple(references)
    fields["false_positives"] = tuple(false_positives)
    return fields, "\n".join(lines[consumed:])


#: The identifier shape every tokenizer here accepts: ASCII only.
#:
#: Stated once because the renderers kept deciding it themselves with
#: `str.isalnum()`, which is UNICODE-aware -- so a Cyrillic field name passed
#: the "safe to write bare" check and then failed to tokenize on the way back
#: in. A renderer emitting what its own parser cannot read is the defect class
#: `tests/test_fidelity.py` exists for, and this is where it started.
BARE_IDENTIFIER: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def is_bare_identifier(name: str) -> bool:
    """True when `name` can be written without quoting in these dialects.

    Dotted paths are checked segment by segment, because `a.b` is a field path
    and each part has to be a legal identifier on its own.
    """
    if not name:
        return False
    return all(BARE_IDENTIFIER.match(part) for part in name.split("."))


def plain_number(value: Any) -> str:
    """A number in PLAIN notation, never scientific.

    `str(Decimal("1e10"))` is `1E+10`, and that is a valid Decimal repr which
    is NOT safely writable into these languages. FQL reads the `+` as its AND
    operator and refuses the rest of the filter; the others happen to accept
    an exponent, but a detection rule carrying `1E+10` where it means ten
    billion is a rule nobody reviewing it will read correctly.

    Shared because the same `str()` was used in six renderers, so the defect
    was six defects.
    """
    if isinstance(value, Decimal):
        if value.is_nan() or value.is_infinite():
            raise Refusal(
                "NUMBER_NOT_FINITE",
                f"`{value}` is not a finite number, and no dialect here has a "
                f"spelling for it. A comparison against it can never be true, "
                f"so writing it out would produce a rule that cannot fire.",
                "render",
            )
        text = format(value, "f")
        if "." in text:
            text = text.rstrip("0").rstrip(".")
        return text or "0"
    return str(value)


def strip_comments(text: str) -> str:
    """Remove comments, preserving newlines so line numbers survive."""
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if text.startswith("//", index) or text.startswith("--", index):
            end = text.find("\n", index)
            index = len(text) if end == -1 else end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end == -1:
                raise Refusal(
                    "COMMENT_UNTERMINATED",
                    f"a `/*` comment starting at character {index + 1} is never "
                    f"closed. The parser would otherwise read the rest of the rule "
                    f"as a comment and produce an empty rule.",
                    "parse",
                )
            out.append("\n" * text.count("\n", index, end))
            index = end + 2
            continue
        if char in ("'", '"', "@"):
            width = _string_width(text, index)
            out.append(text[index:index + width])
            index += width
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _string_width(text: str, index: int) -> int:
    if text.startswith('@"', index) or text.startswith("@`", index):
        closer = '"' if text[index + 1] == '"' else "`"
        cursor = index + 2
        while cursor < len(text):
            if text[cursor] == closer:
                if cursor + 1 < len(text) and text[cursor + 1] == closer:
                    cursor += 2
                    continue
                return cursor - index + 1
            cursor += 1
        return len(text) - index
    closer = text[index]
    cursor = index + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == closer:
            return cursor - index + 1
        cursor += 1
    return len(text) - index


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------


def split_top_level(
    text: str, separator: str = ",", openers: str = "([{", closers: str = ")]}",
) -> list[str]:
    """Split on a separator that is not inside a string, bracket or comment.

    A splitter that ignores strings splits `"a, b"` into two, and a rule with a
    comma inside a quoted value silently becomes a rule with an extra field. This
    is the third or fourth time that has been the bug in a tool like this, which
    is why it is a shared function rather than a per-dialect helper.
    """
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    index = 0
    width = len(separator)
    while index < len(text):
        char = text[index]
        if char in ("'", '"', "@"):
            size = _string_width(text, index)
            current.append(text[index:index + size])
            index += size
            continue
        if text.startswith("//", index) or text.startswith("--", index):
            end = text.find("\n", index)
            index = len(text) if end == -1 else end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = len(text) if end == -1 else end + 2
            continue
        if char in openers:
            depth += 1
        elif char in closers:
            depth = max(0, depth - 1)
        elif depth == 0 and text.startswith(separator, index):
            parts.append("".join(current).strip())
            current = []
            index += width
            continue
        current.append(char)
        index += 1
    parts.append("".join(current).strip())
    return [p for p in parts if p != ""] or [""]


def split_statements(text: str, separator: str = ";"):
    return split_top_level(text, separator)


def qualified_name(tokens: Sequence[Token]) -> str:
    """A dotted name, e.g. `win.eventdata.Image`."""
    return "".join(t.text for t in tokens)


# ---------------------------------------------------------------------------
# Cross-row join predicates
# ---------------------------------------------------------------------------


def _scopes_in(value: Any, depth: int = 0) -> set[str]:
    """Every `FieldRef.scope` an expression tree mentions."""
    if depth > 64:
        return set()
    if isinstance(value, FieldRef):
        return {value.scope}
    if isinstance(value, (list, tuple, set, frozenset)):
        found: set[str] = set()
        for item in value:
            found |= _scopes_in(item, depth + 1)
        return found
    if hasattr(value, "__dataclass_fields__"):
        found = set()
        for name in value.__dataclass_fields__:
            found |= _scopes_in(getattr(value, name, None), depth + 1)
        return found
    return set()


def _contains_span(value: Any, depth: int = 0) -> bool:
    """Whether an expression tree holds a `Span` (a temporal range test)."""
    if depth > 64:
        return False
    if isinstance(value, Span):
        return True
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_span(item, depth + 1) for item in value)
    if hasattr(value, "__dataclass_fields__"):
        return any(
            _contains_span(getattr(value, name, None), depth + 1)
            for name in value.__dataclass_fields__
        )
    return False


def _field_refs(value: Any, depth: int = 0) -> list[FieldRef]:
    """Every `FieldRef` an expression tree mentions."""
    if depth > 64:
        return []
    if isinstance(value, FieldRef):
        return [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        found: list[FieldRef] = []
        for item in value:
            found.extend(_field_refs(item, depth + 1))
        return found
    if hasattr(value, "__dataclass_fields__"):
        found = []
        for name in value.__dataclass_fields__:
            found.extend(_field_refs(getattr(value, name, None), depth + 1))
        return found
    return []


def cross_row_predicate(node: Any) -> bool:
    """Whether a join's predicate names the SAME field on both sides.

    That is the shape a dialect cannot write back. KQL resolves a post-join
    name by COLUMN, so when the left and right side are spelled the same --
    which is exactly what a temporal window between two events of one schema
    looks like -- both occurrences collapse onto one scope. The predicate then
    reads only one side, `validate` refuses it as not-cross-row, and the
    correlation is no longer bounded by anything.

    Distinct names on the two sides (`$left.Account == $right.UserPrincipalName`,
    or a window between `login.t` and `lsass.t`) survive every dialect's round
    trip and are asserted by the existing tests, so they are deliberately NOT
    covered here.
    """
    if getattr(node, "predicate", None) is None:
        return False
    by_name: dict[str, set[str]] = {}
    for ref in _field_refs(node.predicate):
        by_name.setdefault(ref.full, set()).add(ref.scope)
    return any(
        "left" in scopes and "right" in scopes for scopes in by_name.values()
    )


def refuse_cross_row_predicate(node: Any, dialect_label: str, code: str) -> None:
    """Refuse, by name, a join predicate whose two sides cannot be told apart."""
    if not cross_row_predicate(node):
        return
    raise Refusal(
        code,
        f"`{node.id}` joins two streams on a condition that names the SAME "
        f"field on both sides -- a temporal window between two events of one "
        f"schema, usually. {dialect_label} flattens a join into one row and "
        f"resolves a name by column, so once the rows are merged the two sides "
        f"become the same column and the condition ends up comparing the row "
        f"with itself. The join keys are kept; add the temporal clause by hand "
        f"in {dialect_label}.",
        "render",
    )




# ---------------------------------------------------------------------------
# Dialect specification
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DialectSpec:
    """Everything that varies between the eight vendors.

    Data, not code, so the differences can be asserted about in one place. A
    precedence table is here rather than in eight `if` ladders because a
    precedence difference is the single easiest thing to get wrong and the
    hardest thing to see in review.
    """

    key: str
    language: str
    #: operator -> binding power. Higher binds tighter.
    precedence: dict[str, int] = dc_field(default_factory=dict)
    #: Comparison operators this dialect spells, mapped to the model's.
    operators: dict[str, str] = dc_field(default_factory=dict)
    #: Words that are keywords rather than field names.
    keywords: frozenset[str] = frozenset()
    #: Words that introduce a list membership test.
    list_operators: frozenset[str] = frozenset()
    #: Word -> function name, for dialect builtins.
    functions: dict[str, str] = dc_field(default_factory=dict)
    #: Operators that are case-insensitive patterns rather than regexes.
    nocase_operators: frozenset[str] = frozenset()
    #: True when `field value` means equality (SPL) rather than being invalid.
    implicit_equality: bool = False
    default_regex_dialect: str = "posix_extended"

    def precedence_of(self, token: Token) -> int | None:
        """Binding power of an infix operator token.

        Word operators (`and`, `or`, `in`) arrive as `ident` tokens, not `op`
        tokens, so this accepts both. Getting that wrong makes every boolean
        expression stop at its first comparison -- `a == 1 and b == 2` parses as
        just `a == 1` and the rest of the condition is silently unread, which
        produces a rule that matches a different set of events than written.

        It tries the MAPPED name first and the SPELLED name second. Those are
        two tables, and a dialect whose operator table says `endswith` maps to
        `ends_ends_with` while its precedence table keys on the spelling loses
        the lookup entirely -- at which point `| where X endswith "lsass"`
        parses as a bare `X` and the filter matches every row where the field is
        present. Falling back to the spelling makes the two tables unable to
        disagree in the dangerous direction.
        """
        if token.kind not in ("op", "ident"):
            return None
        # Case-folded for word operators, matching `build_comparison`, which
        # already lowercases an ident before looking it up. The two disagreed:
        # the operator MAP resolved `OR` to `or` correctly, but this function
        # never got that far, so it returned None and the expression stopped at
        # its first comparison. `| where a==1 OR b==2` therefore parsed as just
        # `a==1` and the rest was silently unread -- the exact failure this
        # docstring describes, in the dialects that spell their booleans in
        # uppercase (AQL, YARA-L, SPL's eval syntax).
        #
        # A dialect that genuinely cares about the case of a boolean -- SPL's
        # SEARCH grammar, where lowercase `and` is a word to search for -- has
        # to decide that before the parser sees the text, because by here the
        # distinction is already gone.
        spelled = token.text.lower() if token.kind == "ident" else token.text
        for candidate in (token.text, spelled):
            mapped = self.operators.get(candidate)
            if mapped is not None:
                binding = self.precedence.get(mapped)
                if binding is not None:
                    return binding
            binding = self.precedence.get(candidate)
            if binding is not None:
                return binding
        return None


#: Precedence ladder shared by the C-style languages, as data.
#:
#: NOT is the tightest binding unary, then comparison, then AND, then OR. Every
#: dialect that spells `or` lower than `and` gets the same numbers; the ones that
#: do not override them.
C_LIKE_PRECEDENCE: Final[dict[str, int]] = {
    "or": 10,
    "and": 20,
    "==": 30, "!=": 30, "<": 30, "<=": 30, ">": 30, ">=": 30,
    "in": 30, "contains": 30, "startswith": 30, "endswith": 30,
    "matches": 30, "like": 30, "ilike": 30, "has_any": 30, "has_all": 30,
    "between": 30,
    # `!~` is the negated form of `=~`. It needs its own binding power: without
    # one it has no precedence at all, the parser stops at `x`, and
    # `| where cmd !~ "lsass"` silently becomes a rule with no condition.
    "!~": 30, "=~": 30, "~=": 30, "in_set": 30,
    "+": 50, "-": 50,
    "*": 60, "/": 60, "%": 60,
}

#: Binary arithmetic, handled by the same branch in `parse_expression`.
#:
#: They are here rather than being detected by precedence alone because
#: `a + 5 * 2 > 10` reaches `build_comparison` for the `*` otherwise, and a
#: multiplication is not a comparison -- so the tree came out as
#: `a + (5 = ...) > 10` and the rule meant something no author wrote.
ARITHMETIC_OPS: Final[frozenset[str]] = frozenset({"+", "-", "*", "/", "%"})

#: Minimum binding power for a NOT operand: between `and` (20) and a comparison
#: (30), so `not a == 1` is `not (a == 1)` and `not a and b` is
#: `(not a) and b`.
NOT_BINDING: Final[int] = 25

#: Words that appear between a pattern operator and its argument.
#:
#: `matches regex "p"`, `contains_cs "p"`, `has_any_ci (...)`. Each vendor
#: spells this differently and all of them are optional, so they are consumed
#: wherever an infix operator is seen rather than being part of any one operator.
MODIFIER_WORDS: Final[tuple[str, ...]] = (
    "regex", "nocase", "sensitively", "insensitively", "cs", "ci", "cc",
    "culture", "startswith", "endswith", "contains", "contains_cs",
    "has_any", "has_all", "has", "hasprefix", "hassuffix", "matches",
    "like", "ilike", "in", "contains_any", "contains_all", "startswith_cs",
    "endswith_cs",
)

#: Modifiers that mean "ignore case", collected into `Regex.nocase`.
NOCASE_MODIFIERS: Final[frozenset[str]] = frozenset({
    "nocase", "ci", "contains_cs", "has_cs", "has_any_cs", "ilike",
    "insensitively", "startswith_cs", "endswith_cs",
})

#: Words that are never a value. A field genuinely named `and` is possible in
#: some payloads and a dialect may allow it quoted, but an UNQUOTED one is
#: nearly always a missing operand, and reading it as a field turns a typo into
#: a rule that matches nothing.
RESERVED_IN_OPERAND_POSITION: Final[frozenset[str]] = frozenset({
    "and", "or", "not", "between", "then", "else", "by", "asc", "desc",
    "on", "join", "where", "from", "select", "having", "group",
})


# ---------------------------------------------------------------------------
# Expression parser
# ---------------------------------------------------------------------------


class Parser:
    """A precedence-climbing expression parser over a `DialectSpec`.

    Written once and configured per vendor. `parse_expression` is the entry
    point; a dialect's lowerer drives it with its own token stream.
    """

    def __init__(
        self,
        tokens: Sequence[Token],
        spec: DialectSpec,
        default_scope: str = "current",
        field_scopes: dict[str, str] | None = None,
    ) -> None:
        self.tokens = list(tokens)
        self.spec = spec
        self.index = 0
        self._pending_nocase = False
        #: Which row an UNQUALIFIED field reads from.
        #:
        #: `right` after a join. Splunk, KQL and YARA-L all flatten both sides
        #: into one namespace once two streams are combined, so an unqualified
        #: name is genuinely ambiguous. Resolving it to `current` makes
        #: `| where LoginTime between (LSASSTime .. LSASSTime + 10m)` compare
        #: the merged row with ITSELF -- a comparison that is true for every row
        #: that joined, which discards the correlation without any error.
        #:
        #: Set per predicate, not globally, because the same name means different
        #: things either side of a join.
        self.default_scope = default_scope
        #: Column name -> which side of a join declares it.
        #:
        #: This is how an unqualified name after a join is resolved WITHOUT
        #: guessing. KQL, Splunk and YARA-L all flatten two streams into one
        #: namespace and give you no syntax to say which side a column came
        #: from. Defaulting everything to one side makes
        #: `| where LoginTime between (LSASSTime .. LSASSTime + 10m)` compare a
        #: column with itself, and defaulting everything to `current` does the
        #: same. What actually settles it is that `LSASSTime` is declared by the
        #: left pipeline and `LoginTime` by the right one -- so the column sets
        #: are read off the two streams and the name is looked up.
        #:
        #: A name in NEITHER set stays at `default_scope` and the discrepancy is
        #: reported, because a column that exists on neither side is a column
        #: whose value can only ever be ABSENT.
        self.field_scopes = dict(field_scopes or {})

    # -- token access ------------------------------------------------------

    @property
    def current(self) -> Token:
        return self.tokens[self.index]

    def peek(self, offset: int = 0) -> Token:
        position = min(self.index + offset, len(self.tokens) - 1)
        return self.tokens[position]

    def advance(self) -> Token:
        token = self.tokens[self.index]
        if token.kind != "eof":
            self.index += 1
        return token

    def accept(self, *texts: str) -> Token | None:
        if self.current.text in texts and self.current.kind in ("op", "punct"):
            return self.advance()
        return None

    def accept_word(self, *words: str) -> Token | None:
        if self.current.is_word(*words):
            return self.advance()
        return None

    def expect(self, *texts: str) -> Token:
        if self.current.text in texts and self.current.kind in ("op", "punct"):
            return self.advance()
        raise self.unexpected(f"expected {' or '.join(texts)}")

    def expect_word(self, *words: str) -> Token:
        if self.current.is_word(*words):
            return self.advance()
        raise self.unexpected(f"expected {' or '.join(words)}")

    def unexpected(self, wanted: str) -> Refusal:
        found = self.current
        where = found.text if found.kind != "eof" else "the end of the input"
        return Refusal(
            "PARSE_UNEXPECTED",
            f"found {where!r} at character {found.at + 1} but needed {wanted}. "
            f"Everything from here on was not read, so nothing after this point "
            f"has been checked.",
            "parse",
        )

    # -- expressions -------------------------------------------------------

    def parse_expression(self, minimum: int = 0) -> Expr:
        left = self.parse_prefix()
        while True:
            token = self.current
            if token.kind == "eof":
                break
            if token.is_word("between") and 30 >= minimum:
                left = self.parse_between(left)
                continue
            if token.kind == "op" and token.text in ARITHMETIC_OPS and \
                    (self.spec.precedence_of(token) or 0) >= minimum:
                self.advance()
                right = self.parse_expression(
                    (self.spec.precedence_of(token) or 0) + 1
                )
                left = Arith(token.text, left, right)
                continue
            binding = self.spec.precedence_of(token)
            if binding is None or binding < minimum:
                break
            self.advance()
            # `matches regex "p"` and `contains_cs "p"` put a MODIFIER word
            # between the operator and its argument. It has to be consumed here,
            # in the infix path, because that is the path a pattern operator
            # actually takes. Left alone, `regex` is read as the field being
            # compared and `| where x matches regex "lsass"` lowers to
            # `x matches regex` -- a rule that compares a string to a column
            # called `regex` and matches nothing.
            self._consume_modifiers()
            right = self.parse_expression(binding + 1)
            left = self.build_comparison(token, left, right)
        return left

    def _consume_modifiers(self) -> None:
        while self.current.is_word(*MODIFIER_WORDS):
            modifier = self.advance().text.lower()
            if modifier in NOCASE_MODIFIERS:
                self._pending_nocase = True

    def parse_prefix(self) -> Expr:
        token = self.current

        if token.is_word("not") or token.is_op("!", "~~"):
            self.advance()
            # NOT binds looser than a comparison but tighter than AND. Parsing
            # its operand at comparison level is what makes `not a == 1` mean
            # `not (a == 1)`. Binding it tighter gives `NOT a == 1`, which reads
            # as `(NOT a) == 1` and negates a field instead of a condition --
            # the kind of difference that only shows up in production.
            return Not(self.parse_expression(NOT_BINDING))
        if token.is_op("-"):
            self.advance()
            return Arith("-", Literal(Decimal(0)), self.parse_expression(70))
        if token.is_op("("):
            # `(a, b)` is a LIST and `(a AND b)` is a GROUP. KQL and SPL spell
            # lists with parentheses, so the two cannot be told apart by the
            # bracket -- only by whether a TOP-LEVEL comma appears before the
            # closing paren. Guessing wrong here turns `in (1, 2)` into a
            # comparison against a group, which is a rule that matches nothing.
            if self._parenthesised_holds_a_list():
                return self.parse_list("(", ")")
            self.advance()
            inner = self.parse_expression(0)
            self.expect(")")
            return inner
        return self.parse_atom()

    def _parenthesised_holds_a_list(self) -> bool:
        """Scan the current `(` group for a comma at depth 1.

        An immediately-closed `()` counts as a list, so `x in ()` reports that
        the list is empty rather than complaining about a stray paren. Both are
        refusals, but only one of them tells the analyst what to change.
        """
        depth = 0
        index = self.index
        while index < len(self.tokens):
            token = self.tokens[index]
            if token.kind == "punct" and token.text in "([{":
                depth += 1
                if depth == 1 and index + 1 < len(self.tokens) \
                        and self.tokens[index + 1].is_op(")"):
                    return True
            elif token.kind == "punct" and token.text in ")]}":
                depth -= 1
                if depth == 0:
                    return False
            elif token.kind == "punct" and token.text == "," and depth == 1:
                return True
            elif token.kind == "eof":
                return False
            index += 1
        return False

    def parse_atom(self) -> Expr:
        token = self.advance()

        if token.kind == "hex":
            # A HEX MASK is a string in every vendor that writes one, not a
            # number: `GrantedAccess IN (0x1010, 0x1410)` compares against the
            # text of the value, and Windows event fields carry the `0x` form.
            # Turning it into 4112 would compare against a value no event has,
            # and render it back in a spelling the source rule never used.
            return Literal(token.text)
        if token.kind == "number":
            return Literal(Decimal(token.text))
        if token.kind == "duration":
            # A duration is ONE token. Lexing `10m` as `10` followed by a column
            # called `m` makes `| where T > ago(10m)` compare against a field
            # that does not exist, which is a rule that silently matches nothing.
            parsed = duration_seconds(token.text)
            if parsed is None:
                raise Refusal(
                    "DURATION_UNKNOWN",
                    f"`{token.text}` looks like a time span but names no unit "
                    f"this parser knows. Write it as `10m`, `30s`, `2h` or `1d`.",
                    "parse",
                )
            return Literal(parsed)
        if token.kind == "string":
            return Literal(token.text)
        # The opening token has ALREADY been consumed, so the list reader takes
        # only a CLOSER. Calling `parse_list("[")` here tries to consume a second
        # `[` and refuses on `EventID in [4624, 4688]`.
        if token.is_op("["):
            return self._list_items("]")
        if token.is_op("("):
            return self._list_items(")")
        if token.is_op("/"):
            return self.parse_regex_literal()

        if token.kind == "ident":
            lowered = token.text.lower()
            # A reserved word in VALUE position is a mistake, and reading it as
            # a field name is the worst available reading: `a == and b` becomes
            # `a == <field named and>`, which parses, renders, and matches
            # nothing at all, with no warning anywhere in the tool.
            if lowered in RESERVED_IN_OPERAND_POSITION:
                raise Refusal(
                    "RESERVED_WORD_AS_FIELD",
                    f"`{token.text}` is a reserved word and cannot be a value "
                    f"here. It looks like a condition is missing an operand, so "
                    f"nothing after this point has been read.",
                    "parse",
                )
            # A word that names a function is a FUNCTION, even when it is also a
            # keyword. `ago`, `now`, `make_set` and `count` are all in the
            # keyword set, and treating them as field names instead turned
            # `| where T > ago(30m)` into a comparison against a column called
            # `ago` -- a rule that silently matches nothing, and does so without
            # a single warning.
            if self.current.is_op("(") and lowered in ("true", "false"):
                # SPL spells the fallback branch of `case()` / `if()` as
                # `true()` -- a zero-argument function that MEANS the literal.
                # Reading it as a bare boolean left the `(` unconsumed, so the
                # whole `case(...)` was refused as a parse error: `eval sev =
                # case(EventID == 4625, "high", true(), "none")` is one of the
                # most common shapes in real Splunk tuning and none of it could
                # be imported.
                self.advance()
                if not self.accept(")"):
                    raise self.unexpected("`)` to close `%s(`" % lowered)
                return Literal(lowered == "true")
            if self.current.is_op("(") and (
                lowered not in self.spec.keywords or lowered in self.spec.functions
            ):
                return self.parse_call(token.text)
            if lowered in self.spec.keywords and lowered not in (
                "true", "false", "null", "and", "or", "not", "between", "in"
            ):
                return self.parse_keyword_atom(lowered, token)

            name = token.text
            if lowered in ("true", "false"):
                return Literal(lowered == "true")
            if lowered == "null":
                return Literal(None)
            if self.spec.implicit_equality and self.current.kind in (
                "string", "number"
            ):
                value = self.advance()
                return Comparison(
                    "==", self.to_field(name), self._scalar(value)
                )
            return self.to_field(name)

        raise self.unexpected("a value, a field name or a condition")

    def _list_items(self, closer: str) -> Expr:
        """The body of a list, with the opening delimiter already consumed."""
        items: list[Expr] = []
        while not self.current.is_op(closer) and self.current.kind != "eof":
            items.append(self.parse_expression(0))
            if not self.accept(","):
                break
        if not self.current.is_op(closer):
            raise self.unexpected(f"{closer} to close the list")
        self.advance()
        if not items:
            raise Refusal(
                "LIST_EMPTY",
                "an empty list in a membership test matches nothing, which is "
                "almost never what the author meant",
                "parse",
            )
        return ListExpr(tuple(items))

    def parse_list(self, opener: str = "[", closer: str = "]") -> Expr:
        self.expect(opener)
        items: list[Expr] = []
        while not self.current.is_op(closer):
            items.append(self.parse_expression(0))
            if not self.accept(","):
                break
        self.expect(closer)
        if not items:
            raise Refusal(
                "LIST_EMPTY",
                "an empty list in a membership test matches nothing, which is "
                "almost never what the author meant",
                "parse",
            )
        return ListExpr(tuple(items))

    def parse_regex_literal(self) -> Regex:
        self.advance()  # the opening slash
        body: list[str] = []
        while self.current.kind == "string" or self.current.is_op("/"):
            body.append(self.advance().text)
        if not body:
            raise self.unexpected("a pattern between slashes")
        pattern = "".join(body)
        nocase = False
        if self.current.is_word("nocase") or self.current.is_word("i"):
            self.advance()
            nocase = True
        return Regex(pattern, self.spec.default_regex_dialect, nocase)

    def parse_call(self, name: str) -> Expr:
        self.expect("(")
        args: list[Expr] = []
        while not self.current.is_op(")"):
            args.append(self.parse_expression(0))
            if not self.accept(","):
                break
        self.expect(")")
        mapped = self.spec.functions.get(name.lower(), name)
        flags: list[str] = []
        for flag in self.spec.keywords:
            if self.current.is_word(flag):
                break
        return Call(mapped, tuple(args), tuple(flags))

    def parse_keyword_atom(self, word: str, token: Token) -> Expr:
        """A keyword-prefixed expression: `matches regex "x"`, `contains "y"`,
        `has_any (a, b)`."""
        if word in ("matches", "contains", "has", "startswith", "endswith",
                    "like", "ilike", "has_any", "has_all", "contains_any",
                    "contains_all"):
            subject = self.parse_expression(NOT_BINDING)
            # `matches regex "p"` and `contains_cs "p"` carry a MODIFIER word
            # between the operator and its argument. Consuming it here matters:
            # read as a field, `regex` becomes the thing being compared, and
            # `| where x matches regex "lsass"` lowers to `x matches regex`.
            while self.current.is_word("regex", "cs", "culture", "nocase",
                                       "sensitively", "insensitively",
                                       "startswith", "endswith", "contains",
                                       "has", "has_any", "has_cs", "has_any_cs"):
                modifier = self.advance().text.lower()
                if modifier == "nocase" or modifier in ("cs", "has_cs", "has_any_cs"):
                    self._pending_nocase = True
                if modifier == "insensitively":
                    self._pending_nocase = True
            if self.current.kind in ("string", "ident", "number", "duration"):
                argument = self.parse_atom()
            elif self.current.is_op("[", "("):
                argument = self.parse_list(
                    "[" if self.current.text == "[" else "(", "]"
                    if self.current.text == "[" else ")"
                )
            else:
                raise self.unexpected(f"a value for {word}")
            op = "matches" if word == "has" else word
            return Comparison(op, subject, self._as_pattern(argument))
        return self.to_field(token.text)

    def parse_between(self, subject: Expr) -> Expr:
        self.advance()  # 'between'
        if self.current.is_op("("):
            self.advance()
            low = self.parse_expression(0)
            self.expect("..")
            high = self.parse_expression(0)
            self.expect(")")
        else:
            low = self.parse_expression(31)
            self.expect_word("and")
            high = self.parse_expression(31)
        return Span(subject, low, high)

    def build_comparison(self, token: Token, left: Expr, right: Expr) -> Expr:
        word = token.text.lower() if token.kind == "ident" else token.text
        op = self.spec.operators.get(word, word)

        if op == "and":
            return _flatten_bool("and", left, right)
        if op == "or":
            return _flatten_bool("or", left, right)

        if op in ("!=", "<>"):
            return Comparison("!=", left, right)

        # A leading `!` NEGATES, whatever follows it.
        #
        # `DialectSpec.operators` maps a spelling to an engine operator and
        # then forgets the spelling, so `!in` and `!in~` both arrived here as
        # plain `in` -- and the `in` branch below built a comparison with
        # `negate=False`. A rule written `A !in~ ("x")` therefore lowered, and
        # RENDERED, as `A in ("x")`: the exact inverse of what the author
        # wrote, with no diagnostic. Every negated membership and substring
        # test in KQL was flipped.
        #
        # `!=` and `!~` are handled above because they are single operators
        # rather than a negation of something else.
        negated = (
            (word.startswith("!") and word not in ("!=", "!~"))
            or word.startswith("not ")
        )

        # A modifier can also TRAIL its argument: `matches regex "p" nocase`.
        # Consumed here rather than only before the argument, because
        # postfix is how SPL and KQL both spell it and reading it as a field
        # would silently drop the case-insensitivity.
        self._consume_modifiers()

        if op in ("=~", "matches"):
            pattern = self._as_pattern(right)
            if word in self.spec.nocase_operators and isinstance(pattern, Regex):
                # A spelling that MEANS "ignore case" -- EQL's `regex~`, `like~`
                # -- folds the pattern. The mapping from spelling to engine
                # operator drops the tilde, so without this the fold was read and
                # discarded and `regex~ "ENC"` lowered to a case-SENSITIVE
                # `regex`, which is the opposite of what was written.
                pattern = dc_replace(pattern, nocase=True)
            return Comparison("matches", left, pattern, negate=negated)
        if op == "!~":
            return Comparison("matches", left, self._as_pattern(right), negate=True)
        if op in ("in", "in_set"):
            # `x in (b)` is a ONE-element list, not a parenthesised value. A
            # bare scalar on the right of a membership test is otherwise a
            # comparison against a group, which is a rule that matches nothing.
            if not isinstance(right, ListExpr):
                right = ListExpr((right,))
            return Comparison("in", left, right, negate=negated)
        if op in ("has_any", "has_all", "contains_any", "contains_all"):
            if not isinstance(right, ListExpr):
                right = ListExpr((right,))
            return Comparison(op, left, right, negate=negated)
        return Comparison(op, left, right, negate=negated)

    def to_field(self, name: str) -> Expr:
        ref = FieldRef.parse(name)
        if ref.scope != "current":
            return ref
        resolved = self.field_scopes.get(ref.full)
        if resolved is not None:
            return FieldRef(ref.name, ref.path, resolved)
        if self.default_scope == "current":
            return ref
        return FieldRef(ref.name, ref.path, self.default_scope)

    def _as_pattern(self, right: Expr) -> Expr:
        """A bare string on the right of a pattern operator is a pattern.

        The dialect is attached, not guessed: running it with the wrong regex
        engine and calling the result a match is a false claim about a security
        control, which is why the dialect travels with the node.

        The string arrives as a `Literal`, not a `str`, because the expression
        parser produces values. Reading it as a `str` and finding a `Literal`
        instead is why this needs the unwrap below.
        """
        nocase = self._pending_nocase
        self._pending_nocase = False
        if isinstance(right, Regex):
            return right
        text = right.value if isinstance(right, Literal) else right
        if isinstance(text, str):
            return Regex(text, self.spec.default_regex_dialect, nocase=nocase)
        return right

    def _scalar(self, token: Token) -> Expr:
        if token.kind == "hex":
            return Literal(token.text)
        if token.kind == "number":
            return Literal(Decimal(token.text))
        if token.kind == "string":
            return Literal(token.text)
        return self.to_field(token.text)


    def _with_nocase_unused(self) -> None:  # pragma: no cover
        pass


def _flatten_bool(op: str, left: Expr, right: Expr) -> Expr:
    """`a and b and c` becomes one BoolOp, not a left-leaning nest.

    Flat because a nest renders as `((a and b) and c)`, and an author comparing
    that to what they wrote has to work out that the parentheses carry no
    meaning. It also keeps a long condition from nesting deep enough to hit the
    expression-depth limit for no reason.
    """
    if isinstance(left, BoolOp) and left.op == op:
        return BoolOp(op, left.operands + (right,))
    return BoolOp(op, (left, right))
