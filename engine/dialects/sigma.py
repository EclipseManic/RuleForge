"""Sigma: the vendor-neutral rule format, read into the vendor-neutral IR.

Sigma is the cheapest honest test of whether `ir.py` is genuinely neutral or
secretly KQL-shaped. It is YAML rather than a query language, it has no
pipeline, and its detection logic is a set of named predicates composed by a
separate `condition:` string. Nothing about that resembles the dialect this
engine was first written against, so anything that only works for KQL fails
here.

Three design decisions are worth stating, because the obvious choice is wrong in
each case.

**Selections become ONE predicate, not bindings.** `condition: selection and not
filter` applies both selections to the SAME event. There is no second stream and
no join. Modelling each selection as an `ir.Binding` would model a single-event
Sigma rule as a correlation across two streams, which is a different detection.
So the named selections are lowered to expressions, the condition composes them
into one tree, and the result is a single `ir.Filter`. `Binding` is reserved for
Sigma *correlation* rules, where a second stream genuinely exists.

**The condition is parsed by the SHARED parser, not by hand.** `and`/`or`/`not`
precedence has to agree with every other dialect in this tool -- a rule whose
`a and b or c` groups differently here than in `kql.py` is a rule that matches a
different set of events after translation. So `1 of them` and `all of
selection_*` are pre-expanded into explicit parenthesised groups, the result
goes through `common.Parser`, and the identifiers it returns as `FieldRef`s are
then substituted for the predicates they name.

**Metadata round-trips.** `kql.py` builds `Annotations(title="")` and never
renders it, so a rule imported from Sentinel and exported again loses its title,
severity and ATT&CK mapping. That is a known defect, and Sigma is the dialect
where it must not be copied: Sigma is mostly metadata, and a converter that
drops it produces a rule a SOC cannot triage. Everything that fits
`ir.Annotations` goes there; everything else is preserved under a `sigma.` key
in `Rule.metadata` so the renderer can put it back.

No PyYAML. This package has no third-party dependencies on purpose, so the
reader below covers the YAML subset that Sigma rules actually use and REFUSES
the rest by name. A reader that guessed at anchors, flow mappings or tags would
be inventing rule content, and the one thing a detection tool must never do is
quietly decide what a rule says.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field as dc_field
from decimal import Decimal
from typing import Any, Final

from ..ir import (
    Project,
    Aggregate,
    Annotations,
    Binding,
    BoolOp,
    Call,
    Comparison,
    Correlation,
    Emit,
    Expr,
    FieldRef,
    Filter,
    ListExpr,
    Literal,
    Measure,
    Not,
    Read,
    Regex,
    Rule,
    Window,
    render_expr,
)
from ..validate import validate
from ..values import Duration, Refusal, duration_seconds
from .common import plain_number, C_LIKE_PRECEDENCE, DialectSpec, Diagnostic, Parser, split_top_level, tokenize

__all__ = [
    "DIALECT",
    "LANGUAGE",
    "SPEC",
    "ParsedSigma",
    "parse_sigma",
    "lower_sigma",
    "render_sigma",
    "read_yaml",
]

DIALECT: Final = "sigma"
LANGUAGE: Final = "Sigma YAML"


# ---------------------------------------------------------------------------
# The YAML subset
# ---------------------------------------------------------------------------
#
# Indentation-driven, two-space convention, block lists, block scalars, quoted
# and bare scalars, comments. Everything outside that is refused BY NAME rather
# than approximated, because a reader that silently mishandles an anchor hands
# back a rule that is not the rule on disk.


def _strip_comment(raw: str) -> str:
    """Remove a trailing `# comment`, honouring quotes.

    YAML needs whitespace before an inline `#`, so a `#` inside an unquoted
    value -- a colour, a fragment, a Windows path with a hash -- survives.
    """
    quote = ""
    for index, char in enumerate(raw):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "'\"":
            quote = char
            continue
        if char == "#" and (index == 0 or raw[index - 1] in " \t"):
            return raw[:index]
    return raw


def _split_key(text: str) -> tuple[str, str, str]:
    """Split `key: value` on the first unquoted `:` that ends a key.

    The `:` must be followed by a space or end of line. That is what keeps a
    URL value (`https://example`) and a Windows drive (`C:\\Windows`) from being
    read as a key.
    """
    quote = ""
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in "'\"":
            quote = char
            continue
        if char == ":" and text[index + 1:index + 2] in ("", " "):
            return text[:index].strip(), ":", text[index + 1:]
    return text, "", ""


def _unescape_double(body: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body):
            nxt = body[index + 1]
            out.append({
                "n": "\n", "t": "\t", "r": "\r", "0": "\0",
                '"': '"', "\\": "\\", "/": "/",
            }.get(nxt, "\\" + nxt))
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


_INT = re.compile(r"-?\d+")
_FLOAT = re.compile(r"-?\d*\.\d+")
_HEX = re.compile(r"0[xX][0-9a-fA-F]+")


def _scalar(text: str, line: int) -> Any:
    body = text.strip()
    if body == "":
        return None

    if len(body) >= 2 and body[0] == "'" and body[-1] == "'":
        return body[1:-1].replace("''", "'")
    if len(body) >= 2 and body[0] == '"' and body[-1] == '"':
        return _unescape_double(body[1:-1])

    if body.startswith("[") and body.endswith("]"):
        inner = body[1:-1].strip()
        if not inner:
            return []
        return [_scalar(part, line) for part in split_top_level(inner, ",")]

    if body.startswith("{"):
        raise Refusal(
            "SIGMA_YAML_FLOW_MAP",
            f"line {line}: an inline `{{a: b}}` mapping is outside the YAML "
            f"subset this reader accepts. Write it as an indented block, so the "
            f"rule reads the same way to a person and to this tool.",
            "parse",
        )
    if body[0] in "&*!":
        raise Refusal(
            "SIGMA_YAML_ANCHOR",
            f"line {line}: `{body[0]}` starts a YAML anchor, alias or tag. This "
            f"reader does not resolve them, and resolving them wrongly would "
            f"change what the rule detects. Write the value out in full.",
            "parse",
        )

    # Hex before int: `0x1410` is a GrantedAccess mask, and the field it is
    # compared against holds it as text. Coercing it to 5136 would stop the
    # comparison matching.
    if _HEX.fullmatch(body):
        return body
    if _INT.fullmatch(body):
        return int(body)
    if _FLOAT.fullmatch(body):
        return float(body)

    lowered = body.lower()
    if lowered in ("null", "~"):
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return body


class _YamlReader:
    """A cursor over raw lines.

    Raw rather than pre-stripped, because a block scalar's body is literal: its
    indentation and its `#` characters are content, not syntax.
    """

    def __init__(self, text: str) -> None:
        normalised = (text or "").replace("\r\n", "\n").replace("\r", "\n")
        self.lines = normalised.split("\n")
        self.at = 0

    def _next_data(self) -> int | None:
        index = self.at
        while index < len(self.lines):
            body = _strip_comment(self.lines[index]).strip()
            if body in ("---", "..."):
                # A document boundary. Returned rather than skipped, so the
                # caller can refuse a second rule instead of folding it into the
                # first -- which would silently merge two detections.
                return index
            if body:
                return index
            index += 1
        return None

    def _is_boundary(self, index: int) -> bool:
        return _strip_comment(self.lines[index]).strip() in ("---", "...")

    def _info(self, index: int) -> tuple[int, str]:
        body = _strip_comment(self.lines[index])
        if "\t" in body[:len(body) - len(body.lstrip(" \t"))]:
            raise Refusal(
                "SIGMA_YAML_TAB",
                f"line {index + 1} is indented with a tab. YAML forbids it, and "
                f"two editors will disagree about what the rule says.",
                "parse",
            )
        return len(body) - len(body.lstrip(" ")), body.strip()

    def document(self) -> dict[str, Any]:
        start = self._next_data()
        # A leading `---` opens the first document and is fine; a later one opens
        # a second, which is refused below.
        while start is not None and self._is_boundary(start):
            self.at = start + 1
            start = self._next_data()
        if start is None:
            raise Refusal(
                "SIGMA_EMPTY",
                "there is no rule here: the document is empty or all comments.",
                "parse",
            )
        indent, content = self._info(start)
        if content.startswith("- "):
            raise Refusal(
                "SIGMA_YAML_NOT_A_MAPPING",
                "this document starts with a list. A Sigma rule is a mapping "
                "with `title`, `logsource` and `detection` at the top level.",
                "parse",
            )
        self.at = start
        value = self.map_at(indent)
        trailing = self._next_data()
        if trailing is not None:
            if self._is_boundary(trailing):
                raise Refusal(
                    "SIGMA_YAML_TRAILING",
                    f"line {trailing + 1} starts a second YAML document. This "
                    f"file holds more than one rule; lower them one at a time. "
                    f"Reading the first and discarding the rest would hide "
                    f"detections, which is the worst way for this to fail.",
                    "parse",
                )
            _, leftover = self._info(trailing)
            raise Refusal(
                "SIGMA_YAML_TRAILING",
                f"line {trailing + 1} (`{leftover[:40]}`) is outside the rule's "
                f"top-level mapping.",
                "parse",
            )
        return value

    def map_at(self, indent: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        while True:
            index = self._next_data()
            if index is None or self._is_boundary(index):
                break
            here, content = self._info(index)
            if here < indent or content == "-" or content.startswith("- "):
                break
            if here > indent:
                raise Refusal(
                    "SIGMA_YAML_INDENT",
                    f"line {index + 1} (`{content[:40]}`) is indented further "
                    f"than the key it follows, so which mapping it belongs to "
                    f"is ambiguous.",
                    "parse",
                )
            key, found, rest = _split_key(content)
            if not found:
                raise Refusal(
                    "SIGMA_YAML_NOT_A_MAPPING",
                    f"line {index + 1} (`{content[:40]}`) is not `key: value`.",
                    "parse",
                )
            if key in out:
                raise Refusal(
                    "SIGMA_DUPLICATE_KEY",
                    f"`{key}` is given twice at line {index + 1}. One of the two "
                    f"would silently win, and which one is not something a "
                    f"reader should decide.",
                    "parse",
                )
            self.at = index + 1
            rest = rest.strip()
            if rest in ("|", "|-", "|+", ">", ">-", ">+"):
                out[key] = self.block_at(indent, rest)
            elif rest == "":
                out[key] = self.nested_at(indent)
            else:
                out[key] = _scalar(rest, index + 1)
        return out

    def nested_at(self, key_column: int) -> Any:
        """The value under a `key:` with nothing on its own line."""
        index = self._next_data()
        if index is None or self._is_boundary(index):
            return None
        here, content = self._info(index)
        # A block list may sit at the key's own column; a nested map may not.
        if (content == "-" or content.startswith("- ")) and here >= key_column:
            return self.list_at(here)
        if here <= key_column:
            return None
        return self.map_at(here)

    def list_at(self, indent: int) -> list[Any]:
        out: list[Any] = []
        while True:
            index = self._next_data()
            if index is None or self._is_boundary(index):
                break
            here, content = self._info(index)
            if here != indent or not (content == "-" or content.startswith("- ")):
                break
            self.at = index + 1
            item = content[1:].strip()
            if item == "":
                out.append(self.nested_at(indent))
                continue
            key, found, rest = _split_key(item)
            if found:
                # `- key: value` plus any siblings, which sit two columns in.
                column = indent + 2
                entry: dict[str, Any] = {}
                rest = rest.strip()
                if rest in ("|", "|-", "|+", ">", ">-", ">+"):
                    entry[key] = self.block_at(column, rest)
                elif rest == "":
                    entry[key] = self.nested_at(column)
                else:
                    entry[key] = _scalar(rest, index + 1)
                entry.update(self.map_at(column))
                out.append(entry)
                continue
            out.append(_scalar(item, index + 1))
        return out

    def block_at(self, key_indent: int, style: str) -> str:
        """A `|` or `>` block scalar. Raw: comments here are content."""
        collected: list[str] = []
        base: int | None = None
        while self.at < len(self.lines):
            raw = self.lines[self.at]
            if raw.strip() == "":
                collected.append("")
                self.at += 1
                continue
            here = len(raw) - len(raw.lstrip(" "))
            if here <= key_indent:
                break
            if base is None:
                base = here
            collected.append(raw[base:] if len(raw) >= base else raw.strip())
            self.at += 1
        while collected and collected[-1] == "":
            collected.pop()

        if style.startswith(">"):
            parts: list[str] = []
            buffer: list[str] = []
            for line in collected:
                if line == "":
                    if buffer:
                        parts.append(" ".join(buffer))
                        buffer = []
                    parts.append("")
                else:
                    buffer.append(line.strip())
            if buffer:
                parts.append(" ".join(buffer))
            return "\n".join(parts)
        # The trailing newline a bare `|` would keep is dropped on purpose: it
        # only ever shows up as stray whitespace in a rendered description.
        return "\n".join(collected)


def read_yaml(text: str) -> dict[str, Any]:
    """The Sigma YAML subset, as plain Python. Public for tests."""
    return _YamlReader(text).document()


# ---------------------------------------------------------------------------
# The condition grammar
# ---------------------------------------------------------------------------

#: Only booleans. The operands of a Sigma condition are selection NAMES, so the
#: comparison operators in the shared precedence table are never reached -- but
#: the table is reused anyway, because `and`/`or` must bind here exactly as they
#: bind in every other dialect. A rule whose `a and b or c` groups differently
#: after conversion is a rule that matches different events.
SPEC: Final = DialectSpec(
    key=DIALECT,
    language=LANGUAGE,
    precedence=dict(C_LIKE_PRECEDENCE),
    operators={"and": "and", "or": "or"},
    keywords=frozenset({"and", "or", "not"}),
)

#: Field modifiers that map onto a comparison operator directly.
MODIFIER_OPS: Final[dict[str, str]] = {
    "contains": "contains",
    "startswith": "startswith",
    "endswith": "endswith",
    "lt": "<",
    "lte": "<=",
    "gt": ">",
    "gte": ">=",
}

#: Modifiers that change how a list of values combines, or how a pattern is
#: matched, rather than which operator is used. `cased` asks for the
#: case-sensitive comparison that is already the default, so it is accepted and
#: has no effect; `i` is Sigma's case-insensitive regex flag.
MODIFIER_FLAGS: Final[frozenset[str]] = frozenset({
    "all", "re", "cidr", "cased", "i",
})

#: Refused by name, each with the reason. Transforming a value is not the same
#: as comparing it, and this engine has no field-transformation stage -- so
#: lowering `|base64offset` as plain equality would produce a rule that looks
#: right and matches nothing.
MODIFIER_REFUSALS: Final[dict[str, str]] = {
    "base64": "the value has to be base64-encoded before it is compared, and "
              "this engine has no encode-then-compare stage. Lowering it as a "
              "plain comparison would produce a rule that matches nothing.",
    "base64offset": "the same as `base64`, three times over for the three byte "
                    "alignments. There is no transform stage to express it.",
    "utf16": "the value has to be re-encoded to UTF-16 before comparison, which "
             "needs a transform stage this engine does not have.",
    "utf16le": "see `utf16`: no transform stage exists to express it.",
    "utf16be": "see `utf16`: no transform stage exists to express it.",
    "wide": "an alias for `utf16le`: no transform stage exists to express it.",
    "windash": "it expands one value into several spellings of a command-line "
               "dash. The expansion is a transform, not a comparison, so "
               "lowering it as equality would silently narrow the detection.",
    "fieldref": "the right-hand side names another FIELD rather than a value. "
                "The IR can express that, but Sigma's own semantics for it are "
                "still moving, and guessing at them would silently change what "
                "the rule compares.",
    "expand": "it substitutes a placeholder from a pipeline config file. There "
              "is no config to expand against here, so the rule is incomplete "
              "rather than wrong -- and a rule with an unexpanded placeholder "
              "must not be presented as ready.",
}


def _modifiers(raw_key: str) -> tuple[str, list[str]]:
    parts = raw_key.split("|")
    return parts[0].strip(), [p.strip().lower() for p in parts[1:] if p.strip()]


def _literal(value: Any) -> Literal:
    """A Sigma scalar as an IR literal.

    Numbers become `Decimal`. The engine is Decimal end to end, and a threshold
    that arrives as a float is a different threshold.
    """
    if isinstance(value, bool):
        return Literal(value)
    if isinstance(value, int):
        return Literal(Decimal(value))
    if isinstance(value, float):
        return Literal(Decimal(str(value)))
    return Literal(value)


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------

#: Keys Sigma defines at the top level. Anything else is carried through rather
#: than dropped -- Sigma is an evolving spec and a custom key is more often an
#: organisation's own field than a mistake.
KNOWN_KEYS: Final[frozenset[str]] = frozenset({
    "title", "id", "related", "status", "description", "references", "author",
    "date", "modified", "tags", "logsource", "detection", "fields",
    "falsepositives", "level", "license", "name", "correlation", "action",
})


@dataclass(frozen=True, slots=True)
class ParsedSigma:
    """The document, split but not yet interpreted.

    A SPLIT, not a lowering: what is dialect-specific here is knowing that
    `detection` holds named selections plus one `condition`, and that everything
    else is metadata.
    """

    document: dict[str, Any] = dc_field(default_factory=dict)
    selections: dict[str, Any] = dc_field(default_factory=dict)
    condition: str = ""
    logsource: dict[str, Any] = dc_field(default_factory=dict)
    correlation: dict[str, Any] = dc_field(default_factory=dict)
    raw: str = ""


def parse_sigma(text: str) -> ParsedSigma:
    """Read the YAML and separate the detection from the metadata."""
    document = read_yaml(text)

    correlation = document.get("correlation") or {}
    if correlation and not isinstance(correlation, dict):
        raise Refusal(
            "SIGMA_CORRELATION_MALFORMED",
            "`correlation` has to be a mapping with at least `type` and `rules`.",
            "parse",
        )

    detection = document.get("detection")
    if detection is None and not correlation:
        raise Refusal(
            "SIGMA_NO_DETECTION",
            "this rule has no `detection` block, so it states no detection at "
            "all. A rule with nothing to match is not an empty rule, it is a "
            "rule that matches everything or nothing depending on who reads it.",
            "parse",
        )
    if detection is not None and not isinstance(detection, dict):
        raise Refusal(
            "SIGMA_DETECTION_MALFORMED",
            f"`detection` has to be a mapping of named selections plus a "
            f"`condition`, not a {type(detection).__name__}.",
            "parse",
        )

    detection = detection or {}
    condition = detection.get("condition")
    selections = {k: v for k, v in detection.items() if k != "condition"}

    if detection and condition is None:
        raise Refusal(
            "SIGMA_NO_CONDITION",
            f"`detection` defines {sorted(selections) or 'nothing'} but no "
            f"`condition`, so how the selections combine is unstated. Sigma does "
            f"not default it, and guessing between AND and OR would produce two "
            f"different detections from one rule.",
            "parse",
        )
    if condition is not None and not isinstance(condition, str):
        raise Refusal(
            "SIGMA_CONDITION_MALFORMED",
            f"`condition` has to be a single expression over the selection "
            f"names, not a {type(condition).__name__}. A list of conditions is "
            f"Sigma v1 syntax that was removed because nobody agreed on how the "
            f"entries combined.",
            "parse",
        )
    if detection and not selections:
        raise Refusal(
            "SIGMA_NO_SELECTION",
            "`detection` has a condition but no selections for it to refer to.",
            "parse",
        )

    logsource = document.get("logsource") or {}
    if logsource and not isinstance(logsource, dict):
        raise Refusal(
            "SIGMA_LOGSOURCE_MALFORMED",
            f"`logsource` has to be a mapping of product/service/category, not "
            f"a {type(logsource).__name__}.",
            "parse",
        )

    return ParsedSigma(
        document=document,
        selections=selections,
        condition=condition or "",
        logsource=logsource,
        correlation=correlation,
        raw=text,
    )


# ---------------------------------------------------------------------------
# Lower: a selection to an expression
# ---------------------------------------------------------------------------


def _field_predicate(
    raw_key: str, value: Any, diagnostics: list[Diagnostic]
) -> Expr:
    """One `Field|modifier: value` entry as a predicate.

    A LIST means OR and a MAP means AND, and that asymmetry is the single
    easiest thing to get backwards in Sigma. Backwards, `EventID: [10, 11]`
    becomes "10 AND 11", which is unsatisfiable -- a rule that silently never
    fires. So the two cases are written out separately here rather than sharing
    a combinator.
    """
    name, modifiers = _modifiers(raw_key)
    if not name:
        raise Refusal(
            "SIGMA_FIELD_NAME_EMPTY",
            f"`{raw_key}` has modifiers but no field name.",
            "lower",
        )

    for modifier in modifiers:
        if modifier in MODIFIER_REFUSALS:
            raise Refusal(
                "SIGMA_MODIFIER_UNSUPPORTED",
                f"`{name}|{modifier}` cannot be lowered: "
                f"{MODIFIER_REFUSALS[modifier]}",
                "lower",
            )
        if modifier not in MODIFIER_OPS and modifier not in MODIFIER_FLAGS:
            raise Refusal(
                "SIGMA_MODIFIER_UNKNOWN",
                f"`{modifier}` on `{name}` is not a Sigma modifier this dialect "
                f"knows. Known: "
                f"{', '.join(sorted(set(MODIFIER_OPS) | MODIFIER_FLAGS))}. It is "
                f"refused rather than ignored, because ignoring a modifier "
                f"widens the detection without saying so.",
                "lower",
            )

    combine_with_and = "all" in modifiers
    field = FieldRef.parse(name)

    operator = "=="
    for modifier in modifiers:
        if modifier in MODIFIER_OPS:
            operator = MODIFIER_OPS[modifier]

    if "re" in modifiers and "cidr" in modifiers:
        raise Refusal(
            "SIGMA_MODIFIER_CONFLICT",
            f"`{name}` carries both `re` and `cidr`. One treats the value as a "
            f"pattern and the other as a network; they cannot both be true.",
            "lower",
        )

    values = value if isinstance(value, list) else [value]
    if not values:
        raise Refusal(
            "SIGMA_VALUE_LIST_EMPTY",
            f"`{name}` is given an empty list. An empty membership test matches "
            f"nothing, which is almost never the intent -- say so explicitly if "
            f"it is.",
            "lower",
        )

    terms: list[Expr] = []
    for single in values:
        if "re" in modifiers:
            if not isinstance(single, str):
                raise Refusal(
                    "SIGMA_REGEX_NOT_TEXT",
                    f"`{name}|re` was given a {type(single).__name__}; a pattern "
                    f"has to be text.",
                    "lower",
                )
            # RE2-ish, not PCRE. Sigma's spec leans on the backend's engine, and
            # most backends are RE2 or ERE. Calling it `pcre` would be the
            # pessimistic choice -- `evaluate.py` refuses every PCRE pattern for
            # local execution, so every Sigma rule would become untestable here.
            # `posix_extended` lets the portable majority run and still refuses
            # the constructs that are genuinely dialect-specific.
            terms.append(Comparison(
                "matches", field,
                Regex(single, dialect="posix_extended", nocase="i" in modifiers),
            ))
            continue
        if "cidr" in modifiers:
            if not isinstance(single, str):
                raise Refusal(
                    "SIGMA_CIDR_NOT_TEXT",
                    f"`{name}|cidr` was given a {type(single).__name__}; a "
                    f"network has to be text like `10.0.0.0/8`.",
                    "lower",
                )
            # cidr_contains(address, network) IS executable locally -- it is pure
            # computation over two arguments, so a Sigma rule using |cidr can be
            # test-run against a sample here.
            terms.append(Comparison(
                "==",
                Call("cidr_contains", (field, Literal(single))),
                Literal(True),
            ))
            continue
        if single is None:
            # `field: null` asks whether the field IS NULL. That is not the same
            # question as whether it is absent, and this engine keeps the two
            # apart -- see tests/test_core.py::AbsentIsNotNullIsNotEmpty.
            #
            # `== null` would be the obvious lowering and is the wrong one: the
            # evaluator treats any comparison against null as UNDECIDED, on the
            # grounds that null is a third thing rather than a value to compare.
            # So the test would never answer. `is_null` is in LOCAL_FUNCTIONS and
            # returns a real boolean -- True for null, False for a value, and
            # UNDECIDED for an absent field, which is exactly the three-way
            # answer Sigma's `field: null` deserves.
            terms.append(Call("is_null", (field,)))
            continue
        # EVERY Sigma string comparison folds case unless `|cased` is spelled
        # out -- plain equality included. Only the substring family carried the
        # fold, so `OriginalFileName: 'CertUtil.exe'` lowered exact-case and a
        # standard Certutil LOLBin rule missed `CERTUTIL.EXE` in Sigma and in
        # every dialect it was exported to.
        folds = (
            isinstance(single, str)
            and "cased" not in modifiers
            and operator in ("==", "!=", "in", "contains", "startswith",
                             "endswith")
        )
        terms.append(Comparison(
            operator, field, _literal(single), nocase=folds,
        ))

    if len(terms) == 1:
        return terms[0]
    if combine_with_and:
        return BoolOp("and", tuple(terms))
    return BoolOp("or", tuple(terms))


def _selection_predicate(
    name: str, body: Any, diagnostics: list[Diagnostic]
) -> Expr:
    """One named selection as a predicate."""
    if isinstance(body, dict):
        if not body:
            raise Refusal(
                "SIGMA_SELECTION_EMPTY",
                f"selection `{name}` is empty, so it places no condition on an "
                f"event. An empty selection matches everything, which is the "
                f"defect this tool refuses to produce.",
                "lower",
            )
        terms = [_field_predicate(k, v, diagnostics) for k, v in body.items()]
        return terms[0] if len(terms) == 1 else BoolOp("and", tuple(terms))

    if isinstance(body, list):
        if not body:
            raise Refusal(
                "SIGMA_SELECTION_EMPTY",
                f"selection `{name}` is an empty list.",
                "lower",
            )
        if all(isinstance(item, dict) for item in body):
            # A list of maps is an OR of the maps.
            terms = [_selection_predicate(f"{name}[{i}]", item, diagnostics)
                     for i, item in enumerate(body)]
            return terms[0] if len(terms) == 1 else BoolOp("or", tuple(terms))
        raise Refusal(
            "SIGMA_KEYWORD_SEARCH_UNSUPPORTED",
            f"selection `{name}` is a list of bare values, which in Sigma means "
            f"a full-text keyword search across the whole event. This engine "
            f"evaluates named fields, and there is no field to search -- so a "
            f"keyword list cannot be lowered without inventing one. Name the "
            f"field you mean.",
            "lower",
        )

    raise Refusal(
        "SIGMA_SELECTION_MALFORMED",
        f"selection `{name}` is a {type(body).__name__}. A selection is a "
        f"mapping of field to value, or a list of such mappings.",
        "lower",
    )


# ---------------------------------------------------------------------------
# Lower: the condition
# ---------------------------------------------------------------------------

_OF_PATTERN = re.compile(
    r"\b(?P<count>\d+|all|any)\s+of\s+(?P<target>them|[A-Za-z_][\w*]*)",
    re.IGNORECASE,
)


def _expand_of_forms(condition: str, names: list[str]) -> str:
    """Rewrite `1 of them` / `all of selection_*` into explicit groups.

    Done before parsing so that `and`/`or` precedence still comes from the
    shared table. `1 of a` and `any of a` both mean "at least one", which is an
    OR; `all of a` is an AND. Sigma has no "exactly N", and silently reading
    `2 of them` as "at least 2" would be a different detection -- so it is
    refused rather than approximated.
    """
    def replace(match: re.Match[str]) -> str:
        count = match.group("count").lower()
        target = match.group("target")

        if target.lower() == "them":
            chosen = list(names)
        elif target.endswith("*"):
            prefix = target[:-1]
            chosen = [n for n in names if n.startswith(prefix)]
        else:
            chosen = [n for n in names if n == target]

        if not chosen:
            raise Refusal(
                "SIGMA_CONDITION_UNKNOWN_SELECTION",
                f"`{count} of {target}` matches no selection in this rule. "
                f"Defined: {sorted(names)}.",
                "lower",
            )

        if count in ("1", "any"):
            joiner = " or "
        elif count == "all":
            joiner = " and "
        else:
            raise Refusal(
                "SIGMA_CONDITION_COUNT_UNSUPPORTED",
                f"`{count} of {target}` asks for exactly {count} of "
                f"{len(chosen)} selections. The IR has no n-of-m operator, and "
                f"reading it as `at least {count}` or as `all` would each be a "
                f"different detection. Write the combination out.",
                "lower",
            )
        return "(" + joiner.join(chosen) + ")"

    return _OF_PATTERN.sub(replace, condition)


def _substitute(expr: Expr, predicates: dict[str, Expr], used: set[str]) -> Expr:
    """Replace each selection name with the predicate it names.

    Every branch ends in a refusal. A silent fallback here would drop part of
    the condition and leave a rule that reads correctly and matches differently.
    """
    if isinstance(expr, FieldRef):
        name = expr.full
        if name not in predicates:
            raise Refusal(
                "SIGMA_CONDITION_UNKNOWN_SELECTION",
                f"the condition refers to `{name}`, which is not a selection in "
                f"this rule. Defined: {sorted(predicates)}.",
                "lower",
            )
        used.add(name)
        return predicates[name]
    if isinstance(expr, BoolOp):
        return BoolOp(expr.op, tuple(
            _substitute(operand, predicates, used) for operand in expr.operands
        ))
    if isinstance(expr, Not):
        return Not(_substitute(expr.operand, predicates, used))
    if isinstance(expr, Comparison):
        raise Refusal(
            "SIGMA_CONDITION_NOT_BOOLEAN",
            f"`{render_expr(expr)}` compares values. A Sigma condition combines "
            f"selection NAMES with and/or/not; the comparisons belong inside a "
            f"selection.",
            "lower",
        )
    raise Refusal(
        "SIGMA_CONDITION_NOT_BOOLEAN",
        f"`{render_expr(expr)}` is not something a Sigma condition can contain. "
        f"A condition is and/or/not over the selection names.",
        "lower",
    )


def _lower_condition(
    condition: str, predicates: dict[str, Expr], diagnostics: list[Diagnostic]
) -> Expr:
    text = _expand_of_forms(condition.strip(), list(predicates))
    if not text:
        raise Refusal(
            "SIGMA_NO_CONDITION", "the condition is empty.", "lower"
        )

    reserved = set(SPEC.keywords) & set(predicates)
    if reserved:
        raise Refusal(
            "SIGMA_SELECTION_NAME_RESERVED",
            f"selection name(s) {sorted(reserved)} collide with the condition "
            f"grammar's own words, so the condition cannot be read "
            f"unambiguously. Rename them.",
            "lower",
        )

    parser = Parser(tokenize(text), SPEC)
    tree = parser.parse_expression()

    used: set[str] = set()
    lowered = _substitute(tree, predicates, used)

    unused = sorted(set(predicates) - used)
    if unused:
        # Not an error -- Sigma rules legitimately carry a selection the
        # condition does not reference during development. But an unreferenced
        # selection is dead weight that reads as if it were doing something, so
        # the analyst is told.
        diagnostics.append(Diagnostic(
            "SIGMA_SELECTION_UNUSED",
            f"selection(s) {unused} are defined but never referenced by the "
            f"condition, so they place no restriction on what this rule "
            f"matches.",
            severity="caution",
            evidence=condition,
        ))
    return lowered


# ---------------------------------------------------------------------------
# Lower: metadata
# ---------------------------------------------------------------------------

#: Sigma `level` is already the vocabulary `Annotations.severity` wants.
LEVELS: Final[frozenset[str]] = frozenset({
    "informational", "low", "medium", "high", "critical",
})

_TECHNIQUE = re.compile(r"^t\d{4}(\.\d{3})?$", re.IGNORECASE)


def _mitre(tags: list[Any]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """ATT&CK tags as a tactic-to-techniques mapping.

    Sigma writes the two at the same level -- `attack.credential_access` and
    `attack.t1003.001` are sibling tags -- so the grouping has to be inferred
    from the shape of each tag. Techniques found with no tactic are kept under
    an empty tactic rather than discarded: losing the technique id would lose
    the thing a SOC actually pivots on.
    """
    tactics: list[str] = []
    techniques: list[str] = []
    for tag in tags:
        if not isinstance(tag, str) or not tag.lower().startswith("attack."):
            continue
        body = tag.split(".", 1)[1]
        if _TECHNIQUE.match(body.split(".")[0]) and body[0].lower() == "t":
            techniques.append(body.upper())
        else:
            tactics.append(body.replace("_", "-"))
    if not tactics and not techniques:
        return ()
    if not tactics:
        return (("", tuple(techniques)),)
    # Every technique is attributed to every tactic named on the rule. Sigma
    # carries no linkage between them, and inventing one would be asserting
    # something the rule does not say.
    return tuple((tactic, tuple(techniques)) for tactic in tactics)


def _text_list(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, list):
        return tuple(str(item) for item in value if item is not None)
    return (str(value),)


def _annotations(
    document: dict[str, Any], diagnostics: list[Diagnostic]
) -> Annotations:
    level = str(document.get("level") or "").strip().lower()
    if level and level not in LEVELS:
        diagnostics.append(Diagnostic(
            "SIGMA_LEVEL_UNKNOWN",
            f"`level: {level}` is not one of Sigma's five levels "
            f"({', '.join(sorted(LEVELS))}). It is carried through unchanged, "
            f"but a SIEM that triages on severity will not know what to do "
            f"with it.",
            severity="caution",
            evidence=level,
        ))
    return Annotations(
        title=str(document.get("title") or ""),
        description=str(document.get("description") or "").strip(),
        severity=level,
        author=str(document.get("author") or ""),
        mitre_attack=_mitre(document.get("tags") or []),
        references=_text_list(document.get("references")),
        false_positives=_text_list(document.get("falsepositives")),
    )


def _metadata(parsed: ParsedSigma) -> dict[str, str]:
    """Everything Annotations cannot hold, so the renderer can put it back.

    `Rule.metadata` is a string-to-string mapping, so structured leftovers are
    JSON-encoded. Verbose, but a round trip that loses a rule's `id` is a round
    trip that breaks every reference to it.
    """
    document = parsed.document
    out: dict[str, str] = {
        "dialect": DIALECT,
        "language": LANGUAGE,
        "artifact": "rule",
    }
    for key in ("id", "status", "date", "modified", "license", "name"):
        value = document.get(key)
        if value is not None:
            out[f"sigma.{key}"] = str(value)
    if parsed.logsource:
        out["sigma.logsource"] = json.dumps(parsed.logsource, sort_keys=True)
    tags = document.get("tags")
    if tags:
        out["sigma.tags"] = json.dumps(_text_list(tags))
    fields = document.get("fields")
    if fields:
        out["sigma.fields"] = json.dumps(_text_list(fields))
    related = document.get("related")
    if related:
        out["sigma.related"] = json.dumps(related, sort_keys=True)
    if parsed.correlation:
        # Kept whole because `Correlation.parent` had to be rewritten to a local
        # stage id, so the rule reference it originally named cannot be
        # recovered from the IR alone.
        out["sigma.correlation"] = json.dumps(
            parsed.correlation, sort_keys=True, default=str
        )

    unknown = {k: v for k, v in document.items() if k not in KNOWN_KEYS}
    if unknown:
        out["sigma.extra"] = json.dumps(unknown, sort_keys=True, default=str)
    return out


def _read_stage(parsed: ParsedSigma) -> Read:
    """`logsource` as the source stage.

    The selector is kept VERBATIM and never parsed into a predicate: a log
    source is resolved by the backend's own index mapping, before any row
    exists, so treating it as a row filter would let a local evaluation claim a
    match it cannot produce. `Read.selector`'s own docstring makes the same
    point.
    """
    source = parsed.logsource
    # The most specific name available becomes the table, because that is the
    # one a backend's mapping is usually keyed on.
    table = ""
    for key in ("category", "service", "product"):
        value = source.get(key)
        if value:
            table = str(value)
            break
    selector = ", ".join(
        f"{k}={source[k]}" for k in sorted(source) if source[k] is not None
    )
    if not table:
        table = "events"
    return Read(id="source", table=table, selector=selector)


# ---------------------------------------------------------------------------
# Lower: correlations
# ---------------------------------------------------------------------------

CORRELATION_REFUSALS: Final[dict[str, str]] = {
    "temporal": "a `temporal` correlation fires when SEVERAL different rules "
                "match inside one timespan. The IR's Correlation counts ONE "
                "parent, so expressing it would mean dropping all but one of "
                "the rules -- which is a different detection.",
    "temporal_ordered": "an ordered sequence needs an IR node this engine does "
                        "not have yet: Correlation is a count threshold, not an "
                        "ordering, and lowering an ordered rule as an unordered "
                        "count would fire on evidence in the wrong order.",
}

_CONDITION_OPS: Final[dict[str, str]] = {
    "gte": ">=", "gt": ">", "lte": "<=", "lt": "<", "eq": "==", "neq": "!=",
}


def _correlation_stages(
    parsed: ParsedSigma,
    parent: str,
    diagnostics: list[Diagnostic],
) -> list[Any]:
    """A Sigma correlation as IR stages.

    `parent` is the id of the stage the count runs over. Sigma names the rule it
    correlates by `id` or `name`, which is a reference into a rule COLLECTION --
    something this function has no access to. So the caller resolves it to the
    local detection stage and the original reference is kept in the diagnostics,
    rather than being written into `Correlation.parent` where `ir.Rule` would
    refuse it as a dangling reference.
    """
    block = parsed.correlation
    kind = str(block.get("type") or "").strip().lower()
    if not kind:
        raise Refusal(
            "SIGMA_CORRELATION_NO_TYPE",
            "a `correlation` block needs a `type`.",
            "lower",
        )
    if kind in CORRELATION_REFUSALS:
        raise Refusal(
            "SIGMA_CORRELATION_UNSUPPORTED",
            f"`type: {kind}` cannot be lowered: {CORRELATION_REFUSALS[kind]}",
            "lower",
        )
    if kind not in ("event_count", "value_count"):
        raise Refusal(
            "SIGMA_CORRELATION_TYPE_UNKNOWN",
            f"`type: {kind}` is not a Sigma correlation type this dialect "
            f"knows. Known: event_count, value_count, and temporal/"
            f"temporal_ordered which are refused with reasons.",
            "lower",
        )

    rules = _text_list(block.get("rules"))
    if not rules:
        raise Refusal(
            "SIGMA_CORRELATION_NO_RULES",
            "a correlation has to name the rule(s) it counts over.",
            "lower",
        )
    if len(rules) > 1:
        raise Refusal(
            "SIGMA_CORRELATION_MULTI_RULE",
            f"this correlation counts over {len(rules)} rules "
            f"({', '.join(rules)}). The IR's Correlation has one parent, and "
            f"silently using the first would count the wrong events.",
            "lower",
        )

    group_by = _text_list(block.get("group-by") or block.get("group_by"))
    if not group_by:
        raise Refusal(
            "SIGMA_CORRELATION_NO_GROUP",
            "this correlation has no `group-by`, so the count is 'anywhere in "
            "the log'. That is almost never the intent, and it turns a per-host "
            "threshold into a global one.",
            "lower",
        )

    timespan_text = str(block.get("timespan") or "").strip()
    timespan = duration_seconds(timespan_text) if timespan_text else None
    if timespan is None:
        raise Refusal(
            "SIGMA_CORRELATION_TIMESPAN",
            f"`timespan: {timespan_text or '(missing)'}` is not a span this "
            f"engine can read. Use a number with a unit, like `15m` or `1h` -- "
            f"a count with no window is not a threshold.",
            "lower",
        )

    condition = block.get("condition") or {}
    if not isinstance(condition, dict) or not condition:
        raise Refusal(
            "SIGMA_CORRELATION_CONDITION",
            "a correlation needs a `condition` such as `gte: 10`, or there is "
            "no threshold to fire on.",
            "lower",
        )

    keys = tuple(FieldRef.parse(name) for name in group_by)

    if kind == "event_count":
        operator, threshold = _threshold(condition)
        if operator != ">=":
            raise Refusal(
                "SIGMA_CORRELATION_CONDITION_UNSUPPORTED",
                f"`{operator} {threshold}` cannot be expressed as a Correlation, "
                f"whose frequency is a minimum. Only `gte` maps directly; "
                f"anything else needs an Aggregate plus a Filter, and quietly "
                f"substituting one would change when the rule fires.",
                "lower",
            )
        return [
            Correlation(
                id="correlate",
                parent=parent,
                frequency=int(threshold),
                timeframe=timespan,
                group_by=keys,
            )
        ]

    # value_count: distinct values of one field per group, over a window.
    field = str(block.get("field") or "").strip()
    if not field:
        raise Refusal(
            "SIGMA_CORRELATION_NO_FIELD",
            "a `value_count` correlation counts DISTINCT values of a field, so "
            "it needs `field`.",
            "lower",
        )
    operator, threshold = _threshold(condition)
    return [
        Aggregate(
            id="count_values",
            measures=(Measure("dcount", "value_count", FieldRef.parse(field),
                              distinct=True),),
            keys=keys,
            window=Window(kind="tumbling", size=timespan),
        ),
        Filter(
            id="threshold",
            condition=Comparison(
                operator, FieldRef("value_count"), Literal(threshold)
            ),
        ),
    ]


def _threshold(condition: dict[str, Any]) -> tuple[str, Decimal]:
    if len(condition) != 1:
        raise Refusal(
            "SIGMA_CORRELATION_CONDITION",
            f"a correlation condition takes one comparison, not "
            f"{sorted(condition)}.",
            "lower",
        )
    name, value = next(iter(condition.items()))
    operator = _CONDITION_OPS.get(str(name).strip().lower())
    if operator is None:
        raise Refusal(
            "SIGMA_CORRELATION_CONDITION",
            f"`{name}` is not a correlation comparison. Known: "
            f"{', '.join(sorted(_CONDITION_OPS))}.",
            "lower",
        )
    try:
        threshold = Decimal(str(value))
    except Exception as exc:
        raise Refusal(
            "SIGMA_CORRELATION_CONDITION",
            f"`{name}: {value!r}` is not a number.",
            "lower",
        ) from exc
    return operator, threshold


# ---------------------------------------------------------------------------
# Lower
# ---------------------------------------------------------------------------


def lower_sigma(text: str, rule_id: str = "rule") -> tuple[Rule, list[Diagnostic]]:
    """A Sigma rule to a Rule, plus what could not be represented."""
    parsed = parse_sigma(text)
    diagnostics: list[Diagnostic] = []

    if not parsed.document.get("title"):
        diagnostics.append(Diagnostic(
            "SIGMA_NO_TITLE",
            "this rule has no `title`. Sigma requires one, and an untitled rule "
            "arrives in a SOC queue with nothing to triage on.",
            severity="caution",
        ))

    stages: list[Any] = [_read_stage(parsed)]
    detection_id = ""

    if parsed.selections:
        predicates = {
            name: _selection_predicate(name, body, diagnostics)
            for name, body in parsed.selections.items()
        }
        detection_id = "detection"
        stages.append(Filter(
            id=detection_id,
            condition=_lower_condition(parsed.condition, predicates, diagnostics),
        ))

    if parsed.correlation:
        if not detection_id:
            # Sigma correlation rules normally live beside the rules they count,
            # in a collection this function cannot see. Without a local detection
            # there is nothing to count, and inventing a parent would produce a
            # rule that fires on the wrong events.
            raise Refusal(
                "SIGMA_CORRELATION_NO_LOCAL_RULE",
                f"this correlation counts over "
                f"{_text_list(parsed.correlation.get('rules')) or '(nothing)'}, "
                f"which is not defined in this file. Lower the referenced rule "
                f"and its correlation together, or the count has no events to "
                f"run over.",
                "lower",
            )
        referenced = _text_list(parsed.correlation.get("rules"))
        if referenced:
            diagnostics.append(Diagnostic(
                "SIGMA_CORRELATION_RULE_RESOLVED",
                f"the correlation names rule `{referenced[0]}`, which is a "
                f"reference into a rule collection. It has been resolved to this "
                f"file's own detection stage, which is the only thing available "
                f"here -- confirm that is the rule you meant.",
                severity="caution",
                verified=False,
                evidence=referenced[0],
            ))
        stages.extend(
            _correlation_stages(parsed, detection_id, diagnostics)
        )

    stages.append(Emit(id="out"))

    # The rule id comes from Sigma's own `id` when the caller did not choose
    # one, because that uuid is what every reference to this rule uses.
    resolved = rule_id
    if resolved == "rule" and parsed.document.get("id"):
        resolved = str(parsed.document["id"])

    rule = Rule(
        rule_id=resolved,
        pipeline=tuple(stages),
        annotations=_annotations(parsed.document, diagnostics),
        metadata=_metadata(parsed),
    )
    validate(rule)
    return rule, diagnostics


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


class _Raw(str):
    """Text already in YAML body form; `_quote` must pass it through.

    A membership list is a YAML STRUCTURE, not a scalar, so it cannot go
    through the scalar quoter: quoting it produced
    `User: '[''alice'', ''bob'']'`, one string literal containing brackets.
    """


def _quote(value: Any) -> str:
    if isinstance(value, _Raw):
        return str(value)
    """A scalar as YAML. Quoted whenever bare would change its meaning."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Decimal):
        # Plain notation. `str(Decimal("1e10"))` is `1E+10`, which YAML reads
        # back as a STRING rather than a number -- so a numeric comparison
        # became a text one on re-import.
        return plain_number(value)
    text = str(value)
    if text == "":
        return "''"
    if "\n" in text or "\r" in text or "\t" in text:
        # A value with a line break CANNOT be written bare, and this used to
        # write it bare: a `CommandLine` read from a `|` block scalar came out
        # as
        #
        #     CommandLine: multi
        #     line
        #
        # which is not `key: value` at all -- this module's own reader refuses
        # it with SIGMA_YAML_NOT_A_MAPPING. The renderer was emitting YAML its
        # own parser rejects.
        #
        # Double-quoted with escapes rather than a block scalar, because a
        # block scalar's meaning depends on the indentation of the line it
        # sits under and `_quote` does not know its own column.
        escaped = (
            text.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\r", "\\r")
            .replace("\n", "\\n")
            .replace("\t", "\\t")
        )
        return '"' + escaped + '"'
    needs_quoting = (
        text[0] in "-?:,[]{}#&*!|>'\"%@` "
        or text[-1] == " "
        or ": " in text
        or " #" in text
        or text.lower() in ("null", "true", "false", "~", "yes", "no", "on", "off")
        or _INT.fullmatch(text) is not None
        or _FLOAT.fullmatch(text) is not None
    )
    if needs_quoting:
        return "'" + text.replace("'", "''") + "'"
    return text


#: Operators whose repetition on one field is expressible as Sigma's `|all`.
#:
#: Equality is deliberately EXCLUDED. `field|all: [a, b]` asks a scalar field
#: to equal two different values at once, which no event satisfies -- so
#: folding `x == 1 and x == 2` into it would turn a contradiction into a
#: plausible-looking rule that silently never fires. Those stay two
#: selections, which is what `_by_distinct_fields` produces.
_ALL_MODIFIER_OPS: Final[frozenset[str]] = frozenset({
    "contains", "startswith", "endswith",
})


def _groupable_pair(expr: Expr) -> tuple[str, Any] | None:
    """`(key, value)` when a conjunct is a plain field test that can share a
    `|all` group, or None when it needs its own rendering."""
    if not isinstance(expr, Comparison) or expr.negate:
        return None
    if expr.op not in _ALL_MODIFIER_OPS:
        return None
    if not isinstance(expr.left, FieldRef) or not isinstance(expr.right, Literal):
        return None
    key, value = _render_value(
        expr.left, expr.right, expr.op, nocase=expr.nocase
    )
    return key, value


def _sigma_wildcards(text: str) -> str:
    """A SQL/glob pattern as Sigma's own wildcard syntax.

    Sigma spells its wildcards `*` and `?`. A `like` pattern arrives carrying
    SQL's `%` and `_`, and writing those through unchanged produced a Sigma
    selection matching a LITERAL percent sign -- a rule that looks right, is
    valid YAML, and can never fire. The two spellings have to be translated,
    not copied.

    A literal `*`, `?` or backslash in the source is escaped with a backslash,
    which is Sigma's own escape, so the translation cannot invent a wildcard
    the author did not write.
    """
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            # `\%` and `\_` mean the literal character; everything else keeps
            # its backslash so a Windows path survives.
            following = text[index + 1]
            if following in "%_":
                out.append("\\" + following)
            else:
                out.append("\\\\" + following)
            index += 2
            continue
        if char == "%":
            out.append("*")
        elif char == "_":
            out.append("?")
        elif char in "*?":
            out.append("\\" + char)
        else:
            out.append(char)
        index += 1
    return "".join(out)


#: Sigma modifiers whose comparison is CASE-INSENSITIVE by the specification.
_SUFFIX_NOCASE: Final[dict[str, str]] = {
    "contains": "|contains",
    "startswith": "|startswith",
    "endswith": "|endswith",
}

#: The same three with `|cased`, which turns the fold OFF.
#:
#: Both halves matter. Importing `User|contains: bob` and writing it back
#: without `|cased` is correct; importing an exact-case test and writing it
#: back WITHOUT `|cased` silently WIDENS it.
_SUFFIX_EXACT: Final[dict[str, str]] = {
    "contains": "|contains|cased",
    "startswith": "|startswith|cased",
    "endswith": "|endswith|cased",
}


def _render_value(
    field: FieldRef, right: Expr, operator: str, nocase: bool = False
) -> tuple[str, Any]:
    """An IR comparison back to a `Field|modifier: value` pair.

    `!=` is deliberately refused here rather than defaulted. Sigma has no
    per-field negation -- it negates a whole named selection in `condition:` --
    so `_split_condition` rewrites a `!=` conjunct into `Not(== ...)` before
    this is reached. Letting `!=` fall through the old `.get(operator, "")`
    default is exactly how `CommandLine != "x"` rendered as `CommandLine: x`:
    a filter written to EXCLUDE an event became a detection that fires on it.
    """
    if operator == "!=":
        raise Refusal(
            "SIGMA_RENDER_NEGATED_OPERATOR",
            f"`{render_expr(right)}` is compared with `!=`, and Sigma has no "
            f"per-field negation. It negates a whole selection in "
            f"`condition:`, so this comparison has to move there rather than "
            f"be written as a field test.",
            "render",
        )
    if operator in ("like", "ilike"):
        if not isinstance(right, Literal):
            raise Refusal(
                "SIGMA_RENDER_VALUE",
                f"`{render_expr(right)}` is a wildcard pattern, and Sigma "
                f"writes a wildcard inside the value itself, so it needs a "
                f"constant.",
                "render",
            )
        # A `like` pattern is a GLOB: `%` is any run and `_` is one character.
        # Sigma's are `*` and `?`. Copying the pattern across unchanged wrote
        # a literal percent sign into the rule, so it could never fire.
        return field.full, _sigma_wildcards(str(right.value))
    if operator == "in" and isinstance(right, ListExpr):
        # Sigma spells membership as a YAML list under one key -- the exact
        # shape this module's own reader lowers back to `in`. Refusing it
        # meant a rule the reader accepts could not be written back out.
        values: list[Any] = []
        for item in right.items:
            if not isinstance(item, Literal):
                raise Refusal(
                    "SIGMA_RENDER_VALUE",
                    f"`{render_expr(item)}` is inside a membership list, and "
                    f"Sigma's list holds constants only.",
                    "render",
                )
            values.append(item.value)
        return field.full, _Raw(
            "[" + ", ".join(_quote(v) for v in values) + "]"
        )
    if operator in ("has", "has_any", "has_all", "contains_any", "contains_all"):
        raise Refusal(
            "SIGMA_RENDER_TERM_OPERATOR",
            f"`{operator}` is a whole-token term test, and Sigma has no "
            f"modifier for one: its `|contains` is a SUBSTRING test and would "
            f"match more than the rule states. Express it as the field values "
            f"you actually want, or keep this rule in a dialect that has term "
            f"matching.",
            "render",
        )
    suffix = {
        "<": "|lt", "<=": "|lte", ">": "|gt", ">=": "|gte",
    }.get(operator, "")
    if operator in _SUFFIX_NOCASE:
        # A case fold the SOURCE asked for is Sigma's default here, so nothing
        # is written. An exact-case test needs `|cased` spelled out, or
        # exporting it silently widens the rule instead of narrowing it.
        suffix = _SUFFIX_NOCASE[operator] if nocase else _SUFFIX_EXACT[operator]
    if isinstance(right, Regex):
        # `|re` is case-sensitive in Sigma and `|re|i` is not, so the fold has
        # to travel with the pattern. Dropping it narrowed every
        # case-insensitive regex on export.
        key = field.full + ("|re|i" if right.nocase else "|re")
        return key, right.pattern
    if isinstance(right, Literal):
        return field.full + suffix, right.value
    raise Refusal(
        "SIGMA_RENDER_VALUE",
        f"`{render_expr(right)}` is not a value Sigma can put on the "
        f"right-hand side of a field. Sigma compares a field to a constant or "
        f"a pattern; anything else has no syntax here.",
        "render",
    )


def _render_call(call: Call) -> str:
    """A function predicate back to the Sigma entry it came from.

    Only the two functions this dialect produces. Anything else is refused by
    name: Sigma expresses functions as field modifiers, so a function with no
    modifier has no syntax here, and writing a plausible-looking key would
    produce a rule no backend understands.
    """
    if call.function == "is_null" and len(call.args) == 1:
        field = call.args[0]
        if isinstance(field, FieldRef):
            return f"{field.full}: null"
    if call.function == "cidr_contains" and len(call.args) == 2:
        field, network = call.args
        if isinstance(field, FieldRef) and isinstance(network, Literal):
            return f"{field.full}|cidr: {_quote(network.value)}"
    raise Refusal(
        "SIGMA_RENDER_CALL",
        f"`{render_expr(call)}` has no Sigma syntax. Sigma expresses functions "
        f"as field modifiers, and there is no modifier for this one.",
        "render",
    )


def _render_selection(expr: Expr, lines: list[str], indent: str) -> None:
    """One predicate as an indented selection body.

    Every branch ends in a refusal. A silent `else` would write a selection
    missing a clause, which is a rule that looks complete and matches more
    events than it says.
    """
    if isinstance(expr, BoolOp) and expr.op == "and":
        # Conjuncts on the SAME field with the SAME substring operator are
        # Sigma's `|all` modifier -- `CommandLine|contains|all: [a, b]` --
        # which is how this module's own parser reads that shape back.
        #
        # Emitted one key per value, they were a DUPLICATE YAML key:
        #
        #     CommandLine|contains: ' -enc'
        #     CommandLine|contains: 'JAB'
        #
        # Most YAML readers keep only the last, so the rule silently stopped
        # requiring ` -enc` and fired on `JAB` alone -- a widened rule that
        # still looks right. This module's reader refuses it as
        # SIGMA_DUPLICATE_KEY, so the rendered rule could not be re-imported
        # either.
        # Walked in the AUTHOR'S order, emitting each key where it first
        # appears. An earlier version collected the groupable pairs and wrote
        # them before everything else, which reordered the selection body and
        # made a re-lowered rule compare unequal to the original.
        counts: dict[str, int] = {}
        for operand in expr.operands:
            pair = _groupable_pair(operand)
            if pair is not None:
                counts[pair[0]] = counts.get(pair[0], 0) + 1
        written: set[str] = set()
        for operand in expr.operands:
            pair = _groupable_pair(operand)
            if pair is None:
                _render_selection(operand, lines, indent)
                continue
            key, value = pair
            if counts[key] == 1:
                lines.append(f"{indent}{key}: {_quote(value)}")
                continue
            if key in written:
                continue  # already carried by the `|all` list below
            written.add(key)
            lines.append(f"{indent}{key}|all:")
            for other in expr.operands:
                other_pair = _groupable_pair(other)
                if other_pair is not None and other_pair[0] == key:
                    lines.append(f"{indent}    - {_quote(other_pair[1])}")
        return

    # A bare Call, which is how `field: null` and `field|cidr:` are lowered --
    # both are predicates in their own right rather than comparisons.
    if isinstance(expr, Call):
        lines.append(indent + _render_call(expr))
        return

    if isinstance(expr, Comparison):
        if isinstance(expr.left, Call):
            # A wrapped call, e.g. `cidr_contains(ip, net) == true`. Unwrap it
            # when the comparison is the trivial one, and refuse otherwise
            # rather than emitting a key Sigma has no meaning for.
            if (
                expr.op == "=="
                and isinstance(expr.right, Literal)
                and expr.right.value is True
                and not expr.negate
            ):
                lines.append(indent + _render_call(expr.left))
                return
            raise Refusal(
                "SIGMA_RENDER_CALL",
                f"`{render_expr(expr)}` compares the result of a function. "
                f"Sigma expresses functions as field modifiers, and a modifier "
                f"has no syntax for comparing its result to something else.",
                "render",
            )
        if not isinstance(expr.left, FieldRef):
            raise Refusal(
                "SIGMA_RENDER_NOT_A_FIELD",
                f"`{render_expr(expr.left)}` is on the left of a comparison, but "
                f"Sigma only compares named fields.",
                "render",
            )
        if expr.negate:
            raise Refusal(
                "SIGMA_RENDER_NEGATED_FIELD",
                f"`{render_expr(expr)}` negates a single field comparison. "
                f"Sigma has no per-field negation; it negates a whole selection "
                f"in the condition, so this needs its own selection.",
                "render",
            )
        key, value = _render_value(
            expr.left, expr.right, expr.op, nocase=expr.nocase
        )
        lines.append(f"{indent}{key}: {_quote(value)}")
        return

    if isinstance(expr, BoolOp) and expr.op == "or":
        # An OR over one field with several values is a value list. An OR across
        # different fields is not expressible inside one selection.
        fields = set()
        values: list[Any] = []
        key = ""
        for operand in expr.operands:
            if not isinstance(operand, Comparison) or not isinstance(
                operand.left, FieldRef
            ):
                fields.add(None)
                break
            rendered_key, value = _render_value(
                operand.left, operand.right, operand.op, nocase=operand.nocase
            )
            fields.add(rendered_key)
            key = rendered_key
            values.append(value)
        if len(fields) == 1 and None not in fields:
            lines.append(f"{indent}{key}:")
            for value in values:
                lines.append(f"{indent}    - {_quote(value)}")
            return

        # An OR across DIFFERENT fields is a LIST OF MAPS, which is Sigma's
        # own syntax for it: list items are ORed and the keys inside one item
        # are ANDed, so a list of maps is exactly a disjunction of
        # conjunctions.
        #
        # This used to refuse, on the grounds that splitting the OR into
        # several named selections was "a decision about the rule". That
        # reasoning missed the list form entirely, so a rule as ordinary as
        #
        #     sel:
        #       - Image|endswith: '\powershell.exe'
        #       - OriginalFileName: 'PowerShell.EXE'
        #
        # -- the standard "match the image or its original filename" idiom,
        # which the PARSER here already reads -- could be imported and then
        # not written back out.
        items: list[list[str]] = []
        for operand in expr.operands:
            body: list[str] = []
            _render_selection(operand, body, "")
            if not body:
                raise Refusal(
                    "SIGMA_RENDER_OR_EMPTY_BRANCH",
                    f"one branch of `{render_expr(expr)}` renders to nothing, "
                    f"so writing the list out would silently drop an "
                    f"alternative and narrow the rule.",
                    "render",
                )
            items.append(body)
        for body in items:
            lines.append(f"{indent}- {body[0]}")
            for extra in body[1:]:
                # Two spaces past the dash, so continuation keys stay inside
                # the same list item and keep their AND with the first key.
                lines.append(f"{indent}  {extra}")
        return


    if isinstance(expr, Not):
        raise Refusal(
            "SIGMA_RENDER_NESTED_NOT",
            f"`{render_expr(expr)}` negates part of a selection. Sigma negates "
            f"whole selections in the condition, so this needs restructuring "
            f"rather than reformatting.",
            "render",
        )

    if isinstance(expr, ListExpr):
        raise Refusal(
            "SIGMA_RENDER_BARE_LIST",
            f"`{render_expr(expr)}` is a bare list with no field to attach it "
            f"to.",
            "render",
        )

    raise Refusal(
        "SIGMA_RENDER_EXPR",
        f"`{render_expr(expr)}` ({type(expr).__name__}) has no Sigma syntax. It "
        f"is refused rather than skipped, because a dropped clause produces a "
        f"rule that reads correctly and matches more events than it states.",
        "render",
    )


def _negation_as_not(expr: Expr) -> Expr:
    """A per-field negation, rewritten as `Not(<positive form>)`.

    Sigma has no per-field negation: it negates a whole named selection in
    `condition:`. `Comparison` carries the negation TWO ways -- the `!=`
    operator and the `negate` flag -- and `_render_value` used to have no entry
    for `!=`, so

        CommandLine != "x"

    rendered as `CommandLine: x` under `condition: selection`, which is the
    INVERSE of the rule: an exclusion became a detection. That is the worst
    defect this renderer can have, because the output is valid, plausible, and
    alerts on exactly the events the author suppressed.

    Rewriting here rather than in `_render_selection` is deliberate: the
    negation has to move OUT to the condition, so it is the condition splitter
    that must see a `Not`, not the per-selection writer.
    """
    if isinstance(expr, Comparison):
        positive: Comparison | None = None
        if expr.op == "!=":
            positive = Comparison("==", expr.left, expr.right, nocase=expr.nocase)
        elif expr.negate:
            positive = Comparison(expr.op, expr.left, expr.right, nocase=expr.nocase)
        if positive is None:
            return expr
        # Two negations cancel: `!=` with `negate` set is a plain `==`.
        return Not(positive) if not expr.negate or expr.op != "!=" else positive
    return expr


def _split_condition(condition: Expr) -> tuple[dict[str, Expr], str]:
    """A composed predicate back into named selections plus a condition.

    The inverse of lowering, and genuinely lossy in one direction: Sigma has no
    syntax for "NOT this one field", only "NOT this whole selection". So a top
    level AND whose operands are `Not(...)` becomes `selection and not filter_N`,
    and anything that cannot be cut along those lines is refused rather than
    reshaped into a rule that means something slightly different.
    """
    operands = [_negation_as_not(o) for o in _flatten_and(condition)]

    selections: dict[str, Expr] = {}
    positive: list[Expr] = []
    negative: list[tuple[str, Expr]] = []
    terms: list[str] = []

    for operand in operands:
        if isinstance(operand, Not):
            name = "filter" if not negative else f"filter_{len(negative) + 1}"
            negative.append((name, operand.operand))
        else:
            positive.append(operand)

    # `selection` first, so the rendered rule reads the way a Sigma author
    # writes one: what it matches, then what it excludes.
    #
    # Positives are split so no SELECTION constrains the same field twice. A
    # Sigma selection is a YAML mapping, so `x == 1 and x == 2` wrote
    #
    #     selection:
    #         x: 1
    #         x: 2
    #
    # which is a duplicate key -- invalid YAML, and this module's own reader
    # refuses it with SIGMA_DUPLICATE_KEY. Two constraints on one field need
    # two selections ANDed in the condition, which is how a Sigma author
    # writes it.
    for group in _by_distinct_fields(positive):
        name = "selection" if "selection" not in selections \
            else f"selection_{len(selections) + 1}"
        selections[name] = (
            group[0] if len(group) == 1 else BoolOp("and", tuple(group))
        )
        terms.append(name)
    for name, inner in negative:
        selections[name] = inner
        terms.append(f"not {name}")

    if not selections:
        raise Refusal(
            "SIGMA_RENDER_EMPTY_DETECTION",
            "there is nothing to write into `detection`, and a Sigma rule with "
            "an empty detection matches every event.",
            "render",
        )
    return selections, " and ".join(terms)


def _flatten_and(condition: Expr) -> list[Expr]:
    """Every conjunct of a nested AND, as one flat list.

    Only the TOP level was unpacked, so `A and (B and C)` -- which is how
    lowering nests a multi-value `|all` beside another selection -- arrived as
    two operands, and `(B and C)` was handed to one selection whole. Any field
    repeated inside it was then invisible to `_by_distinct_fields`, which sees
    a set of field names and cannot tell one mention from two.
    """
    if isinstance(condition, BoolOp) and condition.op == "and":
        out: list[Expr] = []
        for operand in condition.operands:
            out.extend(_flatten_and(operand))
        return out
    return [condition]


def _needs_list_form(expr: Expr) -> bool:
    """Whether a conjunct can only be written as a YAML LIST of maps.

    An OR across different fields is written as a sequence, and a sequence
    cannot share a selection with `key: value` entries: the selection's body
    would be both a list and a mapping at once. That produced

        selection:
            - Image|endswith: \\powershell.exe
            - OriginalFileName: PowerShell.EXE
            CommandLine|contains: ' -enc'

    which is not YAML at all -- this module's own reader raised on the
    ambiguous indentation. Such a conjunct gets a selection to itself.
    """
    if not isinstance(expr, BoolOp) or expr.op != "or":
        return False
    fields: set[str] = set()
    for operand in expr.operands:
        if not isinstance(operand, Comparison) or not isinstance(
            operand.left, FieldRef
        ):
            return True  # a branch that is not a single field test
        fields.add(operand.left.full)
    return len(fields) > 1


def _by_distinct_fields(operands: list[Expr]) -> list[list[Expr]]:
    """Group conjuncts so no group writes the same YAML KEY twice.

    Greedy and order-preserving: each conjunct joins the first group that can
    still take it. Reordering them would change the rendered rule's reading
    order for no benefit, and a stable grouping is what keeps a re-render
    byte-identical.

    The constraint is the KEY, not the field. `x|contains` and `x|startswith`
    are two different mapping keys and sit happily in one selection, while two
    `x|contains` entries are a duplicate -- and those merge into
    `x|contains|all` rather than needing a second selection, which is how a
    Sigma author writes "contains both of these".
    """
    groups: list[list[Expr]] = []
    claimed: list[set[str]] = []
    for operand in operands:
        # A list-form conjunct is ISOLATED: it is a YAML sequence, and a
        # sequence cannot coexist with mapping keys in one selection body.
        if _needs_list_form(operand):
            groups.append([operand])
            claimed.append({_LIST_FORM_CLAIM})
            continue

        pair = _groupable_pair(operand)
        for index, taken in enumerate(claimed):
            if _LIST_FORM_CLAIM in taken:
                continue
            if pair is not None:
                # Repeating a groupable key is fine: the two become `|all`.
                # Only a clash with a NON-groupable claim on the same field
                # forces a new selection.
                if pair[0] in taken or not (_fields_of(operand) & taken):
                    groups[index].append(operand)
                    taken.add(pair[0])
                    break
                continue
            if not (_fields_of(operand) & taken):
                groups[index].append(operand)
                taken.update(_fields_of(operand))
                break
        else:
            groups.append([operand])
            claimed.append(
                {pair[0]} if pair is not None else set(_fields_of(operand))
            )
    return groups


#: Sentinel marking a group that holds a YAML sequence and so must stay alone.
#: A real field can never collide with it because `|` cannot appear in a Sigma
#: field name.
_LIST_FORM_CLAIM: Final[str] = "|list-form|"


def _fields_of(expr: Expr) -> set[str]:
    """Every field name a predicate constrains."""
    found: set[str] = set()

    def walk(node: Expr) -> None:
        if isinstance(node, FieldRef):
            found.add(node.full)
        elif isinstance(node, Comparison):
            walk(node.left)
            walk(node.right)
        elif isinstance(node, BoolOp):
            for operand in node.operands:
                walk(operand)
        elif isinstance(node, Not):
            walk(node.operand)
        elif isinstance(node, ListExpr):
            for item in node.items:
                walk(item)
        elif isinstance(node, Call):
            for argument in node.args:
                walk(argument)

    walk(expr)
    return found


#: Stages Sigma has no syntax for, and what writing the rule without each one
#: would actually do.
#:
#: Refused BY NAME. `render_sigma` used to `next()` the first `Filter` out of
#: the pipeline and ignore everything else -- there was no dispatch chain, so
#: nothing could end in a refusal, and seven stage kinds were dropped in
#: silence including a SECOND filter (half a conjunction) and a `Limit`.
#:
#: Sigma is a DETECTION FORMAT, not a query language: it describes what to
#: match and leaves selecting, ordering and trimming to whichever backend
#: compiles it. So these are genuine absences rather than gaps to fill.
UNSUPPORTED_STAGES: Final[dict[str, str]] = {
    "Sort": (
        "Sigma describes what to match and leaves ordering to the backend "
        "that compiles it. A rule whose meaning depends on order -- `the most "
        "recent`, `the top ten` -- loses that meaning entirely, and the "
        "remaining rule fires on every match instead of the ranked few"
    ),
    "Limit": (
        "Sigma has no row limit. Dropping it widens the rule to every match, "
        "and the limit is usually what kept the alert actionable"
    ),
    "Distinct": (
        "Sigma cannot de-duplicate. Without it the same finding is reported "
        "once per matching event rather than once"
    ),
    "Derive": (
        "Sigma cannot compute a new field; it tests fields the log already "
        "has. A rule testing a derived value has nothing left to test once "
        "the derivation is gone"
    ),
    "Expand": (
        "Sigma cannot expand a list into rows. Dropping it leaves a rule "
        "testing a whole list against a single value, which never matches"
    ),
    "Join": (
        "Sigma correlates through a `correlation` rule referring to another "
        "rule by name, not by joining two streams inline. Writing one side "
        "alone matches every event that side would have contributed, "
        "including the ones the join excluded"
    ),
    "Sequence": (
        "Sigma's correlation types are `event_count`, `value_count` and "
        "`temporal`; none of them is an ordered sequence. `temporal` says the "
        "events co-occur, not that one follows the other -- and writing a "
        "sequence as `temporal` fires on the two events in either order, "
        "where the reverse order is usually the benign one"
    ),
}


def render_sigma(rule: Rule) -> str:
    """Write a Rule back out as a Sigma rule.

    Metadata first, because that is the half `kql.py` loses: a rule exported
    without its title, level and ATT&CK tags is a rule a SOC cannot triage.

    The pipeline is WALKED, and every stage is either placed or refused by
    name -- see `UNSUPPORTED_STAGES`.
    """
    meta = rule.metadata
    annotations = rule.annotations
    lines: list[str] = []

    if rule.bindings:
        raise Refusal(
            "SIGMA_RENDER_BINDINGS",
            "Sigma has no inline sub-queries; a correlation rule refers to "
            "another rule by name. Writing only the main stream would drop "
            "whatever the bindings constrained.",
            "render",
        )

    correlation = next(
        (n for n in rule.pipeline if isinstance(n, Correlation)), None
    )
    aggregate = next(
        (n for n in rule.pipeline if isinstance(n, Aggregate)), None
    )

    # The threshold filter belongs to the aggregate, and `_render_correlation`
    # writes it. Identified by SHAPE rather than by `id == "threshold"`, which
    # is what the previous version matched on: a rule whose threshold stage
    # happened to be named anything else had its condition silently dropped.
    threshold_filter = _threshold_filter(rule, aggregate)

    detections = [
        n for n in rule.pipeline
        if isinstance(n, Filter) and n is not threshold_filter
    ]

    for node in rule.pipeline:
        if isinstance(node, (Read, Emit, Filter, Correlation, Aggregate)):
            continue
        if isinstance(node, Project):
            # `fields:` is Sigma's own way of naming the columns that matter,
            # so a projection has a home -- but only when nothing after it
            # TESTS a column it removed. A projection that feeds a later
            # filter does change what matches, and writing that as a display
            # hint would quietly widen the rule.
            if _filters_after(rule, node):
                raise Refusal(
                    "SIGMA_RENDER_PROJECT_BEFORE_FILTER",
                    f"`{node.id}` drops columns and a later stage still tests "
                    f"them. In Sigma `fields:` only tells the backend what to "
                    f"display, so writing this projection there would leave "
                    f"the later test running against columns the rule claims "
                    f"to have removed -- a rule that matches more than this "
                    f"one does.",
                    "render",
                )
            continue
        kind = type(node).__name__
        reason = UNSUPPORTED_STAGES.get(kind)
        if reason is None:
            raise Refusal(
                "SIGMA_RENDER_STAGE",
                f"a `{kind}` stage has no Sigma syntax, and writing the rule "
                f"without it would produce one that compiles, runs, and "
                f"matches a different set of events.",
                "render",
            )
        raise Refusal(
            f"SIGMA_RENDER_NO_{kind.upper()}",
            f"{reason}. This rule cannot be expressed as a Sigma rule.",
            "render",
        )

    lines.append(f"title: {_quote(annotations.title or rule.rule_id)}")
    identifier = meta.get("sigma.id") or rule.rule_id
    if identifier:
        lines.append(f"id: {_quote(identifier)}")
    if meta.get("sigma.status"):
        lines.append(f"status: {_quote(meta['sigma.status'])}")
    if annotations.description:
        lines.append("description: |")
        for line in annotations.description.split("\n"):
            lines.append(f"    {line}")
    if annotations.references:
        lines.append("references:")
        lines.extend(f"    - {_quote(r)}" for r in annotations.references)
    if annotations.author:
        lines.append(f"author: {_quote(annotations.author)}")
    if meta.get("sigma.date"):
        lines.append(f"date: {_quote(meta['sigma.date'])}")
    if meta.get("sigma.modified"):
        lines.append(f"modified: {_quote(meta['sigma.modified'])}")

    tags = _restore_tags(meta, annotations)
    if tags:
        lines.append("tags:")
        lines.extend(f"    - {_quote(t)}" for t in tags)

    logsource = _restore_logsource(meta, rule)
    lines.append("logsource:")
    for key in sorted(logsource):
        lines.append(f"    {key}: {_quote(logsource[key])}")

    detection = detections[0] if detections else None
    if detection is None:
        raise Refusal(
            "SIGMA_RENDER_NO_DETECTION",
            "this rule has no filter stage, so there is no detection to write. "
            "A Sigma rule with an empty detection matches every event, which is "
            "refused rather than emitted.",
            "render",
        )

    # Several filter stages are a CONJUNCTION. Only the first was written
    # before, so `where A | where B` became `A` alone and the rule matched
    # events B excluded.
    combined = (
        detection.condition if len(detections) == 1
        else BoolOp("and", tuple(n.condition for n in detections))
    )
    selections, condition = _split_condition(combined)
    lines.append("detection:")
    for name in selections:
        lines.append(f"    {name}:")
        body: list[str] = []
        _render_selection(selections[name], body, "        ")
        lines.extend(body)
    lines.append(f"    condition: {condition}")

    if meta.get("sigma.fields"):
        fields = json.loads(meta["sigma.fields"])
        if fields:
            lines.append("fields:")
            lines.extend(f"    - {_quote(f)}" for f in fields)
    else:
        # A projection with nothing testing its output becomes `fields:`,
        # which is what Sigma calls the same idea. Dropping it silently was
        # the old behaviour, and it lost the analyst's chosen column set on
        # every KQL rule ending in `| project` -- which is most of them.
        projected = [
            ref.full
            for node in rule.pipeline if isinstance(node, Project)
            for ref in node.keeps
        ]
        if projected:
            lines.append("fields:")
            lines.extend(f"    - {_quote(f)}" for f in projected)
    if annotations.false_positives:
        lines.append("falsepositives:")
        lines.extend(f"    - {_quote(f)}" for f in annotations.false_positives)
    if annotations.severity:
        lines.append(f"level: {_quote(annotations.severity)}")

    correlation = next(
        (n for n in rule.pipeline if isinstance(n, Correlation)), None
    )
    aggregate = next(
        (n for n in rule.pipeline if isinstance(n, Aggregate)), None
    )
    if correlation is not None or aggregate is not None:
        lines.extend(_render_correlation(rule, correlation, aggregate))

    return "\n".join(lines) + "\n"


def _filters_after(rule: Rule, node: Any) -> bool:
    """True when a stage after `node` still tests a row.

    A projection only matters to a Sigma rule when something downstream reads
    what it removed. Last in the pipeline it is a display choice; before a
    filter it changes what matches.
    """
    nodes = list(rule.pipeline)
    for later in nodes[nodes.index(node) + 1:]:
        if isinstance(later, (Filter, Aggregate, Correlation)):
            return True
    return False


def _threshold_filter(rule: Rule, aggregate: Any) -> Any:
    """The filter that states an aggregate's threshold, if there is one.

    Found by SHAPE -- a comparison between a measure's output name and a
    constant, positioned after the aggregate -- rather than by matching
    `id == "threshold"`, which is what this used to do. A rule whose stage
    happened to carry any other id had that filter treated as a detection
    selection, so `Hits >= 5` was written into the `detection:` block as a
    field test against a column no event has.
    """
    if aggregate is None:
        return None
    names = {m.name for m in aggregate.measures if m.name}
    nodes = list(rule.pipeline)
    position = nodes.index(aggregate)
    for node in nodes[position + 1:]:
        if not isinstance(node, Filter):
            continue
        condition = node.condition
        if (
            isinstance(condition, Comparison)
            and isinstance(condition.left, FieldRef)
            and condition.left.full in names
            and isinstance(condition.right, Literal)
        ):
            return node
    return None


def _render_correlation(
    rule: Rule, correlation: Correlation | None, aggregate: Aggregate | None
) -> list[str]:
    """The `correlation:` block.

    The rule reference comes from `metadata["sigma.correlation"]` rather than
    from `Correlation.parent`, because lowering had to rewrite the parent to a
    local stage id -- the name Sigma used points into a rule collection that is
    not part of this rule.
    """
    stored: dict[str, Any] = {}
    raw = rule.metadata.get("sigma.correlation")
    if raw:
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                stored = loaded
        except json.JSONDecodeError:
            stored = {}

    lines = ["correlation:"]
    if correlation is not None:
        lines.append("    type: event_count")
        rules = _text_list(stored.get("rules")) or (correlation.parent,)
        lines.append("    rules:")
        lines.extend(f"        - {_quote(name)}" for name in rules)
        lines.append("    group-by:")
        lines.extend(
            f"        - {_quote(key.full)}" for key in correlation.group_by
        )
        lines.append(f"    timespan: {_render_timespan(correlation.timeframe)}")
        lines.append("    condition:")
        lines.append(f"        gte: {correlation.frequency}")
        return lines

    assert aggregate is not None  # one of the two, by the caller's check
    measure = aggregate.measures[0]

    # `count()` is Sigma's `event_count`: the number of matching events. Only
    # `dcount` is a `value_count`, which needs the column it counts distinct
    # values of. Refusing `count()` here meant the single most common threshold
    # shape -- `summarize FailedCount = count() by Account | where
    # FailedCount >= 10` -- could not be written to Sigma at all.
    if measure.function == "count" and measure.field is None:
        kind = "event_count"
    elif measure.function == "dcount" and measure.field is not None:
        kind = "value_count"
    else:
        raise Refusal(
            "SIGMA_RENDER_AGGREGATE",
            f"`{measure.function}` is not a Sigma correlation. Sigma counts "
            f"events (`event_count`) or distinct values (`value_count`); "
            f"anything else has no `correlation:` syntax, and writing one would "
            f"produce a rule no backend understands.",
            "render",
        )

    # Found by SHAPE, not by `id == "threshold"`. A KQL or SPL threshold is
    # whatever filter compares the measure's own alias, so hardcoding the id
    # refused every alias but `count` with a message about Sigma correlations
    # that said nothing about the real problem.
    threshold = _threshold_filter(rule, aggregate)
    if threshold is None or not isinstance(threshold.condition, Comparison):
        raise Refusal(
            "SIGMA_RENDER_AGGREGATE",
            f"`{measure.name}` is aggregated but never compared to a constant, "
            f"so there is no threshold to fire on. A Sigma correlation is a "
            f"count and the condition that count has to meet.",
            "render",
        )
    operator = {v: k for k, v in _CONDITION_OPS.items()}.get(
        threshold.condition.op
    )
    if operator is None:
        raise Refusal(
            "SIGMA_RENDER_AGGREGATE",
            f"`{threshold.condition.op}` is not a Sigma correlation comparison.",
            "render",
        )
    if aggregate.window is None or aggregate.window.size is None:
        raise Refusal(
            "SIGMA_RENDER_AGGREGATE",
            f"`{measure.name}` is a threshold with no time window, so the count "
            f"has no `timespan` and Sigma would read it as all of history.",
            "render",
        )
    rules = _text_list(stored.get("rules")) or ("detection",)
    lines.append(f"    type: {kind}")
    lines.append("    rules:")
    lines.extend(f"        - {_quote(name)}" for name in rules)
    lines.append("    group-by:")
    lines.extend(f"        - {_quote(key.full)}" for key in aggregate.keys)
    if kind == "value_count":
        lines.append(f"    field: {_quote(measure.field.full)}")
    lines.append(f"    timespan: {_render_timespan(aggregate.window.size)}")
    lines.append("    condition:")
    right = threshold.condition.right
    value = right.value if isinstance(right, Literal) else right
    # A STRICT `>` is written as `gte: N+1`. Sigma's correlation frequency is a
    # minimum and its own parser accepts only `gte`, so emitting `gt: N` here
    # produced text the Sigma reader refused -- for integer event counts the two
    # are identical, so this is exact rather than approximate.
    if operator == "gt" and isinstance(value, Decimal):
        operator, value = "gte", value + 1
    lines.append(f"        {operator}: {_quote(value)}")
    return lines
    return lines


def _render_timespan(timeframe: Duration) -> str:
    """Seconds back to Sigma's compact span form."""
    seconds = int(timeframe.seconds)
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds and seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def _restore_tags(meta: dict[str, str], annotations: Annotations) -> list[str]:
    """The original tag list when there is one, else rebuilt from ATT&CK.

    Preferring the stored list is what makes a round trip exact: it keeps
    non-ATT&CK tags (`cve.2021-44228`, an organisation's own taxonomy) that
    `Annotations` has nowhere to put.
    """
    stored = meta.get("sigma.tags")
    if stored:
        try:
            return list(json.loads(stored))
        except json.JSONDecodeError:
            pass
    rebuilt: list[str] = []
    for tactic, techniques in annotations.mitre_attack:
        if tactic:
            rebuilt.append(f"attack.{tactic.replace('-', '_')}")
        rebuilt.extend(f"attack.{t.lower()}" for t in techniques)
    return rebuilt


def _restore_logsource(meta: dict[str, str], rule: Rule) -> dict[str, Any]:
    stored = meta.get("sigma.logsource")
    if stored:
        try:
            loaded = json.loads(stored)
            if isinstance(loaded, dict) and loaded:
                return loaded
        except json.JSONDecodeError:
            pass
    read = next((n for n in rule.pipeline if isinstance(n, Read)), None)
    if read is None:
        raise Refusal(
            "SIGMA_RENDER_NO_LOGSOURCE",
            "this rule has no source stage, so there is no log source to write. "
            "A Sigma rule without one does not say what it runs against.",
            "render",
        )
    # The selector is a RAW DIALECT EXPRESSION, so it is only Sigma's when the
    # rule came from Sigma. Parsing an SPL selector here turned `index=main`
    # into a logsource key called `index`, which Sigma has no such field for and
    # no backend would map. For a rule from elsewhere, the table is the only
    # thing that honestly transfers.
    if meta.get("dialect") == DIALECT and read.selector.strip():
        out: dict[str, Any] = {}
        for part in read.selector.split(","):
            key, found, value = part.partition("=")
            if found and key.strip():
                out[key.strip()] = value.strip()
        if out:
            return out
    return {"category": read.table or "unknown"}
