"""Splunk SPL -> parsed pipeline.

Built against Splunk's own documentation for the constructs that constrain the
lowering, because the interesting SPL rules are the ones where the *plumbing*
carries the detection.

THE FIVE FACTS THAT SHAPE EVERYTHING HERE (Splunk SearchReference, 8.2/9.x)

1. `tstats` is a REPORT-generating command over tsidx, reading INDEX-TIME fields
   from an accelerated data model or a namespace. It does not read raw events.
   A `tstats` rule therefore cannot be evaluated against a sample of events at
   all -- there is no honest way to simulate indexed-field statistics over raw
   payloads -- so it is DECLARED and refused locally by name, never approximated
   as `stats`. Same treatment as YARA-L's PCRE.

2. A tstats `WHERE` clause must contain INDEXED field-value pairs. A predicate
   over an unindexed extracted field is not a filter tstats can honour, so
   lowering it as one would produce counts the agent never computes.

3. `BY _time` REQUIRES `span=`, or every event collapses into one bucket.

4. tstats has a FIXED function list. There is no `dc()` in tstats -- that is the
   `stats` alias, and the tstats spelling is `distinct_count`. Accepting `dc` as
   tstats-executable would be a false claim about what the agent runs.

5. No wildcards in a tstats BY clause or in a function's field name.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..engine.ir import Refusal

DIALECT = "splunk"
LANGUAGE = "SPL"

#: Commands that filter rows. `search` uses search-language syntax; `where` uses
#: an eval expression. They are NOT interchangeable and collapsing them would
#: change what a rule matches.
ROW_FILTERING = frozenset({"search", "where", "regex", "rex", "lookup",
                           "inputlookup", "dedup", "sort", "head", "rename",
                           "eval", "fillnull", "transaction", "fields",
                           "table", "format", "makeresults", "spath",
                           "eventstats", "streamstats", "collector", "transaction"})

#: Commands that AGGREGATE. `stats` over raw events, `tstats` over tsidx.
AGGREGATING = frozenset({"stats", "tstats", "eventstats", "streamstats",
                         "timechart"})

#: `tstats` may only use these. Deliberately does NOT include `dc` -- see fact 4.
TSTATS_FUNCTIONS = frozenset({
    "avg", "count", "distinct_count", "estdc", "max", "median", "min", "mode",
    "range", "stdev", "stdevp", "sum", "sumsq", "var", "varp", "first", "last",
    "values", "earliest", "earliest_time", "latest", "latest_time", "rate",
    "perc", "exactperc", "upperperc",
})

#: `stats` may additionally use. `dc` and `c` are the `stats` spellings.
STATS_ONLY_FUNCTIONS = frozenset({"dc", "c"})

#: The `stats`/`tstats` function -> IR Measure.function mapping. Only where the
#: names coincide; everything else is refused by name rather than guessed.
MEASURE_FUNCTIONS = {
    "count": "count",
    "c": "count",
    "dc": "distinct_count",
    "distinct_count": "distinct_count",
    "estdc": "distinct_count",
    "avg": "avg",
    "min": "min",
    "max": "max",
    "sum": "sum",
    "values": "set",
    "list": "set",
    "first": "first",
    "last": "last",
}

#: Search-language term operators. `IN` is a value-list, handled separately.
#: `=` and `==` BOTH mean equality in Splunk -- a dict cannot hold them as
#: separate keys, and the IR uses `=` for equality, so they collapse here.
_TERM_OPERATORS = {
    "=": "=", "==": "=", "!=": "!=", "<": "<", "<=": "<=", ">": ">", ">=": ">=",
}


class SplParseError(Refusal):
    pass


@dataclass(frozen=True, slots=True)
class SplTerm:
    """One `field op value` term, or a bare `field`, or a NOT, or a list."""

    field: str | None = None
    op: str | None = None
    value: Any = None
    negate: bool = False
    children: tuple[Any, ...] = ()
    #: `IN`/`NOT IN` value list.
    values: tuple[Any, ...] = ()


@dataclass(frozen=True, slots=True)
class SplMeasure:
    function: str
    field: str | None
    alias: str | None
    #: True when the function was spelled `PREFIX(x)`, which tstats treats as an
    #: aggregated raw segment rather than a field.
    prefix: bool = False


@dataclass(frozen=True, slots=True)
class SplStats:
    measures: tuple[SplMeasure, ...]
    keys: tuple[str, ...] = ()
    span: str | None = None
    #: `FROM` clause: namespace, `datamodel=X.Y`, or `sid=`.
    from_clause: str | None = None
    #: WHERE terms, which tstats requires to be indexed.
    where: tuple[Any, ...] = ()
    prestats: bool = False


@dataclass(frozen=True, slots=True)
class SplCommand:
    name: str
    args: str = ""
    #: The leading `search` of a bare search line, e.g. `index=main foo=bar`.
    bare_search: str = ""


@dataclass(slots=True)
class SplSearch:
    """A whole search: leading search terms, then a pipeline."""

    terms: tuple[Any, ...] = ()
    pipeline: list[SplCommand] = field(default_factory=list)
    text: str = ""

    @property
    def indexes(self) -> tuple[str, ...]:
        return tuple(t.value for t in walk_terms(self.terms)
                     if t.field == "index" and t.op == "=")

    @property
    def sourcetypes(self) -> tuple[str, ...]:
        return tuple(t.value for t in walk_terms(self.terms)
                     if t.field == "sourcetype" and t.op == "=")


def walk_terms(tree: tuple[Any, ...],
               keep_structure: bool = False) -> list[Any]:
    """The terms in a parsed tree.

    `keep_structure=False` returns every SplTerm at any depth -- for callers that
    genuinely want a flat list of leaves.

    `keep_structure=True` returns the TREE, preserving the `("and", ...)` /
    `("or", ...)` / `("not", ...)` nodes. That flag exists because the flat form
    DESTROYS the operator: the SPL lowering consumed leaves and rejoined them
    with "and", so `a="1" OR b="2"` became `a="1" AND b="2"` -- an inverted
    detection rather than a missing one. Nothing in the parser can recover the
    operator once the tree is flattened, so the tree is now carried whole.
    """
    if keep_structure:
        return list(tree)
    found: list[SplTerm] = []

    def visit(node: Any) -> None:
        if isinstance(node, SplTerm):
            found.append(node)
            return
        if isinstance(node, (tuple, list)):
            if node and node[0] in ("and", "or", "not"):
                for child in node[1:]:
                    visit(child)
                return
            for child in node:
                visit(child)

    for node in tree:
        visit(node)
    return found


def parse_spl(text: str) -> SplSearch:
    """Parse an SPL search into a leading term set and a command pipeline."""
    body = text.strip()
    if not body:
        raise SplParseError("SPL_EMPTY", "there is no search to parse", DIALECT)

    head, _, rest = _split_first_pipe(body)
    terms = parse_search_terms(head) if head.strip() else ()
    pipeline = [c for c in (parse_command(chunk) for chunk in _split_pipes(rest))
                if c is not None]
    return SplSearch(terms=terms, pipeline=pipeline, text=body)


def _split_first_pipe(text: str) -> tuple[str, str, str]:
    depth = 0
    in_quote = False
    for index, char in enumerate(text):
        if char == '"':
            in_quote = not in_quote
        elif not in_quote and char == "(":
            depth += 1
        elif not in_quote and char == ")":
            depth -= 1
        elif char == "|" and depth == 0 and not in_quote:
            return text[:index], "|", text[index + 1:]
    return text, "", ""


def _split_pipes(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    in_quote = False
    for char in text:
        if char == '"':
            in_quote = not in_quote
        elif not in_quote and char == "(":
            depth += 1
        elif not in_quote and char == ")":
            depth -= 1
        if char == "|" and depth == 0 and not in_quote:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    if current:
        parts.append("".join(current))
    return [p for p in (part.strip() for part in parts) if p]


def parse_command(chunk: str) -> SplCommand | None:
    text = chunk.strip()
    if not text:
        return None
    head, _, args = text.partition(" ")
    name = head.strip().lower()
    if not name:
        return None
    return SplCommand(name=name, args=args.strip())


# ---------------------------------------------------------------------------
# Search-language terms
# ---------------------------------------------------------------------------

_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")

#: Characters that begin a comparison operator, and therefore also end a field
#: name. An earlier version split only on whitespace and parentheses, so
#: `index=windows` arrived as ONE token and every leading search term was
#: refused -- the parser could not read a single real Splunk search.
_OPERATOR_CHARS = frozenset("=!<>")
_DELIMITERS = frozenset("()") | _OPERATOR_CHARS


def parse_search_terms(text: str) -> tuple[Any, ...]:
    """Parse a search expression into a term tree.

    Handles `OR` at the top level, `NOT`, parentheses, and `field op value`.
    Everything it cannot parse is refused by name, because a silently dropped
    term is a rule that matches more than the analyst wrote.
    """
    tokens = _tokenise_search(text)
    if not tokens:
        return ()
    parser = _TermParser(tokens)
    result = parser.parse_or()
    if parser.position < len(parser.tokens):
        raise SplParseError(
            "SPL_TERM_UNPARSED",
            f"could not parse {parser.tokens[parser.position]!r} in the search "
            f"terms. An unparsed term is a term that would be silently dropped, "
            f"which makes the rule match more than it says.", DIALECT)
    return (result,)


def _tokenise_search(text: str) -> list[str]:
    """Split search text into field names, operators, values, parens and keywords.

    Quoted regions are never split, so a value containing `=` or a space survives
    intact. Multi-character operators (`!=`, `<=`, `>=`, `==`) stay together,
    because splitting `<=` into `<` and `=` would compare a field to nothing.
    """
    tokens: list[str] = []
    current: list[str] = []
    in_quote = False

    def flush() -> None:
        if current:
            tokens.append("".join(current).strip())
            current.clear()

    index = 0
    length = len(text)
    while index < length:
        char = text[index]

        if char == '"':
            in_quote = not in_quote
            current.append(char)
            index += 1
            continue

        if in_quote:
            current.append(char)
            index += 1
            continue

        if char in _OPERATOR_CHARS:
            flush()
            operator = char
            index += 1
            while index < length and text[index] in _OPERATOR_CHARS:
                operator += text[index]
                index += 1
            tokens.append(operator)
            continue

        if char.isspace() or char in "()":
            flush()
            if char in "()":
                tokens.append(char)
            index += 1
            continue

        current.append(char)
        index += 1

    flush()
    return [t for t in tokens if t]


class _TermParser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.position = 0

    def peek(self) -> str | None:
        return (self.tokens[self.position]
                if self.position < len(self.tokens) else None)

    def next(self) -> str | None:
        token = self.peek()
        if token is not None:
            self.position += 1
        return token

    def parse_or(self) -> Any:
        parts = [self.parse_and()]
        while (self.peek() or "").upper() == "OR":
            self.next()
            parts.append(self.parse_and())
        return parts[0] if len(parts) == 1 else ("or", tuple(parts))

    def parse_and(self) -> Any:
        parts = [self.parse_atom()]
        while True:
            token = self.peek()
            if token is None or token in (")",) or token.upper() in ("OR", "AND"):
                break
            parts.append(self.parse_atom())
        return parts[0] if len(parts) == 1 else ("and", tuple(parts))

    def parse_atom(self) -> Any:
        token = self.next()
        if token is None:
            raise SplParseError("SPL_TERM_TRUNCATED",
                                "the search terms end mid-expression", DIALECT)
        if token == "(":
            inner = self.parse_or()
            if self.next() != ")":
                raise SplParseError("SPL_TERM_UNCLOSED",
                                    "a parenthesised term is never closed", DIALECT)
            return inner
        if token.upper() == "NOT":
            inner = self.parse_atom()
            if isinstance(inner, SplTerm):
                return SplTerm(field=inner.field, op=inner.op, value=inner.value,
                               negate=not inner.negate, children=inner.children,
                               values=inner.values)
            return ("not", (inner,))

        following = self.peek()
        if following is not None:
            upper = following.upper()
            if upper in ("IN", "NOT"):
                if upper == "NOT" and (self.tokens[self.position + 1:self.position + 2]
                                       or [""])[0].upper() == "IN":
                    self.next()
                    self.next()
                    return self._parse_in(token, negate=True)
                if upper == "IN":
                    self.next()
                    return self._parse_in(token, negate=False)
            if following in _TERM_OPERATORS:
                self.next()
                value_token = self.next()
                if value_token is None:
                    raise SplParseError(
                        "SPL_TERM_OPERATOR_WITHOUT_VALUE",
                        f"{token} {following} has no value", DIALECT)
                return SplTerm(field=token, op=_TERM_OPERATORS[following],
                               value=_unquote(value_token))

        if not _FIELD.match(token):
            raise SplParseError(
                "SPL_BARE_TERM_NOT_A_FIELD",
                f"{token!r} is neither a field nor a field/value pair. A bare "
                f"word in a search means 'the raw event contains this string', "
                f"which is a different test from a field comparison.", DIALECT)
        return SplTerm(field=token)

    def _parse_in(self, name: str, negate: bool) -> Any:
        if self.next() != "(":
            raise SplParseError(
                "SPL_IN_WITHOUT_LIST", f"{name} IN must be followed by a value "
                f"list in parentheses", DIALECT)
        options: list[str] = []
        while True:
            token = self.next()
            if token is None:
                raise SplParseError("SPL_IN_UNCLOSED",
                                    "an IN value list is never closed", DIALECT)
            if token == ")":
                break
            # The tokeniser splits on parens and operators but NOT on commas, so
            # every value except the last arrives with its separator attached:
            # `IN ("a.exe", "b.exe")` yielded ('"a.exe",', 'b.exe'), and the
            # first option then matched nothing at all.
            for piece in (p.strip() for p in token.split(",")):
                if piece:
                    options.append(_unquote(piece))
        return SplTerm(field=name, op="in", values=tuple(options), negate=negate)


def _unquote(token: str) -> Any:
    text = token.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


# ---------------------------------------------------------------------------
# stats / tstats
# ---------------------------------------------------------------------------

def parse_stats(args: str, command: str) -> SplStats:
    """Parse `stats`/`tstats`/`eventstats` arguments."""
    text = args.strip()
    prestats = False
    if text.startswith("prestats=t") or text.startswith("prestats=true"):
        prestats = True
        _, _, text = text.partition(" ")
        text = text.strip()

    measures, rest = _split_measures(text, command)
    if not measures:
        raise SplParseError(
            "SPL_STATS_NO_MEASURES",
            f"{command} has no aggregate function. {command} computes statistics, "
            f"so it needs at least one of count, dc, values, avg and the rest.",
            DIALECT)

    from_clause = None
    where_terms: tuple[Any, ...] = ()
    keys: tuple[str, ...] = ()
    span: str | None = None

    remainder = rest
    match = re.search(r"\bFROM\b", remainder, re.IGNORECASE)
    if match:
        # FROM ends at WHERE or BY, whichever comes FIRST. An earlier version cut
        # it only at BY, so `... FROM datamodel=X.Y WHERE index=main BY host`
        # captured the whole WHERE clause as part of the datamodel name and the
        # WHERE terms were never parsed at all.
        tail = remainder[match.end():]
        stop = len(tail)
        for keyword in (re.search(r"\bWHERE\b", tail, re.IGNORECASE),
                        re.search(r"\bBY\b", tail, re.IGNORECASE)):
            if keyword is not None and keyword.start() < stop:
                stop = keyword.start()
        from_clause = tail[:stop].strip()
        remainder = remainder[:match.start()] + tail[stop:]

    match = re.search(r"\bWHERE\b", remainder, re.IGNORECASE)
    if match:
        tail = remainder[match.end():]
        by_match = re.search(r"\bBY\b", tail, re.IGNORECASE)
        where_text = tail[:by_match.start()] if by_match else tail
        remainder = (remainder[:match.start()]
                     + (tail[by_match.start():] if by_match else ""))
        if where_text.strip():
            where_terms = parse_search_terms(where_text)

    by_match = re.search(r"\bBY\b", remainder, re.IGNORECASE)
    if by_match:
        by_text = remainder[by_match.end():]
        span_match = re.search(r"\bspan\s*=\s*(\S+)", by_text, re.IGNORECASE)
        if span_match:
            span = span_match.group(1).strip('"')
            by_text = (by_text[:span_match.start()]
                       + by_text[span_match.end():])
        # SPL SEPARATES BY FIELDS WITH COMMAS *OR* WHITESPACE. Splitting on
        # commas alone turned `by host user` into the single key "host user",
        # which is a field that does not exist.
        keys = tuple(k for k in re.split(r"[,\s]+", by_text.strip()) if k)

    return SplStats(measures=measures, keys=keys, span=span,
                    from_clause=from_clause, where=where_terms, prestats=prestats)


def _split_measures(text: str, command: str) -> tuple[tuple[SplMeasure, ...], str]:
    measures: list[SplMeasure] = []
    index = 0
    length = len(text)

    # A BARE `count`/`c` HAS NO PARENTHESES, and it can appear ANYWHERE among the
    # measures -- not only at the front. `stats values(user) as u count as c by
    # host` used to keep only `u`, because the scan looked for `name(` and gave
    # up at the bare `count`. Losing a threshold makes the rule match MORE than
    # the analyst wrote, so the loop now handles a bare count wherever it appears
    # and refuses anything else it cannot read.

    while index < length:
        rest = text[index:]
        if not rest.strip():
            break
        if re.match(r"\s*(by|where|from)\b", rest, re.IGNORECASE):
            break

        bare_first = re.match(r"\s*(count|c)\b(?!\s*\()", rest, re.IGNORECASE)
        if bare_first:
            name = bare_first.group(1).lower()
            after = rest[bare_first.end():]
            alias_match = re.match(r"\s+AS\s+([A-Za-z_][A-Za-z0-9_]*)", after,
                                   re.IGNORECASE)
            _check_function(name, command)
            measures.append(SplMeasure(
                function=name, field=None,
                alias=alias_match.group(1) if alias_match else None))
            index += bare_first.end() + (alias_match.end() if alias_match else 0)
            continue

        match = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(").search(text, index)
        if not match:
            leftover = text[index:].strip()
            if not leftover or re.match(r"(by|where|from)\b", leftover,
                                        re.IGNORECASE):
                break
            raise SplParseError(
                "SPL_STATS_MEASURE_UNPARSED",
                f"could not read {leftover!r} as a measure. Dropping it would "
                f"remove a threshold from the rule and make it match more than "
                f"you wrote, so it is named instead.", DIALECT)
        name = match.group(1).lower()
        open_at = match.end() - 1
        close_at = _matching_paren(text, open_at)
        if close_at < 0:
            raise SplParseError(
                "SPL_STATS_UNCLOSED_FUNCTION",
                f"{name}( is never closed", DIALECT)
        inner = text[open_at + 1:close_at].strip()
        alias = None
        after = text[close_at + 1:]
        alias_match = re.match(r"\s+AS\s+([A-Za-z_][A-Za-z0-9_]*)", after,
                               re.IGNORECASE)
        if alias_match:
            alias = alias_match.group(1)
            index = close_at + 1 + alias_match.end()
        else:
            index = close_at + 1

        _check_function(name, command)

        target: str | None = None
        prefix = False
        if inner:
            prefix_match = re.match(r"^PREFIX\s*\(\s*(.+?)\s*\)$", inner,
                                    re.IGNORECASE)
            if prefix_match:
                prefix = True
                target = prefix_match.group(1).strip()
            else:
                target = inner.strip().strip('"')
                if not _FIELD.match(target):
                    raise SplParseError(
                        "SPL_STATS_FIELD_NOT_A_FIELD",
                        f"{name}({inner}) -- {inner!r} is not a field name, and "
                        f"these commands cannot aggregate a computed value", DIALECT)

        if name in ("count", "c") and not target and not prefix:
            target = None
        measures.append(SplMeasure(function=name, field=target, alias=alias,
                                   prefix=prefix))

    return tuple(measures), text[index:].strip()


def _matching_paren(text: str, open_at: int) -> int:
    depth = 0
    in_quote = False
    for index in range(open_at, len(text)):
        char = text[index]
        if char == '"':
            in_quote = not in_quote
        elif not in_quote and char == "(":
            depth += 1
        elif not in_quote and char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _check_function(name: str, command: str) -> None:
    """Refuse a function the command does not have, BY NAME.

    The important case is `dc` under `tstats`. Splunk's tstats function list does
    not include `dc`; the tstats spelling is `distinct_count`. Accepting `dc`
    would mean claiming the agent runs something it does not.
    """
    if command == "tstats":
        if name in STATS_ONLY_FUNCTIONS:
            raise SplParseError(
                "SPL_TSTATS_FUNCTION_NOT_SUPPORTED",
                f"`{name}` is a stats function, not a tstats function. tstats "
                f"spells it `distinct_count`. Accepting `{name}` here would claim "
                f"the agent runs a function tstats does not have.", DIALECT)
        if name not in TSTATS_FUNCTIONS:
            raise SplParseError(
                "SPL_TSTATS_FUNCTION_UNKNOWN",
                f"`{name}` is not in tstats's function list "
                f"({', '.join(sorted(TSTATS_FUNCTIONS))})", DIALECT)
        return
    if name not in TSTATS_FUNCTIONS and name not in STATS_ONLY_FUNCTIONS:
        raise SplParseError(
            "SPL_STATS_FUNCTION_UNKNOWN",
            f"`{name}` is not a {command} aggregate function this lowering "
            f"knows. Guessing a substitute would change the numbers the rule "
            f"reports.", DIALECT)
