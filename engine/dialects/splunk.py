"""Splunk SPL: a pipeline language, like KQL, with three traps KQL does not have.

`kql.py` is the model this module follows -- a `DialectSpec`, a `parse_*` that
SPLITS the pipeline, a stage dispatcher, and a renderer whose dispatch ends in
refusals. Where SPL differs, it differs in ways that are silent when got wrong.

**Implicit AND.** `index=main EventCode=4624 user=svc` is three predicates ANDed,
with nothing written between them. The shared parser cannot see that: after
reading `EventCode=4624` it looks for an infix operator, finds the identifier
`user`, and stops -- leaving the rest of the search SILENTLY UNREAD. That is the
exact failure `common.py`'s docstring warns about, and it produces a rule that
runs, reports success, and matches far more events than it says. So the search
grammar is normalised first: adjacent terms get an explicit `AND` inserted, and
only then does it go through the shared parser, where `and`/`or`/`not`
precedence comes from the same table every other dialect uses.

**Case matters in a search.** `AND`, `OR` and `NOT` are operators only in
uppercase. Lowercase `and` is a search TERM -- Splunk looks for the literal word.
Folding the two together would turn a search for the word "and" into a boolean,
so the normaliser treats only the uppercase forms as operators.

**`search` and `where` are different grammars.** `| search status=200` is
search-term syntax; `| where status=200` is eval syntax, where Splunk itself
rejects a single `=`. They are not interchangeable, so they are lowered by
different functions rather than by one that squints at both.

Two honest limits, stated here because they are the kind of thing that looks like
a bug:

`index=`, `sourcetype=` and friends go into `Read.selector` VERBATIM and are
never evaluated locally. They are index-time filters, resolved by the indexer
before any event exists, so treating them as row predicates would let a local
run claim a match it cannot produce. `pipeline.py` emits an `INDEX_TIME_FILTER`
caveat, which also means a non-match on an SPL rule is reported as
`not_evaluated` rather than as a confident `no_match`.

SPL regex is PCRE, so `Regex.dialect` is `pcre`, and `evaluate.py` REFUSES to
execute PCRE locally rather than running it with Python's `re` and calling the
result Splunk. A pattern-matching SPL rule therefore lowers and renders
correctly and cannot be test-run here. That is the intended behaviour: the
alternative is a false claim about a security control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from decimal import Decimal, InvalidOperation
from typing import Any, Final

from ..ir import (
    Aggregate,
    Annotations,
    Binding,
    BoolOp,
    Call,
    Comparison,
    Derive,
    Distinct,
    Emit,
    Expand,
    Expr,
    FieldRef,
    Filter,
    Join,
    Limit,
    ListExpr,
    Literal,
    Measure,
    Node,
    Not,
    Project,
    Read,
    Regex,
    Rule,
    Sort,
    Window,
    render_expr,
)
from ..validate import validate
from ..values import Capability, Duration, Refusal, duration_seconds
from .common import (
    plain_number,
    is_bare_identifier,
    C_LIKE_PRECEDENCE,
    DialectSpec,
    Diagnostic,
    Parser,
    split_top_level,
    strip_comments,
    tokenize,
)

__all__ = [
    "DIALECT",
    "LANGUAGE",
    "SPEC",
    "ParsedSpl",
    "ParsedStage",
    "INDEX_TIME_FIELDS",
    "AGGREGATES",
    "UNSUPPORTED_COMMANDS",
    "parse_splunk",
    "lower_splunk",
    "render_splunk",
]

DIALECT: Final = "splunk"
LANGUAGE: Final = "SPL"


# ---------------------------------------------------------------------------
# Spec
# ---------------------------------------------------------------------------

#: SPL regex is PCRE. Modelled honestly, which means `evaluate.py` refuses to
#: run it: there is no PCRE engine here, and using Python's `re` and calling the
#: answer Splunk would be a false claim about a detection.
#:
#: TWO specs, because SPL has two grammars with DIFFERENT PRECEDENCE, and this is
#: the single most dangerous thing about the language.
#:
#: Splunk's documented evaluation order for the SEARCH language is: parentheses,
#: then NOT, then OR, then AND. OR binds TIGHTER than AND -- the opposite of
#: every C-like language and of this engine's shared default. So
#: `a=1 OR b=2 c=3` means `(a=1 OR b=2) AND c=3` in a search, and
#: `a=1 OR (b=2 AND c=3)` under the usual precedence. Those select different
#: events, nothing warns, and the rule reads identically either way.
#:
#: The eval language used by `| where` follows the ordinary order, where AND
#: binds tighter. One table for both would therefore be wrong for one of them.
_SEARCH_PRECEDENCE: Final[dict[str, int]] = dict(C_LIKE_PRECEDENCE)
_SEARCH_PRECEDENCE["or"] = 22
_SEARCH_PRECEDENCE["and"] = 12

_COMMON_OPERATORS: Final[dict[str, str]] = {
    "=": "==", "==": "==",
    "!=": "!=", "<>": "!=",
    "<": "<", "<=": "<=", ">": ">", ">=": ">=",
    "and": "and", "or": "or",
    "in": "in", "like": "like",
}

#: Words that are keywords rather than field names. Every one of these that is a
#: FUNCTION must also appear in `functions`, or the shared parser routes it to
#: `parse_keyword_atom` and the call is read as a bare identifier -- which is how
#: `cidrmatch("10.0.0.0/8", ip)` silently became a field named `cidrmatch`.
_KEYWORDS: Final[frozenset[str]] = frozenset({
    "and", "or", "not", "in", "like", "by", "as", "span",
    "true", "false", "null",
    "if", "case", "coalesce", "cidrmatch", "match", "len", "lower", "upper",
    "substr", "tostring", "tonumber", "round", "abs", "min", "max",
    "mvcount", "strftime", "now", "relative_time", "isnull", "isnotnull",
})

_FUNCTIONS: Final[dict[str, str]] = {
    "if": "iff", "case": "case", "coalesce": "coalesce",
    "len": "strlen", "lower": "lower", "upper": "upper",
    "substr": "substring", "tostring": "to_string",
    "tonumber": "to_int", "round": "round", "abs": "abs",
    "min": "min", "max": "max", "now": "now",
    "strftime": "strftime", "isnull": "is_null",
    "isnotnull": "is_not_null", "match": "matches_regex",
    "mvcount": "length",
    # The one that matters most. Splunk writes `cidrmatch(network, address)`
    # and this engine's function takes the address first; the swap happens in
    # `_fix_argument_orders`, but it cannot happen at all unless the call is
    # parsed as a CALL, which needs the name here as well as in `keywords`.
    "cidrmatch": "cidr_contains",
    "relative_time": "relative_time",
    # `like` is an eval FUNCTION in SPL, not an infix operator, and
    # `render_splunk` writes substring tests in that form. Without the name
    # here the call never parsed as a call: `like(` failed, and the rest of
    # the condition went unread -- so the renderer emitted valid SPL that its
    # own parser refused with "`AND` is a reserved word". `_fold_eval_predicates`
    # turns it back into the comparison it means.
    "like": "like",
}

#: The search language: OR binds tighter than AND.
SEARCH_SPEC: Final = DialectSpec(
    key=DIALECT,
    language=LANGUAGE,
    precedence=_SEARCH_PRECEDENCE,
    operators=dict(_COMMON_OPERATORS),
    keywords=_KEYWORDS,
    functions=dict(_FUNCTIONS),
    default_regex_dialect="pcre",
)

#: The eval language used by `| where`: the ordinary precedence.
SPEC: Final = DialectSpec(
    key=DIALECT,
    language=LANGUAGE,
    precedence=dict(C_LIKE_PRECEDENCE),
    operators=dict(_COMMON_OPERATORS),
    keywords=_KEYWORDS,
    functions=dict(_FUNCTIONS),
    default_regex_dialect="pcre",
)

#: Resolved by the indexer before any event exists, so they belong in
#: `Read.selector` and are never evaluated locally.
#:
#: `host` is deliberately NOT here. It is an indexed field, but it is also
#: genuinely present on every event, so a pasted sample can carry it and a local
#: run can honestly decide it. Putting it in the selector would quietly stop a
#: per-host rule from being testable.
INDEX_TIME_FIELDS: Final[frozenset[str]] = frozenset({
    "index", "sourcetype", "source", "eventtype", "tag", "splunk_server",
    "splunk_server_group", "_index_earliest", "_index_latest",
})

#: SPL aggregate -> (engine function, distinct).
AGGREGATES: Final[dict[str, tuple[str, bool]]] = {
    "count": ("count", False),
    "c": ("count", False),
    "dc": ("dcount", True),
    "distinct_count": ("dcount", True),
    "estdc": ("dcount", True),
    "values": ("make_set", True),
    "list": ("make_list", False),
    "sum": ("sum", False),
    "avg": ("avg", False),
    "mean": ("avg", False),
    "min": ("min", False),
    "max": ("max", False),
    "stdev": ("stdev", False),
    "earliest": ("earliest", False),
    "latest": ("latest", False),
    "first": ("earliest", False),
    "last": ("latest", False),
}

#: Refused by name, each with the reason. A partial implementation of any of
#: these returns confidently wrong results, which is worse than a refusal.
#: Commands that GENERATE rows instead of filtering them.
#:
#: A search beginning `| tstats ...` starts with one of these, so the leading
#: pipe leaves the first token where an index search is expected and it was
#: refused as `SPL_BARE_SEARCH_TERM` -- telling the analyst that `tstats` is
#: "a full-text match across every field of the event". It is not; it is a
#: command, and the message sent them hunting for a quoting problem that was
#: never there. `tstats` is in a large share of real Splunk detections, so
#: this was the first thing many rules hit.
#:
#: Each reason says what the command actually reads, because every one of them
#: reads something other than events -- which is why there is nothing here to
#: evaluate a sample against.
GENERATING_COMMANDS: Final[dict[str, str]] = {
    "tstats": "it reads an ACCELERATED SUMMARY or a data model, not events. "
              "The rows it returns are pre-aggregated counts whose source "
              "events no longer exist as rows, so there is nothing for a "
              "sample of events to be tested against",
    "mstats": "it reads a metrics index, where a point is a name, a timestamp "
              "and a number. A detection over metrics is a different kind of "
              "rule from a detection over events, and this model expresses "
              "the second",
    "datamodel": "it reads a data model's constraints rather than an index, "
                 "so the fields it returns are defined on the search head and "
                 "cannot be resolved from a sample",
    "from": "it reads a named dataset, data model or saved search. What it "
            "returns depends on a definition stored in Splunk, not on "
            "anything in the rule text",
    "metadata": "it reports on the INDEX -- which sourcetypes and hosts exist "
                "and when they were last seen. That is a statement about the "
                "deployment, not about any event",
    "inputcsv": "it reads a CSV from disk. A rule whose input is a file is "
                "not a detection over a log stream",
    "loadjob": "it reads the results of a previous search job, which no "
               "longer exist by the time a rule is reviewed",
    "savedsearch": "it runs a search stored in Splunk by name. The detection "
                   "is in that saved search, not in this text, so lowering "
                   "this would produce a rule with no condition at all",
    "rest": "it queries Splunk's own management API. There is no event "
            "stream here to detect anything in",
    "dbinspect": "it reports on index buckets, which is a statement about "
                 "storage rather than about events",
    "inputlookup": "it reads a lookup table. There is no table here, so the "
                   "rows would never materialise",
}

UNSUPPORTED_COMMANDS: Final[dict[str, str]] = {
    "eventstats": "it ADDS aggregate columns to every row instead of collapsing "
                  "rows into groups. The IR's Aggregate collapses, so lowering "
                  "it that way would delete the rows the rest of the rule reads.",
    "streamstats": "it computes a running aggregate per row, which needs an "
                   "order-dependent stage the IR does not have. Lowering it as a "
                   "plain Aggregate would compute one number for the whole group "
                   "instead of one per row.",
    "transaction": "it groups events into sessions by a set of start, end and "
                   "duration rules. The IR has a session Window, but it keys on "
                   "a gap alone -- so a transaction's start/end conditions would "
                   "be dropped and the grouping would be wrong.",
    "map": "it runs a search once per input row. That is a loop, not a stage, "
           "and unrolling it would need the rows before the rule is lowered.",
    "foreach": "it expands a template over matching field names, which depends "
               "on the data's schema rather than on the rule.",
    "lookup": "it joins against a CSV or KV store on the search head. There is "
              "no lookup mechanism anywhere in this package, so the enrichment "
              "would silently be missing and every comparison against it would "
              "read as absent.",
    "inputlookup": "see `lookup`: there is no table here to read.",
    "outputlookup": "it WRITES a lookup table. This tool reads rules; it does "
                    "not model side effects.",
    "append": "it concatenates a second search's results. The IR expresses a "
              "second stream as a Binding joined in, not appended, and the two "
              "produce different row counts.",
    "appendcols": "it staples a second search's columns onto these rows "
                  "positionally. Nothing in the IR joins by row position, and "
                  "faking it with a key would invent a relationship.",
    "multisearch": "see `append`.",
    "union": "see `append`.",
    "spath": "it extracts fields from JSON or XML on the search head. Field "
             "extraction is appliance-only here, so the extracted fields would "
             "never resolve.",
    "xmlkv": "see `spath`.",
    "kvform": "see `spath`.",
    "extract": "see `spath`.",
    "makeresults": "it generates synthetic rows. A rule that invents its own "
                   "events is a test fixture, not a detection.",
    "collect": "it writes results to an index. This tool does not model side "
               "effects.",
    "sendemail": "it is an action, not a detection.",
    "fillnull": "it replaces absent fields with a value, which collapses the "
                "difference between absent and present-but-empty. That "
                "distinction is the core of how this engine decides a rule, so "
                "erasing it would make every later comparison lie.",
    "convert": "it rewrites field types in place, which needs a transform stage "
               "the IR does not have.",
    "makemv": "it splits a field into a multivalue field, which is a transform.",
    "nomv": "see `makemv`.",
    "transpose": "it swaps rows and columns, which is a presentation change with "
                 "no predicate meaning.",
}

_SPAN = re.compile(r"^span\s*=\s*(?P<value>\S+)$", re.IGNORECASE)
_AS = re.compile(r"\s+as\s+", re.IGNORECASE)
_BY = re.compile(r"\s+by\s+", re.IGNORECASE)
_AGG_CALL = re.compile(r"^(?P<name>[A-Za-z_][\w]*)\s*\((?P<arg>.*)\)$", re.DOTALL)
_PERCENTILE = re.compile(r"^(?:perc|p)(?P<n>\d{1,2})$", re.IGNORECASE)
_BOOLEANS: Final[frozenset[str]] = frozenset({"AND", "OR", "NOT"})


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ParsedStage:
    operator: str
    body: str


@dataclass(frozen=True, slots=True)
class ParsedSpl:
    """The pipeline, split but not interpreted."""

    search: str = ""
    stages: list[ParsedStage] = dc_field(default_factory=list)
    raw: str = ""


def _split_terms(text: str) -> list[str]:
    """Top-level whitespace-separated terms, respecting quotes and brackets.

    `field="a b"` is ONE term and `(a=1 OR b=2)` is one term, because splitting
    either of them would hand the parser a fragment.
    """
    terms: list[str] = []
    buffer: list[str] = []
    quote = ""
    depth = 0
    for char in text:
        if quote:
            buffer.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "'\"":
            quote = char
            buffer.append(char)
            continue
        if char in "([":
            depth += 1
            buffer.append(char)
            continue
        if char in ")]":
            depth -= 1
            if depth < 0:
                raise Refusal(
                    "SPL_UNBALANCED",
                    f"`{text[:60]}` closes a bracket that was never opened.",
                    "parse",
                )
            buffer.append(char)
            continue
        if char.isspace() and depth == 0:
            if buffer:
                terms.append("".join(buffer))
                buffer = []
            continue
        buffer.append(char)
    if quote:
        raise Refusal(
            "SPL_UNTERMINATED_STRING",
            f"`{text[:60]}` has a quote that is never closed, so where the "
            f"value ends is a guess.",
            "parse",
        )
    if depth:
        raise Refusal(
            "SPL_UNBALANCED",
            f"`{text[:60]}` leaves {depth} bracket(s) open.",
            "parse",
        )
    if buffer:
        terms.append("".join(buffer))
    return terms


def normalise_search(text: str) -> str:
    """Insert the ANDs SPL leaves implicit, so nothing is silently unread.

    Only UPPERCASE `AND`/`OR`/`NOT` count as operators. Lowercase `and` is a
    search term in SPL -- Splunk looks for the literal word -- and treating it
    as a boolean would change what the rule matches.
    """
    terms = _split_terms(text.strip())
    rebuilt: list[str] = []
    index = 0
    while index < len(terms):
        term = terms[index]
        # `field IN (a, b)` is ONE search term in SPL, and the splitter breaks
        # it into three: `field`, `IN`, `(a, b)`. Re-joined here before the
        # implicit-AND pass, so the list reaches the parser as a comparison.
        # Without this, `GrantedAccess IN ("0x1010")` was refused as a bare
        # search term -- a rule real analysts write, refused for an accident
        # of tokenisation.
        if (index + 2 < len(terms)
                and terms[index + 1].upper() == "IN"
                and terms[index + 2].startswith("(")
                and is_bare_identifier(term)):
            rebuilt.append(f"{term} IN {terms[index + 2]}")
            index += 3
            continue
        if term.upper().startswith("NOT(") and term.endswith(")"):
            rebuilt.append("NOT")
            rebuilt.append("(" + normalise_search(term[4:-1]) + ")")
            index += 1
            continue
        if len(term) >= 2 and term[0] == "(" and term[-1] == ")":
            rebuilt.append("(" + normalise_search(term[1:-1]) + ")")
            index += 1
            continue
        rebuilt.append(term)
        index += 1

    out: list[str] = []
    for term in rebuilt:
        if term in _BOOLEANS:
            out.append(term.lower())
            continue
        if out and out[-1] not in ("and", "or", "not"):
            out.append("and")
        out.append(term)
    return " ".join(out)


def _strip_spl_comments(text: str) -> str:
    """Remove SPL's ``` ``` ``` comments, preserving newlines.

    The SHARED `strip_comments` knows `//`, `--` and `/* */`; SPL uses
    triple-backticks and nothing else. So a comment this renderer writes
    itself -- the "source selected in Sigma as ..." note in `_render_stream`
    -- came back through the parser as a bare search term and was refused.
    The renderer was emitting text its own parser rejected.

    Done before the shared pass, and before the macro check, because a
    backtick comment starts with the same character a macro does.
    """
    out: list[str] = []
    index = 0
    in_string = False
    while index < len(text):
        char = text[index]
        if in_string:
            if char == "\\" and index + 1 < len(text):
                out.append(text[index:index + 2])
                index += 2
                continue
            if char == '"':
                in_string = False
            out.append(char)
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if text.startswith("```", index):
            end = text.find("```", index + 3)
            stop = len(text) if end < 0 else end + 3
            # Newlines are kept so a later refusal still names the right line.
            out.append("\n" * text.count("\n", index, stop))
            index = stop
            continue
        out.append(char)
        index += 1
    return "".join(out)


def parse_splunk(text: str) -> ParsedSpl:
    """Split an SPL search into its leading search and its `|` stages.

    A SPLIT, not a parse: what is dialect-specific here is knowing that `|`
    separates stages, that the first segment is the search with no command word,
    and that a `|` inside a string or a subsearch is not a separator.
    """
    cleaned = strip_comments(_strip_spl_comments(text or "")).strip()
    if not cleaned:
        raise Refusal(
            "SPL_EMPTY",
            "there is no search here. An empty search matches every event in "
            "every index, which is why it is refused rather than lowered.",
            "parse",
        )

    parts = split_top_level(cleaned, "|")
    head = parts[0].strip()
    # `| stats ...` with no leading search is legal SPL on an accelerated data
    # model, but as a detection it reads the whole index.
    stages: list[ParsedStage] = []
    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue
        if part.startswith("`"):
            raise Refusal(
                "SPL_MACRO",
                f"`{part[:40]}` is a macro call. A macro expands to arbitrary "
                f"SPL stored on the search head, so what this rule actually "
                f"does is not in the text. Paste the expansion.",
                "parse",
            )
        operator, _, body = part.partition(" ")
        stages.append(ParsedStage(operator=operator.strip(), body=body.strip()))

    if head.lower().startswith("search "):
        head = head[len("search "):].strip()

    return ParsedSpl(search=head, stages=stages, raw=text or "")


# ---------------------------------------------------------------------------
# Lower: the search
# ---------------------------------------------------------------------------


def _expression(
    text: str,
    node_id: str,
    *,
    spec: DialectSpec = SPEC,
    scopes: dict[str, str] | None = None,
) -> Expr:
    """Parse with the spec for the grammar being read.

    `spec` is not a detail: SEARCH_SPEC and SPEC differ in whether OR or AND
    binds tighter, and reading a search with the eval spec regroups every mixed
    boolean without a warning.
    """
    if not text.strip():
        raise Refusal(
            "SPL_EMPTY_CONDITION",
            f"`{node_id}` has no condition. An empty condition is not a "
            f"condition; depending on where it sits it matches everything or "
            f"nothing.",
            "lower",
        )
    parser = Parser(tokenize(text), spec, field_scopes=scopes)
    return _fold_eval_predicates(parser.parse_expression(0))


#: SPL eval FUNCTIONS that mean the same thing as a comparison operator.
#:
#: `render_splunk` writes a substring test as `like(field, "%x%")` -- which is
#: correct SPL, because `like` in eval is a function, not an infix operator --
#: and the parser only knew the infix form. So the renderer emitted valid SPL
#: that its own parser refused with "`AND` is a reserved word", because the
#: failed `like(` left the rest of the condition unread.
_PREDICATE_FUNCTIONS: Final[dict[str, str]] = {
    "like": "like",
    "match": "matches",
}


def _fold_eval_predicates(expr: Expr) -> Expr:
    """Rewrite `like(a, b)` and `match(a, p)` into comparisons.

    Both spellings reach the same engine operator, so the function form and
    the infix form cannot drift apart.
    """
    if isinstance(expr, Call):
        args = tuple(_fold_eval_predicates(a) for a in expr.args)
        operator = _PREDICATE_FUNCTIONS.get(expr.function)
        if operator is not None and len(args) == 2:
            right = args[1]
            if operator == "matches" and isinstance(right, Literal) \
                    and isinstance(right.value, str):
                # `match()` takes a REGEX, and SPL's flavour is PCRE -- which
                # `evaluate.py` refuses to execute. Tagged rather than run, so
                # the refusal names the engine instead of guessing.
                right = Regex(right.value, SPEC.default_regex_dialect, False)
            return Comparison(operator, args[0], right)
        return Call(expr.function, args, expr.flags)
    if isinstance(expr, BoolOp):
        return BoolOp(
            expr.op, tuple(_fold_eval_predicates(o) for o in expr.operands)
        )
    if isinstance(expr, Not):
        return Not(_fold_eval_predicates(expr.operand))
    if isinstance(expr, Comparison):
        return Comparison(
            expr.op,
            _fold_eval_predicates(expr.left),
            _fold_eval_predicates(expr.right),
            expr.negate,
        )
    return expr


def _is_index_term(term: str) -> bool:
    name, found, _ = term.partition("=")
    if not found:
        return False
    # `sourcetype::value` is the explicitly index-time spelling.
    return name.strip().strip('"').lower().replace("::", "") in INDEX_TIME_FIELDS


def _split_search(
    search: str, diagnostics: list[Diagnostic]
) -> tuple[str, str]:
    """Separate index-time terms from row predicates.

    A term is hoisted into the selector only when it is a top-level AND operand.
    Because OR binds tighter than AND in SPL, `index=main a=1 OR b=2` really is
    `index=main AND (a=1 OR b=2)`, so the index term there IS top level and is
    safe to lift.

    `index=main OR index=other` is NOT: lifting either half would change which
    events the search reads. Those stay in the predicate and are REPORTED,
    because a rule that filters on a column called `index` will find nothing --
    no event carries one -- and the analyst needs to know that is why.
    """
    if not search.strip():
        return "", ""

    terms = [t for t in _split_terms(search.strip()) if t.upper() != "AND"]
    hoisted: list[str] = []
    kept: list[str] = []
    stranded: list[str] = []

    for index, term in enumerate(terms):
        if term.upper() in _BOOLEANS:
            kept.append(term)
            continue
        previous = terms[index - 1].upper() if index else ""
        following = terms[index + 1].upper() if index + 1 < len(terms) else ""
        if not _is_index_term(term):
            kept.append(term)
            continue
        if previous == "OR" or following == "OR" or previous == "NOT":
            stranded.append(term)
            kept.append(term)
            continue
        hoisted.append(term)

    if stranded:
        diagnostics.append(Diagnostic(
            "SPL_INDEX_TERM_IN_DISJUNCTION",
            f"{', '.join(stranded)} selects an index or sourcetype from inside "
            f"an OR or a NOT, so it cannot be lifted into the source without "
            f"changing which events the search reads. It has been left as a row "
            f"predicate, which means it will not resolve against any sample: no "
            f"event carries a field called `index`.",
            severity="problem",
            evidence=" ".join(stranded),
        ))

    # Strip a joiner left dangling by the hoist. Only AND and OR: they are
    # INFIX, so a leading one is debris. NOT is PREFIX and legitimately leads --
    # trimming it turned `index=main NOT a=1` into `a=1`, which matches exactly
    # the events the author excluded.
    while kept and kept[0].upper() in ("AND", "OR"):
        kept.pop(0)
    while kept and kept[-1].upper() in _BOOLEANS:
        kept.pop()

    return " ".join(hoisted), " ".join(kept)


def _bare_terms(predicates: str) -> list[str]:
    """Search terms that name no field, and so can only be full-text.

    `field IN (a, b)` is three terms to the splitter, so the middle one, `IN`,
    looks exactly like a bare word. Judged on the SPL semantics instead: the
    whole `field IN (...)` group is one comparison, and none of its pieces is
    a bare term.

    Compared EXACTLY, not uppercased. A lowercase `or` is a search TERM in
    SPL -- Splunk looks for the literal word -- so folding the case here let
    `a=1 or b=2` through to the parser, which then refused it with a message
    about reserved words that told the analyst nothing about why.
    """
    terms = _split_terms(predicates)
    bare: list[str] = []
    index = 0
    while index < len(terms):
        term = terms[index]
        if (index + 2 < len(terms)
                and terms[index + 1].upper() == "IN"
                and terms[index + 2].startswith("(")
                and is_bare_identifier(term)):
            index += 3
            continue
        if (term not in _BOOLEANS
                and "=" not in term
                and not term.startswith("(")
                and not any(op in term for op in ("!=", "<", ">", "<=", ">="))):
            bare.append(term)
        index += 1
    return bare


def _lower_search(
    search: str, diagnostics: list[Diagnostic]
) -> tuple[Read, Filter | None]:
    # A GENERATING command reached here only because the leading `|` left its
    # name where an index search belongs. Named for what it is, rather than
    # refused as a bare search term -- see `GENERATING_COMMANDS`.
    head = search.strip().split(None, 1)[0].lower() if search.strip() else ""
    reason = GENERATING_COMMANDS.get(head)
    if reason is not None:
        raise Refusal(
            f"SPL_GENERATING_{head.upper()}",
            f"`{head}` is a generating command: {reason}. This rule cannot be "
            f"modelled or tested here. The detection logic inside it may well "
            f"be expressible -- rewrite it as a `search` over an index and "
            f"this tool can read it.",
            "lower",
        )

    selector, predicates = _split_search(search, diagnostics)

    table = ""
    for term in _split_terms(selector):
        name, _, value = term.partition("=")
        if name.strip().lower() in ("index", "sourcetype"):
            table = value.strip().strip('"')
            if name.strip().lower() == "index":
                break
    read = Read(id="search", table=table or "events", selector=selector)

    if not predicates.strip():
        return read, None

    bare = _bare_terms(predicates)
    if bare:
        offender = bare[0]
        if offender.upper() in _BOOLEANS:
            raise Refusal(
                "SPL_BOOLEAN_NOT_UPPERCASE",
                f"`{offender}` is lowercase, so SPL reads it as a search TERM -- "
                f"the literal word `{offender}` anywhere in the event -- rather "
                f"than as the operator. Write it as `{offender.upper()}` if you "
                f"meant the boolean.",
                "lower",
            )
        raise Refusal(
            "SPL_BARE_SEARCH_TERM",
            f"`{offender}` is a bare search term, which in SPL is a full-text "
            f"match across every field of the event. This engine evaluates named "
            f"fields, so there is nothing to search -- name the field you mean.",
            "lower",
        )

    condition = _expression(
        normalise_search(predicates), "where_search", spec=SEARCH_SPEC
    )
    return read, Filter(id="where_search", condition=condition)


# ---------------------------------------------------------------------------
# Lower: stages
# ---------------------------------------------------------------------------


def _count(body: str, operator: str) -> int:
    head = body.strip().split(" ")[0] if body.strip() else ""
    try:
        return int(head)
    except ValueError:
        raise Refusal(
            "SPL_LIMIT_NOT_A_NUMBER",
            f"`{operator} {body[:30]}` needs a row count. Without one the stage "
            f"silently keeps Splunk's default, which is not what the rule says.",
            "lower",
        ) from None


def _measure_from(piece: str, index: int) -> Measure:
    """`dc(user) as Users` as one aggregate."""
    body = piece.strip()
    alias = ""
    split = _AS.split(body, maxsplit=1)
    if len(split) == 2:
        body, alias = split[0].strip(), split[1].strip()

    match = _AGG_CALL.match(body)
    if match:
        name = match.group("name").lower()
        argument = match.group("arg").strip()
    elif body.lower() in ("count", "c"):
        name, argument = "count", ""
    else:
        raise Refusal(
            "SPL_AGGREGATE_MALFORMED",
            f"`{piece.strip()}` is not an aggregate. Splunk writes them as "
            f"`func(field)`, optionally `as name`.",
            "lower",
        )

    param: Decimal | None = None
    percentile = _PERCENTILE.match(name)
    if percentile is not None:
        try:
            param = Decimal(percentile.group("n"))
        except InvalidOperation:
            param = None
        engine, distinct = "percentile", False
    elif name == "median":
        engine, distinct, param = "percentile", False, Decimal(50)
    elif name in AGGREGATES:
        engine, distinct = AGGREGATES[name]
    else:
        raise Refusal(
            "SPL_AGGREGATE_UNKNOWN",
            f"`{name}()` is not an aggregate this dialect maps. Known: "
            f"{', '.join(sorted(AGGREGATES))}, median, percNN. It is refused "
            f"rather than passed through, because an aggregate this engine "
            f"cannot compute would silently produce no value.",
            "lower",
        )

    condition = None
    if (name in ("count", "c") and argument.lower().startswith("eval(")
            and argument.endswith(")")):
        condition = _expression(argument[5:-1].strip(), f"measure_{index}")
        argument = ""

    field = FieldRef.parse(argument) if argument else None
    if engine != "count" and field is None:
        raise Refusal(
            "SPL_AGGREGATE_NEEDS_FIELD",
            f"`{name}()` aggregates a field, so it needs one.",
            "lower",
        )
    # Splunk's own default output name, so a later `| where Users > 5` resolves.
    default = f"{name}({argument})" if argument else "count"
    return Measure(
        function=engine,
        name=alias or default,
        field=field,
        distinct=distinct,
        param=param,
        condition=condition,
    )


def _lower_stats(
    body: str, node_id: str, diagnostics: list[Diagnostic], *, accelerated: bool
) -> list[Node]:
    stripped = body.strip()
    if re.match(r"^by\s+", stripped, re.IGNORECASE):
        raise Refusal(
            "SPL_STATS_NO_MEASURE",
            f"`{node_id}` groups but measures nothing, which produces one row "
            f"per group and discards every value. Say `count` if that is what "
            f"you want, or use `| dedup` if you wanted distinct rows.",
            "lower",
        )
    halves = _BY.split(body, maxsplit=1)
    measure_text = halves[0].strip()
    by_text = halves[1].strip() if len(halves) == 2 else ""

    if not measure_text:
        raise Refusal(
            "SPL_STATS_NO_MEASURE",
            f"`{node_id}` groups but measures nothing, which produces one row "
            f"per group and discards every value. Say `count` if that is what "
            f"you want.",
            "lower",
        )

    measures = tuple(
        _measure_from(piece, index)
        for index, piece in enumerate(split_top_level(measure_text, ","))
        if piece.strip()
    )

    keys: list[FieldRef] = []
    window: Window | None = None
    for piece in split_top_level(by_text, ","):
        piece = piece.strip()
        if not piece:
            continue
        for term in _split_terms(piece):
            span = _SPAN.match(term)
            if span is not None:
                size = duration_seconds(span.group("value"))
                if size is None:
                    raise Refusal(
                        "SPL_SPAN_UNREADABLE",
                        f"`span={span.group('value')}` is not a time span this "
                        f"engine can read. Use a number and a unit, like `5m`.",
                        "lower",
                    )
                window = Window(kind="tumbling", size=size)
                continue
            if term.startswith("_time"):
                # `by _time span=5m` is the window, not a grouping key: keeping
                # it as a key would group every second separately.
                continue
            keys.append(FieldRef.parse(term))

    capability = (
        Capability.DECLARED_ONLY if accelerated else Capability.EVALUATED
    )
    note = ""
    if accelerated:
        note = (
            "tstats reads index-time acceleration (tsidx), which no sample of "
            "events carries. It renders correctly and cannot be evaluated here."
        )
        diagnostics.append(Diagnostic(
            "SPL_TSTATS_APPLIANCE_ONLY",
            f"`{node_id}` uses tstats, which reads accelerated index-time "
            f"fields. The stage is modelled and will render, but it can only be "
            f"computed by Splunk itself.",
            severity="caution",
        ))
    return [Aggregate(
        id=node_id,
        measures=measures,
        keys=tuple(keys),
        window=window,
        capability=capability,
        note=note,
    )]


def _lower_eval(body: str, node_id: str) -> list[Node]:
    assignments: list[tuple[str, Expr]] = []
    for piece in split_top_level(body, ","):
        piece = piece.strip()
        if not piece:
            continue
        target, found, expression = piece.partition("=")
        if not found or not target.strip():
            raise Refusal(
                "SPL_EVAL_MALFORMED",
                f"`{piece[:40]}` is not an assignment. `eval` writes "
                f"`name = expression`.",
                "lower",
            )
        assignments.append((
            target.strip(),
            _lower_eval_expression(expression.strip(), node_id),
        ))
    if not assignments:
        raise Refusal(
            "SPL_EVAL_EMPTY", f"`{node_id}` computes nothing.", "lower"
        )
    return [Derive(id=node_id, assignments=tuple(assignments))]


def _lower_eval_expression(text: str, node_id: str) -> Expr:
    """An eval expression, with Splunk's argument orders corrected.

    `cidrmatch` is the one that matters: Splunk writes
    `cidrmatch("10.0.0.0/8", ip)` -- network FIRST -- while this engine's
    `cidr_contains(address, network)` takes the address first. Passing them
    through in written order would ask whether the network is inside the
    address, which is false for every real input and so looks like a rule that
    simply never fires.
    """
    tree = _expression(text, node_id)
    return _fix_argument_orders(tree)


def _fix_argument_orders(expr: Expr) -> Expr:
    if isinstance(expr, Call):
        args = tuple(_fix_argument_orders(a) for a in expr.args)
        if expr.function == "cidr_contains" and len(args) == 2:
            args = (args[1], args[0])
        return Call(expr.function, args, expr.flags)
    if isinstance(expr, Comparison):
        return Comparison(
            expr.op,
            _fix_argument_orders(expr.left),
            _fix_argument_orders(expr.right),
            expr.negate,
        )
    if isinstance(expr, BoolOp):
        return BoolOp(expr.op, tuple(_fix_argument_orders(o) for o in expr.operands))
    if isinstance(expr, Not):
        return Not(_fix_argument_orders(expr.operand))
    return expr


def _lower_fields(body: str, node_id: str) -> list[Node]:
    body = body.strip()
    dropping = body.startswith("-")
    if body[:1] in ("+", "-"):
        body = body[1:].strip()
    refs = tuple(
        FieldRef.parse(part.strip())
        for part in split_top_level(body, ",")
        if part.strip()
    )
    if not refs:
        raise Refusal(
            "SPL_FIELDS_EMPTY",
            f"`{node_id}` names no fields, so what it keeps or drops is unstated.",
            "lower",
        )
    if dropping:
        return [Project(id=node_id, drops=refs)]
    return [Project(id=node_id, keeps=refs)]


def _lower_rename(body: str, node_id: str) -> list[Node]:
    renames: list[tuple[FieldRef, str]] = []
    for piece in split_top_level(body, ","):
        piece = piece.strip()
        if not piece:
            continue
        halves = _AS.split(piece, maxsplit=1)
        if len(halves) != 2:
            raise Refusal(
                "SPL_RENAME_MALFORMED",
                f"`{piece[:40]}` is not a rename. Splunk writes `old AS new`.",
                "lower",
            )
        source, target = halves[0].strip(), halves[1].strip().strip('"')
        if "*" in source or "*" in target:
            raise Refusal(
                "SPL_RENAME_WILDCARD",
                f"`{piece.strip()}` renames by wildcard, which depends on the "
                f"data's field names rather than on the rule. Which columns come "
                f"out cannot be known from the text.",
                "lower",
            )
        renames.append((FieldRef.parse(source), target))
    if not renames:
        raise Refusal("SPL_RENAME_EMPTY", f"`{node_id}` renames nothing.", "lower")
    return [Project(id=node_id, renames=tuple(renames))]


def _lower_sort(body: str, node_id: str) -> list[Node]:
    body = body.strip()
    limit: int | None = None
    terms = _split_terms(body)
    if terms and terms[0].isdigit():
        limit = int(terms[0])
        terms = terms[1:]
        body = " ".join(terms)

    keys: list[tuple[FieldRef, bool]] = []
    for piece in split_top_level(body, ","):
        piece = piece.strip()
        if not piece:
            continue
        descending = False
        if piece.startswith("-"):
            descending, piece = True, piece[1:].strip()
        elif piece.startswith("+"):
            piece = piece[1:].strip()
        lowered = piece.lower()
        if lowered.endswith(" desc"):
            descending, piece = True, piece[:-5].strip()
        elif lowered.endswith(" asc"):
            piece = piece[:-4].strip()
        # `sort str(field)` and friends name a sort TYPE, which changes the
        # ordering rather than the column.
        typed = re.match(r"^(?:str|num|ip|auto)\((?P<inner>.+)\)$", piece,
                         re.IGNORECASE)
        if typed is not None:
            piece = typed.group("inner").strip()
        keys.append((FieldRef.parse(piece), descending))
    if not keys:
        raise Refusal(
            "SPL_SORT_NO_KEY",
            f"`{node_id}` sorts by nothing, so the order it produces is "
            f"whatever the previous stage happened to leave.",
            "lower",
        )
    return [Sort(id=node_id, keys=tuple(keys), limit=limit)]


def _lower_join(
    body: str, node_id: str, bindings: list[Binding], left: str,
    diagnostics: list[Diagnostic],
) -> list[Node]:
    """`join type=inner host [ search ... ]` as a Join over a Binding.

    The subsearch becomes a named Binding, which is what the IR models a second
    stream as. Nothing here flattens it into the main pipeline: a subsearch is a
    separate stream with its own stages, and merging them would change which
    rows the join sees.
    """
    opened = body.find("[")
    if opened < 0 or not body.rstrip().endswith("]"):
        raise Refusal(
            "SPL_JOIN_NO_SUBSEARCH",
            f"`{node_id}` has no `[ ... ]` subsearch. An SPL join always reads a "
            f"second search; without one there is no right-hand side.",
            "lower",
        )
    head = body[:opened].strip()
    inner = body[opened + 1:body.rstrip().rfind("]")].strip()

    how = "inner"
    keys: list[FieldRef] = []
    for term in _split_terms(head):
        name, found, value = term.partition("=")
        if found and name.strip().lower() == "type":
            kind = value.strip().lower()
            how = {
                "inner": "inner", "outer": "left", "left": "left",
            }.get(kind, "")
            if not how:
                raise Refusal(
                    "SPL_JOIN_TYPE_UNKNOWN",
                    f"`type={kind}` is not a join type. Splunk has inner and "
                    f"outer (left); this engine also models right, full and "
                    f"anti, but SPL has no syntax for them.",
                    "lower",
                )
            continue
        if found and name.strip().lower() in (
            "usetime", "earlier", "overwrite", "max"
        ):
            diagnostics.append(Diagnostic(
                "SPL_JOIN_OPTION_IGNORED",
                f"`{term}` on `{node_id}` controls how Splunk's join picks among "
                f"duplicate matches. It is not modelled, so this join may "
                f"produce more rows here than Splunk would.",
                severity="caution",
                verified=False,
                evidence=term,
            ))
            continue
        keys.append(FieldRef.parse(term))

    if not keys:
        raise Refusal(
            "SPL_JOIN_NO_KEY",
            f"`{node_id}` names no join field, so every row on the left would "
            f"match every row on the right.",
            "lower",
        )

    if inner.lower().startswith("search "):
        inner = inner[len("search "):].strip()
    right_name = f"{node_id}_right"
    inner_parsed = parse_splunk(inner)
    inner_nodes = _lower_stream(inner_parsed, right_name, diagnostics, bindings)
    bindings.append(Binding(name=right_name, pipeline=tuple(inner_nodes)))

    on = tuple(
        (FieldRef(key.name, key.path), FieldRef(key.name, key.path, "right"))
        for key in keys
    )
    return [Join(id=node_id, left=left, right=right_name, how=how, on=on)]


def _lower_rex(body: str, node_id: str, diagnostics: list[Diagnostic]) -> list[Node]:
    """`rex field=cmd "(?<user>\\w+)"` as declared-only extractions.

    Field extraction needs the vendor's parser, so each named group becomes a
    `rex_extract` call marked DECLARED_ONLY. It renders correctly and refuses to
    evaluate, which is the honest answer -- inventing the extracted value would
    make every later comparison against it meaningless.
    """
    source = "_raw"
    pattern = ""
    for term in _split_terms(body):
        name, found, value = term.partition("=")
        if found and name.strip().lower() == "field":
            source = value.strip().strip('"')
            continue
        if found and name.strip().lower() in ("max_match", "offset_field", "mode"):
            continue
        if term[:1] in ("\"", "'"):
            pattern = term[1:-1] if len(term) >= 2 else term
    if not pattern:
        raise Refusal(
            "SPL_REX_NO_PATTERN",
            f"`{node_id}` has no quoted pattern, so what it extracts is unstated.",
            "lower",
        )

    groups = re.findall(r"\(\?P?<([A-Za-z_]\w*)>", pattern)
    if not groups:
        raise Refusal(
            "SPL_REX_NO_CAPTURE",
            f"`{node_id}` has no named capture group, so it creates no field. "
            f"Splunk's rex only extracts through `(?<name>...)`.",
            "lower",
        )
    diagnostics.append(Diagnostic(
        "SPL_REX_APPLIANCE_ONLY",
        f"`{node_id}` extracts {', '.join(groups)} with a PCRE pattern on the "
        f"search head. The extraction is modelled and renders correctly, but no "
        f"sample of events carries the result, so any later comparison against "
        f"those fields cannot be evaluated here.",
        severity="caution",
    ))
    return [Derive(
        id=node_id,
        assignments=tuple(
            (
                name,
                Call("rex_extract", (
                    FieldRef.parse(source),
                    Literal(pattern),
                    Literal(name),
                )),
            )
            for name in groups
        ),
        capability=Capability.DECLARED_ONLY,
        note="rex extraction runs on the search head",
    )]


def _lower_top(
    body: str, node_id: str, rare: bool, diagnostics: list[Diagnostic]
) -> list[Node]:
    """`top 5 user by host` as count + sort + limit.

    THREE stages from one command, because that is what it means. Lowering it as
    a bare Aggregate would drop the ordering and the cut-off, which are the
    whole point of `top`.
    """
    halves = _BY.split(body, maxsplit=1)
    head = halves[0].strip()
    extra = halves[1].strip() if len(halves) == 2 else ""

    terms = _split_terms(head)
    limit = 10
    if terms and terms[0].isdigit():
        limit = int(terms[0])
        terms = terms[1:]
    fields = [
        FieldRef.parse(part.strip())
        for part in split_top_level(" ".join(terms), ",")
        if part.strip() and not part.strip().lower().startswith(
            ("limit=", "countfield=", "percentfield=", "showperc", "useother")
        )
    ]
    if not fields:
        raise Refusal(
            "SPL_TOP_NO_FIELD",
            f"`{node_id}` names no field to rank.",
            "lower",
        )
    for part in split_top_level(extra, ","):
        if part.strip():
            fields.append(FieldRef.parse(part.strip()))

    return [
        Aggregate(
            id=f"{node_id}_count",
            measures=(Measure("count", "count"),),
            keys=tuple(fields),
        ),
        Sort(
            id=f"{node_id}_sort",
            keys=((FieldRef("count"), not rare),),
        ),
        Limit(id=node_id, count=limit),
    ]


def _lower_stage(
    stage: ParsedStage,
    node_id: str,
    bindings: list[Binding],
    previous: str,
    diagnostics: list[Diagnostic],
) -> list[Node]:
    """One `| command` as one or more stages.

    Returns a LIST because SPL commands are not one-to-one with IR stages:
    `top` is a count plus a sort plus a limit, and collapsing it to one node
    would drop two thirds of what it means.

    Every branch ends in a refusal. A silent `else` here drops a stage and
    produces a complete-looking search with the detection missing -- the defect
    `render_kql`'s docstring describes.
    """
    operator = stage.operator.lower()
    body = stage.body.strip()

    if operator in UNSUPPORTED_COMMANDS:
        raise Refusal(
            "SPL_COMMAND_UNSUPPORTED",
            f"`| {operator}` cannot be lowered: {UNSUPPORTED_COMMANDS[operator]}",
            "lower",
        )

    if operator == "where":
        if re.search(r"(?<![=!<>])=(?!=)", body):
            diagnostics.append(Diagnostic(
                "SPL_WHERE_SINGLE_EQUALS",
                f"`| where {body[:40]}` uses a single `=`. Splunk's `where` is "
                f"eval syntax and rejects it -- `==` is equality there. It has "
                f"been read as a comparison, but Splunk would not run this.",
                severity="problem",
                evidence=body[:60],
            ))
        return [Filter(
            id=node_id,
            condition=_fix_argument_orders(_expression(body, node_id)),
        )]

    if operator == "search":
        return [Filter(
            id=node_id,
            condition=_expression(
                normalise_search(body), node_id, spec=SEARCH_SPEC
            ),
        )]

    if operator == "regex":
        return [_lower_regex_stage(body, node_id)]

    if operator in ("stats", "tstats"):
        return _lower_stats(
            body, node_id, diagnostics, accelerated=(operator == "tstats")
        )

    if operator == "timechart":
        # `timechart span=5m count by host` is an Aggregate with a window; the
        # difference from `stats` is presentational.
        #
        # The span comes FIRST in `timechart`, ahead of the measure -- so
        # handing the body through unchanged sent `span=1h count` to
        # `_measure_from`, which read it as neither a call nor `count` and
        # refused with "is not an aggregate". A timechart is one of the
        # commonest Splunk commands there is.
        head, _, rest = body.strip().partition(" ")
        moved = ""
        if _SPAN.match(head):
            moved = f" by {head}"
            body = rest
        return _lower_stats(
            f"{body}{moved}" if _BY.search(body) else f"{body}{moved}",
            node_id, diagnostics, accelerated=False,
        )

    if operator == "eval":
        return _lower_eval(body, node_id)

    if operator in ("fields", "table"):
        return _lower_fields(body, node_id)

    if operator == "rename":
        return _lower_rename(body, node_id)

    if operator == "sort":
        return _lower_sort(body, node_id)

    if operator in ("head", "tail"):
        return [Limit(
            id=node_id, count=_count(body, operator),
            keep_last=(operator == "tail"),
        )]

    if operator == "dedup":
        keys = tuple(
            FieldRef.parse(part.strip())
            for part in split_top_level(body, ",")
            if part.strip() and "=" not in part
        )
        if not keys:
            raise Refusal(
                "SPL_DEDUP_NO_KEY",
                f"`{node_id}` de-duplicates on nothing, which would keep one row "
                f"in total.",
                "lower",
            )
        return [Distinct(id=node_id, keys=keys)]

    if operator == "mvexpand":
        terms = _split_terms(body)
        if not terms:
            raise Refusal(
                "SPL_MVEXPAND_NO_FIELD",
                f"`{node_id}` names no field to expand.",
                "lower",
            )
        return [Expand(id=node_id, field=FieldRef.parse(terms[0]))]

    if operator == "join":
        return _lower_join(body, node_id, bindings, previous, diagnostics)

    if operator == "rex":
        return _lower_rex(body, node_id, diagnostics)

    if operator in ("top", "rare"):
        return _lower_top(body, node_id, operator == "rare", diagnostics)

    if operator in ("bin", "bucket"):
        return _lower_bin(body, node_id)

    raise Refusal(
        "SPL_COMMAND_UNKNOWN",
        f"`| {operator}` is not an SPL command this dialect knows. It is refused "
        f"rather than skipped: a dropped stage produces a search that reads "
        f"correctly and matches a different set of events.",
        "lower",
    )


def _lower_regex_stage(body: str, node_id: str) -> Node:
    field, found, pattern = body.partition("=")
    if not found:
        raise Refusal(
            "SPL_REGEX_NO_FIELD",
            f"`| regex {body[:40]}` does not name a field. Bare `| regex` "
            f"matches against the whole raw event, and there is no raw event "
            f"here -- only named fields.",
            "lower",
        )
    pattern = pattern.strip()
    negate = field.strip().endswith("!")
    name = field.strip().rstrip("!=").strip()
    if len(pattern) >= 2 and pattern[0] in "\"'" and pattern[-1] == pattern[0]:
        pattern = pattern[1:-1]
    if not pattern:
        raise Refusal(
            "SPL_REGEX_NO_PATTERN", f"`{node_id}` has no pattern.", "lower"
        )
    return Filter(
        id=node_id,
        condition=Comparison(
            "matches", FieldRef.parse(name),
            Regex(pattern, dialect="pcre"), negate=negate,
        ),
    )


def _lower_bin(body: str, node_id: str) -> list[Node]:
    terms = _split_terms(body)
    field = ""
    span = ""
    alias = ""
    skip = False
    for index, term in enumerate(terms):
        if skip:
            skip = False
            continue
        name, found, value = term.partition("=")
        if found and name.lower() == "span":
            span = value.strip()
            continue
        if found and name.lower() in ("bins", "minspan", "start", "end", "aligntime"):
            continue
        if term.lower() == "as" and index + 1 < len(terms):
            alias = terms[index + 1]
            skip = True
            continue
        if not field:
            field = term
    if not field:
        raise Refusal(
            "SPL_BIN_NO_FIELD", f"`{node_id}` names no field to bin.", "lower"
        )
    if not span:
        raise Refusal(
            "SPL_BIN_NO_SPAN",
            f"`{node_id}` has no `span=`. Splunk would pick one from the data, "
            f"which means the rule's buckets depend on the events rather than on "
            f"the rule.",
            "lower",
        )
    return [Derive(
        id=node_id,
        assignments=((
            alias or field,
            Call("bin", (FieldRef.parse(field), Literal(span))),
        ),),
    )]


def _lower_stream(
    parsed: ParsedSpl,
    prefix: str,
    diagnostics: list[Diagnostic],
    bindings: list[Binding],
) -> list[Node]:
    read, search_filter = _lower_search(parsed.search, diagnostics)
    read = Read(
        id=f"{prefix}_search", table=read.table, selector=read.selector
    )
    nodes: list[Node] = [read]
    if search_filter is not None:
        nodes.append(Filter(
            id=f"{prefix}_terms", condition=search_filter.condition
        ))

    for index, stage in enumerate(parsed.stages, start=1):
        node_id = f"{prefix}_{stage.operator.lower().replace('-', '_')}_{index}"
        produced = _lower_stage(
            stage, node_id, bindings, nodes[-1].id, diagnostics
        )
        nodes.extend(produced)
    return nodes


def lower_splunk(text: str, rule_id: str = "rule") -> tuple[Rule, list[Diagnostic]]:
    """SPL text to a Rule, plus what could not be represented."""
    parsed = parse_splunk(text)
    diagnostics: list[Diagnostic] = []
    bindings: list[Binding] = []

    nodes = _lower_stream(parsed, "main", diagnostics, bindings)
    if not any(isinstance(n, Emit) for n in nodes):
        # SPL has no output stage: the result is whatever the last command
        # leaves. Stated here rather than implied, because `ir.Rule` requires it.
        nodes.append(Emit(id="main_out"))

    rule = Rule(
        rule_id=rule_id,
        pipeline=tuple(nodes),
        bindings=tuple(bindings),
        annotations=Annotations(title=""),
        metadata={
            "dialect": DIALECT,
            "language": LANGUAGE,
            "artifact": "search",
        },
    )
    validate(rule)
    return rule, diagnostics


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def _quote(value: Any) -> str:
    """A constant as SPL eval syntax.

    Strings are ALWAYS quoted. In eval syntax a bare word is a FIELD NAME, so
    `user != guest` asks whether the user column differs from the guest column
    -- not from the string "guest". Rendering an unquoted string therefore
    produces a search that runs, returns rows, and tests something else
    entirely.
    """
    if value is None:
        return "null()"
    if isinstance(value, bool):
        return "true()" if value else "false()"
    if isinstance(value, Decimal):
        return plain_number(value)
    if isinstance(value, (int, float)):
        return str(value)
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _bare(value: Any) -> str:
    """A constant as a SEARCH term, where bare is idiomatic and safe.

    Search-term syntax is the other half of SPL: there `index=main` needs no
    quotes, and adding them would still work but stops matching how every
    Splunk rule in the world is written.
    """
    text = str(value)
    if text == "" or any(c.isspace() for c in text) or any(
        c in text for c in '"\'()[]|=<>!,'
    ):
        return '"' + text.replace('"', '\\"') + '"'
    return text


#: Engine operator -> SPL spelling, for `where`.
_RENDER_OPS: Final[dict[str, str]] = {
    "==": "==", "!=": "!=", "<": "<", "<=": "<=", ">": ">", ">=": ">=",
    "like": "LIKE",
}


#: SPL's `LIKE` is a SQL wildcard test: `%` is any run, `_` is one character.
#:
#: Both are therefore METACHARACTERS, and a literal one in the rule's value has
#: to be escaped. It was not, so `contains "%"` rendered as `LIKE "%%%"` and
#: `contains "_"` as `LIKE "%_%"` -- patterns that match EVERY row. A rule
#: written to find one literal character became a rule that alerts on
#: everything, and reported success. AQL's renderer escaped these correctly, so
#: this was a per-renderer omission rather than a misunderstanding.
def _like_escape(text: str) -> str:
    out: list[str] = []
    for char in text:
        if char in "\\%_":
            out.append("\\")
        out.append(char)
    return "".join(out)


def _like_body(operator: str, value: str, nocase: bool = False) -> str:
    """The LIKE pattern for a substring test, with the value escaped.

    `*` is used as the internal wildcard marker by the caller's table and is
    translated to `%` here, AFTER escaping, so a literal `%` in the value can
    never be mistaken for the wildcard the renderer itself added.
    """
    wildcards = {
        "contains": "%{0}%", "startswith": "{0}%", "endswith": "%{0}",
    }[operator]
    escaped = _like_escape(value).replace('"', '\\"')
    if nocase:
        # The subject is lowercased by `_like_subject`, so the pattern has to
        # be folded too. Folding only one side makes an uppercase character in
        # the pattern unmatchable, which is how an exclusion silently stops
        # excluding.
        escaped = escaped.lower()
    return wildcards.format(escaped).replace("*", "%")


def _like_subject(expr: Any) -> str:
    """The left side of a LIKE test, lowercased when the fold is requested.

    SPL's `LIKE` is case-SENSITIVE. A case-insensitive substring test is
    therefore written as `lower(field) LIKE "...lowercased pattern..."`, which
    is the idiom Splunk's own documentation uses. Without it the fold was
    dropped entirely: `contains "ENC"` became `match(CommandLine, "ENC")`, an
    exact-case test, so every lowercase `-enc` command line was missed.
    """
    subject = _render_expression(expr.left)
    return f"lower({subject})" if expr.nocase else subject


def _render_expression(expr: Expr) -> str:
    """An expression as SPL eval syntax.

    Ends in a refusal. A silent fallback would emit a fragment that parses as
    something else, which is worse than not rendering at all.
    """
    if isinstance(expr, Literal):
        return _quote(expr.value)
    if isinstance(expr, FieldRef):
        if expr.scope != "current":
            # SPL has no cross-row reference in eval. The join already placed
            # the column, so the prefix is the honest spelling.
            return f"{expr.scope}_{expr.full}"
        # SPL's bare field name is ASCII. An irregular name needs single
        # quotes, which this dialect's tokenizer does not read -- so emitting
        # it bare produced a search its OWN parser refused.
        if not is_bare_identifier(expr.full):
            raise Refusal(
                "SPL_RENDER_FIELD_NOT_AN_IDENTIFIER",
                f"`{expr.full}` is not a bare SPL field name: those are ASCII "
                f"letters, digits and underscores. Splunk writes an irregular "
                f"name in single quotes, which this tool does not yet read "
                f"back -- so it is refused rather than written into a search "
                f"that cannot be re-imported. Map the field to an ASCII name "
                f"first.",
                "render",
            )
        return expr.full
    if isinstance(expr, Regex):
        # Splunk's `match()` is PCRE, so `(?i)` is the inline fold. Dropping it
        # here turned a case-insensitive test into an exact-case one: `=~ "ENC"`
        # (KQL's ignore-case equality) rendered as a case-sensitive pattern and
        # stopped matching `-enc` command lines.
        return f'"(?i){expr.pattern}"' if expr.nocase else f'"{expr.pattern}"'
    if isinstance(expr, Not):
        return f"NOT ({_render_expression(expr.operand)})"
    if isinstance(expr, BoolOp):
        joiner = f" {expr.op.upper()} "
        return "(" + joiner.join(
            _render_expression(o) for o in expr.operands
        ) + ")"
    if isinstance(expr, Call):
        if expr.function == "cidr_contains" and len(expr.args) == 2:
            # Back to Splunk's order: network first.
            return (
                f"cidrmatch({_render_expression(expr.args[1])}, "
                f"{_render_expression(expr.args[0])})"
            )
        spelling = {
            "iff": "if", "strlen": "len", "to_string": "tostring",
            "to_int": "tonumber", "substring": "substr", "is_null": "isnull",
            "is_not_null": "isnotnull", "matches_regex": "match",
            "length": "mvcount",
        }.get(expr.function, expr.function)
        inner = ", ".join(_render_expression(a) for a in expr.args)
        return f"{spelling}({inner})"
    if isinstance(expr, Comparison):
        if isinstance(expr.right, Regex) or expr.op in ("matches", "=~", "!~"):
            pattern = expr.right
            if not isinstance(pattern, Regex):
                raise Refusal(
                    "SPL_RENDER_PATTERN",
                    f"`{render_expr(expr)}` is a pattern match whose right-hand "
                    f"side is not a pattern.",
                    "render",
                )
            # `(?i)` is PCRE's inline fold and `match()` is PCRE, so this is the
            # only place the fold can go. It used to be dropped here, which
            # made `=~ "ENC"` (KQL's ignore-case equality) a case-SENSITIVE
            # pattern on export.
            fold = "(?i)" if pattern.nocase else ""
            body = (
                f"match({_render_expression(expr.left)}, "
                f'"{fold}{pattern.pattern}")'
            )
            negated = expr.negate ^ (expr.op == "!~")
            return f"NOT {body}" if negated else body
        if expr.op in ("contains", "startswith", "endswith"):
            wildcards = {
                "contains": "*{0}*", "startswith": "{0}*", "endswith": "*{0}",
            }[expr.op]
            right = expr.right
            if not isinstance(right, Literal):
                raise Refusal(
                    "SPL_RENDER_SUBSTRING",
                    f"`{render_expr(expr)}` matches a substring against "
                    f"something that is not a constant. SPL expresses it as a "
                    f"wildcard literal, which needs one.",
                    "render",
                )
            body = (
                f"{_like_subject(expr)} LIKE "
                f'"{_like_body(expr.op, str(right.value), expr.nocase)}"'
            )
            # The INFIX spelling, matching how a `like` comparison renders a
            # few lines down. The function form `like(f, "%x")` was used here
            # and the infix form there, so a rule whose `endswith` came back
            # from a round trip as `like` rendered differently the second
            # time -- the same rule, two texts, and every save looking like an
            # edit.
            return f"NOT ({body})" if expr.negate else body
        if expr.op in ("in", "contains_any", "contains_all"):
            # `field IN (a, b)` is valid in BOTH places this renderer emits:
            # the search head and `| where` (eval accepts the `IN` keyword as
            # well as `in(f, ...)`). The previous refusal claimed the spelling
            # depended on the stage, which Splunk's documentation does not
            # support -- and refusing it meant any imported membership rule
            # could not be written back out at all.
            right = expr.right
            if not isinstance(right, ListExpr):
                raise Refusal(
                    "SPL_RENDER_MEMBERSHIP",
                    f"`{render_expr(expr)}` tests membership against something "
                    f"that is not a list. SPL spells the list inline, so there "
                    f"is nothing to write.",
                    "render",
                )
            if expr.op in ("contains_any", "contains_all"):
                raise Refusal(
                    "SPL_RENDER_MEMBERSHIP",
                    f"`{render_expr(expr)}` applies a substring test to every "
                    f"item, and SPL has no one spelling for that. Writing it "
                    f"as `IN` would compare whole values and match less.",
                    "render",
                )
            members = ", ".join(
                _render_expression(item) for item in right.items
            )
            negate = "NOT " if expr.negate else ""
            return f"{negate}{_render_expression(expr.left)} IN ({members})"
        spelling = _RENDER_OPS.get(expr.op)
        if spelling is None:
            raise Refusal(
                "SPL_RENDER_OPERATOR",
                f"`{expr.op}` has no SPL spelling in this renderer. It is "
                f"refused rather than approximated, because a comparison that "
                f"renders as a different operator is a different rule.",
                "render",
            )
        body = (
            f"{_render_expression(expr.left)} {spelling} "
            f"{_render_expression(expr.right)}"
        )
        return f"NOT ({body})" if expr.negate else body

    raise Refusal(
        "SPL_RENDER_EXPR",
        f"`{render_expr(expr)}` ({type(expr).__name__}) has no SPL spelling. It "
        f"is refused rather than skipped, because a dropped clause produces a "
        f"search that reads correctly and matches more events than it states.",
        "render",
    )


def _render_measure(measure: Measure) -> str:
    spelling = {
        "count": "count", "count_if": "count", "dcount": "dc",
        "make_set": "values", "make_list": "list", "sum": "sum",
        "avg": "avg", "min": "min", "max": "max", "stdev": "stdev",
        "earliest": "earliest", "latest": "latest",
    }.get(measure.function)
    if spelling is None:
        if measure.function == "percentile" and measure.param is not None:
            spelling = f"perc{int(measure.param)}"
        else:
            raise Refusal(
                "SPL_RENDER_AGGREGATE",
                f"`{measure.function}()` has no SPL spelling in this renderer.",
                "render",
            )
    inner = measure.field.full if measure.field is not None else ""
    if measure.condition is not None:
        if spelling != "count":
            raise Refusal(
                "SPL_RENDER_CONDITIONAL_AGGREGATE",
                "only count(eval(...)) has a faithful conditional aggregate "
                "spelling in SPL.",
                "render",
            )
        body = "count(eval(" + _render_expression(measure.condition) + "))"
    else:
        body = f"{spelling}({inner})" if inner else spelling
    default = f"{spelling}({inner})" if inner else "count"
    if measure.name and measure.name != default:
        return f"{body} as {measure.name}"
    return body


def _render_stage(node: Node, rule: Rule) -> list[str]:
    """One IR stage as `| command` lines. Ends in a refusal."""
    if isinstance(node, Read):
        return []
    if isinstance(node, Emit):
        # SPL has no output stage; the result is what the last command leaves.
        if node.keeps:
            return ["| fields " + ", ".join(k.full for k in node.keeps)]
        return []
    if isinstance(node, Filter):
        return ["| where " + _render_expression(node.condition)]
    if isinstance(node, Derive):
        return ["| eval " + ", ".join(
            f"{name} = {_render_expression(value)}"
            for name, value in node.assignments
        )]
    if isinstance(node, Project):
        if node.drops:
            return ["| fields - " + ", ".join(d.full for d in node.drops)]
        parts: list[str] = []
        if node.renames:
            parts.append("| rename " + ", ".join(
                f"{source.full} AS {target}" for source, target in node.renames
            ))
        if node.keeps:
            parts.append("| fields " + ", ".join(k.full for k in node.keeps))
        if not parts:
            # An identity projection. Emitting nothing is correct and is NOT a
            # silent drop: the node states that every column survives.
            return []
        return parts
    if isinstance(node, Aggregate):
        command = "tstats" if node.capability is Capability.DECLARED_ONLY else "stats"
        body = ", ".join(_render_measure(m) for m in node.measures)
        by: list[str] = []
        if node.window is not None and node.window.size is not None:
            by.append(f"_time span={_render_span(node.window.size)}")
        by.extend(key.full for key in node.keys)
        line = f"| {command} {body}"
        if by:
            line += " by " + ", ".join(by)
        return [line]
    if isinstance(node, Sort):
        body = ", ".join(
            ("-" if descending else "+") + key.full
            for key, descending in node.keys
        )
        head = f"| sort {node.limit} {body}" if node.limit else f"| sort {body}"
        return [head]
    if isinstance(node, Limit):
        return [f"| {'tail' if node.keep_last else 'head'} {node.count}"]
    if isinstance(node, Distinct):
        return ["| dedup " + ", ".join(k.full for k in node.keys)]
    if isinstance(node, Expand):
        # `mvexpand` expands IN PLACE: the expanded value stays under the
        # original field name. `Expand.into` renames it, and dropping that
        # rename left any later stage testing a field no event has -- so
        # `expand tags into tag | where tag == "x"` became
        # `| mvexpand tags | where tag="x"`, which matches nothing and says
        # nothing. The `eval` puts the value where the rest of the rule looks
        # for it.
        head = [f"| mvexpand {node.field.full}"]
        if node.into and node.into != node.field.full:
            head.append(f"| eval {node.into}={node.field.full}")
        return head
    if isinstance(node, Join):
        binding = next(
            (b for b in rule.bindings if b.name == node.right), None
        )
        if binding is None:
            raise Refusal(
                "SPL_RENDER_JOIN_NO_STREAM",
                f"`{node.id}` joins `{node.right}`, which is not a binding in "
                f"this rule. SPL writes the right-hand side as an inline "
                f"subsearch, so there is nothing to write.",
                "render",
            )
        keys = ", ".join(left.full for left, _ in node.on)
        # One line. A subsearch is delimited by brackets, not by newlines, and
        # Splunk rejects a multi-line one -- so rendering the nested stream with
        # line breaks produced SPL that reads correctly and will not run.
        inner = " ".join(
            line.strip()
            for line in _render_stream(binding.pipeline, rule).splitlines()
            if line.strip()
        )
        kind = {"inner": "inner", "left": "outer"}.get(node.how)
        if kind is None:
            raise Refusal(
                "SPL_RENDER_JOIN_TYPE",
                f"`{node.how}` has no SPL spelling. Splunk's join does inner and "
                f"outer only, and rendering a {node.how} join as one of those "
                f"would change which rows survive.",
                "render",
            )
        return [f"| join type={kind} {keys} [ search {inner} ]"]

    raise Refusal(
        "SPL_RENDER_STAGE",
        f"`{type(node).__name__}` has no SPL spelling in this renderer. It is "
        f"refused rather than skipped: a dropped stage produces a search that "
        f"looks complete with the detection missing.",
        "render",
    )


def _render_span(duration: Duration) -> str:
    seconds = int(duration.seconds)
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds and seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def _render_stream(pipeline: tuple[Node, ...], rule: Rule) -> str:
    read = next((n for n in pipeline if isinstance(n, Read)), None)
    if read is None:
        raise Refusal(
            "SPL_RENDER_NO_SOURCE",
            "this pipeline has no source stage, so there is no search to write. "
            "An SPL search with no index reads everything.",
            "render",
        )

    # `Read.selector` is a RAW DIALECT EXPRESSION -- its docstring says so -- so
    # it is only SPL when the rule came from SPL. Emitting a Sigma logsource
    # (`product=windows, category=process_access`) as a Splunk search produced
    # text that looks like SPL, parses as three bare terms, and searches for
    # fields no Splunk index has. The original is kept as a comment instead, so
    # a cross-dialect translation says what it could not map rather than
    # inventing a source.
    native = rule.metadata.get("dialect") == DIALECT
    lines: list[str] = []
    if read.selector.strip() and native:
        head = read.selector.strip()
    else:
        head = f"index={_bare(read.table)}" if read.table else "index=*"
        if read.selector.strip():
            lines.append(
                f"``` source selected in {rule.metadata.get('language', 'another dialect')} "
                f"as: {read.selector.strip()} -- map this to an index and "
                f"sourcetype before deploying ```"
            )

    lines.append(head)
    for node in pipeline:
        lines.extend(_render_stage(node, rule))
    return "\n".join(lines)


def render_splunk(rule: Rule) -> str:
    """Write a Rule back out as SPL.

    Annotations are NOT rendered, and that is a limit rather than an oversight:
    SPL has no syntax for a title, a severity or an ATT&CK mapping. Those live
    in a savedsearches.conf stanza, which is a different artifact -- and writing
    them as comments would put a rule's triage metadata somewhere no Splunk
    search reads.
    """
    return _render_stream(rule.pipeline, rule)
