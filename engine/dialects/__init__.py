"""The dialect registry: one lookup point for every vendor language.

Every caller above this package -- the HTTP API, the GUI, a test -- asks for a
dialect BY KEY and gets back functions. None of them import a vendor module
directly, which is what keeps vendor knowledge from leaking upward into code
that should not have it.

Three things make this a registry rather than a dict:

**Modules are imported on demand.** Eight parsers is a lot of import time to
pay for a caller that wanted one, and a half-finished dialect must not be able
to break `import dialects` for the seven that work.

**Unimplemented dialects are listed, not omitted.** A key with no module is
declared `planned`, so the GUI can show a greyed-out entry and `get()` can
answer "planned, not implemented" instead of "unknown dialect". A roadmap that
lives in data cannot drift from a roadmap that lives in a docstring -- which is
exactly what happened here before: three separate docstrings claimed eight
dialects while one existed.

**Capabilities are declared and then asserted.** `can_parse` and `can_render`
are written down per dialect, and `tests/test_dialects.py` imports every ready
dialect and fails if the declaration does not match the module. A dialect that
claims it can parse and cannot is worse than one that admits it cannot, because
the first silently returns an empty rule and the second refuses.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from types import ModuleType
from typing import Any, Callable, Final

from ..ir import Rule
from ..values import Refusal
from .common import Diagnostic

__all__ = [
    "Dialect",
    "REGISTRY",
    "all_dialects",
    "ready_dialects",
    "get",
    "load",
    "parse",
    "lower",
    "render",
    "catalogue",
]


@dataclass(frozen=True, slots=True)
class Dialect:
    """What the tool knows about one vendor language before importing it.

    `key` is the stable identifier. It is what the GUI sends, what the API
    takes, and what `Rule.metadata["dialect"]` already carries, so it must
    never change once a rule has been saved with it.
    """

    key: str
    label: str
    language: str
    #: Dotted module name relative to this package. None means "planned".
    module: str | None
    #: Attribute names the module exports. Dialects are not required to use a
    #: uniform `lower`/`render` naming -- `kql.py` predates this registry and
    #: exports `lower_kql` -- so the names are data rather than a convention
    #: that a new dialect could silently get wrong.
    parse_attr: str = "parse"
    lower_attr: str = "lower"
    render_attr: str = "render"
    can_parse: bool = False
    can_render: bool = False
    #: Whether a rendered rule carries `ir.Annotations` -- its title,
    #: description, severity, author, ATT&CK mapping and references.
    #:
    #: Declared rather than discovered, because the consequence of getting it
    #: wrong is silent. Five of these dialects rendered a Sigma rule's entire
    #: triage header as NOTHING: a query with no name to alert on, no severity
    #: to route by and no technique to attribute to. Sigma and YARA-L carry it
    #: natively, Wazuh has `<description>`, and KQL, AQL and EQL carry it as a
    #: comment header. SPL and FQL cannot -- see `_annotation_diagnostics`.
    carries_annotations: bool = False
    #: Shown in the UI next to a planned dialect, or as a known limitation of a
    #: ready one. Empty means no caveat worth surfacing.
    note: str = ""

    @property
    def ready(self) -> bool:
        return self.module is not None

    @property
    def status(self) -> str:
        return "ready" if self.ready else "planned"

    def as_dict(self) -> dict[str, Any]:
        """The shape the API hands a dialect picker."""
        return {
            "key": self.key,
            "label": self.label,
            "language": self.language,
            "status": self.status,
            "can_parse": self.can_parse,
            "can_render": self.can_render,
            "carries_annotations": self.carries_annotations,
            "note": self.note,
        }


#: Order is display order: ready dialects first, then planned ones roughly by
#: how cheap they are to add. Sigma is listed first among the planned because
#: it is YAML rather than a language, which makes it the cheapest real proof
#: that the IR is actually vendor-neutral rather than KQL-shaped.
#:
#: Planned entries already carry their `*_attr` names even though nothing can
#: call them yet. The convention is `<verb>_<key>` -- sigma.py exports
#: `lower_sigma`, not `lower` -- and leaving the attrs at their bare defaults
#: would mean that flipping a dialect to ready by setting `module=` alone made
#: it refuse with DIALECT_CAPABILITY_MISSING, looking for `lower` in a module
#: that exports `lower_sigma`. Writing the names down now makes going ready a
#: two-field change: the module and the capability flags. The convention is
#: pinned by tests/test_dialects.py so it cannot quietly drift back.
REGISTRY: Final[dict[str, Dialect]] = {
    d.key: d
    for d in (
        Dialect(
            key="sentinel",
            label="Microsoft Sentinel",
            language="KQL",
            module="kql",
            parse_attr="parse_kql",
            lower_attr="lower_kql",
            render_attr="render_kql",
            can_parse=True,
            can_render=True,
            carries_annotations=True,
            note=(
                "Annotations are not rendered: title, severity and MITRE "
                "mapping do not survive a round trip. Correlation renders as a "
                "comment, not executable KQL."
            ),
        ),
        Dialect(
            key="sigma",
            label="Sigma",
            language="Sigma YAML",
            module="sigma",
            parse_attr="parse_sigma",
            lower_attr="lower_sigma",
            render_attr="render_sigma",
            can_parse=True,
            can_render=True,
            carries_annotations=True,
            note=(
                "Metadata round-trips, unlike Sentinel: title, level, author and "
                "the ATT&CK tags all survive both directions. Keyword searches, "
                "the encoding modifiers (base64, utf16, windash) and temporal "
                "correlations are refused by name rather than approximated. "
                "Rendering refuses an OR across different fields, because "
                "splitting that into selections is a decision about the rule "
                "rather than a formatting one."
            ),
        ),
        Dialect(
            key="splunk",
            label="Splunk",
            language="SPL",
            module="splunk",
            parse_attr="parse_splunk",
            lower_attr="lower_splunk",
            render_attr="render_splunk",
            can_parse=True,
            can_render=True,
            note=(
                "Search syntax evaluates OR BEFORE AND, unlike every other "
                "dialect here, and that is honoured. Index-time terms "
                "(index=, sourcetype=) stay in the selector and are never run "
                "locally, so a non-match is reported as not-evaluated rather "
                "than as a confident no. SPL regex is PCRE and cannot be "
                "executed here. eventstats, streamstats, transaction, lookup "
                "and the append family are refused by name."
            ),
        ),
        Dialect(
            key="qradar",
            label="IBM QRadar",
            language="AQL",
            module="qradar",
            parse_attr="parse_qradar",
            lower_attr="lower_qradar",
            render_attr="render_qradar",
            can_parse=True,
            can_render=True,
            carries_annotations=True,
            note=(
                "AQL is SQL, so the clauses are written in an order that is "
                "not the order they run: SELECT is written first and executes "
                "LAST, after GROUP BY and HAVING. Lowering reorders them, "
                "because a projection placed ahead of a predicate drops the "
                "columns the predicate reads. `'x'` is a string and `\"x\"` is "
                "a column, as in SQL. `LAST 24 HOURS` is the Ariel time range "
                "and is kept on the source stage rather than evaluated. "
                "MATCHES is Java regex and cannot be executed here; LIKE and "
                "ILIKE can. A computed SELECT expression and a multi-source "
                "FROM are refused rather than guessed at."
            ),
        ),
        Dialect(
            key="elastic",
            label="Elastic Security",
            language="EQL",
            module="elastic",
            parse_attr="parse_elastic",
            lower_attr="lower_elastic",
            render_attr="render_elastic",
            can_parse=True,
            can_render=True,
            carries_annotations=True,
            note=(
                "EQL's `sequence` is the construct the IR gained a node for: "
                "`ir.Sequence` carries ORDER, which `Join` (unordered pairing) "
                "and `Correlation` (one repeated condition) cannot. `:` is a "
                "case-INSENSITIVE wildcard match and `==` is exact, so "
                "collapsing them narrows or widens every rule that used the "
                "other. The event category is a predicate on "
                "`event.category`, not an index name. `maxspan` bounds the "
                "whole sequence and `until` cancels a partial one. Regex goes "
                "to Elasticsearch and cannot be executed here; `:` and "
                "`wildcard()` are globs and can. `sample` and the aggregating "
                "pipes are refused by name."
            ),
        ),
        Dialect(
            key="wazuh",
            label="Wazuh",
            language="Wazuh XML",
            module="wazuh",
            parse_attr="parse_wazuh",
            lower_attr="lower_wazuh",
            render_attr="render_wazuh",
            can_parse=True,
            can_render=True,
            carries_annotations=True,
            note=(
                "An empty rule, an empty matcher and an unknown element are all "
                "REFUSED, because in Wazuh an absence is a match. `<match>` is a "
                "substring test and runs locally; `<regex>` is OS-Regex and "
                "`<pcre2>` is PCRE2, and neither can be executed here. "
                "`if_sid` becomes a source precondition while `if_matched_sid` "
                "becomes a threshold -- they are different rules. A document "
                "holding several rules must name which one to lower."
            ),
        ),
        Dialect(
            key="chronicle",
            label="Google SecOps",
            language="YARA-L 2.0",
            module="chronicle",
            parse_attr="parse_chronicle",
            lower_attr="lower_chronicle",
            render_attr="render_chronicle",
            can_parse=True,
            can_render=True,
            carries_annotations=True,
            note=(
                "In `events:` the same `=` is equality, a regex test, or a "
                "VARIABLE BINDING depending on the right-hand side, and a "
                "binding filters nothing -- reading it as a comparison makes "
                "the rule match nothing. `#e` is an event COUNT, not a field, "
                "and `#e > 5` is strict so it lowers to a frequency of six. "
                "`match:` supplies the group keys a threshold needs. Regex is "
                "RE2 and DOES execute here, unlike PCRE and Java, because RE2 "
                "has no backreferences or lookaround and so cannot outrun the "
                "portable screen. `meta:` round-trips through ir.Annotations. "
                "A rule correlating two event variables is a join and is "
                "refused rather than flattened."
            ),
        ),
        Dialect(
            key="crowdstrike",
            label="CrowdStrike Falcon",
            language="FQL",
            module="crowdstrike",
            parse_attr="parse_crowdstrike",
            lower_attr="lower_crowdstrike",
            render_attr="render_crowdstrike",
            can_parse=True,
            can_render=True,
            note=(
                "FQL is a filter and nothing more: `+` is AND and `,` is OR, "
                "which is the reverse of how every other list syntax reads, so "
                "a comma meant as AND widens the rule to the union. `:` "
                "introduces a matcher whose prefix is part of the operator "
                "(`:!` not-equal, `:*` wildcard, `:>=` ordering, `:[a,b]` "
                "membership). The wildcard is a GLOB, not a regex. There is no "
                "aggregation, sort, limit, join or correlation, so a rule that "
                "counts or correlates is REFUSED on render rather than having "
                "its threshold dropped."
            ),
        ),
    )
}

#: Imported modules, keyed by (dialect key, module name). A dialect is imported
#: at most once -- but the module name is part of the key deliberately. Keying on
#: the dialect key alone meant that repointing a registry entry at a DIFFERENT
#: module still handed back the first module ever imported under that key, so a
#: test (or an integration step) that swapped the entry was silently served the
#: stale module and proved nothing.
_LOADED: dict[tuple[str, str], ModuleType] = {}


def all_dialects() -> tuple[Dialect, ...]:
    """Every dialect the tool knows about, ready or planned."""
    return tuple(REGISTRY.values())


def ready_dialects() -> tuple[Dialect, ...]:
    """Only the dialects with a module behind them."""
    return tuple(d for d in REGISTRY.values() if d.ready)


def catalogue() -> list[dict[str, Any]]:
    """The dialect list as plain data, for an API response or a picker."""
    return [d.as_dict() for d in REGISTRY.values()]


def get(key: str) -> Dialect:
    """The registry entry for `key`, or a refusal that says what is available.

    A planned dialect and an unknown dialect get DIFFERENT refusals. "Sigma is
    planned" sends the caller to the roadmap; "sigma is not a dialect" sends
    them hunting for a typo they did not make.
    """
    entry = REGISTRY.get((key or "").strip().lower())
    if entry is None:
        known = ", ".join(sorted(REGISTRY))
        raise Refusal(
            "DIALECT_UNKNOWN",
            f"`{key}` is not a dialect this tool knows. Available: {known}.",
            "registry",
        )
    if not entry.ready:
        raise Refusal(
            "DIALECT_NOT_IMPLEMENTED",
            f"{entry.label} ({entry.language}) is a planned dialect with no "
            f"implementation yet. {entry.note}".strip(),
            "registry",
        )
    return entry


def load(key: str) -> ModuleType:
    """Import a ready dialect's module, once.

    The cache is keyed on the module name as well as the dialect key, so an
    entry that is repointed at another module is re-imported rather than served
    the previous one.
    """
    entry = get(key)
    assert entry.module is not None  # get() refuses planned dialects
    cache_key = (entry.key, entry.module)
    cached = _LOADED.get(cache_key)
    if cached is not None:
        return cached
    module = importlib.import_module(f".{entry.module}", __name__)
    _LOADED[cache_key] = module
    return module


def _function(key: str, attr: str, capability: str) -> Callable[..., Any]:
    entry = get(key)
    module = load(key)
    func = getattr(module, attr, None)
    if func is None or not callable(func):
        raise Refusal(
            "DIALECT_CAPABILITY_MISSING",
            f"{entry.label} is registered as able to {capability}, but its "
            f"module does not export `{attr}`. The registry and the module "
            f"disagree, so nothing here can be trusted to {capability} "
            f"correctly.",
            "registry",
        )
    return func


def parse(key: str, text: str) -> Any:
    """Native rule text to that dialect's own parsed structure.

    Rarely what a caller wants. `lower` is the useful entry point; this exists
    for tests and for showing an analyst how their text was split.
    """
    entry = get(key)
    if not entry.can_parse:
        raise Refusal(
            "DIALECT_CANNOT_PARSE",
            f"{entry.label} rules cannot be read in yet -- this dialect can "
            f"only be written out. {entry.note}".strip(),
            "registry",
        )
    return _function(key, entry.parse_attr, "parse")(_without_bom(text))


def _without_bom(text: str) -> str:
    """Rule text with any leading byte-order mark removed.

    A UTF-8 BOM decodes to `\\ufeff`, and it silently corrupts the FIRST
    token of a rule: a Sigma file saved by a Windows editor parsed its opening
    key as `\\ufefftitle`, so the title vanished and the tool reported "this
    rule has no title" about a rule whose first line was the title. In a
    dialect where the first token is a field name rather than a key, the same
    BOM renames the field.

    Windows editors, PowerShell redirection and Git on Windows all produce
    them, so this is the common case for a pasted file rather than an exotic
    one. Stripped at the seam every caller goes through, rather than in eight
    separate parsers.
    """
    return text.lstrip("\ufeff") if text else text


def lower(key: str, text: str, rule_id: str = "rule") -> tuple[Rule, list[Diagnostic]]:
    """Native rule text to a Rule, plus what could not be represented.

    This is the import half of paste-and-tune: the function the GUI calls when
    an analyst pastes a rule they did not write.
    """
    entry = get(key)
    if not entry.can_parse:
        raise Refusal(
            "DIALECT_CANNOT_PARSE",
            f"{entry.label} rules cannot be read in yet -- this dialect can "
            f"only be written out. {entry.note}".strip(),
            "registry",
        )
    try:
        return _function(key, entry.lower_attr, "parse")(
            _without_bom(text), rule_id
        )
    except RecursionError as error:
        raise Refusal(
            "INPUT_TOO_DEEPLY_NESTED",
            "this rule nests parentheses or sub-expressions far deeper than any "
            "real rule does, and was refused before it could exhaust the parser. "
            "Flatten it, or split it into several rules.",
            "parse",
        ) from error
    except ValueError as error:
        if "digits" in str(error):
            raise Refusal(
                "INPUT_NUMBER_TOO_LONG",
                "a number in this rule has thousands of digits. That is not a "
                "threshold or an id; quote it if it is meant as text.",
                "parse",
            ) from error
        raise


def _transfer_diagnostics(key: str, rule: Rule) -> list[Diagnostic]:
    """What this rule loses by being written out in a different language.

    Rendering across dialects is the one operation in this package that can
    make a detection BROADER while reporting success -- the defect
    `render_kql`'s docstring names. A Wazuh rule carrying `<if_sid>5700</if_sid>`
    lowers to `Read.selector='if_sid=5700'`, a PRECONDITION limiting it to
    events a parent rule already matched. Rendered to KQL that selector is
    gone, and the result fires on every event the filter matches rather than
    the handful the parent passed.

    The renderers are not wrong to drop it. `Read.selector` is RAW DIALECT
    TEXT, so reusing a foreign one is worse than losing it: parsing an SPL
    `index=main` as a Sigma logsource once produced a key called `index` that
    no backend maps. `sigma.py` guards against exactly that, and `kql.py`
    never writes a selector at all.

    What was missing is the report. Dropping a narrowing clause is defensible;
    dropping it in silence is the thing this codebase exists to prevent. The
    audit lives here rather than in the four renderers because transferability
    needs BOTH the source dialect and the target, and a renderer handed a rule
    only knows its own.
    """
    source = (rule.metadata.get("dialect") or "").strip()
    if not source or source == key:
        # Same language in and out: the renderer round-trips its own selector
        # verbatim, which the per-dialect round-trip tests assert.
        return []

    source_label = REGISTRY[source].label if source in REGISTRY else source
    target_label = REGISTRY[key].label

    # Bindings are walked as well as the main pipeline. A Splunk join subsearch
    # becomes a Binding with its OWN Read, so `[ search index=threat ... ]`
    # carries a selector that is just as narrowing and just as droppable as the
    # outer one. Auditing only `rule.pipeline` reported the outer loss and
    # stayed quiet about the inner one, which is the same defect with a smaller
    # blast radius.
    streams: list[tuple[str, tuple[Any, ...]]] = [("", rule.pipeline)]
    streams.extend((binding.name, binding.pipeline) for binding in rule.bindings)

    notes: list[Diagnostic] = []
    for owner, stream in streams:
        for node in stream:
            selector = getattr(node, "selector", "")
            if not isinstance(selector, str) or not selector.strip():
                continue
            where = f"the `{owner}` sub-stream" if owner else "the source stage"
            notes.append(
                Diagnostic(
                    code="SELECTOR_NOT_TRANSFERABLE",
                    message=(
                        f"{where} narrows the input with "
                        f"`{selector.strip()}`, which is {source_label} text "
                        f"and has NOT been written into the {target_label} "
                        f"output. Re-express it for {target_label} before "
                        f"deploying: without it this rule reads more events "
                        f"than the original and so can match where the "
                        f"original would not."
                    ),
                    severity="problem",
                    verified=True,
                )
            )
    return notes


def _annotation_diagnostics(key: str, rule: Rule) -> list[Diagnostic]:
    """What a rule's triage header loses by being written out in `key`.

    `ir.Annotations` is the part of a rule a SOC acts on: the name an alert
    fires under, the severity it is routed by, the technique it is attributed
    to. Five of these dialects rendered all of it as nothing, so converting a
    Sigma rule -- the most common thing this tool will be asked to do -- came
    out as an unnamed, unrated query. The text looked complete and the call
    reported success.

    Three of those five now write a comment header and read it back. SPL and
    FQL genuinely cannot: `render_splunk`'s docstring makes the argument, which
    is that SPL's metadata lives in a `savedsearches.conf` stanza and a comment
    would put triage data somewhere no Splunk search reads; and FQL is a single
    filter string with no comment syntax at all. Those two drop it -- but they
    now SAY so, which is the whole difference.
    """
    entry = REGISTRY.get(key)
    if entry is None or entry.carries_annotations:
        return []

    annotations = rule.annotations
    present = [
        name for name in ("title", "description", "severity", "author")
        if getattr(annotations, name, "")
    ]
    if annotations.mitre_attack:
        present.append("ATT&CK mapping")
    if annotations.references:
        present.append("references")
    if annotations.false_positives:
        present.append("known false positives")
    if not present:
        # Nothing to lose. A warning here would fire on every hand-written
        # rule and train the analyst to dismiss the one that matters.
        return []

    return [Diagnostic(
        code="ANNOTATIONS_NOT_TRANSFERABLE",
        message=(
            f"{entry.label} has no syntax for a rule's triage header, so its "
            f"{', '.join(present)} {'is' if len(present) == 1 else 'are'} NOT "
            f"in the output. The detection logic is complete; what is missing "
            f"is the name the alert fires under and the severity it is routed "
            f"by, so record {'it' if len(present) == 1 else 'them'} wherever "
            f"{entry.label} keeps rule metadata before deploying this."
        ),
        severity="caution",
        verified=True,
    )]


def _comparisons(rule: Rule) -> list[dict[str, Any]]:
    """Every comparison in a rule, flattened, in pipeline order.

    `comparable` is False when the comparison was not written against a plain
    field -- `lower(User) LIKE "%bob%"` comes back with a Call on the left. The
    audit then has nothing it can line up, and guessing would be worse than
    saying nothing.
    """
    found: list[dict[str, Any]] = []
    streams = [rule.pipeline] + [b.pipeline for b in rule.bindings]

    def walk(expr: Any, negated: bool = False) -> None:
        if expr is None:
            return
        name = type(expr).__name__
        if name == "Not":
            walk(expr.operand, not negated)
            return
        if name == "Comparison":
            right = expr.right
            value = ""
            fold = bool(getattr(expr, "nocase", False))
            if type(right).__name__ == "Regex":
                value = right.pattern
                fold = fold or bool(right.nocase)
            elif type(right).__name__ == "Literal":
                value = _literal_text(right.value)
            elif type(right).__name__ == "ListExpr":
                value = "|".join(
                    _literal_text(item.value) for item in right.items
                    if type(item).__name__ == "Literal"
                )
            flipped = bool(expr.negate) != negated
            op = expr.op
            if flipped and op == "==":
                op = "!="
            elif flipped and op == "!=":
                op = "=="
            found.append({
                "op": op,
                "fold": fold,
                "value": value,
                "comparable": type(expr.left).__name__ == "FieldRef",
            })
            return
        for attribute in ("operands", "operand", "left", "right"):
            child = getattr(expr, attribute, None)
            if isinstance(child, (list, tuple)):
                for item in child:
                    walk(item, negated)
            elif child is not None and hasattr(child, "op"):
                walk(child, negated)

    for stream in streams:
        for node in stream:
            walk(getattr(node, "condition", None))
            walk(getattr(node, "predicate", None))
            for step in getattr(node, "steps", ()) or ():
                walk(getattr(step, "condition", None))
    return found


def _literal_text(value: Any) -> str:
    return "" if value is None else str(value)


def _wildcard_neutral(text: str) -> str:
    """`%` and `*` are the same wildcard in different languages."""
    return text.replace("%", "*").replace("_", "?")


def _fidelity_diagnostics(key: str, rule: Rule, text: str) -> list[Diagnostic]:
    """What the rendered text means compared with what the rule meant.

    "Rendered without raising" was being treated as fidelity. Nothing compared
    the operator, the case fold or the value before and after, so a dropped
    case fold and an inverted `!=` both came back with an EMPTY diagnostic list
    and the pane reported success.

    The check is a round trip: read the dialect's own output back and compare
    each comparison with the one it was written from.

    It is deliberately conservative. A diagnostic that fires on a CORRECT
    render is the same fault as a pane that says "nothing was lost" over a
    lossy one, so a comparison is only reported when both readings line up:
    the same field, the same operator. `QRadar LIKE` and `Splunk lower(x)` are
    both case-insensitive without carrying a fold flag, and neither is called a
    loss. Silence on a real loss is the old behaviour; a false alarm would be a
    new bug.
    """
    entry = REGISTRY.get(key)
    if entry is None or not entry.can_parse:
        return []
    try:
        again, _ = lower(key, text, rule.rule_id)
    except Refusal:
        # The dialect cannot read its own output. That is a parser gap, and
        # guessing at what it means would be worse than saying nothing.
        return []

    before = _comparisons(rule)
    after = _comparisons(again)
    if not before or len(before) != len(after):
        return []

    notes: list[Diagnostic] = []
    for original, reread in zip(before, after):
        if not original["comparable"] or not reread["comparable"]:
            continue
        if (original["op"] != reread["op"]
                and {original["op"], reread["op"]} == {"==", "!="}):
            notes.append(Diagnostic(
                code="RENDER_OPERATOR_CHANGED",
                message=(
                    f"`{original['op']}` came back as `{reread['op']}` when "
                    f"{entry.label} read its own output: the comparison is "
                    f"INVERTED, so the rendered rule matches the rows the "
                    f"original was written to exclude."
                ),
                severity="problem",
                verified=True,
            ))
            continue
        if original["op"] != reread["op"]:
            # The dialect spells the operator differently on the way back in
            # (`contains` as `LIKE`, `matches` as a field test). Comparing a
            # fold across two different operators is how a false alarm is
            # manufactured, so the rest of the check needs the same operator.
            continue
        if original["fold"] and not reread["fold"]:
            notes.append(Diagnostic(
                code="RENDER_CASE_FOLD_LOST",
                message=(
                    f"`{original['value']}` was matched regardless of case in "
                    f"this rule, and {entry.label} matches it EXACTLY. The "
                    f"rendered rule is narrower than the one it came from."
                ),
                severity="problem",
                verified=True,
            ))
            continue
        if reread["fold"] and not original["fold"]:
            # The mirror image, and the more dangerous one: the source matched
            # this value EXACTLY and the target cannot say so (FQL's `:` and
            # Sigma without `|cased` fold unconditionally). Silence here meant an
            # exact-case rule fired on every capitalisation after export.
            notes.append(Diagnostic(
                code="RENDER_CASE_FOLD_ADDED",
                message=(
                    f"`{original['value']}` was matched EXACTLY in this rule, "
                    f"and {entry.label} matches it regardless of case. The "
                    f"rendered rule is wider than the one it came from."
                ),
                severity="problem",
                verified=True,
            ))
            continue
        if (original["value"] and reread["value"]
                and original["value"] != reread["value"]
                and _wildcard_neutral(original["value"])
                != _wildcard_neutral(reread["value"])
                and "\\" not in original["value"] + reread["value"]):
            notes.append(Diagnostic(
                code="RENDER_VALUE_REINTERPRETED",
                message=(
                    f"`{original['value']}` was written as "
                    f"`{reread['value']}` and {entry.label} reads that back as "
                    f"a different value, so the rendered rule tests something "
                    f"the original did not."
                ),
                severity="problem",
                verified=True,
            ))
    return notes


def render(key: str, rule: Rule) -> tuple[str, list[Diagnostic]]:
    """A Rule back out as native text in `key`'s language.

    Returns the text AND what the text does not say, mirroring `lower`. The
    second half is not optional decoration: rendering into a dialect other
    than the rule's own silently drops the source selector, and a dialect with
    no metadata syntax silently drops the rule's whole triage header. A caller
    that shows only the text shows a rule that is broader, or more anonymous,
    than the one it was given. See `_transfer_diagnostics` and
    `_annotation_diagnostics`.
    """
    entry = get(key)
    if not entry.can_render:
        raise Refusal(
            "DIALECT_CANNOT_RENDER",
            f"{entry.label} rules cannot be written out yet. {entry.note}".strip(),
            "registry",
        )
    text = _function(key, entry.render_attr, "render")(rule)
    return text, (
        _transfer_diagnostics(entry.key, rule)
        + _annotation_diagnostics(entry.key, rule)
        + _fidelity_diagnostics(entry.key, rule, text)
    )
