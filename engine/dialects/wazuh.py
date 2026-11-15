"""Wazuh XML: the dialect this codebase's architecture was built around.

Several docstrings in this package cite one defect as the reason nothing here
is allowed a silent fallback -- `render_kql`'s names it directly: "the defect
that once made a Wazuh rule match every event while reporting success." This
module is the one most able to reproduce it, because in Wazuh an absence is a
match. A `<rule>` with no matchers fires on every event the parent passed; a
matcher that gets dropped widens the detection and nothing says so.

So this module refuses in places another dialect would shrug:

* An empty `<rule>` is REFUSED, not lowered to a pass-through.
* An unrecognised element is REFUSED BY NAME, never skipped.
* A `<group>` holding several rules is REFUSED unless the caller says which one,
  because lowering the first and discarding the rest hides detections.

Three Wazuh-specific decisions worth stating:

**`<match>` is a substring test, `<regex>` is OS-Regex, `<pcre2>` is PCRE2, and
they are not interchangeable.** OS-Regex has no grouping parentheses and no
bracket classes, so `(a|b)` and `[a-z]` are partly literal text in Wazuh and are
operators everywhere else. `evaluate.py` therefore refuses to execute both
`os_regex` and `pcre2` locally. `<match>` lowers to `contains`, which does
execute -- and that is what most real Wazuh rules use, so most of them stay
testable.

**`<if_sid>` and `<if_matched_sid>` are different things.** `if_sid` is a
PRECONDITION: this rule only looks at events the parent rule already matched. It
narrows the input, so it belongs on the source stage. `if_matched_sid` is a
CORRELATION: fire when the parent matched N times inside a timeframe. It is a
threshold over a stream, so it becomes `ir.Correlation`. Treating the first as
the second invents a threshold the rule does not have; treating the second as
the first drops the threshold entirely and fires on a single event.

**`<same_source_ip>` and friends are the correlation's group_by.** Dropping them
turns a per-host threshold into a global one -- five failures spread across five
machines would fire a rule that means five failures on ONE machine.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field as dc_field
from decimal import Decimal
from typing import Any, Final

from ..ir import (
    Aggregate,
    Annotations,
    BoolOp,
    Call,
    Comparison,
    Correlation,
    Emit,
    Expr,
    FieldRef,
    Filter,
    Literal,
    Not,
    Read,
    Regex,
    Rule,
    render_expr,
)
from ..validate import validate
from ..values import Duration, Refusal, duration_seconds
from .common import plain_number, Diagnostic

__all__ = [
    "DIALECT",
    "LANGUAGE",
    "MATCHERS",
    "FIELD_ELEMENTS",
    "SAME_ELEMENTS",
    "IGNORED_ELEMENTS",
    "ParsedWazuh",
    "parse_wazuh",
    "lower_wazuh",
    "render_wazuh",
]

DIALECT: Final = "wazuh"
LANGUAGE: Final = "Wazuh XML"

#: Elements that test the raw log text. Each carries its own semantics.
MATCHERS: Final[dict[str, str]] = {
    "match": "contains",     # plain substring
    "regex": "matches",      # OS-Regex
    "pcre2": "matches",      # real PCRE2
}

#: Elements that test a named field of the decoded event.
FIELD_ELEMENTS: Final[dict[str, str]] = {
    "srcip": "srcip",
    "dstip": "dstip",
    "srcport": "srcport",
    "dstport": "dstport",
    "user": "dstuser",
    "srcuser": "srcuser",
    "dstuser": "dstuser",
    "program_name": "program_name",
    "hostname": "hostname",
    "id": "id",
    "status": "status",
    "url": "url",
    "extra_data": "extra_data",
    "location": "location",
    "action": "action",
    "data": "data",
    "system_name": "system_name",
    "protocol": "protocol",
    "compiled_rule": "compiled_rule",
}

#: Correlation group keys. `different_*` is the inverse and is refused, because
#: the IR groups rows together and has no "these must differ" grouping.
SAME_ELEMENTS: Final[dict[str, str]] = {
    "same_source_ip": "srcip",
    "same_src_ip": "srcip",
    "same_dest_ip": "dstip",
    "same_destination_ip": "dstip",
    "same_source_port": "srcport",
    "same_dst_port": "dstport",
    "same_id": "id",
    "same_user": "dstuser",
    "same_location": "location",
    "same_field": "field",
    "same_agent": "agent",
}

#: Carried as metadata or annotations rather than as predicates.
#:
#: `list` and `check_diff` were in here and they are NOT metadata -- both are
#: PREDICATES. `<list field="srcip" lookup="address_match_key">blacklist</list>`
#: means "srcip appears in this CDB list", and skipping it left the rest of
#: the rule matching alone: strictly broader, with no diagnostic. That is the
#: silent widening the refusal a few lines below exists to prevent, happening
#: by way of this very set. They are handled by `_appliance_predicate` now.
IGNORED_ELEMENTS: Final[frozenset[str]] = frozenset({
    "description", "group", "mitre", "var", "comment",
})

#: Elements that TEST something the appliance holds and this engine does not.
#:
#: A CDB list lives in a file on the manager; `check_diff` compares against
#: the value the manager saw last time. Neither can be evaluated from a sample
#: of events, so they are modelled as appliance-only calls: preserved,
#: rendered back, and reported as not locally testable -- rather than dropped,
#: which widened the rule, or refused, which would reject a large part of the
#: stock Wazuh ruleset.
APPLIANCE_ELEMENTS: Final[frozenset[str]] = frozenset({
    "list", "check_diff",
})

#: Carried verbatim so a round trip does not lose them.
#:
#: `<options>no_full_log</options>` suppresses the full log in the alert and
#: `<info>` carries the analyst's reference link. Neither changes what the
#: rule matches, and both were silently discarded.
TEXT_ELEMENTS: Final[frozenset[str]] = frozenset({"options", "info"})

_LEVEL_SEVERITY: Final[tuple[tuple[int, str], ...]] = (
    (15, "critical"), (12, "critical"), (10, "high"), (7, "medium"),
    (4, "low"), (0, "informational"),
)

_ENTITY = re.compile(r"<!(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ParsedWazuh:
    """The rule elements, split but not interpreted."""

    rules: list[Any] = dc_field(default_factory=list)
    group_names: tuple[str, ...] = ()
    raw: str = ""


def parse_wazuh(text: str) -> ParsedWazuh:
    """Read the XML and find the `<rule>` elements.

    Entity declarations are refused before parsing rather than handled, because
    Wazuh rules reaching this tool are untrusted input and an expanding entity
    is a denial of service against whoever pasted it. ElementTree does not
    resolve external entities, but it does expand internal ones.
    """
    body = (text or "").strip()
    if not body:
        raise Refusal(
            "WAZUH_EMPTY",
            "there is no rule here. An empty ruleset is not a rule that matches "
            "nothing; it is a file with no detection in it.",
            "parse",
        )
    if _ENTITY.search(body):
        raise Refusal(
            "WAZUH_XML_ENTITY",
            "this document declares an XML entity. Entity expansion is a "
            "denial-of-service vector and a rule has no legitimate use for one, "
            "so the document is refused rather than parsed.",
            "parse",
        )

    # A bare `<rule>` with no enclosing `<group>` is legal and common.
    wrapped = body if body.lstrip().startswith("<group") else f"<group>{body}</group>"
    try:
        root = ElementTree.fromstring(wrapped)
    except ElementTree.ParseError as exc:
        raise Refusal(
            "WAZUH_XML_MALFORMED",
            f"this is not well-formed XML: {exc}.",
            "parse",
        ) from exc

    rules = list(root.iter("rule"))
    if not rules:
        raise Refusal(
            "WAZUH_NO_RULE",
            "this document contains no `<rule>` element.",
            "parse",
        )

    names = tuple(
        name.strip()
        for name in (root.get("name") or "").split(",")
        if name.strip()
    )
    return ParsedWazuh(rules=rules, group_names=names, raw=text or "")


# ---------------------------------------------------------------------------
# Lower
# ---------------------------------------------------------------------------


def _text_of(element: Any) -> str:
    return (element.text or "").strip()


def _negated(element: Any) -> tuple[bool, str]:
    """Read BOTH spellings of negation and return the bare value.

    `negate="yes"` is the attribute form and a leading `!` is the inline form.
    Dropping either inverts the detection, so both are read here rather than in
    the caller, where one of the two would eventually be forgotten.
    """
    negate = (element.get("negate") or "").strip().lower() in ("yes", "true", "1")
    value = _text_of(element)
    if value.startswith("!"):
        negate = not negate
        value = value[1:].strip()
    return negate, value


def _regex_dialect(tag: str) -> str:
    # `<regex>` is OS-Regex and `<pcre2>` is PCRE2. Both are refused for local
    # execution by evaluate.py, for different and equally good reasons.
    return "pcre2" if tag == "pcre2" else "os_regex"


def _matcher_predicate(element: Any, tag: str) -> Expr:
    negate, value = _negated(element)
    if not value:
        raise Refusal(
            "WAZUH_MATCHER_EMPTY",
            f"`<{tag}>` is empty, so it tests nothing. An empty matcher in "
            f"Wazuh succeeds against every event, which is the defect this "
            f"tool refuses to produce.",
            "lower",
        )

    if tag == "match":
        # A plain substring over the raw log line. This one DOES evaluate here.
        return Comparison("contains", FieldRef("full_log"), Literal(value),
                          negate=negate)
    return Comparison(
        "matches", FieldRef("full_log"),
        Regex(value, dialect=_regex_dialect(tag)), negate=negate,
    )


def _field_predicate(element: Any, tag: str) -> Expr:
    negate, value = _negated(element)
    if tag == "field":
        name = (element.get("name") or "").strip()
        if not name:
            raise Refusal(
                "WAZUH_FIELD_NO_NAME",
                "`<field>` has no `name` attribute, so which decoded field it "
                "tests is unstated.",
                "lower",
            )
    else:
        name = FIELD_ELEMENTS[tag]

    if not value:
        raise Refusal(
            "WAZUH_MATCHER_EMPTY",
            f"`<{tag}>` is empty, so it tests nothing and matches every event.",
            "lower",
        )

    # Wazuh treats these values as OS-Regex unless they are plainly literal.
    # Modelled as a regex when it carries regex syntax, and as equality when it
    # does not -- reading a literal as a pattern would make `10.0.0.1` match
    # `10X0Y0Z1`, because `.` is a metacharacter.
    if any(ch in value for ch in "^$|*+\\"):
        return Comparison(
            "matches", FieldRef.parse(name),
            Regex(value, dialect="os_regex"), negate=negate,
        )
    return Comparison("==", FieldRef.parse(name), Literal(value), negate=negate)


def _severity(level: str) -> str:
    try:
        numeric = int(level)
    except (TypeError, ValueError):
        return ""
    for threshold, name in _LEVEL_SEVERITY:
        if numeric >= threshold:
            return name
    return "informational"


def _annotations(element: Any, groups: tuple[str, ...]) -> Annotations:
    description = ""
    info: list[str] = []
    techniques: list[str] = []
    rule_groups: list[str] = list(groups)

    for child in element:
        if child.tag == "description":
            description = _text_of(child)
        elif child.tag == "info":
            value = _text_of(child)
            if value:
                info.append(value)
        elif child.tag == "group":
            rule_groups.extend(
                part.strip() for part in _text_of(child).split(",") if part.strip()
            )
        elif child.tag == "mitre":
            techniques.extend(
                _text_of(technique).upper()
                for technique in child.iter("id")
                if _text_of(technique)
            )

    mitre: tuple[tuple[str, tuple[str, ...]], ...] = ()
    if techniques:
        # Wazuh names techniques and not tactics, so the tactic is left empty
        # rather than guessed. Inventing one would assert something the rule
        # does not say, and the technique id is what a SOC pivots on anyway.
        mitre = (("", tuple(techniques)),)

    return Annotations(
        title=description,
        description=description,
        severity=_severity(element.get("level") or ""),
        author="",
        mitre_attack=mitre,
        references=tuple(info),
        false_positives=(),
    )


def _correlation_group(element: Any, diagnostics: list[Diagnostic]) -> list[FieldRef]:
    keys: list[FieldRef] = []
    for child in element:
        if child.tag in SAME_ELEMENTS:
            name = SAME_ELEMENTS[child.tag]
            if child.tag == "same_field":
                named = (child.get("name") or _text_of(child)).strip()
                if not named:
                    raise Refusal(
                        "WAZUH_SAME_FIELD_NO_NAME",
                        "`<same_field>` does not name a field, so what the "
                        "threshold groups on is unstated -- and an ungrouped "
                        "threshold counts across the whole log.",
                        "lower",
                    )
                name = named
            keys.append(FieldRef.parse(name))
        elif child.tag.startswith("different_"):
            raise Refusal(
                "WAZUH_DIFFERENT_NOT_SUPPORTED",
                f"`<{child.tag}>` requires that the grouped events DIFFER on a "
                f"field. The IR groups rows that share a key and has no "
                f"inverse, so lowering this as a normal group_by would invert "
                f"what the rule counts.",
                "lower",
            )
    return keys


def _appliance_predicate(element: Any, tag: str) -> Expr:
    """`<list>` or `<check_diff>` as a predicate this engine cannot run.

    Both TEST something the manager holds: a CDB file on disk, or the value
    the manager saw for this field last time. Neither can be answered from a
    sample of events.

    Modelled rather than dropped, which is what used to happen -- a rule whose
    source IP had to appear in a blacklist came through as the rest of the
    rule alone, matching everything the blacklist was there to narrow.
    Modelled rather than refused, because `<list>` appears throughout the
    stock Wazuh ruleset and refusing it would reject most of it.

    The flag carries the capability, so `pipeline.py` reports the stage as not
    locally executable instead of computing an answer it cannot have.
    """
    if tag == "check_diff":
        return Call("check_diff", (FieldRef.parse("full_log"),),
                    flags=("appliance",))

    field = (element.get("field") or "").strip()
    lookup = (element.get("lookup") or "match_key").strip()
    path = _text_of(element).strip()
    if not field or not path:
        raise Refusal(
            "WAZUH_LIST_INCOMPLETE",
            f"`<list>` needs a `field` and a path to the list, and this one "
            f"has {'no field' if not field else 'no path'}. It is a test "
            f"against a CDB list, so without both there is nothing to test "
            f"and the rule would silently widen to whatever remains.",
            "lower",
        )
    return Call(
        "lookup",
        (FieldRef.parse(field), Literal(path), Literal(lookup)),
        flags=("appliance",),
    )


def _lower_rule(
    element: Any, groups: tuple[str, ...], diagnostics: list[Diagnostic]
) -> tuple[list[Any], Annotations, dict[str, str]]:
    rule_id = (element.get("id") or "").strip()
    if not rule_id:
        raise Refusal(
            "WAZUH_RULE_NO_ID",
            "this `<rule>` has no `id`. Every reference to a Wazuh rule -- "
            "if_sid, if_matched_sid, every override -- is by id.",
            "lower",
        )

    predicates: list[Expr] = []
    parents: list[str] = []
    matched_parent = ""
    unknown: list[str] = []
    carried: dict[str, list[str]] = {}

    for child in element:
        tag = child.tag
        if tag in MATCHERS:
            predicates.append(_matcher_predicate(child, tag))
        elif tag in FIELD_ELEMENTS or tag == "field":
            predicates.append(_field_predicate(child, tag))
        elif tag == "if_sid":
            parents.extend(
                part.strip() for part in _text_of(child).split(",") if part.strip()
            )
        elif tag == "if_group":
            parents.append(f"group:{_text_of(child)}")
        elif tag == "if_matched_sid":
            matched_parent = _text_of(child)
        elif tag == "if_matched_group":
            matched_parent = f"group:{_text_of(child)}"
        elif tag in SAME_ELEMENTS or tag.startswith("different_"):
            continue  # handled by _correlation_group
        elif tag in APPLIANCE_ELEMENTS:
            predicates.append(_appliance_predicate(child, tag))
        elif tag in TEXT_ELEMENTS:
            carried.setdefault(tag, []).append(_text_of(child))
        elif tag in IGNORED_ELEMENTS:
            continue
        else:
            unknown.append(tag)

    if unknown:
        raise Refusal(
            "WAZUH_ELEMENT_UNKNOWN",
            f"`<{unknown[0]}>` is not an element this dialect knows. It is "
            f"refused rather than skipped, because skipping a matcher removes a "
            f"condition and widens the detection without saying so. Elements "
            f"this dialect reads: "
            f"{', '.join(sorted(set(MATCHERS) | set(FIELD_ELEMENTS) | {'field'}))}.",
            "lower",
        )

    frequency = (element.get("frequency") or "").strip()
    timeframe_text = (element.get("timeframe") or "").strip()
    group_keys = _correlation_group(element, diagnostics)

    # THE refusal this module exists for.
    if not predicates and not matched_parent:
        raise Refusal(
            "WAZUH_RULE_MATCHES_EVERYTHING",
            f"rule {rule_id} states no condition at all. In Wazuh that fires on "
            f"every event its parent passed, so it is refused rather than "
            f"lowered: a rule that matches everything while reporting success "
            f"is the defect this tool was built to prevent.",
            "lower",
        )

    nodes: list[Any] = []
    selector = ""
    if parents:
        # A PRECONDITION, not a correlation: it narrows which events this rule
        # ever sees. It belongs on the source, verbatim, because resolving a
        # parent rule needs the whole ruleset and this is one rule.
        selector = "if_sid=" + ",".join(parents)
    nodes.append(Read(id=f"r{rule_id}_source", table="wazuh_alerts",
                      selector=selector))

    if predicates:
        condition = (
            predicates[0] if len(predicates) == 1
            else BoolOp("and", tuple(predicates))
        )
        nodes.append(Filter(id=f"r{rule_id}_match", condition=condition))

    if matched_parent:
        if not frequency:
            raise Refusal(
                "WAZUH_CORRELATION_NO_FREQUENCY",
                f"rule {rule_id} uses if_matched_sid without `frequency`, so "
                f"how many times the parent must match is unstated.",
                "lower",
            )
        timeframe = duration_seconds(timeframe_text or "")
        if timeframe is None:
            try:
                timeframe = Duration(Decimal(timeframe_text))
            except Exception:
                raise Refusal(
                    "WAZUH_CORRELATION_NO_TIMEFRAME",
                    f"rule {rule_id} has `timeframe={timeframe_text or '(missing)'}`, "
                    f"which is not a span this engine can read. Wazuh counts "
                    f"timeframe in seconds; a threshold with no window is not a "
                    f"threshold.",
                    "lower",
                ) from None
        if not group_keys:
            raise Refusal(
                "WAZUH_CORRELATION_NO_GROUP",
                f"rule {rule_id} counts the parent {frequency} times in "
                f"{timeframe_text}s but names no `<same_*>` element, so the "
                f"count is 'anywhere in the log'. That turns a per-host "
                f"threshold into a global one: five failures spread over five "
                f"machines would fire a rule that means five on one.",
                "lower",
            )
        try:
            count = int(frequency)
        except ValueError:
            raise Refusal(
                "WAZUH_CORRELATION_FREQUENCY",
                f"`frequency={frequency}` is not a number.",
                "lower",
            ) from None
        nodes.append(Correlation(
            id=f"r{rule_id}_correlate",
            parent=nodes[-1].id,
            frequency=count,
            timeframe=timeframe,
            group_by=tuple(group_keys),
        ))
    elif group_keys:
        diagnostics.append(Diagnostic(
            "WAZUH_SAME_WITHOUT_CORRELATION",
            f"rule {rule_id} has <same_*> elements but no if_matched_sid, so "
            f"there is no threshold for them to group. They have been read as "
            f"having no effect, which is what Wazuh does with them here.",
            severity="caution",
        ))

    nodes.append(Emit(id=f"r{rule_id}_out"))

    metadata: dict[str, str] = {
        "dialect": DIALECT,
        "language": LANGUAGE,
        "artifact": "rule",
        "wazuh.id": rule_id,
    }
    for attribute in ("level", "frequency", "timeframe", "noalert", "ignore",
                      "overwrite"):
        value = (element.get(attribute) or "").strip()
        if value:
            metadata[f"wazuh.{attribute}"] = value
    if parents:
        metadata["wazuh.if_sid"] = ",".join(parents)
    if matched_parent:
        metadata["wazuh.if_matched_sid"] = matched_parent
    group_text = ",".join(
        part.strip()
        for child in element.iter("group")
        for part in _text_of(child).split(",")
        if part.strip()
    )
    if group_text:
        metadata["wazuh.group"] = group_text
    if groups:
        # The ENCLOSING `<group name="...">` is the ruleset file's grouping and
        # is not the same thing as the rule's own `<group>` element. Using one
        # for the other on the way out silently rewrites both.
        metadata["wazuh.ruleset_group"] = ",".join(groups)

    # `<options>` and `<info>` do not change what the rule matches, and were
    # read and then discarded -- so a rule with `no_full_log` came back
    # without it and started putting whole log lines in alerts again.
    for tag, values in carried.items():
        text = ",".join(v for v in values if v)
        if text:
            metadata[f"wazuh.{tag}"] = text

    return nodes, _annotations(element, groups), metadata


def lower_wazuh(text: str, rule_id: str = "rule") -> tuple[Rule, list[Diagnostic]]:
    """A Wazuh rule to a Rule, plus what could not be represented.

    `rule_id` selects WHICH rule when the document holds several. Lowering the
    first and discarding the rest would hide detections, so a document with
    more than one rule and no selection is refused with the ids it found.
    """
    parsed = parse_wazuh(text)
    diagnostics: list[Diagnostic] = []

    chosen = parsed.rules[0]
    if len(parsed.rules) > 1:
        wanted = rule_id.strip()
        matches = [r for r in parsed.rules if (r.get("id") or "").strip() == wanted]
        if not matches:
            found = ", ".join(
                (r.get("id") or "?").strip() for r in parsed.rules
            )
            raise Refusal(
                "WAZUH_MULTIPLE_RULES",
                f"this document holds {len(parsed.rules)} rules ({found}) and "
                f"`{wanted}` is not one of them. Pass the id of the rule you "
                f"want as `rule_id` -- lowering the first and discarding the "
                f"rest would silently hide detections.",
                "lower",
            )
        chosen = matches[0]

    nodes, annotations, metadata = _lower_rule(
        chosen, parsed.group_names, diagnostics
    )
    rule = Rule(
        rule_id=(chosen.get("id") or rule_id).strip(),
        pipeline=tuple(nodes),
        annotations=annotations,
        metadata=metadata,
    )
    validate(rule)
    return rule, diagnostics


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def _escape(text: Any) -> str:
    """A value as XML text.

    Numbers go through `plain_number` first: `str(Decimal("1e10"))` is
    `1E+10`, and a Wazuh `<field>` holding that compares the log text against
    the five characters `1E+10` rather than against ten billion.
    """
    return (
        plain_number(text) if isinstance(text, Decimal) else str(text)
    ).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _render_predicate(expr: Expr, lines: list[str]) -> None:
    """One predicate as matcher elements. Ends in a refusal.

    Wazuh ANDs the sibling elements of a rule, so an AND flattens into several
    lines. An OR does not: there is no element for it, and the Wazuh way to
    express one is several rules in a group. Emitting the branches as siblings
    would turn the OR into an AND -- a strictly narrower rule that silently
    stops firing.
    """
    if isinstance(expr, BoolOp) and expr.op == "and":
        for operand in expr.operands:
            _render_predicate(operand, lines)
        return

    if isinstance(expr, BoolOp) and expr.op == "or":
        raise Refusal(
            "WAZUH_RENDER_OR",
            f"`{render_expr(expr)}` is an OR. Sibling elements inside a Wazuh "
            f"`<rule>` are ANDed and there is no OR element, so this has to "
            f"become several rules in a group -- which is a decision about the "
            f"ruleset, not a formatting one.",
            "render",
        )

    if isinstance(expr, Not):
        inner = expr.operand
        if isinstance(inner, Comparison):
            _render_comparison(inner, lines, negate=True)
            return
        raise Refusal(
            "WAZUH_RENDER_NESTED_NOT",
            f"`{render_expr(expr)}` negates a compound condition. Wazuh negates "
            f"one matcher at a time, so this needs restructuring rather than "
            f"reformatting.",
            "render",
        )

    if isinstance(expr, Comparison):
        _render_comparison(expr, lines, negate=False)
        return

    # The appliance-side tests, written back as the elements they came from.
    # See `_appliance_predicate`.
    if isinstance(expr, Call) and "appliance" in expr.flags:
        if expr.function == "check_diff":
            lines.append("  <check_diff />")
            return
        if expr.function == "lookup" and len(expr.args) == 3:
            field, path, lookup = expr.args
            lines.append(
                f'  <list field="{_escape(field.full)}" '
                f'lookup="{_escape(lookup.value)}">'
                f"{_escape(path.value)}</list>"
            )
            return

    raise Refusal(
        "WAZUH_RENDER_EXPR",
        f"`{render_expr(expr)}` ({type(expr).__name__}) has no Wazuh element. "
        f"It is refused rather than skipped: a dropped matcher removes a "
        f"condition and widens the detection.",
        "render",
    )


_BY_FIELD: Final[dict[str, str]] = {
    value: key for key, value in reversed(list(FIELD_ELEMENTS.items()))
}


def _render_comparison(expr: Comparison, lines: list[str], *, negate: bool) -> None:
    negated = expr.negate ^ negate
    attribute = ' negate="yes"' if negated else ""

    if not isinstance(expr.left, FieldRef):
        raise Refusal(
            "WAZUH_RENDER_NOT_A_FIELD",
            f"`{render_expr(expr.left)}` is on the left of a comparison, but "
            f"Wazuh matchers test the log text or a named field.",
            "render",
        )
    name = expr.left.full

    if isinstance(expr.right, Regex):
        tag = "pcre2" if expr.right.dialect == "pcre2" else "regex"
        if name == "full_log":
            lines.append(f"  <{tag}{attribute}>{_escape(expr.right.pattern)}</{tag}>")
        else:
            element = _BY_FIELD.get(name)
            if element:
                lines.append(
                    f"  <{element}{attribute}>{_escape(expr.right.pattern)}</{element}>"
                )
            else:
                lines.append(
                    f'  <field name="{_escape(name)}"{attribute}>'
                    f"{_escape(expr.right.pattern)}</field>"
                )
        return

    if not isinstance(expr.right, Literal):
        raise Refusal(
            "WAZUH_RENDER_VALUE",
            f"`{render_expr(expr.right)}` is not a constant. A Wazuh matcher "
            f"compares against literal text or a pattern.",
            "render",
        )
    if expr.right.value is None or str(expr.right.value) == "":
        # An EMPTY matcher element tests nothing, and in Wazuh an absence is a
        # match -- so `<field name="x"></field>` fires on every event the
        # parent rule passed. `parse_wazuh` refuses exactly that with
        # WAZUH_MATCHER_EMPTY; the renderer was writing it anyway, so the
        # module emitted a rule its own reader rejected and would have
        # matched everything if deployed.
        raise Refusal(
            "WAZUH_RENDER_EMPTY_VALUE",
            f"`{name}` is compared with an empty value, and an empty Wazuh "
            f"matcher tests nothing: the element would fire on every event "
            f"its parent passed. Wazuh has no way to say \"this field is "
            f"present and empty\", so this is refused rather than written.",
            "render",
        )
    value = _escape(expr.right.value)

    if expr.op == "contains" and name == "full_log":
        lines.append(f"  <match{attribute}>{value}</match>")
        return
    if expr.op in ("==", "contains"):
        element = _BY_FIELD.get(name)
        if element:
            lines.append(f"  <{element}{attribute}>{value}</{element}>")
        else:
            lines.append(
                f'  <field name="{_escape(name)}"{attribute}>{value}</field>'
            )
        return

    raise Refusal(
        "WAZUH_RENDER_OPERATOR",
        f"`{expr.op}` has no Wazuh element. Wazuh matchers are substring, "
        f"regex and equality; rendering `{expr.op}` as one of those would be a "
        f"different test.",
        "render",
    )


#: Stages Wazuh has no element for, and what writing the rule without each
#: one would actually do.
#:
#: Refused BY NAME. This function used to pick the first `Correlation` and the
#: first `Filter` out of the pipeline and ignore everything else -- there was
#: no dispatch chain at all, so nothing could end in a refusal. Eight stage
#: kinds were dropped in silence, including a SECOND filter (half a
#: conjunction) and an `Aggregate` (the whole threshold).
UNSUPPORTED_STAGES: Final[dict[str, str]] = {
    "Sort": (
        "Wazuh has no ordering. A rule whose meaning depends on order -- "
        "`the most recent`, `the highest` -- has no Wazuh form, and writing "
        "it without the ordering returns a different event than the one the "
        "rule picked"
    ),
    "Limit": (
        "Wazuh has no row limit. Dropping it widens the result, and the limit "
        "is usually what kept an alert actionable"
    ),
    "Distinct": (
        "Wazuh cannot de-duplicate. Without it the same finding is reported "
        "once per matching event rather than once"
    ),
    "Project": (
        "Wazuh alerts carry the decoded event, not a chosen column set. A "
        "projection has no element, and dropping it silently would make the "
        "rule look like it reports fields it does not"
    ),
    "Derive": (
        "Wazuh cannot compute a new field. A rule testing a derived value has "
        "nothing to test once the derivation is gone"
    ),
    "Expand": (
        "Wazuh cannot expand a list into rows. Dropping it leaves a rule "
        "testing a whole list against a single value, which never matches"
    ),
    "Join": (
        "Wazuh correlates with `if_matched_sid` against a PARENT rule, not by "
        "joining two streams. Writing one side alone matches every event that "
        "side would have contributed, including the ones the join excluded"
    ),
    "Sequence": (
        "Wazuh has no ordered sequence. `if_matched_sid` is a count of one "
        "parent, not `this then that`, so writing it without the ordering "
        "fires on the two events in either order -- and the reverse order is "
        "usually the benign one"
    ),
}


def _threshold_from(
    nodes: list[Any],
) -> tuple[int, int, tuple[Any, ...]] | None:
    """An `Aggregate` plus its threshold filter, as Wazuh spells it.

    `summarize Hits=count() by Account | where Hits >= 5` and
    `frequency="5" timeframe="300"` are the same statement, so the pair is
    TRANSLATED rather than refused. Both were being dropped instead: a rule
    meaning "five failed logons from one account" rendered as "any failed
    logon" and fired on the first event, with no diagnostic -- which is the
    defect this module's own docstring cites as the reason the package exists.

    Returns None when the shape is not a plain count threshold, so the caller
    refuses rather than guessing.
    """
    aggregate = next((n for n in nodes if isinstance(n, Aggregate)), None)
    if aggregate is None:
        return None
    if len(aggregate.measures) != 1:
        return None
    measure = aggregate.measures[0]
    if measure.function.lower() not in ("count", "count_if", "countif"):
        return None
    if aggregate.window is None or aggregate.window.size is None:
        # Wazuh's `frequency` is meaningless without a `timeframe`, and
        # inventing one would invent the rule's sensitivity.
        return None

    position = nodes.index(aggregate)
    for node in nodes[position + 1:]:
        if not isinstance(node, Filter):
            continue
        condition = node.condition
        if (
            isinstance(condition, Comparison)
            and condition.op in (">=", ">")
            and isinstance(condition.left, FieldRef)
            and condition.left.full == measure.name
            and isinstance(condition.right, Literal)
        ):
            minimum = int(condition.right.value)
            # `> N` fires on N+1; Wazuh's `frequency` fires when the count
            # REACHES it. Copying the number across a strict comparison makes
            # the rule fire one event early.
            if condition.op == ">":
                minimum += 1
            return (
                minimum,
                int(aggregate.window.size.seconds),
                aggregate.keys,
            )
    return None


#: `<rule>` attributes that are carried through but are not the threshold.
#:
#: `lower_wazuh` reads every one of these into metadata and the renderer wrote
#: none of them back, so a rule imported with `noalert="1"` came out WITHOUT
#: it -- and `noalert` is what stops a correlation rule's own parent events
#: flooding the alert queue. `ignore="60"` is a per-rule cooldown and
#: `overwrite="yes"` says the rule REPLACES an existing id: dropping that one
#: turns an override into a duplicate definition.
#:
#: Written in a fixed order so a re-render is byte-identical.
CARRIED_ATTRIBUTES: Final[tuple[str, ...]] = (
    "noalert", "ignore", "overwrite",
)


def render_wazuh(rule: Rule) -> str:
    """Write a Rule back out as a Wazuh rule inside a `<group>`.

    The pipeline is WALKED, and every stage is either placed or refused by
    name. The previous version pulled the first `Correlation` and the first
    `Filter` out with `next()` and ignored the rest, so there was no dispatch
    chain to end in a refusal -- see `UNSUPPORTED_STAGES`.
    """
    meta = rule.metadata
    annotations = rule.annotations
    nodes = list(rule.pipeline)

    if rule.bindings:
        raise Refusal(
            "WAZUH_RENDER_BINDINGS",
            "Wazuh has no named sub-queries. Writing only the main stream "
            "would drop whatever the bindings constrained.",
            "render",
        )

    correlation = next(
        (n for n in nodes if isinstance(n, Correlation)), None
    )
    threshold = _threshold_from(nodes) if correlation is None else None

    # Walk every stage. A filter that feeds the threshold is accounted for by
    # `threshold`, so it is not also written as a matcher.
    aggregate = next((n for n in nodes if isinstance(n, Aggregate)), None)
    threshold_filter: Any = None
    if threshold is not None and aggregate is not None:
        position = nodes.index(aggregate)
        threshold_filter = next(
            (n for n in nodes[position + 1:] if isinstance(n, Filter)), None
        )

    conditions: list[Any] = []
    for node in nodes:
        if isinstance(node, (Read, Emit, Correlation)):
            continue
        if node is aggregate and threshold is not None:
            continue
        if node is threshold_filter:
            continue
        if isinstance(node, Filter):
            conditions.append(node.condition)
            continue
        if isinstance(node, Aggregate):
            # Distinguished from the generic refusal, because the analyst can
            # act on this one: the same rule WITH a window is exactly Wazuh's
            # `frequency`/`timeframe` form, and `_threshold_from` translates
            # it. Saying only "Aggregate has no Wazuh element" would hide that.
            measures = ", ".join(
                f"{m.function}({m.field.full if m.field else '*'})"
                for m in node.measures
            )
            if (
                len(node.measures) == 1
                and node.measures[0].function.lower() in (
                    "count", "count_if", "countif"
                )
                and (node.window is None or node.window.size is None)
            ):
                raise Refusal(
                    "WAZUH_RENDER_THRESHOLD_NEEDS_A_WINDOW",
                    f"`{measures}` is a count, and Wazuh writes a count as "
                    f"`frequency` -- which is meaningless without a "
                    f"`timeframe`. This aggregate has no time window, so it "
                    f"counts over all input, and inventing a window here "
                    f"would invent the rule's sensitivity. Give the "
                    f"aggregation a window and it becomes a Wazuh threshold.",
                    "render",
                )
            raise Refusal(
                "WAZUH_RENDER_AGGREGATE",
                f"Wazuh expresses only one aggregate: a count, as "
                f"`frequency` over a `timeframe`. `{measures}` is not that, "
                f"so there is nothing to write -- and writing the rule "
                f"without it would drop the number the alert was tuned on.",
                "render",
            )
        kind = type(node).__name__
        reason = UNSUPPORTED_STAGES.get(kind)
        if reason is None:
            raise Refusal(
                "WAZUH_RENDER_STAGE",
                f"a `{kind}` stage has no Wazuh element, and writing the rule "
                f"without it would produce one that loads, runs, and matches "
                f"a different set of events.",
                "render",
            )
        raise Refusal(
            f"WAZUH_RENDER_NO_{kind.upper()}",
            f"{reason}. This rule cannot be expressed as a Wazuh rule.",
            "render",
        )

    attributes = [f'id="{_escape(meta.get("wazuh.id") or rule.rule_id)}"']
    level = meta.get("wazuh.level") or _level_from(annotations.severity)
    attributes.append(f'level="{_escape(level)}"')

    if correlation is not None:
        attributes.append(f'frequency="{correlation.frequency}"')
        attributes.append(f'timeframe="{int(correlation.timeframe.seconds)}"')
    elif threshold is not None:
        minimum, window, _keys = threshold
        attributes.append(f'frequency="{minimum}"')
        attributes.append(f'timeframe="{window}"')

    # Everything else the rule carried. See `CARRIED_ATTRIBUTES`: these were
    # read on the way in and written nowhere on the way out.
    for name in CARRIED_ATTRIBUTES:
        value = meta.get(f"wazuh.{name}")
        if value:
            attributes.append(f'{name}="{_escape(value)}"')

    lines = [
        f"<group name=\"{_escape(meta.get('wazuh.ruleset_group') or 'local')},\">"
    ]
    lines.append(f"  <rule {' '.join(attributes)}>")

    body: list[str] = []
    parent = meta.get("wazuh.if_sid")
    if parent:
        body.append(f"  <if_sid>{_escape(parent)}</if_sid>")
    matched = meta.get("wazuh.if_matched_sid")
    if matched:
        body.append(f"  <if_matched_sid>{_escape(matched)}</if_matched_sid>")

    if not conditions and correlation is None and threshold is None:
        raise Refusal(
            "WAZUH_RENDER_NO_CONDITION",
            "this rule states no condition, and a Wazuh rule with no matcher "
            "fires on every event its parent passed. It is refused rather than "
            "written out.",
            "render",
        )
    for condition in conditions:
        # Several filter stages are a CONJUNCTION. Only the first was written
        # before, so a two-stage `where A | where B` became `A` alone and the
        # rule matched events B excluded.
        _render_predicate(condition, body)

    group_keys = (
        correlation.group_by if correlation is not None
        else threshold[2] if threshold is not None
        else ()
    )
    for key in group_keys:
        element = next(
            (tag for tag, field in SAME_ELEMENTS.items()
             if field == key.full and not tag.startswith("same_field")),
            None,
        )
        if element is None:
            body.append(f'  <same_field name="{_escape(key.full)}" />')
        else:
            body.append(f"  <{element} />")

    lines.extend("  " + line for line in body)
    # `<options>` and `<info>` ride along: read on the way in, and until now
    # written nowhere on the way out.
    for tag in ("options", "info"):
        value = meta.get(f"wazuh.{tag}")
        if value:
            for part in value.split(","):
                if part.strip():
                    lines.append(
                        f"    <{tag}>{_escape(part.strip())}</{tag}>"
                    )
    if annotations.description:
        lines.append(
            f"    <description>{_escape(annotations.description)}</description>"
        )
    for _, techniques in annotations.mitre_attack:
        if techniques:
            lines.append("    <mitre>")
            lines.extend(f"      <id>{_escape(t)}</id>" for t in techniques)
            lines.append("    </mitre>")
    group = meta.get("wazuh.group")
    if group:
        lines.append(f"    <group>{_escape(group)}</group>")

    lines.append("  </rule>")
    lines.append("</group>")
    return "\n".join(lines) + "\n"


def _level_from(severity: str) -> str:
    return {
        "critical": "12", "high": "10", "medium": "7", "low": "4",
        "informational": "1",
    }.get(severity, "5")
