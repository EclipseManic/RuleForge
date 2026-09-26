"""Wazuh ruleset XML -> parsed structure.

Written against the real ruleset, not a hand-written fixture, because a fixture
I invented would be correct by construction and would test nothing. The chain
used here is verbatim from `wazuh/wazuh-ruleset` `rules/0580-win-security_rules.xml`:

    60001 (channel) -> 60104 (audit failure) -> 60107 (privileged op failed)
                    -> 60203 (frequency 5 / 240s on targetUserName)

THE CHAIN IS THE POINT. 60203 alone is meaningless -- it says "five times in four
minutes on the same user" and names no condition of its own. All of its meaning
lives in `if_matched_sid`, which is a POINTER to another rule. A parser that reads
only the rule the user pasted would produce a rule that matches everything, and
would have no way to know it had thrown away the actual detection. So this parser
resolves the chain and refuses when a link is missing rather than lowering the
orphan.

`$MS_FREQ` IS NOT A NUMBER. The real ruleset writes `frequency="$MS_FREQ"`, an
ossec.conf preprocessor variable expanded at agent start. Treating it as 1 would
silently invert the rule's meaning; inventing a plausible number would be worse.
It is reported as needing the user's configured value.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from ..engine.ir import Refusal

DIALECT = "wazuh"
LANGUAGE = "XML"

#: The `same_*` elements, in Wazuh's own spelling, mapped to what they mean.
SAME_ELEMENTS = {
    "same_srcip": "source address",
    "same_dstip": "destination address",
    "same_user": "user name",
    "same_host": "host",
    "same_id": "id",
    "same_field": "a named field",
}

#: `if_sid` / `if_slevel` / `if_group` select an already-decided alert, not a raw
#: event condition. Only `if_sid` is resolved here; the others are recorded and
#: refused, because honouring them needs a rule-tree we do not have.
TRIGGER_ELEMENTS = ("if_sid", "if_slevel", "if_group", "if_matched_sid",
                    "if_matched_group")


@dataclass(frozen=True, slots=True)
class WazuhField:
    name: str
    kind: str          # pcre2, pcre, os_regex, etc
    pattern: str
    negate: bool = False


@dataclass(frozen=True, slots=True)
class WazuhRule:
    rule_id: str
    level: str
    description: str = ""
    mitre: tuple[str, ...] = ()
    fields: tuple[WazuhField, ...] = ()
    if_sid: str | None = None
    if_matched_sid: str | None = None
    if_matched_group: str | None = None
    frequency: str = ""
    timeframe: str = ""
    same: tuple[str, ...] = ()
    #: A raw `$VAR` that ossec.conf expands at agent start. Kept as text, never
    #: guessed at.
    unexpanded: tuple[str, ...] = ()
    other_triggers: tuple[str, ...] = ()

    @property
    def is_correlation(self) -> bool:
        return bool(self.if_matched_sid or self.if_matched_group)


@dataclass(slots=True)
class WazuhChain:
    """A resolved `if_sid` chain, root first."""

    rules: list[WazuhRule] = field(default_factory=list)

    @property
    def parent(self) -> WazuhRule:
        return self.rules[0]

    @property
    def leaf(self) -> WazuhRule:
        return self.rules[-1]


class WazuhParseError(Refusal):
    pass


#: Elements that are presentation, grouping or agent plumbing, and genuinely do
#: not change WHICH events a rule matches. Ignoring these is correct -- unlike
#: ignoring a `<match>`, which removes the detection entirely.
#: Elements that are presentation, grouping or AGENT PLUMBING, and genuinely do
#: not change which events a rule matches. `<decoded_as>` and `<category>` tell
#: the agent how to decode an event and how to classify an alert; neither is a
#: predicate, so ignoring them is correct. `<match>` is NOT in here -- that one IS
#: a predicate, which is why dropping it was so damaging.
_IGNORED_ELEMENTS = frozenset({
    "group", "options", "info", "check_diff", "comment", "rule",
    "group_name", "documentation", "category", "decoded_as", "hostname",
    "status", "firewall", "location", "list", "program_name", "sha1",
    "sha256", "md5", "extra_data", "data", "fixed_fields", "json", "regex",
})


_VAR = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")


def parse_wazuh(xml_text: str) -> dict[str, WazuhRule]:
    """Parse a Wazuh rules XML document into rules keyed by id.

    Uses a real XML parser. Wazuh's files contain regexes full of `<`, `>` and
    `&` inside `<field>` bodies, and hand-rolled tag splitting is exactly how
    those get silently truncated into a rule that matches something else.
    """
    try:
        root = ET.fromstring(xml_text.strip())
    except ET.ParseError as exc:
        raise WazuhParseError(
            "WAZUH_XML_MALFORMED",
            f"this is not well-formed XML: {exc}. Wazuh rule bodies contain "
            f"regexes full of angle brackets, so the document is parsed with a "
            f"real XML parser rather than by splitting on tags.", "wazuh") from exc

    rules: dict[str, WazuhRule] = {}
    for element in root.iter("rule"):
        rule = _parse_rule(element)
        rules[rule.rule_id] = rule
    if not rules:
        raise WazuhParseError(
            "WAZUH_NO_RULES", "the document parsed but contains no <rule> elements",
            "wazuh")
    return rules


def _parse_rule(element: ET.Element) -> WazuhRule:
    rule_id = (element.get("id") or "").strip()
    if not rule_id:
        raise WazuhParseError(
            "WAZUH_RULE_NO_ID", "a <rule> has no id attribute", "wazuh")

    fields: list[WazuhField] = []
    same: list[str] = []
    unexpanded: list[str] = []
    other_triggers: list[str] = []
    mitre: list[str] = []
    if_matched_sid = if_matched_group = if_sid = None
    description = ""

    for child in element:
        tag = child.tag
        text = (child.text or "").strip()

        if tag == "field":
            name = child.get("name")
            if not name:
                raise WazuhParseError(
                    "WAZUH_FIELD_NO_NAME",
                    f"rule {rule_id} has a <field> with no name attribute", "wazuh")
            kind = (child.get("type") or "os_regex").lower()
            negate = (child.get("negate") or "").strip() in ("yes", "true", "1")
            fields.append(WazuhField(name=name, kind=kind, pattern=text,
                                    negate=negate))
        elif tag in SAME_ELEMENTS:
            # `same_srcip` is a FIXED FIELD; `same_field` CARRIES THE FIELD NAME
            # in its body. Collapsing them into one string without this
            # distinction turns "the same source address" into "a field called
            # srcip", which is a different rule.
            if tag == "same_field":
                if text:
                    same.append(text)
            else:
                same.append(_FIXED_SAME_FIELDS[tag])
        elif tag == "if_sid":
            if_sid = text
        elif tag == "if_matched_sid":
            if_matched_sid = text
        elif tag == "if_matched_group":
            if_matched_group = text
        elif tag in TRIGGER_ELEMENTS:
            other_triggers.append(tag)
        elif tag in _IGNORED_ELEMENTS:
            # Presentation and grouping only. These genuinely do not affect
            # which events a rule matches, so ignoring them is correct.
            pass
        elif tag == "mitre":
            mitre.extend((node.text or "").strip() for node in child
                         if (node.text or "").strip())
        elif tag == "description":
            description = text
        elif tag in ("frequency", "timeframe"):
            unexpanded.extend(f"{tag}={v}" for v in _VAR.findall(text))
        else:
            # NO SILENT `else`, AND THIS IS THE WORST VERSION OF THAT BUG.
            # `<match>` is what the shipped Wazuh rulesets actually use --
            # `<match field="win.eventdata.CommandLine" type="pcre2">` -- and it
            # was dropped on the floor, so the rule lowered to Read -> Emit with
            # NO FILTER AT ALL. `notepad.exe` matched. `lsass.exe` matched. The
            # tool reported "the rule matched 3 of 3 events" and showed no
            # warning anywhere. A detection that fires on everything while
            # reporting success is the worst output this project can produce, so
            # an element we do not understand is named instead.
            raise WazuhParseError(
                "WAZUH_ELEMENT_UNKNOWN",
                f"rule {rule_id} contains a <{tag}> element, which this lowering "
                f"does not understand. Dropping it would remove the condition "
                f"from the rule and leave it matching every event in the log "
                f"while reporting success. <match> in particular is the form the "
                f"shipped Wazuh rulesets use, so this is a real gap rather than "
                f"an exotic one.", "wazuh")

    for attribute in ("frequency", "timeframe"):
        value = (element.get(attribute) or "").strip()
        unexpanded.extend(f"{attribute}={v}" for v in _VAR.findall(value))

    return WazuhRule(
        rule_id=rule_id,
        level=element.get("level") or "",
        description=description,
        mitre=tuple(mitre),
        fields=tuple(fields),
        if_sid=if_sid,
        if_matched_sid=if_matched_sid,
        if_matched_group=if_matched_group,
        frequency=(element.get("frequency") or "").strip(),
        timeframe=(element.get("timeframe") or "").strip(),
        same=tuple(dict.fromkeys(same)),
        unexpanded=tuple(dict.fromkeys(unexpanded)),
        other_triggers=tuple(dict.fromkeys(other_triggers)),
    )


#: Wazuh's fixed `same_*` elements name a well-known field. Mapping them to the
#: actual event field is the difference between a working rule and a rule that
#: groups on a column called "srcip" that does not exist.
_FIXED_SAME_FIELDS = {
    "same_srcip": "srcip",
    "same_dstip": "dstip",
    "same_user": "user",
    "same_host": "hostname",
    "same_id": "id",
}


def resolve_chain(rules: dict[str, WazuhRule], rule_id: str,
                  max_depth: int = 16) -> WazuhChain:
    """Walk `if_sid` back to the root, refusing a dangling or looping link."""
    chain: list[WazuhRule] = []
    seen: set[str] = set()
    current = rules.get(rule_id)
    if current is None:
        raise WazuhParseError(
            "WAZUH_PARENT_MISSING",
            f"rule {rule_id} is not in the supplied document. Its meaning is "
            f"defined by what it points at, so it cannot be parsed alone -- pass "
            f"the whole ruleset file, not just the child rule.", "wazuh")

    while current is not None:
        if current.rule_id in seen:
            raise WazuhParseError(
                "WAZUH_CYCLE",
                f"the if_sid chain loops back to {current.rule_id}. Wazuh's own "
                f"loader would recurse forever, so this is refused rather than "
                f"followed.", "wazuh")
        seen.add(current.rule_id)
        chain.append(current)
        if len(chain) > max_depth:
            raise WazuhParseError(
                "WAZUH_CHAIN_TOO_DEEP",
                f"the if_sid chain from {rule_id} exceeds {max_depth} links. A "
                f"chain that deep is almost certainly a mistake, and walking it "
                f"unbounded is how a rule file takes an agent down.", "wazuh")
        if not current.if_sid:
            break
        nxt = rules.get(current.if_sid)
        if nxt is None:
            raise WazuhParseError(
                "WAZUH_PARENT_MISSING",
                f"rule {current.rule_id} points at {current.if_sid}, which is "
                f"not in the supplied document. Lowering only the child would "
                f"produce a rule that matches everything while looking correct.",
                "wazuh")
        current = nxt

    chain.reverse()
    return WazuhChain(rules=chain)


def correlation_child(rules: dict[str, WazuhRule], rule_id: str) -> WazuhRule:
    """The `if_matched_sid` child of a rule, refusing the group form."""
    child = rules[rule_id]
    if child.if_matched_group:
        raise WazuhParseError(
            "WAZUH_GROUP_TRIGGER_UNSUPPORTED",
            f"rule {rule_id} uses if_matched_group, which correlates on a whole "
            f"group of sibling rules rather than on one event. That is a "
            f"different correlation and is not lowered here.", "wazuh")
    if not child.if_matched_sid:
        raise WazuhParseError(
            "WAZUH_NOT_A_CORRELATION",
            f"rule {rule_id} has no if_matched_sid, so it is a plain rule rather "
            f"than a correlation", "wazuh")
    if child.rule_id in rules and rules[child.rule_id].rule_id != rule_id:
        raise WazuhParseError(
            "WAZUH_SELF_PARENT",
            f"rule {rule_id} points at itself", "wazuh")
    return child


def as_int(value: str, rule_id: str, what: str) -> int:
    """Read a frequency/timeframe, refusing an unexpanded `$VAR` by name."""
    text = (value or "").strip()
    if not text:
        raise WazuhParseError(
            f"WAZUH_NO_{what.upper()}",
            f"rule {rule_id} has no {what}. A correlation needs both, and "
            f"guessing one would change what the rule detects.", "wazuh")
    if _VAR.search(text):
        names = ", ".join(sorted(set(_VAR.findall(text))))
        raise WazuhParseError(
            f"WAZUH_{what.upper()}_IS_OSCONF_VARIABLE",
            f"rule {rule_id} sets {what}=\"{text}\", which is an ossec.conf "
            f"preprocessor variable ({names}), expanded by the agent at start-up "
            f"and not present in the rule file. This is not a number the rule "
            f"declares, so it is not one RuleForge will invent -- supply the "
            f"value from your ossec.conf.", "wazuh")
    try:
        parsed = int(text)
    except ValueError as exc:
        raise WazuhParseError(
            f"WAZUH_{what.upper()}_NOT_AN_INTEGER",
            f"rule {rule_id} sets {what}=\"{text}\", which is not an integer",
            "wazuh") from exc
    if parsed <= 0:
        raise WazuhParseError(
            f"WAZUH_{what.upper()}_NOT_POSITIVE",
            f"rule {rule_id} sets {what}={parsed}, which is not positive. A "
            f"count in no window, or a window of no length, does not describe a "
            f"detection.", "wazuh")
    return parsed


def rule_metadata(rule: WazuhRule) -> dict[str, str]:
    return {
        "dialect": DIALECT,
        "wazuh_id": rule.rule_id,
        "level": rule.level,
        "mitre": ", ".join(rule.mitre),
    }
