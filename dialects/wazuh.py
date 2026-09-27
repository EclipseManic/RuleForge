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

#: The XML parser used for UNTRUSTED input, and the refusal if it is absent.
#:
#: `defusedxml` is not optional and there is no fallback to `xml.etree`, because
#: a fallback would restore the exact accident this replaces and would do it
#: invisibly. See `parse_wazuh` for the measurement that motivated it.
try:
    from defusedxml import ElementTree as _SAFE
    from defusedxml.ElementTree import DTDForbidden, EntitiesForbidden
except ImportError as _exc:  # pragma: no cover - depends on the environment
    raise ImportError(
        "defusedxml is required to parse Wazuh rulesets. It is what stops a "
        "pasted document from expanding XML entities into gigabytes of memory, "
        "and RuleForge will not fall back to the stdlib parser, which does not "
        "make that guarantee. Install it with:  pip install defusedxml"
    ) from _exc

#: The stdlib module is still imported, but ONLY for its `Element` type, which
#: annotates `_parse_rule`'s parameter. It parses nothing. The parser is `_SAFE`
#: and every `except` clause below is on `_SAFE.ParseError` or on a defusedxml
#: exception, never on `ET.ParseError` -- an earlier version of this comment
#: claimed the opposite, which is the sort of thing that makes a reader trust
#: the wrong line.
__all__ = ["ET", "parse_wazuh"]
from dataclasses import dataclass, field

from engine.ir import Refusal

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

#: `if_sid` / `if_level` / `if_group` select an already-decided alert, not a raw
#: event condition. Only `if_sid` is resolved here; the others are recorded and
#: refused, because honouring them needs a rule-tree we do not have.
#:
#: THIS WAS `if_slevel`, WHICH IS NOT A WAZUH ELEMENT. The official syntax doc
#: lists `if_level`; `if_slevel` appears nowhere in Wazuh. So the two halves of
#: that entry were both wrong: a real `<if_level>5</if_level>` hit the unknown-
#: element refusal, and the whitelist name could never match anything real.
TRIGGER_ELEMENTS = ("if_sid", "if_level", "if_group", "if_matched_sid",
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


#: Elements that are PRESENTATION, GROUPING or AGENT PLUMBING, and genuinely do
#: not change WHICH events a rule matches. Ignoring these is correct.
#:
#: THIS SET USED TO BE TWICE AS BIG, AND THE EXTRA HALF WAS PREDICATES. The
#: Wazuh Rules Syntax doc lists `program_name`, `hostname`, `status`, `data`,
#: `extra_data`, `location`, `regex`, `list` and `check_diff` as "a requisite to
#: trigger a rule" -- they ARE conditions. The reviewer reproduced it with one
#: element changed:
#:
#:     <rule id="100200" level="12"><program_name>syslogd</program_name>...
#:
#:     parse_wazuh  -> ok
#:     lower        -> 0 Filter nodes
#:     jobs.author  -> ok=True, refusal=None, graph ['Read','Emit']
#:     jobs.tune    -> "The rule matched 3 of 3 events."
#:
#: That is the round-3 `<match>` critical reached through a different tag: a
#: detection that fires on everything while reporting success. Every element in
#: here now has to be genuinely presentational, which is a much smaller set.
#:
#: `options` stays, and it is a judgement call worth naming: `<options>noalert
#: </options>` changes whether an ALERT is raised, not which events match. The
#: IR models matching, so lowering cannot represent it. Refusing it would make
#: real rulesets unusable over a cosmetic concern, which is over-strict in the
#: wrong direction -- so it is ignored, and the gap is stated here rather than
#: discovered later: a noalert rule comes back as an alerting rule.
#:
#: Decoder-derived PREDICATES. Not ignored and not lowered: the IR has no way to
#: say "the decoder classified this event", so a rule built on one cannot be
#: executed or rendered faithfully. They are RECORDED, and the lowerer refuses
#: when they are the rule's only condition -- because then the rule would
#: otherwise be Read -> Emit and match every event. Alongside a real `<field>`
#: the rule lowers, with the gap stated rather than hidden.
#:
#: The Wazuh Rules Syntax doc says of BOTH, verbatim: "Used as a requisite to
#: trigger a rule. It will be triggered if the event has been decoded by a certain
#: decoder." That is the same sentence it uses for the nine predicates round 4
#: removed. Round 5 caught that these two were still being ignored outright, which
#: gave `ok=True`, `graph ['Read','Emit']` and "The rule matched 3 of 3 events."
_DECODER_PREDICATES = frozenset({"category", "decoded_as"})

_IGNORED_ELEMENTS = frozenset({
    "group", "group_name", "info", "comment", "documentation", "rule",
    "fixed_fields", "options",
})


_VAR = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")


def parse_wazuh(xml_text: str) -> dict[str, WazuhRule]:
    """Parse a Wazuh rules XML document into rules keyed by id.

    Uses a real XML parser. Wazuh's files contain regexes full of `<`, `>` and
    `&` inside `<field>` bodies, and hand-rolled tag splitting is exactly how
    those get silently truncated into a rule that matches something else.

    PARSED WITH `defusedxml`, NOT `xml.etree`, AND THE REASON IS A STATED
    INVARIANT RATHER THAN A LUCKY PLATFORM.

    A pasted ruleset is attacker-reachable -- it can come from a shared document,
    a SIEM export or a ticket -- and XML entity expansion is a memory
    amplification primitive. A three-level "billion laughs" document with three
    `<!ENTITY>` declarations was measured against this parser BEFORE this
    change: it parsed in 0.5ms and returned one rule, with no error and no
    diagnostic. It did not exhaust memory, and that was entirely libexpat's
    amplification limit -- an implementation detail of one C library, which
    differs between platforms and Python builds, and which nothing here asserts.

    `defusedxml` refuses entity declarations and, with `forbid_dtd=True` set
    below, refuses DTDs outright. The guarantee is therefore "this tool will not
    expand entities" rather than "this tool happens not to expand entities very
    far on this machine". The second is not a security property; it is a
    coincidence that fails silently when the platform changes.

    `forbid_dtd` IS NOT DEFUSEDXML'S DEFAULT. Its signature is
    `fromstring(text, forbid_dtd=False, forbid_entities=True,
    forbid_external=True)`, so the default parser refuses entity DECLARATIONS
    but happily parses a document that carries a DTD -- which is where entity
    declarations live. Measured on 0.7.1 before this line was added: a
    billion-laughs document and a bare `<!DOCTYPE group SYSTEM "rules.dtd">` both
    PARSED, with no error. So the first version of this switch did not do what
    its own comment said, which is the exact failure this project keeps finding.

    Passing `forbid_dtd=True` closes that. Verified rather than assumed: the real
    shipped Wazuh ruleset still parses all 8 of its rules, because it has no
    DTD, and a document whose only entities are character references (`&amp;`,
    `&#65;`) still parses, because those are not declarations.

    WITH `forbid_dtd=True` A BILLION-LAUGS DOCUMENT RAISES `DTDForbidden`, NOT
    `EntitiesForbidden` -- the DTD is refused before its contents are read. The
    `EntitiesForbidden` clause below is therefore a second line of defence rather
    than the primary one, and stays so that a future change in defusedxml's
    precedence cannot quietly reopen entity expansion.

    THERE IS NO SILENT FALLBACK TO `xml.etree`. Falling back would restore
    exactly the accident this replaced, and would do it invisibly -- so a missing
    `defusedxml` is a loud refusal naming the package, not a quiet downgrade to
    the parser this line used to use.
    """
    try:
        root = _SAFE.fromstring(xml_text.strip(), forbid_dtd=True)
    except DTDForbidden as exc:
        raise WazuhParseError(
            "WAZUH_XML_DTD_FORBIDDEN",
            "this document carries a DTD, which RuleForge refuses outright. A "
            "pasted ruleset has no legitimate use for one: a DTD is how an XML "
            "parser is talked into expanding entities, and a few declarations "
            "can expand to gigabytes of memory before anything is evaluated. "
            "Wazuh rulesets do not need a DTD, so this is either not a Wazuh "
            "ruleset or it is not one you want this tool reading.", "wazuh"
        ) from exc
    except EntitiesForbidden as exc:
        raise WazuhParseError(
            "WAZUH_XML_ENTITY_DECLARATION",
            "this document declares XML entities, which RuleForge refuses to "
            "expand. Entity expansion is a memory amplification primitive, and a "
            "pasted ruleset is not a trusted document. Wazuh rulesets do not need "
            "entities, so this is either not a Wazuh ruleset or it is not one "
            "you want this tool reading.", "wazuh") from exc
    except _SAFE.ParseError as exc:
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
            # THE COMMENT ABOVE SAYS "RECORDED AND REFUSED". NOTHING REFUSED.
            #
            # `other_triggers.append(tag)` stored the NAME and threw the VALUE
            # away, so `<if_level>10</if_level>` did not even survive as `10` --
            # and the only reader in the whole package filters for
            # `category`/`decoded_as`, so it was never read either. The rule
            # lowered to Read -> Filter -> Emit, `ok=True`, `diagnostics=[]`, and
            # rendered a rule that fires on levels it must not. That is BROADER
            # than the source, undisclosed, which is the direction that matters.
            #
            # Refused rather than recorded-and-ignored, because there is no
            # honest middle here: the IR cannot say "only when an earlier alert
            # reached level 10", so any rendering of it is a different rule. This
            # is the same call as the nine field predicates, and the same one the
            # Wazuh Rules Syntax doc makes when it lists these as a requisite to
            # trigger a rule.
            raise WazuhParseError(
                "WAZUH_ALERT_LEVEL_TRIGGER_UNSUPPORTED",
                f"rule {rule_id} contains <{tag}>{text.strip()}</{tag}>, which "
                f"selects an ALREADY-DECIDED alert rather than testing an event. "
                f"The IR can only describe conditions over events, so honouring "
                f"it would need the alert tree this tool does not have -- and "
                f"ignoring it produced a rule that fires where the original did "
                f"not, with nothing said. Refuse it and re-parse in Wazuh, where "
                f"the level of a prior alert is real.", "wazuh")
        elif tag in _DECODER_PREDICATES:
            # Recorded, not ignored -- see `_DECODER_PREDICATES`. The lowerer
            # decides what to do with a rule whose only condition is one of
            # these, because only it can see whether a `<field>` came with it.
            other_triggers.append(f"{tag}={text.strip()}")
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
    """Read a frequency/timeframe, refusing an unexpanded `$VAR` by name.

    `int()` IS MORE PERMISSIVE THAN XML'S INTEGER GRAMMAR, AND THE GAP IS NOT
    COSMETIC. Measured on this interpreter:

        int("1_2")   == 12        <- an analyst who wrote frequency="1_2"
        int("+12")   == 12           got TWELVE, with nothing said anywhere
        int("١٢")    == 12        <- Arabic-Indic digits, also twelve
        int("012")   == 12

    So a typo became a different number and the tool reported the analyst's rule
    back to them as if it were what they wrote. `_2` is not a quantity; refusing
    it by name is the only honest answer, and "it is not a number" is a far more
    useful sentence than a rendered correlation that fires on the twelfth event
    of something that was written `1_2`.

    The test is `isascii() and isdigit()` for the same reason as the `level`
    guard in `wazuh_render`: `isdigit()` is true for `'²'`, which `int()` then
    rejects with a ValueError, and for Arabic-Indic digits, which `int()`
    accepts. Requiring ASCII first makes the accepted set exactly `'0'`-`'9'`,
    which `int()` always parses, so nothing below can raise or silently
    re-interpret.

    THERE IS DELIBERATELY NO UPPER BOUND, and a round-7 finding asked for one.
    Refusing it was considered and declined. A Wazuh `frequency` has no vendor
    maximum -- any positive integer is legal -- so any cap would be a number I
    invented, and inventing one means refusing rules that are perfectly valid.
    A frequency of ten million describes a rule that will not fire in any real
    window, and the evaluator already says so honestly: it counts the child rows
    and reports no match, spending from the same budget as everything else. A
    rule that never fires, reported as never firing, is not a silent wrongness.
    Refusing it would be a refusal of correct input, which costs more than the
    thing it prevents. `level` IS bounded, because Wazuh documents that range;
    this is not the same situation and copying the guard here would be cargo
    cult.
    """
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
    if not (text.isascii() and text.isdigit()):
        raise WazuhParseError(
            f"WAZUH_{what.upper()}_NOT_AN_INTEGER",
            f"rule {rule_id} sets {what}=\"{text}\", which is not a plain "
            f"whole number of digits. Underscores, a leading sign, and non-ASCII "
            f"digits are not quantities: Python would read \"1_2\" as twelve and "
            f"report that back as the rule you wrote.", "wazuh")
    parsed = int(text)
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
