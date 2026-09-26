"""Wazuh ruleset XML -> RuleIR.

The whole point of this file is that rule 60203 -- "five times in four minutes on
the same user" -- contains NO condition of its own. Every bit of its meaning is
behind `if_matched_sid`. Lowering the pasted text on its own would produce a
`Package` with an empty child, which fires on every event in the log, and nothing
in the output would say so. So the chain is resolved first and a missing link is
refused by name.
"""
from __future__ import annotations

from typing import Any

from ..engine.values import Refusal
from ..engine.ir import (
    BoolOp,
    Call,
    Comparison,
    Duration,
    Emit,
    FieldExpr,
    FieldRef,
    Filter,
    Literal,
    Not,
    Package,
    Read,
    RuleIR,
    SourceSelector,
)
from .wazuh import (
    DIALECT,
    WazuhField,
    WazuhParseError,
    WazuhRule,
    as_int,
    parse_wazuh,
    resolve_chain,
    rule_metadata,
)

#: Wazuh decodes these before rules ever see the event. A rule that matches on
#: the decoded value must be evaluated against the same string, or the engine
#: would be testing something the agent never tested.
WINDOWS_EVENT_CHANNEL = "windows_eventchannel"

#: Wazuh's `syscheck`/`rootcheck` style fields are flat; eventchannel fields are
#: dotted. Preserved exactly, because remapping them is how a rule silently stops
#: matching in production.


def lower(xml_text: str, rule_id: str,
          ossec: dict[str, int] | None = None,
          time_field: str = "timestamp",
          source_name: str = WINDOWS_EVENT_CHANNEL) -> tuple[RuleIR, list[dict[str, Any]]]:
    """Lower one Wazuh rule, resolving its `if_sid` chain.

    `ossec` supplies values for `$VAR` preprocessor variables, e.g.
    `{"MS_FREQ": 12}`. Without it a rule using `$MS_FREQ` is refused by name
    rather than guessed at.
    """
    diagnostics: list[dict[str, Any]] = []
    rules = parse_wazuh(xml_text)
    target = rules.get(rule_id)
    if target is None:
        raise WazuhParseError(
            "WAZUH_RULE_NOT_IN_DOCUMENT",
            f"rule {rule_id} is not in the supplied document", DIALECT)

    if target.is_correlation:
        ir = _lower_correlation(rules, target, osconf=ossec,
                                time_field=time_field, source_name=source_name,
                                diagnostics=diagnostics)
    else:
        chain = resolve_chain(rules, rule_id)
        ir = _lower_plain(chain, time_field=time_field, source_name=source_name,
                          diagnostics=diagnostics)

    return ir, diagnostics


def _field_expr(name: str) -> FieldExpr:
    """A dotted Wazuh field name, preserved exactly.

    `win.eventdata.targetImage` becomes name=`win`, path=('eventdata',
    'targetImage'). The full spelling is recoverable via `FieldRef.full`, so
    the renderer can put back exactly what the analyst wrote. Nothing is
    remapped to a different field name -- a mapping layer is precisely how a
    rule silently stops matching in production.
    """
    parts = name.split(".")
    return FieldExpr(ref=FieldRef(parts[0], tuple(parts[1:])))


def _field_ref(name: str) -> FieldRef:
    parts = name.split(".")
    return FieldRef(parts[0], tuple(parts[1:]))


def _all_of(conditions: list[Any]) -> Any:
    return conditions[0] if len(conditions) == 1 else BoolOp("and", tuple(conditions))


def _field_condition(spec: WazuhField) -> Any:
    """One `<field>` becomes one comparison, or a named refusal.

    `pcre2` is DECLARED but not executed. Python's `re` is not PCRE2: a pattern
    using `\\K`, `(?>...)`, possessive quantifiers or a real `\\z` behaves
    differently or fails to compile. Lowering it to a call that evaluates under
    the wrong engine would report matches the agent would not produce.
    """
    subject = _field_expr(spec.name)

    if spec.kind in ("pcre2", "pcre"):
        if spec.negate:
            raise WazuhParseError(
                "WAZUH_PCRE_NEGATE_UNSUPPORTED",
                f"rule field {spec.name} is a negated {spec.kind} match. A "
                f"negated regex can only be evaluated by the same engine that "
                f"evaluates the positive one, and {spec.kind} is not executable "
                f"here, so there is nothing to negate.", DIALECT)
        # `pcre2` maps to the IR's `pcre`, which is the closest honest label
        # available. PCRE2 is a superset of PCRE, so a pattern that uses a
        # PCRE2-only feature will be DECLARED and then refused at evaluation
        # rather than quietly evaluated under PCRE and reported as PCRE2.
        return Call(function="matches_regex",
                    args=(subject, Literal(value=spec.pattern)),
                    dialect="pcre")

    if spec.kind == "os_regex":
        return Call(function="matches_regex",
                    args=(subject, Literal(value=spec.pattern)),
                    dialect="posix_extended")

    if spec.kind in ("pcre2_type", "string", "word"):
        return _scalar_comparison(subject, spec.pattern, spec.kind)

    if spec.kind == "numeric":
        return _scalar_comparison(subject, spec.pattern, spec.kind)

    raise WazuhParseError(
        "WAZUH_FIELD_TYPE_UNKNOWN",
        f"rule field {spec.name} declares type=\"{spec.kind}\", which this "
        f"lowering does not know. Guessing a comparison would change what the "
        f"rule matches.", DIALECT)


def _scalar_comparison(subject: Any, pattern: str, kind: str) -> Any:
    try:
        literal: Any = int(pattern)
    except ValueError:
        literal = pattern
    return Comparison(op="=", left=subject, right=Literal(value=literal))


def _rule_condition(rule: WazuhRule,
                    diagnostics: list[dict[str, Any]] | None = None,
                    ) -> tuple[Any, ...]:
    """Every `<field>` in a rule, ANDed. An empty rule has NO condition.

    A negated equality becomes a `not` over the comparison. A negated REGEX is
    refused, because there is no engine here to negate against -- evaluating
    "does not match pcre2" with Python's `re` would report the opposite of what
    the agent decides.
    """
    conditions: list[Any] = []
    for spec in rule.fields:
        if spec.negate and spec.kind not in ("pcre2", "pcre"):
            conditions.append(Not(_scalar_comparison(
                _field_expr(spec.name), spec.pattern, spec.kind)))
            continue
        conditions.append(_field_condition(spec))

    # A RULE WHOSE ONLY CONDITION IS A DECODER PREDICATE HAS NO CONDITION WE CAN
    # HONOUR. `<decoded_as>json</decoded_as>` or `<category>syslog</category>`
    # alone used to lower to Read -> Emit, which reports "The rule matched 3 of 3
    # events" for a rule that should only fire on events a particular decoder
    # classified. The IR cannot express a decoder constraint, so this is refused
    # -- the same direction as the nine field predicates, and the same one the
    # Wazuh Rules Syntax doc uses when it calls both "a requisite to trigger a
    # rule". Alongside a real `<field>` the rule lowers, and the gap is named in
    # the diagnostic rather than left implicit.
    decoder_only = [tag for tag in rule.other_triggers
                    if tag.split("=", 1)[0] in ("category", "decoded_as")]
    if decoder_only and not conditions and not rule.if_sid:
        names = ", ".join(sorted(decoder_only))
        raise Refusal(
            "WAZUH_DECODER_PREDICATE_ONLY",
            f"rule {rule.rule_id}'s only condition is {names}, which says the "
            f"event must have been decoded a particular way. The IR has no way "
            f"to express a decoder constraint, so lowering it would produce a "
            f"rule that matches EVERY event while reporting success. Add a "
            f"<field> to say what the event must contain, or evaluate this rule "
            f"in Wazuh, where the decoder is real.", "wazuh")

    # THE COMMENT ABOVE PROMISED THIS DIAGNOSTIC AND NOTHING WROTE IT.
    # `_rule_condition` had no `diagnostics` parameter at all, so the claim was
    # not merely unimplemented -- it was structurally impossible, and the round-6
    # security review pointed at exactly that: "The comment is false about its
    # own code; that is worse than the bug, because it is what a reviewer would
    # check." A reviewer reads the comment, believes the gap is disclosed, and
    # ships a rule that fires on any decoder's `eventID=577`. So the parameter
    # exists now and the note is emitted, which is what the comment always
    # described.
    if decoder_only and diagnostics is not None:
        names = ", ".join(sorted(decoder_only))
        diagnostics.append({
            "code": "WAZUH_DECODER_PREDICATE_DROPPED",
            "severity": "caution",
            "rule_id": rule.rule_id,
            "message": (
                f"rule {rule.rule_id} also requires {names}. The rule matches on "
                f"the <field> alone, so it will fire on that field's value from "
                f"ANY decoder, not only the one this rule names. The IR cannot "
                f"carry a decoder constraint. Re-check the source rule in Wazuh, "
                f"where the decoder is real."),
        })
    return tuple(conditions)


def _read(node_id: str, source: str) -> Read:
    return Read(id=node_id, selector=SourceSelector(name=source))


def _lower_plain(chain: Any, time_field: str, source_name: str,
                 diagnostics: list[dict[str, Any]]) -> RuleIR:
    """A rule with no correlation: Read -> Filter -> Emit.

    The whole `if_sid` chain is ANDed into one filter. A child rule inherits
    every condition of its ancestors, because in Wazuh a child that fires means
    the parent fired too -- 60107 matching implies 60104 matched. Keeping only
    the leaf's own `<field>` would widen the rule to the whole log.
    """
    conditions: list[Any] = []
    for rule in chain.rules:
        conditions.extend(_rule_condition(rule, diagnostics))

    nodes: list[Any] = [_read("read", source_name), Emit(id="out", input="read")]
    if conditions:
        nodes.insert(1, Filter(id="where", input="read",
                               condition=_all_of(conditions)))
        nodes[2] = Emit(id="out", input="where")

    leaf = chain.leaf
    if leaf.unexpanded:
        diagnostics.append({
            "code": "WAZUH_UNEXPANDED_VARIABLE_PRESENT",
            "severity": "info",
            "message": f"rule {leaf.rule_id} text mentions "
                       f"{', '.join(leaf.unexpanded)}; those are ossec.conf "
                       f"variables and are not part of the lowered conditions.",
        })

    return RuleIR(rule_id=leaf.rule_id, nodes=tuple(nodes), output="out",
                  title=leaf.description, metadata=rule_metadata(leaf))


def _lower_correlation(rules: dict[str, WazuhRule], child: WazuhRule,
                       osconf: dict[str, int] | None,
                       time_field: str, source_name: str,
                       diagnostics: list[dict[str, Any]]) -> RuleIR:
    parent_id = child.if_matched_sid
    if not parent_id:
        raise WazuhParseError(
            "WAZUH_GROUP_TRIGGER_UNSUPPORTED",
            f"rule {child.rule_id} uses if_matched_group, which correlates over "
            f"a group of sibling rules rather than one event. Not lowered here.",
            DIALECT)
    parent = rules.get(parent_id)
    if parent is None:
        raise WazuhParseError(
            "WAZUH_PARENT_MISSING",
            f"rule {child.rule_id} has no conditions of its own; all of its "
            f"meaning is in if_matched_sid={parent_id}, which is not in the "
            f"supplied document. Lowering the child alone would yield a "
            f"correlation with nothing to correlate, which fires on everything.",
            DIALECT)

    # THE PARENT'S WHOLE if_sid CHAIN IS THE PARENT CONDITION. An earlier version
    # used only the immediate parent's own `<field>` elements, which silently
    # dropped 60104's ancestors. In Wazuh, 60107 firing means 60104 fired, which
    # means the event was on the Security channel at all -- so dropping the chain
    # widened the rule to every Windows event, and nothing in the output said so.
    parent_chain = resolve_chain(rules, parent_id)
    parent_conditions: list[Any] = []
    for ancestor in parent_chain.rules:
        parent_conditions.extend(_rule_condition(ancestor, diagnostics))

    osconf = dict(osconf or {})

    def resolve(value: str, what: str) -> int:
        text = (value or "").strip()
        for name, provided in osconf.items():
            text = text.replace(f"${name}", str(provided))
        return as_int(text, child.rule_id, what)

    frequency = resolve(child.frequency, "frequency")
    timeframe = resolve(child.timeframe, "timeframe")

    child_conditions = _rule_condition(child, diagnostics)
    if not child_conditions:
        # Wazuh allows a child with no `<field>` of its own, meaning "the parent,
        # N times". That is legal and must not be refused -- but it must be
        # stated, because it is a much broader rule than it looks.
        diagnostics.append({
            "code": "WAZUH_CORRELATION_HAS_NO_OWN_CONDITION",
            "severity": "warning",
            "message": f"rule {child.rule_id} declares no <field> of its own, so "
                       f"it means '{parent_id} occurred {frequency} times within "
                       f"{timeframe}s on the shared field', not a narrower "
                       f"condition. Lowering it as a filter would be a "
                       f"different rule.",
        })

    same = tuple(child.same) or tuple(parent.same)
    if not same:
        raise WazuhParseError(
            "WAZUH_CORRELATION_WITHOUT_SHARED_FIELD",
            f"rule {child.rule_id} correlates {parent_id} with no same_* element. "
            f"Wazuh groups the two on a shared field; with none, the rule would "
            f"count any occurrence anywhere in the log. Rule 60206 in the shipped "
            f"ruleset is written this way and is genuinely a very broad rule -- "
            f"say which field ties them together, or do not lower it.", DIALECT)

    # A CHILD WITH NO <field> OF ITS OWN IS NOT AN EMPTY CHILD. In Wazuh it means
    # "the parent rule, N times in the timeframe" -- the frequency counts the
    # PARENT's own occurrences. Modelling it as a childless correlation would
    # fire on the FIRST event, turning a frequency-5 rule into a plain one. That
    # is the whole detection: 60205 exists to catch a password spray, not the
    # first wrong password.
    if child_conditions:
        count_subject = "child"
        children: tuple[tuple[Any, ...], ...] = (child_conditions,)
    else:
        count_subject = "parent"
        children = ()
        diagnostics.append({
            "code": "WAZUH_FREQUENCY_COUNTS_THE_PARENT",
            "severity": "info",
            "message": f"rule {child.rule_id} declares no <field> of its own, so "
                       f"its frequency of {frequency} within {timeframe}s counts "
                       f"occurrences of {parent_id} itself on "
                       f"{', '.join(same)} -- not occurrences of a separate child "
                       f"rule. The rule fires when the {frequency}th occurrence "
                       f"lands, not on the first.",
        })

    nodes: list[Any] = [
        _read("read", source_name),
        Package(
            id="correlate",
            input="read",
            parent=tuple(parent_conditions),
            children=children,
            count_subject=count_subject,
            frequency=frequency,
            timeframe=Duration(timeframe),
            same_fields=tuple(_field_ref(name) for name in same),
            time_field=time_field,
        ),
        Emit(id="out", input="correlate"),
    ]

    metadata = rule_metadata(child)
    # The parent id is what makes a correlation writable at all. Wazuh's
    # `if_matched_sid` is a POINTER, so a renderer given only this rule has no way
    # to produce a correlation that behaves like the original -- it would have to
    # emit a child with no parent, which fires on everything. Recording the id
    # here is what lets the renderer say so by name instead of guessing.
    metadata["wazuh_parent"] = parent_id
    if same:
        metadata["wazuh_same"] = ",".join(same)
    metadata["wazuh_count_subject"] = count_subject

    return RuleIR(rule_id=child.rule_id, nodes=tuple(nodes), output="out",
                  title=child.description, metadata=metadata)
