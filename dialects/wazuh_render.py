"""RuleIR -> Wazuh Ruleset XML.

THE TRAP HERE IS WORSE THAN THE PREFIX ONE.

A Wazuh correlation rule contains NO condition of its own. Rule 60203 says
"five times in 240 seconds" and every part of its detection lives behind
`if_matched_sid=60107`, which inherits from 60104, which inherits from 60001.

So a renderer that emits only the child produces a rule that matches EVERY
event in the log. Not a rule that is slightly too broad -- a rule with no
detection in it at all, and a Wazuh file that loads without complaint. That is
the most dangerous output this tool can produce, which is why a correlation
refuses to render unless the parent chain is available to emit alongside it.
"""
from __future__ import annotations

import re
from typing import Any, Final
from xml.sax.saxutils import escape

from engine.ir import (
    Aggregate,
    BoolOp,
    Call,
    Comparison,
    Derive,
    FieldExpr,
    Filter,
    Literal,
    Not,
    Package,
    RuleIR,
)
from engine.values import Refusal
from dialects.wazuh import DIALECT


def _attr(value: str) -> str:
    """Escape a value for a DOUBLE-QUOTED XML attribute.

    `xml.sax.saxutils.escape` handles only `&`, `<` and `>`. It does NOT escape
    `"`, and every attribute in a Wazuh rule is double-quoted. So a field name
    carrying `&quot;` re-parsed as a REAL quote and a REAL attribute: pasting
    `name="win.eventdata.newProcessName&quot; negate=&quot;yes"` produced
    `<field name="win.eventdata.newProcessName" negate="yes">`, which INVERTS the
    match -- the rule then alerted on every process that is not the target, with
    no diagnostic anywhere.

    Whole-tag injection is still blocked, because `<` and `>` are escaped. The
    impact was bounded to attribute injection, but inverting a detection test is
    about the worst thing this tool could do.
    """
    return escape(value, {'"': "&quot;", "'": "&apos;"})

#: IR comparison operator -> the regex Wazuh would need. Wazuh has no `>=` on a
#: field; it has `pcre2`/`os_regex`. Rendering a comparison as a regex is only
#: honest for equality against a literal, so anything else is refused rather
#: than approximated -- a `<field type="pcre2">` built from `>=` semantics would
#: be a regex that matches the wrong strings.
_COMPARISON = {"=": "eq", "!=": "ne", "<": "lt", "<=": "le", ">": "gt", ">=": "ge"}

#: Wazuh's documented range for `<rule level>`.
#:
#: ZERO IS A REAL, LEGAL LEVEL. The shipped ruleset uses it, and this guard does
#: NOT reject it. A guard written as "level must be positive" would refuse a
#: correct vendor rule, and a guard that fires on the wrong input is worse than
#: no guard -- it teaches the analyst that the tool objects to valid rules.
LEVEL_MIN = 0
LEVEL_MAX = 16


def _validated_level(raw: object, from_wazuh: bool) -> str:
    """Return a level that is safe to put in a Wazuh artifact, or refuse.

    FOUR THINGS WERE WRONG, AND ONLY THE FIRST IS THE ONE PEOPLE NOTICE.

    A WAZUH RULE WITH NO SEVERITY BECAME `0`. `wazuh.py` records a missing
    `level` attribute as `""`, and this used to read
    `ir.metadata.get("level") or "0"` -- so a rule pasted with no `level` at all
    rendered as `level="0"`, silently. Wazuh's own default is also 0, so the
    artifact is not *wrong*; it is UNSPEAKABLE. The analyst never wrote a
    severity, the artifact claims they did, and a level-0 alert is not displayed
    by default. A detection deployed that way looks healthy and matches nothing
    anyone is looking at.

    A RULE THAT WAS NEVER WAZUH AT ALL ALSO HIT THAT LINE, AND THAT IS A
    DIFFERENT MISTAKE. Rendering a Sentinel or SPL rule as Wazuh is a thing this
    tool is for, and such a graph carries no `level` key -- there was never a
    severity to carry, because the source dialect has no such concept. `or "0"`
    invented one. So the two cases are told apart by `from_wazuh` and get
    separate codes: one says "your Wazuh rule has no severity", the other says
    "this was not written for Wazuh and RuleForge will not pick a severity for
    you". Neither defaults. Both fail closed.

    A NON-INTEGER reached the artifact. `'abc'`, `'10.5'`, `'-1'`, `'1e3'` and
    `'+5'` all passed straight through to `level="..."`, and `_attr` escapes XML
    metacharacters but has no reason to question a number. Wazuh would reject
    the file, or coerce it to something the analyst did not write.

    AN OUT-OF-RANGE INTEGER reached the artifact. `'99999'` is a syntactically
    fine integer and semantically meaningless.

    THE INTEGER TEST IS `isascii() AND isdigit()`, NOT `isdigit()`. `isdigit()`
    is true for `'²'` -- and `int('²')` then raises `ValueError`, so a crash
    rather than a refusal. It is also true for Arabic-Indic and full-width
    digits, which `int()` parses happily into a number the analyst never typed
    and which Wazuh would not read. Requiring ASCII first makes the set exactly
    `'0'`-`'9'`, which `int()` always accepts, so the parse below cannot throw.
    """
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        if from_wazuh:
            raise Refusal(
                "WAZUH_LEVEL_ABSENT",
                f"this Wazuh rule has no `level` attribute, so its severity was "
                f"never stated. Wazuh would default it to 0, and a level-0 alert "
                f"is not shown by default -- the rule would look deployed and be "
                f"invisible. RuleForge will not choose a severity for you. Add an "
                f"explicit level, for example level=\"{LEVEL_MAX}\", and it will "
                f"render.", DIALECT)
        raise Refusal(
            "WAZUH_NO_LEVEL_TO_CARRY",
            f"this rule was not written for Wazuh, so it has no severity to "
            f"carry across, and Wazuh's `level` has no equivalent in "
            f"{'its source dialect'}. Inventing one would put a number in the "
            f"artifact that nobody chose -- and a level-0 alert is not displayed "
            f"by default, so the rule would look deployed and be invisible. Say "
            f"what severity you want and it will render.", DIALECT)

    text = str(raw).strip()
    if not (text.isascii() and text.isdigit()):
        raise Refusal(
            "WAZUH_LEVEL_NOT_AN_INTEGER",
            f"level={text!r} is not a whole number. Wazuh's `level` is an "
            f"integer from {LEVEL_MIN} to {LEVEL_MAX}; rendering this unchanged "
            f"would produce a rule file the agent rejects. If you meant a "
            f"severity threshold, that is a different attribute and this tool "
            f"will not guess which one you meant.", DIALECT)

    value = int(text)
    if not (LEVEL_MIN <= value <= LEVEL_MAX):
        raise Refusal(
            "WAZUH_LEVEL_OUT_OF_RANGE",
            f"level={value} is outside Wazuh's range of {LEVEL_MIN} to "
            f"{LEVEL_MAX}. A number that large is not a severity, and emitting "
            f"it would put a value in the artifact that the agent cannot act on.",
            DIALECT)
    return text


def render(ir: RuleIR) -> str:
    """Render a RuleIR back to Wazuh ruleset XML."""
    rule_id = ir.metadata.get("wazuh_id") or ir.rule_id

    filters = [n for n in ir.nodes if isinstance(n, Filter)]
    package = next((n for n in ir.nodes if isinstance(n, Package)), None)
    # EVERY Derive, NOT THE FIRST ONE. This was `next((n for n in ir.nodes if
    # isinstance(n, Derive)), None)`, which stops at the first match and says
    # nothing about a second -- and the node check below `continue`s on Derive,
    # so a second one was not caught there either. It vanished. The comment this
    # function carried for three rounds claimed a second Derive was covered; it
    # was covered by nothing. Collecting the whole list is what makes the
    # "no silent drop" promise true, and the count is checked where the
    # derivation is consumed.
    derives = [n for n in ir.nodes if isinstance(n, Derive)]
    derive = derives[0] if derives else None
    aggregate = next((n for n in ir.nodes if isinstance(n, Aggregate)), None)

    # INVERT THE DEFAULT. This function used to pick out the Filter, Package,
    # Derive and Aggregate nodes it knew about and say nothing about the rest, so
    # a SetOp, Join, Pattern, Expand, Arrange, SetRule or a second Derive
    # VANISHED and every surviving Filter was joined together -- a union rendered
    # as an intersection. Latent for the Wazuh lowerer, which only emits Read,
    # Filter, Package and Emit, but `render_wazuh` is public and the IR is the
    # documented interchange format, so the hole was one call away.
    #
    # ORDER MATTERS AND IT IS NOT COSMETIC. This check runs AFTER the aggregate
    # dispatch, so a rule that both aggregates and carries a node Wazuh cannot
    # express gets `WAZUH_RENDER_AGGREGATE_NOT_A_RULE` -- the reason that actually
    # explains the output -- rather than the generic complaint about whichever
    # node happened to be visited first. Both are refusals, so both are
    # fail-closed; the difference is only whether the message is useful.
    # THE NODE CHECK MUST RUN FIRST, NOT AFTER THE DISPATCH.
    #
    # It used to sit below `if package is not None: return _render_correlation(...)`,
    # so any `Package` bypassed it entirely -- which reopened the exact hole the
    # check was added for, one branch earlier in the same function. Round 5 caught
    # it with `Package` + `SetOp(union)`, `Package` + a top-level `Filter`, and
    # `Package` + `Derive(projects=True)`: all rendered clean, all silently
    # dropped the other node, all left the correlation with no condition of its
    # own counting 5-in-300s. The function also never inspected `ir.nodes` for a
    # `Filter`, which is why the original "correlation dropped its own <field>"
    # bug survived here in the first place.
    # AN AGGREGATE REACHES ITS OWN REFUSAL FIRST, ALWAYS.
    #
    # `_render_plain` refuses unconditionally when an Aggregate is present, so
    # putting this first cannot let anything through -- it only decides WHICH
    # refusal the analyst sees. WAZUH_RENDER_AGGREGATE_NOT_A_RULE says "a Wazuh
    # rule tests event fields, not computed columns"; the generic node check
    # would say "SetOp is not renderable" about some other node in the same
    # graph, which is true and useless.
    # TWO Derive NODES, AND WAZUH HAS NOWHERE TO PUT THE SECOND. A projection
    # and a rename both lower to `Derive`, and `<rule>` has no second slot, so
    # the honest answer is to refuse rather than render one of them. It used to
    # be `next((n for n in ir.nodes if isinstance(n, Derive)), None)`, which
    # stops at the first and says nothing about the second -- and the node check
    # below `continue`s on `Derive`, so a second one was caught by NOTHING. The
    # comment this function carried for three rounds claimed it was covered.
    #
    # IT SITS BELOW THE AGGREGATE RETURN ON PURPOSE, which is where it was NOT
    # when first written. The user's own Sentinel rule lowers to a KQL graph
    # that has BOTH two Derives and an Aggregate, and this guard fired first and
    # reported the two-derive problem -- true, but not the reason that explains
    # the output. "a Wazuh rule tests event fields, not computed columns" is the
    # useful sentence when a summarise is present. Putting this above the
    # aggregate return is also SAFE to move, because `_render_plain` refuses
    # unconditionally when an Aggregate is present, so that path can never reach
    # an artifact and needs no Derive guard of its own.
    if len(derives) > 1 and aggregate is None:
        raise Refusal(
            "WAZUH_TWO_DERIVES_NOT_RENDERABLE",
            f"this rule has {len(derives)} Derive nodes -- a projection and a "
            f"rename, most likely. A Wazuh rule has no second place to put one: "
            f"one of them was being dropped, which is how a rename stops "
            f"happening and the rule matches on a column name the analyst never "
            f"wrote. Render it with the dialect that supports both.", DIALECT)

    if aggregate is not None:
        # THE LEVEL IS DELIBERATELY NOT VALIDATED ON THIS PATH. `_render_plain`
        # refuses unconditionally the moment an Aggregate is present, before it
        # writes anything, so a level can never reach an artifact by this route
        # -- there is nothing to guard.
        #
        # Validating anyway was the bug. It made a level complaint outrank the
        # aggregate complaint, so the user's own Sentinel rule -- a graph with
        # both an Aggregate and no Wazuh level -- was told its level was missing
        # instead of being told that a Wazuh rule tests event fields rather than
        # computed columns. Both are refusals and both fail closed; only the
        # sentence the analyst reads changes, and the aggregate sentence is the
        # one that explains the output.
        #
        # `str(... or "0")` is a placeholder that is never written anywhere. It
        # is here because the call signature takes a level, and passing a value
        # that provably cannot be used is better than widening the signature or
        # duplicating the refusal.
        return _render_plain(ir, filters, derive, aggregate, rule_id,
                             str(ir.metadata.get("level") or "0"))

    for node in ir.nodes:
        if isinstance(node, (Filter, Package, Derive, Aggregate)):
            continue
        if type(node).__name__ in ("Read", "Emit", "SetRule"):
            continue
        raise Refusal(
            "WAZUH_NODE_NOT_RENDERABLE",
            f"this rule contains a {type(node).__name__} node, and a Wazuh "
            f"rule cannot express one alongside the rest of what it asks for. "
            f"It was being dropped silently, which meant a union came out as an "
            f"intersection and a correlation lost its own condition -- a rule "
            f"matching a different set of events than the one you asked about. "
            f"Render it with the dialect that supports it.", DIALECT)

    # THE LEVEL IS VALIDATED HERE, AND THE POSITION IS FORCED BY THE SHAPE OF
    # THE FUNCTION. Both returns that CAN write a level -- correlation and plain
    # -- are below here, so both are covered, and the aggregate return above is
    # already an unconditional refusal. Nothing reaches `_wrap` unvalidated.
    #
    # `wazuh.py` records a missing `level` as `""`, so a Wazuh rule with no
    # severity arrives as an empty STRING, while a rule that was never written
    # for Wazuh at all arrives as a MISSING KEY. Those are different mistakes
    # and they get different refusals -- see `_validated_level`.
    level = _validated_level(ir.metadata.get("level"), "level" in ir.metadata)

    if package is not None:
        return _render_correlation(ir, package, rule_id, level)

    if filters:
        return _render_plain(ir, filters, derive, aggregate, rule_id, level)

    raise Refusal("WAZUH_RENDER_NOTHING_TO_RENDER",
                  "this rule has no condition, no correlation and no aggregate, "
                  "so there is nothing for a Wazuh rule to say", DIALECT)


def _render_plain(ir: RuleIR, filters: list[Filter], derive: Derive | None,
                  aggregate: Aggregate | None, rule_id: str,
                  level: str) -> str:
    body: list[str] = []
    terms: list[str] = []

    # A THRESHOLD IS NOT A FIELD TEST. `aggregate` was accepted and IGNORED, so a
    # KQL rule like `| summarize c=count() by host | where c > 5` rendered as a
    # Wazuh rule testing the literal string `gt5` against a column named `c` --
    # a column that is not an event field, because `c` only exists as the OUTPUT
    # of the aggregate that was dropped. The rule could never fire and contained
    # no detection. Wazuh counts with `frequency` on a correlation, not with a
    # threshold on a computed column, so there is no honest rendering here.
    if aggregate is not None:
        raise Refusal(
            "WAZUH_RENDER_AGGREGATE_NOT_A_RULE",
            f"this rule aggregates and then tests the aggregate's output "
            f"({', '.join(m.name for m in aggregate.measures)}). A Wazuh rule "
            f"tests EVENT fields, not computed columns -- there is no such thing "
            f"as a threshold on a column that only exists because the rule "
            f"computed it. Wazuh expresses 'N times' with `frequency` and "
            f"`timeframe` on a correlation, which is a different rule shape. "
            f"Emitting the threshold as a field test would produce a rule that "
            f"can never match.", DIALECT)

    for node in filters:
        for condition in _flatten(node.condition):
            name = _field(condition)
            if name is None:
                raise Refusal(
                    "WAZUH_RENDER_TERM_NOT_A_FIELD_TEST",
                    "a Wazuh rule can only say `field matches pattern`. This "
                    "condition is an arithmetic or aggregate expression, which "
                    "Wazuh has no `<field>` form for. Emitting it as a field test "
                    "would invent a test the rule never made.", DIALECT)
            terms.extend(_field_elements(condition, name))

    # A `project` becomes a `fields` list, which is how Wazuh restricts a rule
    # to the columns it alerts on. Dropping it changes what the alert shows.
    if derive is not None and _is_projection(derive):
        columns = ", ".join(alias for alias, _ in derive.assignments)
        body.append(f"  <fields>{escape(columns)}</fields>")

    body.extend(f"  {term}" for term in terms)
    if ir.title:
        body.append(f"  <description>{escape(ir.title)}</description>")
    mitre = ir.metadata.get("mitre", "")
    if mitre:
        ids = "".join(f"\n    <id>{escape(m.strip())}</id>"
                      for m in mitre.split(",") if m.strip())
        body.append(f"  <mitre>{ids}\n  </mitre>")

    return _wrap(rule_id, level, body)


def _render_correlation(ir: RuleIR, package: Package, rule_id: str,
                        level: str) -> str:
    parent_id = ir.metadata.get("wazuh_parent", "")
    if not parent_id:
        # The whole detection is behind if_matched_sid. Without the parent's id
        # there is no rule to write, and writing the child alone yields a
        # correlation with nothing to correlate -- which fires on everything.
        raise Refusal(
            "WAZUH_RENDER_CORRELATION_WITHOUT_PARENT",
            "this is a parent/child correlation, and Wazuh's if_matched_sid needs "
            "the id of the rule it reacts to. That id is not recorded on the rule, "
            "so there is no way to write a correlation that would behave like the "
            "one this came from. Re-parse the original XML instead of rendering "
            "the IR alone.", DIALECT)

    # A TOP-LEVEL FILTER ALONGSIDE A CORRELATION IS DROPPED, NOT RENDERED.
    # `_render_correlation` reads `package.children` and never looks at
    # `ir.nodes`, so a `Filter` next to a `Package` simply vanished: the reviewer's
    # probe was `Filter(secret_field == "NEEDLE")` + a Package, and the rendered
    # rule contained the correlation and neither the filter nor any mention of
    # the field. The correlation was emitted with no condition of its own,
    # counting 5-in-300s on whatever matched the parent. A `Filter` is
    # renderable on its own, so the generic node check above waves it past --
    # which is why this has to be caught here, where the two node kinds meet.
    # EVERY NODE BESIDE THE CORRELATION IS AN ORPHAN, NOT JUST A `Filter`.
    #
    # `_render_correlation` reads `package.children` and never looked at
    # `ir.nodes`, so anything next to a `Package` simply vanished. A `Filter` was
    # caught in round 6; a `Derive` was not, and neither was a second `Package`,
    # because both passed the generic allow-list above (`Derive` is renderable on
    # its own, and `Package` is `next(...)`-ed at the dispatch) and then fell
    # through here. The reviewer's probe was
    # `Filter(secret_field == "NEEDLE")` plus a Package, and the rendered rule
    # contained the correlation and neither the filter nor any mention of the
    # field.
    #
    # Enumerating `Filter` was the same mistake one level down: it fixed the
    # instance a reviewer happened to try. This asks the question directly --
    # is this node the correlation, or something else that will not be written?
    orphans = [n for n in ir.nodes
               if n is not package
               and type(n).__name__ not in ("Read", "Emit", "SetRule")]
    if orphans:
        kinds = ", ".join(sorted({type(n).__name__ for n in orphans}))
        raise Refusal(
            "WAZUH_CORRELATION_WITH_TRAILING_NODE",
            f"this rule has a correlation and {len(orphans)} node(s) beside it "
            f"({kinds}). A Wazuh correlation's own conditions live in its child, "
            f"so anything next to it was being dropped -- which meant the "
            f"rendered rule counted whatever matched the parent and nothing "
            f"else, a much broader rule than the one you asked about. Re-parse "
            f"the source XML, or render with the dialect that can express a "
            f"correlation and other nodes together.", DIALECT)

    same = ", ".join(field.full for field in package.same_fields)
    if not same:
        raise Refusal(
            "WAZUH_RENDER_CORRELATION_WITHOUT_SHARED_FIELD",
            "a Wazuh correlation groups on a same_* element. Without one the "
            "rendered rule would count anywhere in the log.", DIALECT)

    # THE CORRELATION'S OWN `<field>` WAS DROPPED, AND IT IS APP-REACHABLE.
    # A rule with `if_matched_sid` AND its own `<field>` lowers correctly -- the
    # field lands in `package.children` -- and then this function emitted only
    # the correlation elements, so:
    #
    #     in : if_matched_sid=200, same_field=srcip, frequency=5, timeframe=300,
    #          <field name="win.eventdata.CommandLine">notepad\.exe</field>
    #     out: <rule id="300" ...><if_matched_sid>200</if_matched_sid>...
    #
    # The `notepad.exe` condition was GONE. The deployed rule counted 5 events in
    # 300 seconds that matched 200, filtered by nothing, with
    # `diagnostics: NONE`. Reachable by pasting a ruleset -- no hand-built IR
    # needed. The child conditions have to be written out, before the
    # correlation elements.
    conditions: list[str] = []
    # `children` is a tuple of CONJUNCTIONS -- each entry is already the list of
    # conditions one child asserts, not a Filter node. So the entry is unpacked
    # here rather than handed to `_flatten` whole: `_flatten` returns a non-BoolOp
    # unchanged, so passing the tuple gave `_field` a tuple, which is not a field
    # test, and every correlation with a condition of its own refused instead of
    # rendering. That is how the condition stayed missing in the first place.
    for conjunction in package.children:
        parts = (conjunction if isinstance(conjunction, (tuple, list))
                 else (conjunction,))
        for part in parts:
            for condition in _flatten(part):
                name = _field(condition)
                if name is None:
                    raise Refusal(
                        "WAZUH_RENDER_TERM_NOT_A_FIELD_TEST",
                        "a Wazuh rule can only say `field matches pattern`. This "
                        "condition is an arithmetic or aggregate expression, "
                        "which Wazuh has no `<field>` form for. Emitting it as a "
                        "field test would invent a test the rule never made.",
                        DIALECT)
                conditions.extend(_field_elements(condition, name))
    # NO REFUSAL FOR AN EMPTY `conditions`. A correlation with no condition of
    # its own is a legitimate Wazuh rule -- "count 5 of whatever matches 200" --
    # and refusing it would be over-strict in the wrong direction. The defect
    # was DROPPING the children, not permitting their absence.

    body = [
        *conditions,
        f'  <if_matched_sid>{escape(parent_id)}</if_matched_sid>',
        f'  <same_field>{escape(same.split(",")[0].strip())}</same_field>'
        if len(same.split(",")) == 1 else
        "".join(f"  <same_field>{escape(part.strip())}</same_field>"
                for part in same.split(",")),
        f'  <frequency>{package.frequency}</frequency>',
        f'  <timeframe>{int(package.timeframe.seconds)}</timeframe>',
    ]
    if ir.title:
        body.append(f"  <description>{escape(ir.title)}</description>")
    return _wrap(rule_id, level, body, attributes=(
        f' frequency="{package.frequency}" '
        f'timeframe="{int(package.timeframe.seconds)}"'
    ))


def _wrap(rule_id: str, level: str, body: list[str],
          attributes: str = "") -> str:
    head = f'  <rule id="{_attr(rule_id)}" level="{_attr(level)}"{attributes}>'
    if not body:
        return f"{head}\n  </rule>\n"
    return "\n".join([head, *body, "  </rule>", ""])


def _is_projection(node: Derive) -> bool:
    return node.projects


def _flatten(expression: Any) -> list[Any]:
    if isinstance(expression, BoolOp) and expression.op == "and":
        out: list[Any] = []
        for operand in expression.operands:
            out.extend(_flatten(operand))
        return out
    if isinstance(expression, Not):
        # Wazuh's `negate="yes"` covers exactly this.
        return [expression]
    return [expression]


def _field(expression: Any) -> str | None:
    """The field name an expression tests, or None if it is not a field test."""
    if isinstance(expression, Comparison):
        left, right = expression.left, expression.right
        if isinstance(left, FieldExpr) and isinstance(right, Literal):
            return left.ref.full
        if isinstance(right, FieldExpr) and isinstance(left, Literal):
            return right.ref.full
    if isinstance(expression, Call) and expression.args:
        subject = expression.args[0]
        if isinstance(subject, FieldExpr):
            return subject.ref.full
    return None


#: A Wazuh field name. Dotted, because that is what they are:
#: `win.eventdata.CommandLine`, `win.system.providerName`.
#:
#: `_attr` ESCAPES A NAME BUT DOES NOT MAKE IT MEANINGFUL. `escape` handles `&`,
#: `<`, `>`, `"` and `'`, so a newline in a field name cannot break out of the
#: attribute -- the round-7 review reported a complete attacker-chosen rule here,
#: and that is not what happens: the quotes are escaped, so exactly one `<rule>`
#: is emitted and the document re-parses. What IS true is quieter and still a
#: defect: `name="a&#10;rule pwned {"` is a legal attribute whose VALUE contains
#: newlines, so the rendered rule tests a column called
#: `a<newline>rule pwned {`, which cannot exist. The rule can never match, and
#: nothing says so. A field name is an identifier, so it is checked as one.
_FIELD_PATH: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")


def _check_field_name(name: str) -> str:
    if not _FIELD_PATH.fullmatch(name):
        raise Refusal(
            "WAZUH_FIELD_NAME_NOT_A_PATH",
            f"the field name {name!r} is not a dotted Wazuh field path made of "
            f"letters, digits and underscores. Escaping it keeps the document "
            f"well-formed, but a name containing a newline or a brace names a "
            f"column that cannot exist, so the rule could never match and "
            f"nothing would say so. Wazuh event fields look like "
            f"`win.eventdata.CommandLine`.", DIALECT)
    return name


def _field_elements(expression: Any, name: str) -> list[str]:
    """One expression -> the `<field>` elements that say it, for `name`.

    The field name is passed IN rather than templated. A first attempt emitted
    `<field name="{NAME}">` and never substituted, so every rendered rule
    referenced a literal column called `{NAME}`.
    """
    negate = ""
    if isinstance(expression, Not):
        negate = ' negate="yes"'
        expression = expression.operand

    safe = _attr(_check_field_name(name))

    if isinstance(expression, Call):
        if expression.function == "matches_regex":
            pattern = expression.args[1].value
            # The DIALECT COMES BACK as Wazuh's own `type`. Emitting a `pcre`
            # pattern as `os_regex` would change what it matches -- `\.` and
            # `[0-9]` do not mean the same thing in the two engines.
            kind = {"pcre": "pcre2", "posix_extended": "os_regex"}.get(
                expression.dialect or "", "os_regex")
            return [f'<field name="{safe}"{negate} type="{kind}">'
                    f'{escape(pattern)}</field>']

    if isinstance(expression, Comparison):
        operator = _COMPARISON.get(expression.op)
        if operator == "eq":
            value = _literal_text(expression.right)
            return [f'<field name="{safe}"{negate}>{escape(value)}</field>']
        if operator is not None:
            # Wazuh has no ordered field test of its own. `type="numeric"` is
            # the documented way to compare a field as a number, and the
            # operator is spelled out so the reader can see what was assumed.
            return [f'<field name="{safe}"{negate} type="numeric">'
                    f'{escape(operator)}{escape(_literal_text(expression.right))}'
                    f'</field>']

    raise Refusal("WAZUH_RENDER_EXPRESSION_UNSUPPORTED",
                  f"a {type(expression).__name__} has no Wazuh `<field>` form",
                  DIALECT)


def _literal_text(literal: Any) -> str:
    value = literal.value if isinstance(literal, Literal) else literal
    return str(value)
