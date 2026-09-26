"""Round 4, part 2: Wazuh and YARA-L never got the refusal the other three
dialects got, so they fell through by default.

Eight detection-bypass defects, all the same shape: something was dropped, and
the artifact still looked complete. AQL, KQL and SPL each grew an explicit
unsupported-node refusal. Wazuh and YARA-L did not, so for them the unsafe
behaviour was the DEFAULT.
"""
import dataclasses
import unittest

from ruleforge import jobs
from ruleforge.dialects.wazuh import parse_wazuh
from ruleforge.dialects.wazuh_ir import lower as lower_wazuh
from ruleforge.dialects.wazuh_render import render as render_wazuh
from ruleforge.dialects.yaral import parse_yaral
from ruleforge.dialects.yaral_ir import lower as lower_yaral
from ruleforge.dialects.yaral_ir import render as render_yaral
from ruleforge.engine import Refusal

CORRELATION = (
    '<group name="correlation,">'
    '<rule id="200" level="5">'
    '<field name="cmd">notepad\\.exe</field><description>base</description></rule>'
    '<rule id="300" level="10" frequency="5" timeframe="300">'
    '<if_matched_sid>200</if_matched_sid><same_field>srcip</same_field>'
    '<field name="win.eventdata.CommandLine">lsass\\.exe</field>'
    '<description>cor</description></rule></group>')

YARAL_SINGLE = """rule R {
  meta:
    author = "t"
  events:
    $e0.win.eventdata.CommandLine = /lsass\\.exe/
  condition:
    $e0
}"""


class WazuhPredicatesAreNotPresentation(unittest.TestCase):
    """THE ROUND-3 `<match>` CRITICAL, REACHED THROUGH A DIFFERENT TAG.

    `_IGNORED_ELEMENTS` was documented as "presentation, grouping and agent
    plumbing", and then listed nine documented PREDICATES in it. The Wazuh
    Rules Syntax doc calls `program_name`, `hostname`, `status`, `data`,
    `extra_data`, `location`, `regex`, `list` and `check_diff` "a requisite to
    trigger a rule" -- they ARE conditions. The reviewer's repro, one element
    changed:

        jobs.author -> ok=True, refusal=None, graph ['Read','Emit']
        jobs.tune   -> "The rule matched 3 of 3 events."

    A detection that fires on everything while reporting success.
    """

    def _refusal(self, element):
        xml = (f'<group name="g,"><rule id="1" level="3">{element}'
               f'<description>d</description></rule></group>')
        with self.assertRaises(Refusal) as caught:
            lower_wazuh(xml, "1")
        return caught.exception.code

    def test_program_name_is_a_condition_not_a_label(self):
        self.assertEqual(
            self._refusal("<program_name>syslogd</program_name>"),
            "WAZUH_ELEMENT_UNKNOWN")

    def test_the_other_predicates_are_conditions_too(self):
        for element in ("<status>403</status>",
                        '<regex type="os_regex">^a.*b$</regex>',
                        "<data>x=1</data>",
                        "<extra_data>payload</extra_data>",
                        "<location>/var/log/x</location>",
                        "<hostname>host1</hostname>",
                        '<list field="srcip" type="address">10.0.0.1</list>',
                        "<check_diff>First</check_diff>",
                        "<sha1>abc</sha1>"):
            with self.subTest(element=element):
                self.assertEqual(self._refusal(element),
                                 "WAZUH_ELEMENT_UNKNOWN")

    def test_presentation_elements_are_still_ignored(self):
        # The ignore-list is not empty, and making it empty would be over-strict
        # in the wrong direction: refusing `<category>` would make the SHIPPED
        # ruleset unusable, and it uses both `<category>` and `<decoded_as>`.
        xml = ('<group name="g,"><rule id="1" level="3">'
               "<info>note</info><comment>c</comment>"
               "<documentation>d</documentation>"
               '<field name="cmd">x</field>'
               "<description>d</description></rule></group>")
        ir, _ = lower_wazuh(xml, "1")
        self.assertEqual([type(n).__name__ for n in ir.nodes],
                         ["Read", "Filter", "Emit"])

    def test_decoder_predicates_alone_are_refused(self):
        """`<decoded_as>` and `<category>` are NOT presentation.

        The Wazuh Rules Syntax doc says of both, verbatim: "Used as a requisite
        to trigger a rule. It will be triggered if the event has been decoded by
        a certain decoder." Ignoring them gave `ok=True`, `graph ['Read','Emit']`
        and "The rule matched 3 of 3 events" -- the same critical as the nine
        field predicates, reached through the two elements the doc names
        explicitly.
        """
        for element in ("<category>syslog</category>",
                        "<decoded_as>json</decoded_as>",
                        "<decoded_as>smtpd</decoded_as>"):
            with self.subTest(element=element):
                xml = (f'<group name="g,"><rule id="1" level="3">{element}'
                       f"<description>d</description></rule></group>")
                with self.assertRaises(Refusal) as caught:
                    lower_wazuh(xml, "1")
                self.assertEqual(caught.exception.code,
                                 "WAZUH_DECODER_PREDICATE_ONLY")

    def test_a_decoder_predicate_beside_a_field_still_lowers(self):
        """Refusing here would break the shipped ruleset, which uses both."""
        xml = ('<group name="g,"><rule id="1" level="3">'
               "<category>authentication_failed</category>"
               '<field name="cmd">x</field>'
               "<description>d</description></rule></group>")
        ir, _ = lower_wazuh(xml, "1")
        self.assertEqual([type(n).__name__ for n in ir.nodes],
                         ["Read", "Filter", "Emit"])

    def test_a_dropped_predicate_never_reports_a_match(self):
        """The end-to-end shape of the defect, not just the refusal code."""
        xml = ('<group name="g,"><rule id="1" level="3">'
               "<program_name>syslogd</program_name>"
               "<description>d</description></rule></group>")
        with self.assertRaises(Refusal):
            ir, _ = lower_wazuh(xml, "1")
            jobs.tune(ir, [{"a": 1}, {"a": 2}, {"a": 3}])


class WazuhIfLevelIsNotIfSlevel(unittest.TestCase):
    """`if_slevel` appears nowhere in Wazuh. The real element is `if_level`.

    So the whitelist entry was doubly wrong: a real `<if_level>5</if_level>` hit
    the unknown-element refusal, and the name that WAS accepted could never match
    anything real.
    """

    def test_if_level_is_refused_not_merely_recorded(self):
        """`if_slevel` appears nowhere in Wazuh. The real element is `if_level`.

        So the whitelist entry was doubly wrong: a real `<if_level>5</if_level>`
        hit the unknown-element refusal, and the name that WAS accepted could
        never match anything real.

        THIS TEST USED TO ASSERT ONLY THAT THE STRING WAS RECORDED. Round 7 found
        that the recorded value was never read by anything, and that
        `other_triggers.append(tag)` discarded the `5` as well -- so it passed
        while the rule fired on levels it must not. A test that asserts a value
        was stored, when what matters is whether it was USED, is a test that
        reads as coverage and provides none. It asserts the refusal now.
        """
        for element in ("<if_level>5</if_level>", "<if_group>grp</if_group>"):
            with self.subTest(element=element):
                xml = (f'<group name="g,"><rule id="2" level="3">{element}'
                       f'<description>d</description></rule></group>')
                with self.assertRaises(Refusal) as caught:
                    lower_wazuh(xml, "2")
                self.assertEqual(caught.exception.code,
                                 "WAZUH_ALERT_LEVEL_TRIGGER_UNSUPPORTED")

    def test_if_slevel_is_not_a_wazuh_element(self):
        xml = ('<group name="g,"><rule id="3" level="3">'
               "<if_slevel>5</if_slevel><description>d</description></rule></group>")
        with self.assertRaises(Refusal) as caught:
            lower_wazuh(xml, "3")
        self.assertEqual(caught.exception.code, "WAZUH_ELEMENT_UNKNOWN")


class WazuhCorrelationKeepsItsOwnField(unittest.TestCase):
    """APP-REACHABLE FROM A PASTED RULESET, WITH NO DIAGNOSTIC.

    A rule with `if_matched_sid` AND its own `<field>` lowers correctly -- the
    field lands in `Package.children` -- and the renderer emitted only the
    correlation elements. The deployed rule then counted 5 events in 300 seconds
    that matched 200, filtered by nothing.
    """

    def test_the_child_condition_is_written_out(self):
        ir, _ = lower_wazuh(CORRELATION, "300")
        rendered = render_wazuh(ir)
        self.assertIn("lsass", rendered,
                      "the correlation's own condition was dropped")
        self.assertIn("<if_matched_sid>200</if_matched_sid>", rendered)
        # The condition has to come BEFORE the correlation elements, because
        # that is the order a Wazuh rule reads in.
        self.assertLess(rendered.index("lsass"),
                        rendered.index("if_matched_sid"))

    def test_a_correlation_with_no_condition_is_still_legal(self):
        """Refusing this would be over-strict in the wrong direction.

        "Count 5 of whatever matches 200" is a real Wazuh rule. The defect was
        DROPPING the children, not permitting their absence.
        """
        xml = ('<group name="correlation,">'
               '<rule id="200" level="5"><field name="cmd">x</field>'
               "<description>b</description></rule>"
               '<rule id="301" level="10" frequency="3" timeframe="60">'
               "<if_matched_sid>200</if_matched_sid>"
               "<same_field>srcip</same_field>"
               "<description>c</description></rule></group>")
        ir, _ = lower_wazuh(xml, "301")
        self.assertIn("if_matched_sid", render_wazuh(ir))


def _union_ir():
    """A RuleIR carrying a SetOp.

    Built directly rather than parsed, because KQL refuses `| union` at lower
    time (KQL_OPERATOR_UNSUPPORTED) -- so there is no dialect that will hand us
    one, which is exactly why the renderers need the check.
    """
    from ruleforge.engine.ir import (Comparison, Emit, FieldExpr, FieldRef,
                                    Filter, Literal, Read, RuleIR, SetOp,
                                    SourceSelector)
    return RuleIR(
        rule_id="S",
        nodes=(Read(id="r", selector=SourceSelector(name="x", kind="events")),
               Filter(id="f", input="r", condition=Comparison(
                   "=", FieldExpr(FieldRef("a", ())), Literal("b"))),
               SetOp(id="u", op="union", left="f", right="f",
                    keys=(FieldRef("a", ()),)),
               Emit(id="e", input="u")),
        output="o", title="S", metadata={"wazuh_id": "9", "level": "3"})


class WazuhUnrenderableNodesAreNamed(unittest.TestCase):
    """`render` picked out the node types it knew and said nothing about the
    rest, so a SetOp VANISHED and every surviving Filter was joined with `and` --
    a union rendered as an intersection."""

    def test_a_setop_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            render_wazuh(_union_ir())
        self.assertEqual(caught.exception.code, "WAZUH_NODE_NOT_RENDERABLE")

    def test_a_package_does_not_bypass_the_node_check(self):
        """THE CHECK ONCE SAT BELOW THE PACKAGE DISPATCH.

        `if package is not None: return _render_correlation(...)` came first, so
        any Package skipped the check entirely and a sibling node was dropped
        silently -- the same hole the check was added for, one branch earlier in
        the same function.

        THIS DOCSTRING USED TO CLAIM `Package + Derive(projects=True)` WAS ONE OF
        THE CASES COVERED. IT WAS NOT: the loop below enumerated only SetOp and
        Filter, which is exactly how a `Derive` sibling survived a green suite.
        A comment in a test that overstates its own coverage is worse than a
        missing test, because a reviewer reads it and stops looking. So the third
        case is here now, and it FAILS until the drop is fixed -- which is the
        point of writing it down.
        """
        from ruleforge.engine.ir import (Comparison, Derive, FieldExpr, FieldRef,
                                        Filter, Literal, SetOp)
        base, _ = lower_wazuh(CORRELATION, "300")
        secret = Filter(id="s", input="r", condition=Comparison(
            "=", FieldExpr(FieldRef("secret_field", ())), Literal("NEEDLE")))
        projection = Derive(
            id="d", input="p", projects=True,
            assignments=(("host", FieldExpr(FieldRef("host", ()))),))
        for label, extra in (
                ("SetOp", (SetOp(id="u", op="union", left="s", right="s",
                                 keys=(FieldRef("secret_field", ()),)),)),
                # A `Filter` IS renderable on its own, so the generic check waves
                # it past -- and the correlation renderer never looked at
                # `ir.nodes`, so it vanished.
                ("Filter", (secret,)),
                # Round 6: uncovered by all of the above, because a `Derive` is
                # neither. The `<fields>` projection the analyst asked for
                # disappears with no refusal and no diagnostic.
                ("Derive", (projection,))):
            with self.subTest(extra_node=label):
                with self.assertRaises(Refusal) as caught:
                    render_wazuh(dataclasses.replace(
                        base, nodes=base.nodes + extra))
                # ONE code for all three, because the check asks a single
                # question -- "will this node be written?" -- rather than
                # enumerating the kinds a reviewer happened to try. Two codes
                # for the same defect is how the third one got missed.
                self.assertIn(caught.exception.code, (
                    "WAZUH_NODE_NOT_RENDERABLE",
                    "WAZUH_CORRELATION_WITH_TRAILING_NODE"))


class YaraLUnrenderableNodesAreNamed(unittest.TestCase):
    """THE ALWAYS-TRUE RULE.

    The loop handled `Pattern` and `Filter` and had no `else`, so a `Package`
    fell through, `event_lines` stayed empty, and the fallback emitted:

        events:  $e0.metadata.event_type = ""
        condition:

    which parses, loads, and matches every event, with `diagnostics: NONE`.
    """

    def _correlation_ir(self):
        return lower_wazuh(CORRELATION, "300")[0]

    def test_a_package_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            render_yaral(self._correlation_ir())
        self.assertEqual(caught.exception.code, "YARAL_NODE_NOT_RENDERABLE")

    def test_a_setop_is_refused_not_become_an_intersection(self):
        try:
            out = render_yaral(_union_ir())
        except Refusal as exc:
            self.assertEqual(exc.code, "YARAL_NODE_NOT_RENDERABLE")
        else:
            self.fail(f"a union rendered as: {out!r}")

    def test_an_unrenderable_condition_is_refused(self):
        """`_render_event` returned [] -- the caller then had no events at all."""
        from ruleforge.engine.ir import Call, FieldExpr, FieldRef, Literal
        base, _ = lower_yaral(parse_yaral(YARAL_SINGLE))
        broken = Call(function="contains",
                      args=(FieldExpr(FieldRef("cmd", ())), Literal("x")))
        with self.assertRaises(Refusal) as caught:
            render_yaral(dataclasses.replace(
                base, nodes=tuple(
                    dataclasses.replace(n, condition=broken)
                    if type(n).__name__ == "Filter" else n
                    for n in base.nodes)))
        self.assertEqual(caught.exception.code,
                         "YARAL_CONDITION_NOT_RENDERABLE")

    def test_the_real_rule_still_renders(self):
        ir, _ = lower_yaral(parse_yaral(YARAL_SINGLE))
        self.assertIn("$e0.win.eventdata.CommandLine", render_yaral(ir))


class YaraLTitleCannotOpenARule(unittest.TestCase):
    """AN INJECTION, NOT A FORMATTING BUG.

    `ir.title` IS the `<description>` for a Wazuh paste, so this was reachable
    from the app with no hand-built IR. A description containing newlines
    emitted a complete attacker-chosen `rule pwned { ... }` AHEAD OF the real
    body.
    """

    EVIL = ('ok\nrule pwned {\n  meta:\n    author = "you"\n  events:\n'
            '    $e9.x = "y"\n  condition:\n    true\n}')

    def test_one_rule_declaration_survives(self):
        ir, _ = lower_yaral(parse_yaral(YARAL_SINGLE))
        out = render_yaral(dataclasses.replace(ir, title=self.EVIL))
        self.assertEqual(out.count("rule "), 1,
                         "the title opened a second rule")
        self.assertEqual(out.count("condition:"), 1)

    def test_the_name_is_a_single_identifier(self):
        ir, _ = lower_yaral(parse_yaral(YARAL_SINGLE))
        out = render_yaral(dataclasses.replace(ir, title=self.EVIL))
        first = out.splitlines()[0]
        self.assertTrue(first.startswith("rule "))
        name = first[len("rule "):].rstrip()
        self.assertNotIn(" ", name)
        self.assertNotIn("{", name)
        self.assertNotIn("\n", name)

    def test_an_ordinary_title_with_spaces_still_renders(self):
        """Sanitising is the correct rendering, not a refusal.

        A YARA-L rule name is an identifier by grammar, and a title like
        "Suspicious logon attempt" is an ordinary thing to paste.
        """
        ir, _ = lower_yaral(parse_yaral(YARAL_SINGLE))
        out = render_yaral(dataclasses.replace(ir, title="Suspicious logon"))
        self.assertIn("rule Suspicious_logon", out)


class YaraLBacktickIsNotAFieldName(unittest.TestCase):
    """In YARA-L a backtick is the MATCH-ANYTHING operator.

    `_var_of` returned a bare backtick for any field on the right-hand side, so
    `field == field` rendered as `$e0.parent = \\`` -- a NARROW equality widened
    to an UNBOUNDED one, matching every event that has a parent.
    """

    def test_a_bare_backtick_is_never_emitted(self):
        base, _ = lower_yaral(parse_yaral(YARAL_SINGLE))
        for title in ("B", "R"):
            out = render_yaral(dataclasses.replace(base, title=title))
            for line in out.splitlines():
                self.assertNotRegex(line.strip(), r"= `\s*$",
                                    "a bare backtick widens the condition")

    def test_a_comparison_against_a_field_is_refused(self):
        from ruleforge.engine.ir import Comparison, FieldExpr, FieldRef
        base, _ = lower_yaral(parse_yaral(YARAL_SINGLE))
        node = next(n for n in base.nodes if type(n).__name__ == "Filter")
        both = dataclasses.replace(node, condition=Comparison(
            "=", FieldExpr(FieldRef("parent", ())),
            FieldExpr(FieldRef("parent", ()))))
        with self.assertRaises(Refusal):
            render_yaral(dataclasses.replace(
                base, nodes=tuple(
                    dataclasses.replace(n, condition=both)
                    if type(n).__name__ == "Filter" else n
                    for n in base.nodes)))


class YaraLStringAndRegexEscaping(unittest.TestCase):
    def test_a_real_newline_is_escaped(self):
        from ruleforge.dialects.yaral_ir import json_escape
        self.assertNotIn("\n", json_escape("a\nb")[1:-1])
        self.assertIn("\\n", json_escape("a\nb"))
        self.assertIn("\\t", json_escape("a\tb"))
        self.assertIn("\\r", json_escape("a\rb"))

    def test_the_regex_delimiter_is_escaped(self):
        """`https?://[a-z]+/api` closed the literal at the first `/`."""
        from ruleforge.dialects.yaral_ir import _regex_literal
        self.assertEqual(_regex_literal("https?://a/b"), "https?:\\/\\/a\\/b")


class WazuhParserStillReadsRealRulesets(unittest.TestCase):
    def test_the_shipped_ruleset_still_parses(self):
        from ruleforge.tests.test_wazuh import WAZUH_RULESET
        rules = parse_wazuh(WAZUH_RULESET)
        self.assertGreaterEqual(len(rules), 8)


if __name__ == "__main__":
    unittest.main()
