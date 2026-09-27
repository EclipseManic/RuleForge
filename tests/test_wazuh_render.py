"""Wazuh XML renderer tests.

THE TRAP IS DANGEROUSER THAN THE PREFIX ONE.

A Wazuh correlation rule has no condition of its own. Every part of its
detection lives behind `if_matched_sid`. So a renderer that emits only the child
produces a rule that matches EVERY event in the log -- not a slightly broad rule,
a rule with no detection in it, and a file Wazuh loads without complaint.

These tests hold that line: the renderer must emit `if_matched_sid`, and must
refuse by name when it cannot.
"""
from __future__ import annotations

import pathlib
import unittest
import xml.etree.ElementTree as ET

from dialects.wazuh import parse_wazuh
from dialects.wazuh_ir import lower
from dialects.wazuh_render import render
from engine.ir import (Aggregate, Derive, FieldRef, Frame, Literal, Measure,
                      SetOp)
from engine.values import Refusal
from tests.test_wazuh import WAZUH_RULESET

# 60104 IS HERE BECAUSE 60107's if_sid POINTS AT IT. Passing a child without its
# parent is refused by name -- which is the same guard these renderer tests exist
# to hold, so the fixture has to respect it.
PLAIN_RULE = """
<group name="windows_security,">
  <rule id="60104" level="5">
    <if_sid>60001</if_sid>
    <field name="win.system.severityValue">^AUDIT_FAILURE$|^failure$</field>
    <description>Windows audit failure event</description>
  </rule>

  <rule id="60001" level="0">
    <field name="win.system.channel">^Security$</field>
    <description>Group of Windows rules for the Security channel</description>
  </rule>

  <rule id="60107" level="4">
    <if_sid>60104</if_sid>
    <field name="win.system.eventID">^577$|^4673$</field>
    <description>Failed attempt to perform a privileged operation</description>
  </rule>
</group>
"""


def parse_one(xml: str):
    """The single rule the renderer produced, or a failure."""
    return ET.fromstring(xml.strip())


class CorrelationRenderTests(unittest.TestCase):
    def _ir(self):
        return lower(WAZUH_RULESET, "60205", time_field="timestamp")[0]

    def test_it_emits_if_matched_sid(self):
        """The single most important assertion in this file. Without it the
        rendered rule has no parent and correlates nothing with anything."""
        rule = parse_one(render(self._ir()))
        sid = rule.find("if_matched_sid")
        self.assertIsNotNone(sid, "a correlation rendered without if_matched_sid "
                                  "matches every event in the log")
        self.assertEqual(sid.text, "60104")

    def test_it_emits_the_same_field(self):
        rule = parse_one(render(self._ir()))
        self.assertEqual(rule.find("same_field").text, "win.eventdata.ipAddress")

    def test_frequency_and_timeframe_survive(self):
        rule = parse_one(render(self._ir()))
        self.assertEqual(rule.get("frequency"), "5")
        self.assertEqual(rule.get("timeframe"), "240")

    def test_the_rendered_rule_re_parses_to_the_same_thing(self):
        """THE REAL TEST. Render, re-parse, and confirm the correlation still
        points at the same parent with the same grouping and the same counts."""
        original = parse_wazuh(WAZUH_RULESET)["60205"]
        again = parse_wazuh(render(self._ir()))["60205"]
        self.assertEqual(again.if_matched_sid, original.if_matched_sid)
        self.assertEqual(again.same, original.same)
        self.assertEqual(again.frequency, original.frequency)
        self.assertEqual(again.timeframe, original.timeframe)

    def test_a_correlation_with_no_recorded_parent_is_refused(self):
        """An IR that says `Package` but carries no `wazuh_parent` cannot be
        written as a correlation. It is named rather than guessed."""
        ir = self._ir()
        stripped = type(ir)(
            rule_id=ir.rule_id,
            nodes=ir.nodes, output=ir.output, title=ir.title,
            metadata={k: v for k, v in ir.metadata.items()
                      if k != "wazuh_parent"})
        with self.assertRaises(Refusal) as caught:
            render(stripped)
        self.assertEqual(caught.exception.code,
                         "WAZUH_RENDER_CORRELATION_WITHOUT_PARENT")

    def test_the_refusal_explains_the_consequence(self):
        """The message has to say what BREAKS, not just that something is wrong.

        This used to strip the whole metadata dict. That made it a test of two
        refusals at once -- no parent AND no level -- while asserting only
        about the first, so whichever guard happened to run first decided the
        outcome and the test was quietly coupled to guard ORDER rather than to
        the message. It now strips only the parent, which is the one thing this
        test is about. `test_a_correlation_with_no_recorded_parent_is_refused`
        above already pins the code, so nothing is lost.
        """
        ir = self._ir()
        stripped = type(ir)(
            rule_id=ir.rule_id, nodes=ir.nodes, output=ir.output,
            title=ir.title,
            metadata={k: v for k, v in ir.metadata.items()
                      if k != "wazuh_parent"})
        with self.assertRaises(Refusal) as caught:
            render(stripped)
        self.assertEqual(caught.exception.code,
                         "WAZUH_RENDER_CORRELATION_WITHOUT_PARENT")
        self.assertIn("if_matched_sid", caught.exception.message)


class LevelGuardTests(unittest.TestCase):
    """`level` reached the artifact unvalidated, and nobody noticed for seven
    rounds. Each case below is a value that really did reach the artifact, or
    really would have -- none of them is invented to make a guard look busy.

    The defect had three separate shapes and they need separate tests, because a
    single test with a table would pass if only one of the three guards fired.
    """

    def _plain(self):
        return lower(PLAIN_RULE, "60107")[0]

    def _with_level(self, value):
        ir = self._plain()
        return type(ir)(
            rule_id=ir.rule_id, nodes=ir.nodes, output=ir.output,
            title=ir.title,
            metadata={**ir.metadata, "level": value})

    def test_a_wazuh_rule_with_no_level_attribute_is_refused(self):
        """THE HEADLINE DEFECT, exercised through the REAL parse path.

        The first version of this test deleted the `level` KEY from a lowered
        IR, which also made the rule look like it had never been written for
        Wazuh -- so it exercised the wrong refusal and passed for the wrong
        reason. What actually happens in production is simpler: `wazuh.py` reads
        `element.get("level") or ""`, so a `<rule>` with no `level` attribute
        lowers to a rule whose level is the empty STRING. So that is what this
        feeds in, from real XML.
        """
        no_level = (
            '<group name="test,">'
            '<rule id="900001" description="no severity stated">'
            '<field name="win.system.eventID">^4624$</field>'
            '</rule>'
            '</group>'
        )
        ir = lower(no_level, "900001", time_field="timestamp")[0]
        # Prove the precondition rather than trusting it: the key is present and
        # empty, which is what distinguishes this from a foreign-dialect graph.
        self.assertIn("level", ir.metadata)
        self.assertEqual(ir.metadata["level"], "")
        with self.assertRaises(Refusal) as caught:
            render(ir)
        self.assertEqual(caught.exception.code, "WAZUH_LEVEL_ABSENT")
        # It must not quietly render at all, and the message has to say why that
        # matters rather than just that a field is missing.
        self.assertIn("not", caught.exception.message.lower())

    def test_a_rule_that_was_never_wazuh_says_so_instead_of_inventing_a_level(self):
        """The cross-dialect case, and it is a DIFFERENT mistake.

        Rendering a Sentinel rule as Wazuh is something this tool is for. Such a
        graph has no `level` key at all, because its source dialect has no such
        concept -- there was never a severity to carry. `or "0"` invented one.
        It must be refused as its own thing, not reported as a Wazuh rule with a
        missing attribute, because the fix is different: the analyst has to say
        what severity they want.
        """
        from dialects.kql import parse_kql
        from dialects.kql_ir import lower as lower_any
        from tests.test_reviewer_findings import USER_SENTINEL_RULE

        kql_ir, _ = lower_any(parse_kql(USER_SENTINEL_RULE))
        self.assertNotIn("level", kql_ir.metadata,
                         "the Sentinel rule must not grow a Wazuh level; if it "
                         "does, the dialect is inventing one and this test is "
                         "testing nothing")
        # Reduce the graph to the shape this test is about. The Sentinel rule
        # has both an Aggregate and two Derives, and BOTH of those guards sit
        # above the level guard by design -- each is checked by its own test --
        # so leaving either in place would mean this test asserted the wrong
        # refusal. What is left is a plain Wazuh-shaped graph with no level.
        nodes = tuple(n for n in kql_ir.nodes
                      if type(n).__name__ not in ("Aggregate", "SetOp"))
        first_derive = next(i for i, n in enumerate(nodes)
                            if type(n).__name__ == "Derive")
        nodes = nodes[:first_derive + 1]
        with self.assertRaises(Refusal) as caught:
            render(type(kql_ir)(rule_id=kql_ir.rule_id, nodes=nodes,
                                output=kql_ir.output, title=kql_ir.title,
                                metadata=kql_ir.metadata))
        self.assertEqual(caught.exception.code, "WAZUH_NO_LEVEL_TO_CARRY")


    def test_an_empty_level_is_the_same_defect_as_an_absent_one(self):
        """`wazuh.py` records a MISSING level as `""`, not as a missing key, so
        the absent case arrives as an empty string. Both must be caught."""
        with self.assertRaises(Refusal) as caught:
            render(self._with_level(""))
        self.assertEqual(caught.exception.code, "WAZUH_LEVEL_ABSENT")

    def test_level_zero_is_legal_and_renders(self):
        """A guard that rejected 0 would refuse correct vendor rules -- the
        shipped ruleset uses level 0. Refusing valid input is its own defect."""
        self.assertEqual(
            parse_one(render(self._with_level("0"))).get("level"), "0")

    def test_the_real_shipped_levels_all_render(self):
        """Every level in the shipped Wazuh ruleset must survive. This is the
        test that stops the bound from creeping down to something plausible."""
        for level in ("0", "2", "3", "4", "5", "6", "7", "8", "10", "12", "15", "16"):
            with self.subTest(level=level):
                self.assertEqual(
                    parse_one(render(self._with_level(level))).get("level"),
                    level)

    def test_a_non_integer_level_is_refused(self):
        for bad in ("abc", "10.5", "-1", "1e3", "+5", "12abc", "0x0c", " 1 2 "):
            with self.subTest(level=bad):
                with self.assertRaises(Refusal) as caught:
                    render(self._with_level(bad))
                self.assertEqual(caught.exception.code,
                                 "WAZUH_LEVEL_NOT_AN_INTEGER")

    def test_an_out_of_range_level_is_refused(self):
        for bad in ("17", "99", "99999", "1000000"):
            with self.subTest(level=bad):
                with self.assertRaises(Refusal) as caught:
                    render(self._with_level(bad))
                self.assertEqual(caught.exception.code,
                                 "WAZUH_LEVEL_OUT_OF_RANGE")

    def test_non_ascii_digits_are_refused_and_do_not_crash(self):
        """`isdigit()` is TRUE for '²' and for Arabic-Indic digits, and
        `int('²')` raises ValueError. So a bare isdigit() guard would CRASH on
        '²' instead of refusing it, and would silently accept '١٢' as twelve."""
        for bad in ("²", "١٢", "１２", "٣"):
            with self.subTest(level=bad):
                with self.assertRaises(Refusal) as caught:
                    render(self._with_level(bad))
                self.assertEqual(caught.exception.code,
                                 "WAZUH_LEVEL_NOT_AN_INTEGER")

    def test_both_paths_that_write_a_level_are_guarded(self):
        """There are exactly TWO returns that can put a level into an artifact --
        correlation and plain -- and both are below the guard. The third return,
        aggregate, cannot write one and is covered by
        `test_the_aggregate_path_is_not_guarded_because_it_cannot_write_a_level`
        instead.

        This is the test for the rule I broke in round 6: a guard that sits below
        a sibling return is a guard that does not run. It asserts both live
        paths refuse, so moving the guard under either one turns this red.
        """
        plain = self._plain()
        bad = {**plain.metadata, "level": "abc"}

        # plain: a Filter with no Package.
        with self.assertRaises(Refusal) as caught:
            render(type(plain)(rule_id=plain.rule_id, nodes=plain.nodes,
                               output=plain.output, title=plain.title,
                               metadata=bad))
        self.assertEqual(caught.exception.code, "WAZUH_LEVEL_NOT_AN_INTEGER")

        # correlation: the real shipped 60205, straight from the vendor ruleset.
        corr = lower(WAZUH_RULESET, "60205", time_field="timestamp")[0]
        with self.assertRaises(Refusal) as caught:
            render(type(corr)(rule_id=corr.rule_id, nodes=corr.nodes,
                               output=corr.output, title=corr.title,
                               metadata={**corr.metadata, "level": "abc"}))
        self.assertEqual(caught.exception.code, "WAZUH_LEVEL_NOT_AN_INTEGER")


    def test_the_level_guard_wins_even_over_a_structural_refusal(self):
        """The level guard runs after the node check and before the two returns
        that write a level, and that ordering is pinned here.

        The aggregate return is the one path ABOVE the level guard, and that is
        safe only because `_render_plain` refuses unconditionally when an
        Aggregate is present -- it can never reach `_wrap`. If that ever
        changes, the aggregate path starts writing an unvalidated level and this
        file's aggregate case is what should fail first.
        """
        ir = self._plain()
        unrenderable = SetOp(id="s", op="union", left="r", right="r",
                             keys=(FieldRef(name="host"),))
        with self.assertRaises(Refusal) as caught:
            render(type(ir)(
                rule_id=ir.rule_id, nodes=(*ir.nodes, unrenderable),
                output=ir.output, title=ir.title,
                metadata={**ir.metadata, "level": "abc"}))
        self.assertEqual(caught.exception.code, "WAZUH_NODE_NOT_RENDERABLE")

    def test_the_aggregate_path_is_not_guarded_because_it_cannot_write_a_level(self):
        """The other half of the ordering claim, stated as a test.

        An Aggregate plus a bad level must produce the AGGREGATE refusal, not
        the level one. That is what proves the aggregate return is genuinely
        above the guard -- and, by proving the guard is skipped there, it pins
        the assumption that the aggregate path cannot write a level. If
        `_render_plain` ever stopped refusing, this test is the one that notices
        only if the level value starts reaching the artifact, so the real
        regression guard is `test_a_threshold_on_an_aggregate_is_refused` in
        test_reviewer_findings.py, which asserts the refusal is still the
        aggregate one.
        """
        ir = self._plain()
        agg = Aggregate(id="a", input="r", measures=(Measure("n", "count"),),
                        frame=Frame(kind="per_event"))
        with self.assertRaises(Refusal) as caught:
            render(type(ir)(
                rule_id=ir.rule_id, nodes=(*ir.nodes, agg),
                output=ir.output, title=ir.title,
                metadata={**ir.metadata, "level": "abc"}))
        self.assertEqual(caught.exception.code,
                         "WAZUH_RENDER_AGGREGATE_NOT_A_RULE")



class TwoDeriveTests(unittest.TestCase):
    """A second `Derive` was dropped by `next(...)`, and the node check
    `continue`d on `Derive`, so nothing caught it. The comment above that check
    claimed otherwise for three rounds."""

    def _ir(self):
        return lower(PLAIN_RULE, "60107")[0]

    def test_a_second_derive_is_refused_rather_than_dropped(self):
        ir = self._ir()
        first = Derive(id="d1", input="r", assignments=(("a", Literal("x")),),
                       projects=True)
        second = Derive(id="d2", input="d1", assignments=(("b", Literal("y")),),
                        projects=False)
        with self.assertRaises(Refusal) as caught:
            render(type(ir)(
                rule_id=ir.rule_id, nodes=(*ir.nodes, first, second),
                output=ir.output, title=ir.title, metadata=ir.metadata))
        self.assertEqual(caught.exception.code,
                         "WAZUH_TWO_DERIVES_NOT_RENDERABLE")

    def test_exactly_one_derive_still_renders(self):
        """The guard must not fire on the normal case, or it is noise."""
        self.assertIsNotNone(parse_one(render(self._ir())))


class PlainRuleRenderTests(unittest.TestCase):
    def test_a_field_becomes_a_field_element(self):
        ir = lower(PLAIN_RULE, "60107")[0]
        rule = parse_one(render(ir))
        names = [f.get("name") for f in rule.findall("field")]
        # The rule's OWN field, plus every ancestor's, because a Wazuh child
        # inherits its parent and the lowerer ANDs the whole chain in. Wazuh
        # ANDs multiple <field> elements, so this is the right rendering -- the
        # test asserts membership rather than position for that reason.
        self.assertIn("win.system.eventID", names)
        self.assertIn("win.system.severityValue", names)
        self.assertIn("win.system.channel", names)
        by_name = {f.get("name"): f.text for f in rule.findall("field")}
        self.assertEqual(by_name["win.system.eventID"], "^577$|^4673$")

    def test_the_regex_carries_its_engine_back(self):
        """`os_regex` and `pcre2` do not mean the same thing. Emitting a pcre
        pattern as os_regex would change what it matches."""
        ir = lower(PLAIN_RULE, "60107")[0]
        field = parse_one(render(ir)).find("field")
        self.assertEqual(field.get("type"), "os_regex")

    def test_the_regex_text_is_not_rewritten(self):
        """`\\.+` stays `\\.+`. Rewriting it to `.+` would preserve the matched
        language and change the analyst's bytes, so the diff against the pasted
        rule would show a change they never made."""
        rule = WAZUH_PCRE_RULE
        ir = lower(rule, "70010")[0]
        field = parse_one(render(ir)).find("field")
        self.assertEqual(field.text, r"\.+")
        self.assertEqual(field.get("type"), "pcre2")

    def test_the_rendered_rule_re_parses(self):
        ir = lower(PLAIN_RULE, "60107")[0]
        again = parse_wazuh(render(ir))["60107"]
        patterns = {f.name: f.pattern for f in again.fields}
        self.assertEqual(patterns["win.system.eventID"], "^577$|^4673$")
        self.assertEqual(patterns["win.system.severityValue"],
                         "^AUDIT_FAILURE$|^failure$")

    def test_a_field_name_is_never_left_as_a_placeholder(self):
        """A first attempt emitted `<field name="{NAME}">` and never substituted,
        so every rendered rule pointed at a column literally called `{NAME}`."""
        ir = lower(PLAIN_RULE, "60107")[0]
        self.assertNotIn("{NAME}", render(ir))

    def test_the_description_survives(self):
        ir = lower(PLAIN_RULE, "60107")[0]
        self.assertIn("Failed attempt", render(ir))

    def test_mitre_ids_are_carried(self):
        rule = WAZUH_MITRE_RULE
        ir = lower(rule, "70011")[0]
        rendered = render(ir)
        self.assertIn("<id>T1059.001</id>", rendered)
        again = parse_wazuh(rendered)["70011"]
        self.assertEqual(again.mitre, ("T1059.001",))


WAZUH_PCRE_RULE = """
<group name="custom,">
  <rule id="70010" level="12">
    <field name="win.eventdata.commandLine" type="pcre2">\\.+</field>
    <description>PCRE pattern</description>
  </rule>
</group>
"""

WAZUH_MITRE_RULE = """
<group name="custom,">
  <rule id="70011" level="12">
    <field name="win.eventdata.commandLine">powershell</field>
    <description>With ATT&amp;CK</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>
</group>
"""


class HonestRefusalTests(unittest.TestCase):
    def test_a_non_field_expression_is_refused_not_invented(self):
        """Wazuh rules can only say `field matches pattern`. A rule built from an
        arithmetic expression has no `<field>` form, and pretending otherwise
        would invent a test."""
        from dialects.wazuh_render import _field_elements
        from engine.ir import Arith, Literal
        with self.assertRaises(Refusal) as caught:
            _field_elements(Arith("+", (Literal(value=1), Literal(value=2))),
                            "someField")
        self.assertEqual(caught.exception.code,
                         "WAZUH_RENDER_EXPRESSION_UNSUPPORTED")

    def test_a_call_with_no_wazuh_form_is_refused(self):
        from dialects.wazuh_render import _field_elements
        from engine.ir import Call, FieldExpr, FieldRef
        with self.assertRaises(Refusal):
            _field_elements(Call(function="coalesce",
                                 args=(FieldExpr(ref=FieldRef("a")),)), "a")


class AllowlistNamesMustExistTests(unittest.TestCase):
    """`SetRule` sat in two skip-tuples in `wazuh_render.py` and no such class
    exists in `engine/ir.py`.

    Those tuples are safety controls: a name in them is a node the renderer
    SKIPS instead of refusing. So a name that does not correspond to a real class
    is not harmless dead text -- it is a hole with a class-shaped name in it. The
    day someone writes a `SetRule`, the renderer would skip it silently and the
    node would vanish from the artifact with no diagnostic, which is the exact
    failure this file's other tests exist to prevent.

    Checking the names against `ir.py` catches the whole class rather than this
    one instance, and it fails the moment a tuple and the IR vocabulary drift
    apart in either direction.
    """

    #: Tuples in `wazuh_render.py` whose entries are node-type names.
    SKIP_TUPLES = (
        ("Read", "Emit"),
    )

    def test_every_skipped_node_name_is_a_real_class(self):
        import engine.ir as ir
        for name in dict.fromkeys(n for t in self.SKIP_TUPLES for n in t):
            with self.subTest(name=name):
                self.assertTrue(
                    hasattr(ir, name),
                    f"{name!r} is skipped by the Wazuh renderer but "
                    f"engine/ir.py defines no such class, so the skip is a hole")

    def test_no_setrule_class_exists(self):
        """The specific finding, stated so its removal is recorded rather than
        just absent."""
        import engine.ir as ir
        self.assertFalse(hasattr(ir, "SetRule"))

    def test_the_source_no_longer_names_setrule_in_code(self):
        """Checked through the AST, not through the file text.

        The first version of this test did `assertNotIn("SetRule", source)` and
        failed immediately -- on the COMMENT I had just written explaining that
        `SetRule` had been removed. A text search cannot tell a live reference
        from a note about one, so it can only ever fail for the wrong reason.

        `ast` has no comment nodes at all, so walking it for string constants
        finds the skip-tuples and nothing else. That is the actual claim: no
        STRING LITERAL in this module names a class that does not exist.
        """
        import ast

        import dialects.wazuh_render as mod
        tree = ast.parse(pathlib.Path(mod.__file__).read_text(encoding="utf-8"))
        offenders = [
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value == "SetRule"
        ]
        self.assertEqual(
            offenders, [],
            "SetRule is back in a wazuh_render.py string literal and "
            "engine/ir.py has no such class, so it is a hole in a check whose "
            "job is to refuse")


class EventCapTests(unittest.TestCase):
    """`MAX_EVENTS` and `_cap_events` existed and correctly refused 100,000
    rows -- and `debug_logs_to_rule` returned `ok=True` for the same input,
    because the cap was reached from `tune` and from the three `load_events`
    helpers and not from here.

    Measured before the fix: `debug_logs_to_rule(dialect, 100_000 rows)` gave
    `ok=True` with findings, while `_cap_events` on that list raised
    `TOO_MANY_EVENTS`. The cap was real, documented, and on the wrong side of a
    function boundary.
    """

    def test_a_hundred_thousand_rows_is_refused(self):
        from engine.values import Refusal
        from jobs import debug_logs_to_rule
        rows = [{"EventCode": 4624, "host": f"h{i}"} for i in range(100_000)]
        with self.assertRaises(Refusal) as caught:
            debug_logs_to_rule("wazuh", rows)
        self.assertEqual(caught.exception.code, "TOO_MANY_EVENTS")

    def test_the_cap_is_the_same_one_tune_uses(self):
        """One number, not two. If these ever diverge then the tool is refusing
        different sizes in different places, which is the 'limit on one entrance'
        defect from round 3."""
        from jobs import MAX_EVENTS, _cap_events
        from engine.values import Refusal
        from jobs import debug_logs_to_rule
        over = [{"a": 1}] * (MAX_EVENTS + 1)
        with self.assertRaises(Refusal) as from_cap:
            _cap_events(over)
        with self.assertRaises(Refusal) as from_job:
            debug_logs_to_rule("wazuh", over)
        self.assertEqual(from_cap.exception.code, from_job.exception.code)

    def test_ordinary_input_still_works(self):
        from jobs import debug_logs_to_rule
        out = debug_logs_to_rule("wazuh", [{"EventCode": 4624, "host": "a"},
                                           {"EventCode": 4625, "host": "b"}])
        self.assertTrue(out.ok)
        self.assertTrue(out.findings)

    def test_empty_input_still_gets_its_own_message(self):
        """The cap runs BEFORE the empty check, so this proves the reordering did
        not swallow the more specific refusal."""
        from jobs import debug_logs_to_rule
        out = debug_logs_to_rule("wazuh", [])
        self.assertFalse(out.ok)
        self.assertEqual(out.findings[0].code, "DEBUG_NO_EVENTS")


if __name__ == "__main__":
    unittest.main()
