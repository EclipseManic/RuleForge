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

import unittest
import xml.etree.ElementTree as ET

from ruleforge.dialects.wazuh import parse_wazuh
from ruleforge.dialects.wazuh_ir import lower
from ruleforge.dialects.wazuh_render import render
from ruleforge.engine.values import Refusal
from ruleforge.tests.test_wazuh import WAZUH_RULESET

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
        ir = self._ir()
        stripped = type(ir)(
            rule_id=ir.rule_id, nodes=ir.nodes, output=ir.output,
            title=ir.title, metadata={})
        with self.assertRaises(Refusal) as caught:
            render(stripped)
        self.assertIn("if_matched_sid", caught.exception.message)


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
        from ruleforge.dialects.wazuh_render import _field_elements
        from ruleforge.engine.ir import Arith, Literal
        with self.assertRaises(Refusal) as caught:
            _field_elements(Arith("+", (Literal(value=1), Literal(value=2))),
                            "someField")
        self.assertEqual(caught.exception.code,
                         "WAZUH_RENDER_EXPRESSION_UNSUPPORTED")

    def test_a_call_with_no_wazuh_form_is_refused(self):
        from ruleforge.dialects.wazuh_render import _field_elements
        from ruleforge.engine.ir import Call, FieldExpr, FieldRef
        with self.assertRaises(Refusal):
            _field_elements(Call(function="coalesce",
                                 args=(FieldExpr(ref=FieldRef("a")),)), "a")


if __name__ == "__main__":
    unittest.main()
