"""Wazuh tests, written against the REAL ruleset.

The XML below is verbatim from `wazuh/wazuh-ruleset`,
`rules/0580-win-security_rules.xml`, trimmed only of `<mitre>` and `<group>`
payloads. A fixture I wrote myself would be correct by construction and would
prove nothing about the parser.

The chain is the whole test:

    60001 -> 60104 -> 60107 -> 60203

60203 is a correlation with NO condition of its own. Every part of its meaning
lives behind `if_matched_sid=60107`, which itself inherits from 60104, which
inherits from the 60001 channel rule. A parser that reads only the pasted text
would emit a rule that matches everything and would have no way to say so.
"""
from __future__ import annotations

import unittest

from ruleforge.dialects.wazuh import (
    parse_wazuh,
    resolve_chain,
    as_int,
    WazuhParseError,
)
from ruleforge.dialects.wazuh_ir import lower
from ruleforge.engine import Verdict, evaluate
from ruleforge.engine.ir import FieldRef, Filter, Package

# Verbatim, minus mitre/group/options payload. A raw string because Wazuh regexes
# are full of backslashes and a normal string would eat them: `\.+` in the XML is a
# real backslash-dot to Wazuh, but "\.+" in Python source is not an escape and
# raises a SyntaxWarning, and "\\.+" would put a double backslash in the XML.
#
# 60000 and 60001 come from `0575-win-base_rules.xml`; everything else from
# `0580-win-security_rules.xml`. Both are needed: 60104's `if_sid` is 60001,
# which is in the OTHER file, and that is exactly the cross-file link a user
# hits when they paste one rule out of a ruleset.
WAZUH_RULESET = r"""
<group name="windows_security,">
  <rule id="60000" level="0">
    <category>ossec</category>
    <decoded_as>windows_eventchannel</decoded_as>
    <field name="win.system.providerName">\.+</field>
    <options>no_full_log</options>
    <description>Group of windows rules</description>
  </rule>

  <rule id="60001" level="0">
    <if_sid>60000</if_sid>
    <field name="win.system.channel">^Security$</field>
    <options>no_full_log</options>
    <description>Group of Windows rules for the Security channel</description>
  </rule>

  <rule id="60104" level="5">
    <if_sid>60001</if_sid>
    <field name="win.system.severityValue">^AUDIT_FAILURE$|^failure$</field>
    <description>Windows audit failure event</description>
    <options>no_full_log</options>
  </rule>

  <rule id="60107" level="4">
    <if_sid>60104</if_sid>
    <field name="win.system.eventID">^577$|^4673$</field>
    <description>Failed attempt to perform a privileged operation</description>
    <options>no_full_log</options>
  </rule>

  <rule id="60102" level="5">
    <if_sid>60001</if_sid>
    <field name="win.system.severityValue">^ERROR$</field>
    <description>Windows Security error event</description>
    <options>no_full_log</options>
  </rule>

  <rule id="60203" level="10" frequency="$MS_FREQ" timeframe="240">
    <if_matched_sid>60107</if_matched_sid>
    <same_field>win.eventdata.targetUserName</same_field>
    <description>Multiple failed attempts to perform a privileged operation by the same user</description>
    <options>no_full_log</options>
  </rule>

  <rule id="60205" level="10" frequency="5" timeframe="240">
    <if_matched_sid>60104</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Multiple Windows audit failure events</description>
  </rule>

  <rule id="60206" level="10" frequency="5" timeframe="240">
    <if_matched_sid>60102</if_matched_sid>
    <description>Multiple Windows error Security events</description>
  </rule>
</group>
"""


class ParseTests(unittest.TestCase):
    def test_the_chain_resolves_back_to_the_channel_rule(self):
        rules = parse_wazuh(WAZUH_RULESET)
        chain = resolve_chain(rules, "60107")
        self.assertEqual([r.rule_id for r in chain.rules],
                         ["60000", "60001", "60104", "60107"])

    def test_a_dangling_link_anywhere_up_the_chain_is_refused(self):
        """Not just the leaf. A missing link three levels up breaks it just as
        silently, and the rule would still have looked lowerable."""
        trimmed = WAZUH_RULESET.replace(
            '<rule id="60104" level="5">\n    <if_sid>60001</if_sid>',
            '<rule id="60104" level="5">\n    <if_sid>99999</if_sid>')
        rules = parse_wazuh(trimmed)
        with self.assertRaises(WazuhParseError) as caught:
            resolve_chain(rules, "60107")
        self.assertEqual(caught.exception.code, "WAZUH_PARENT_MISSING")

    def test_a_correlation_child_is_recognised_as_one(self):
        rules = parse_wazuh(WAZUH_RULESET)
        self.assertTrue(rules["60203"].is_correlation)
        self.assertFalse(rules["60107"].is_correlation)

    def test_same_field_carries_the_field_name(self):
        """`same_field` names a field in its body; `same_srcip` does not.

        Collapsing them turns "the same source address" into "a field called
        srcip", which is a different rule.
        """
        rules = parse_wazuh(WAZUH_RULESET)
        self.assertEqual(rules["60203"].same,
                         ("win.eventdata.targetUserName",))

    def test_the_dotted_field_name_is_preserved_exactly(self):
        rules = parse_wazuh(WAZUH_RULESET)
        self.assertEqual(rules["60107"].fields[0].name, "win.system.eventID")
        self.assertEqual(rules["60107"].fields[0].pattern, "^577$|^4673$")

    def test_a_dangling_parent_is_refused_by_name(self):
        """The exact failure a pasted-child paste would cause."""
        rules = parse_wazuh(WAZUH_RULESET)
        with self.assertRaises(WazuhParseError) as caught:
            resolve_chain(rules, "99999")
        self.assertEqual(caught.exception.code, "WAZUH_PARENT_MISSING")

    def test_malformed_xml_is_refused_rather_than_tag_split(self):
        """Wazuh regexes are full of `<` and `&`. Splitting on tags truncates."""
        broken = '<rule id="1" level="3"><field name="a">^a<b$</field>'
        with self.assertRaises(WazuhParseError) as caught:
            parse_wazuh(broken)
        self.assertEqual(caught.exception.code, "WAZUH_XML_MALFORMED")


class OssecVariableTests(unittest.TestCase):
    """`frequency="$MS_FREQ"` is an ossec.conf variable, not a number."""

    def test_an_unexpanded_variable_is_refused_by_name(self):
        with self.assertRaises(WazuhParseError) as caught:
            lower(WAZUH_RULESET, "60203")
        self.assertEqual(caught.exception.code,
                         "WAZUH_FREQUENCY_IS_OSCONF_VARIABLE")
        self.assertIn("MS_FREQ", caught.exception.message)

    def test_supplying_the_value_lets_it_lower(self):
        ir, _ = lower(WAZUH_RULESET, "60203", ossec={"MS_FREQ": 5})
        package = next(n for n in ir.nodes if isinstance(n, Package))
        self.assertEqual(package.frequency, 5)

    def test_it_is_never_defaulted_to_one(self):
        """Defaulting would invert the rule's meaning without saying so."""
        with self.assertRaises(WazuhParseError):
            lower(WAZUH_RULESET, "60203", ossec={})


class CorrelationLoweringTests(unittest.TestCase):
    def test_the_child_keeps_its_parents_condition(self):
        """60203 has no `<field>` of its own. All meaning is inherited."""
        ir, diagnostics = lower(WAZUH_RULESET, "60205")
        package = next(n for n in ir.nodes if isinstance(n, Package))
        # 60205's parent is 60104, which itself inherits from 60001 and 60000.
        # The whole chain must land in the Package's parent conditions, or the
        # rule fires on Windows events that never matched the original chain.
        self.assertGreaterEqual(len(package.parent), 3)
        codes = [d["code"] for d in diagnostics]
        self.assertIn("WAZUH_CORRELATION_HAS_NO_OWN_CONDITION", codes)

    def test_the_timeframe_becomes_a_real_duration(self):
        ir, _ = lower(WAZUH_RULESET, "60205")
        package = next(n for n in ir.nodes if isinstance(n, Package))
        self.assertEqual(package.timeframe.seconds, 240)

    def test_a_correlation_with_no_same_field_is_refused(self):
        """Rule 60206 is genuinely this broad. Refusing is correct."""
        with self.assertRaises(WazuhParseError) as caught:
            lower(WAZUH_RULESET, "60206")
        self.assertEqual(caught.exception.code,
                         "WAZUH_CORRELATION_WITHOUT_SHARED_FIELD")

    def test_the_package_node_also_refuses_it(self):
        """Belt and braces: the guard exists in the IR too, not only here."""
        from ruleforge.engine.ir import Duration, Package as Pkg, Refusal
        with self.assertRaises(Refusal) as caught:
            Pkg(id="p", input="r", parent=(), children=((Filter(id="f", input="r",
                    condition=None).condition,),),
                frequency=5, timeframe=Duration(240),
                same_fields=(), time_field="timestamp")
        self.assertEqual(caught.exception.code, "PACKAGE_REQUIRES_SHARED_FIELD")


class ExecutionTests(unittest.TestCase):
    """The frequency, the window, and the shared field must all be real."""

    def _ir(self):
        ir, _ = lower(WAZUH_RULESET, "60205", time_field="timestamp")
        return ir

    def _row(self, minute, user="analyst", ip="10.0.0.5",
             severity="AUDIT_FAILURE", channel="Security",
             provider="Microsoft.Windows.Security-Auditing"):
        # Carries every field the whole if_sid CHAIN tests, not just the parent's
        # own. 60000 gates on providerName, 60001 on channel, 60104 on
        # severityValue. Dropping any of them makes the test pass for the wrong
        # reason, which is how the earlier version of this fixture passed.
        #
        # The provider name CONTAINS A DOT on purpose -- see
        # `test_rule_60000_only_fires_on_a_provider_name_containing_a_dot`.
        return {
            "timestamp": minute * 60,
            "win.system.providerName": provider,
            "win.system.channel": channel,
            "win.system.severityValue": severity,
            "win.system.eventID": "4673",
            "win.eventdata.ipAddress": ip,
            "win.eventdata.targetUserName": user,
        }

    def test_five_failures_inside_the_window_fire(self):
        rows = [self._row(m) for m in range(5)]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(result.rows[0].get("package_children_matched"), 5)

    def test_four_failures_do_not_fire(self):
        """The counterpart, so the above cannot be a blanket True."""
        rows = [self._row(m) for m in range(4)]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_the_window_is_anchored_on_the_parent(self):
        """Five spread over 400s exceeds the 240s timeframe."""
        rows = [self._row(m) for m in (0, 100, 200, 300, 400)]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_a_different_ip_is_a_different_story(self):
        """same_field groups on ipAddress; five hosts is not one attacker."""
        rows = [self._row(0), self._row(1, ip="10.0.0.6"),
                self._row(2, ip="10.0.0.7"), self._row(3, ip="10.0.0.8"),
                self._row(4, ip="10.0.0.9")]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_an_absent_shared_field_does_not_widen_to_all_hosts(self):
        rows = [self._row(m) for m in range(5)]
        for row in rows:
            del row["win.eventdata.ipAddress"]
        result = evaluate(self._ir(), rows)
        codes = [c.code for c in result.caveats]
        self.assertIn("PACKAGE_UNDECIDABLE_GROUP", codes)
        self.assertIsNot(result.verdict, Verdict.MATCHED)

    def test_a_row_with_the_wrong_severity_is_not_a_parent_at_all(self):
        rows = []
        for m in range(5):
            row = self._row(m)
            if m > 0:
                row["win.system.severityValue"] = "INFORMATION"
            rows.append(row)
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_a_row_from_the_wrong_channel_is_not_a_parent_either(self):
        """60000/60001 are two links up the chain. Dropping them would let any
        Windows channel satisfy the correlation."""
        rows = [self._row(m, channel="System") for m in range(5)]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_an_absent_ancestor_field_does_not_widen_the_rule(self):
        """The invariant, on the parent condition rather than the group key."""
        rows = [self._row(m) for m in range(5)]
        for row in rows:
            del row["win.system.channel"]
        result = evaluate(self._ir(), rows)
        self.assertIsNot(result.verdict, Verdict.MATCHED)

    def test_the_window_slides_rather_than_running_forward_from_the_first(self):
        """Wazuh counts occurrences INSIDE a sliding timeframe.

        An earlier version anchored a forward window on each event and counted
        only what came strictly after, so "5 times in 240s" needed five FURTHER
        events after the first and a spray of exactly five never fired. The
        window has to trail the current event.
        """
        # Five events, 60s apart: the fifth closes the threshold.
        rows = [self._row(m) for m in range(5)]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 1,
                         "one spray crossing the threshold is one alert, not five")
        self.assertEqual(result.rows[0].get("package_children_matched"), 5)

    def test_the_alert_fires_on_the_fifth_not_the_first(self):
        """The detection. Rule 60205 exists to catch a spray, not one failure."""
        running = []
        for m in range(4):
            running.append(self._row(m))
            self.assertIs(evaluate(self._ir(), running).verdict, Verdict.NO_MATCH,
                          f"four failures at minute {m} must not alert")
        running.append(self._row(4))
        self.assertIs(evaluate(self._ir(), running).verdict, Verdict.MATCHED)

    def test_a_child_with_no_field_of_its_own_counts_the_parent(self):
        """60205 has no `<field>`. That is NOT an empty child.

        It means "60104, five times in 240s". Modelling it as a childless
        correlation would fire on the FIRST event, turning a frequency rule into
        a plain one -- the difference between a password-spray detector and a
        rule that alerts on the first wrong password.
        """
        ir, diagnostics = lower(WAZUH_RULESET, "60205")
        package = next(n for n in ir.nodes if isinstance(n, Package))
        self.assertEqual(package.count_subject, "parent")
        self.assertEqual(package.children, ())
        self.assertIn("WAZUH_FREQUENCY_COUNTS_THE_PARENT",
                      [d["code"] for d in diagnostics])

    def test_count_subject_child_without_children_is_refused(self):
        """The IR refuses the contradictory combination by name.

        The parent must be non-empty, or `PACKAGE_EMPTY` fires first and this
        guard is never reached -- which is itself worth asserting, below.
        """
        from ruleforge.engine.ir import (BoolOp, Comparison, Duration,
                                         FieldExpr, Literal,
                                         Package as Pkg, Refusal)
        condition = Comparison("=", FieldExpr(ref=FieldRef("a")),
                               Literal(value=1))
        with self.assertRaises(Refusal) as caught:
            Pkg(id="p", input="r", parent=(condition,), children=(),
                count_subject="child", frequency=5, timeframe=Duration(240),
                same_fields=(FieldRef("user"),), time_field="timestamp")
        self.assertEqual(caught.exception.code,
                         "PACKAGE_CHILD_COUNT_WITHOUT_CHILDREN")

        with self.assertRaises(Refusal) as empty:
            Pkg(id="p", input="r", parent=(), children=(),
                count_subject="child", frequency=5, timeframe=Duration(240),
                same_fields=(FieldRef("user"),), time_field="timestamp")
        self.assertEqual(empty.exception.code, "PACKAGE_EMPTY")
        self.assertIsInstance(condition, BoolOp | Comparison)

    def test_rule_60000_only_fires_on_a_provider_name_containing_a_dot(self):
        """A FINDING ABOUT THE SHIPPED RULESET, recorded rather than smoothed over.

        Wazuh's own level-0 gate 60000 is
        `<field name="win.system.providerName">\\.+</field>`, copied here verbatim.
        `\\.` is an ESCAPED DOT, so the pattern means "one or more literal dots" --
        not "any character". The real provider name for the Security channel is
        `Microsoft-Windows-Security-Auditing`, which contains no dot.

        So on the literal reading, rule 60000 does not match its own channel's
        events, and therefore neither does 60001, 60104, 60107, 60203 or 60205 --
        the whole 60xxx Windows security chain is gated behind a pattern that
        cannot match a normal provider name. The author very likely meant `.+`.

        RuleForge reports what the rule SAYS. It does not "fix" the pattern,
        because silently rewriting `\\.+` to `.+` would make the tool report
        matches the deployed agent does not produce. The finding is surfaced here
        so it is a decision the user makes, not one the tool makes for them.
        """
        rows = [self._row(m, provider="Microsoft-Windows-Security-Auditing")
                for m in range(5)]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.NO_MATCH)

        dotted = [self._row(m) for m in range(5)]
        self.assertIs(evaluate(self._ir(), dotted).verdict, Verdict.MATCHED)


class ConstructionRefusalTests(unittest.TestCase):
    def test_a_zero_frequency_is_refused(self):
        with self.assertRaises(WazuhParseError) as caught:
            as_int("0", "60205", "frequency")
        self.assertEqual(caught.exception.code, "WAZUH_FREQUENCY_NOT_POSITIVE")

    def test_a_zero_timeframe_is_refused(self):
        with self.assertRaises(WazuhParseError) as caught:
            as_int("0", "60205", "timeframe")
        self.assertEqual(caught.exception.code, "WAZUH_TIMEFRAME_NOT_POSITIVE")

    def test_a_non_numeric_timeframe_is_refused(self):
        with self.assertRaises(WazuhParseError) as caught:
            as_int("soon", "60205", "timeframe")
        self.assertEqual(caught.exception.code, "WAZUH_TIMEFRAME_NOT_AN_INTEGER")


if __name__ == "__main__":
    unittest.main()
