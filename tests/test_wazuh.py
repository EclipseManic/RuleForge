"""Wazuh XML.

`TheRuleThatMatchesEverything` is the class this whole module exists for. In
Wazuh an absence is a match: a `<rule>` with no matchers fires on every event
its parent passed, and a matcher that gets silently dropped widens the detection
with nothing reported. That is the defect `render_kql`'s docstring names, and
these tests are what stop it coming back.

`NegationSurvivesBothSpellings` is second in importance. Wazuh writes a negation
two ways -- the `negate="yes"` attribute and a leading `!` -- and dropping either
one INVERTS the detection, producing a rule that matches exactly the events the
author excluded.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from engine.dialects.wazuh import (
    DIALECT,
    FIELD_ELEMENTS,
    LANGUAGE,
    MATCHERS,
    SAME_ELEMENTS,
    lower_wazuh,
    parse_wazuh,
    render_wazuh,
)
from engine.ir import (
    BoolOp,
    Comparison,
    Correlation,
    Emit,
    FieldRef,
    Filter,
    Literal,
    Not,
    Read,
    Regex,
    Rule,
    render_expr,
)
from engine.values import Refusal

SSHD = """<group name="syslog,sshd,">
  <rule id="5710" level="5">
    <if_sid>5700</if_sid>
    <match>Failed password</match>
    <description>sshd: authentication failed</description>
    <mitre><id>T1110</id></mitre>
    <group>authentication_failed,</group>
  </rule>
</group>"""

BRUTE_FORCE = """<group name="syslog,sshd,">
  <rule id="5720" level="10" frequency="8" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>sshd: brute force trying to get access to the system</description>
    <mitre><id>T1110</id></mitre>
  </rule>
</group>"""


def lower(text=SSHD, rule_id="rule"):
    rule, _ = lower_wazuh(text, rule_id)
    return rule


def rule_xml(body: str, attributes: str = 'id="100" level="5"') -> str:
    return f"<rule {attributes}>{body}</rule>"


def first(rule, kind):
    for node in rule.pipeline:
        if isinstance(node, kind):
            return node
    raise AssertionError(f"no {kind.__name__} stage in the rule")


class Parsing(unittest.TestCase):
    def test_a_bare_rule_without_a_group_is_accepted(self):
        # Common in real rule files and in anything pasted from a blog post.
        self.assertEqual(len(parse_wazuh(rule_xml("<match>x</match>")).rules), 1)

    def test_the_enclosing_group_name_is_read(self):
        self.assertEqual(parse_wazuh(SSHD).group_names, ("syslog", "sshd"))

    def test_malformed_xml_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_wazuh("<rule id=5><match>x</match>")
        self.assertEqual(caught.exception.code, "WAZUH_XML_MALFORMED")

    def test_an_empty_document_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_wazuh("   ")
        self.assertEqual(caught.exception.code, "WAZUH_EMPTY")

    def test_a_document_with_no_rule_element_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_wazuh("<group><var name='x'>y</var></group>")
        self.assertEqual(caught.exception.code, "WAZUH_NO_RULE")

    def test_an_xml_entity_is_refused_before_parsing(self):
        # Wazuh rules reaching this tool are untrusted input, and an expanding
        # entity is a denial of service against whoever pasted it. A rule has no
        # legitimate use for one.
        with self.assertRaises(Refusal) as caught:
            parse_wazuh(
                '<!DOCTYPE r [<!ENTITY a "bomb">]>'
                '<rule id="1" level="5"><match>&a;</match></rule>'
            )
        self.assertEqual(caught.exception.code, "WAZUH_XML_ENTITY")


class TheRuleThatMatchesEverything(unittest.TestCase):
    """The defect this codebase was built around."""

    def test_a_rule_with_no_matcher_is_refused(self):
        # In Wazuh this fires on every event its parent passed. Lowering it as
        # a pass-through would produce a rule that matches everything while
        # reporting success.
        with self.assertRaises(Refusal) as caught:
            lower(rule_xml("<description>catch all</description>"))
        self.assertEqual(
            caught.exception.code, "WAZUH_RULE_MATCHES_EVERYTHING"
        )

    def test_a_rule_with_only_an_if_sid_is_refused(self):
        # if_sid narrows the INPUT; it is not a condition on the event. A rule
        # that only has one still matches every event the parent passed.
        with self.assertRaises(Refusal) as caught:
            lower(rule_xml("<if_sid>5700</if_sid>"))
        self.assertEqual(
            caught.exception.code, "WAZUH_RULE_MATCHES_EVERYTHING"
        )

    def test_an_empty_matcher_is_refused(self):
        # An empty `<match>` succeeds against every event.
        for tag in sorted(MATCHERS):
            with self.subTest(tag=tag):
                with self.assertRaises(Refusal) as caught:
                    lower(rule_xml(f"<{tag}></{tag}>"))
                self.assertEqual(caught.exception.code, "WAZUH_MATCHER_EMPTY")

    def test_an_unknown_element_is_refused_rather_than_skipped(self):
        # Skipping a matcher removes a condition and widens the detection
        # without saying so.
        with self.assertRaises(Refusal) as caught:
            lower(rule_xml("<match>x</match><frobnicate>y</frobnicate>"))
        self.assertEqual(caught.exception.code, "WAZUH_ELEMENT_UNKNOWN")
        self.assertIn("frobnicate", caught.exception.message)

    def test_a_rule_with_no_id_is_refused(self):
        # Every reference to a Wazuh rule -- if_sid, if_matched_sid, every
        # override -- is by id.
        with self.assertRaises(Refusal) as caught:
            lower(rule_xml("<match>x</match>", 'level="5"'))
        self.assertEqual(caught.exception.code, "WAZUH_RULE_NO_ID")

    def test_rendering_a_rule_with_no_condition_is_refused(self):
        from engine.ir import Rule

        rule = Rule(
            rule_id="1",
            pipeline=(Read(id="s", table="wazuh_alerts"), Emit(id="o")),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_wazuh(rule)
        self.assertEqual(caught.exception.code, "WAZUH_RENDER_NO_CONDITION")


class SiblingsAreAnded(unittest.TestCase):
    def test_two_matchers_become_an_and(self):
        condition = first(
            lower(rule_xml("<match>a</match><srcip>10.0.0.1</srcip>")), Filter
        ).condition
        self.assertIsInstance(condition, BoolOp)
        self.assertEqual(condition.op, "and")
        self.assertEqual(len(condition.operands), 2)

    def test_one_matcher_is_not_wrapped(self):
        condition = first(lower(rule_xml("<match>a</match>")), Filter).condition
        self.assertIsInstance(condition, Comparison)

    def test_every_matcher_element_lowers(self):
        for tag in sorted(MATCHERS):
            with self.subTest(tag=tag):
                self.assertIsNotNone(
                    first(lower(rule_xml(f"<{tag}>value</{tag}>")), Filter)
                )

    def test_every_field_element_lowers_to_its_field(self):
        for tag, field in sorted(FIELD_ELEMENTS.items()):
            with self.subTest(tag=tag):
                condition = first(
                    lower(rule_xml(f"<{tag}>value</{tag}>")), Filter
                ).condition
                self.assertEqual(condition.left.full, field)

    def test_a_named_field_element_uses_its_name_attribute(self):
        condition = first(
            lower(rule_xml('<field name="win.eventdata.Image">x</field>')), Filter
        ).condition
        self.assertEqual(condition.left.name, "win")
        self.assertEqual(condition.left.path, ("eventdata", "Image"))

    def test_a_field_element_with_no_name_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(rule_xml("<field>x</field>"))
        self.assertEqual(caught.exception.code, "WAZUH_FIELD_NO_NAME")


class MatchersStayDistinct(unittest.TestCase):
    """`<match>`, `<regex>` and `<pcre2>` are three different tests."""

    def test_match_is_a_substring_not_a_pattern(self):
        # Read as a pattern, `10.0.0.1` would match `10X0Y0Z1`, because `.` is
        # a metacharacter.
        condition = first(
            lower(rule_xml("<match>Failed password</match>")), Filter
        ).condition
        self.assertEqual(condition.op, "contains")
        self.assertIsInstance(condition.right, Literal)

    def test_regex_is_os_regex(self):
        condition = first(
            lower(rule_xml("<regex>^Failed</regex>")), Filter
        ).condition
        self.assertIsInstance(condition.right, Regex)
        self.assertEqual(condition.right.dialect, "os_regex")

    def test_pcre2_is_pcre2(self):
        condition = first(
            lower(rule_xml("<pcre2>^Failed</pcre2>")), Filter
        ).condition
        self.assertEqual(condition.right.dialect, "pcre2")

    def test_a_literal_field_value_is_equality_not_a_pattern(self):
        condition = first(
            lower(rule_xml("<srcip>10.0.0.1</srcip>")), Filter
        ).condition
        self.assertEqual(condition.op, "==")

    def test_a_field_value_carrying_regex_syntax_is_a_pattern(self):
        condition = first(
            lower(rule_xml("<srcip>^10\\.0\\.</srcip>")), Filter
        ).condition
        self.assertEqual(condition.op, "matches")

    def test_os_regex_refuses_to_execute_rather_than_pretending(self):
        # OS-Regex has NO grouping parentheses and NO bracket classes, so
        # `[a-z]+` is partly literal there and an operator everywhere else.
        # Running it with Python's re would match a different set of events and
        # report it as a success.
        from engine.pipeline import evaluate

        result = evaluate(
            lower(rule_xml("<regex>^Failed \\w+</regex>")),
            [{"full_log": "Failed password for root"}],
        )
        self.assertFalse(result.matched)
        self.assertIn("REGEX_NOT_EXECUTABLE", [c.code for c in result.caveats])

    def test_a_substring_match_does_evaluate(self):
        # Most real Wazuh rules use `<match>`, so most of them stay testable.
        from engine.pipeline import evaluate

        rule = lower(rule_xml("<match>Failed password</match>"))
        self.assertTrue(
            evaluate(rule, [{"full_log": "Failed password for root"}]).matched
        )
        self.assertFalse(
            evaluate(rule, [{"full_log": "Accepted password for root"}]).matched
        )


class NegationSurvivesBothSpellings(unittest.TestCase):
    """Dropping a negation inverts the detection."""

    def test_the_negate_attribute_is_read(self):
        condition = first(
            lower(rule_xml('<match negate="yes">sudo</match>')), Filter
        ).condition
        self.assertTrue(condition.negate)

    def test_the_leading_bang_is_read(self):
        condition = first(
            lower(rule_xml("<srcip>!10.0.0.1</srcip>")), Filter
        ).condition
        self.assertTrue(condition.negate)
        # The `!` must not survive into the value, or the comparison tests for
        # a host literally called `!10.0.0.1`.
        self.assertEqual(condition.right.value, "10.0.0.1")

    def test_both_spellings_together_cancel(self):
        condition = first(
            lower(rule_xml('<srcip negate="yes">!10.0.0.1</srcip>')), Filter
        ).condition
        self.assertFalse(condition.negate)

    def test_a_negated_rule_actually_excludes(self):
        from engine.pipeline import evaluate

        rule = lower(rule_xml('<match negate="yes">sudo</match>'))
        self.assertTrue(evaluate(rule, [{"full_log": "ssh login"}]).matched)
        self.assertFalse(evaluate(rule, [{"full_log": "sudo su -"}]).matched)

    def test_negation_round_trips(self):
        text = render_wazuh(lower(rule_xml('<match negate="yes">sudo</match>')))
        self.assertIn('negate="yes"', text)
        again, _ = lower_wazuh(text)
        self.assertTrue(first(again, Filter).condition.negate)


class PreconditionIsNotCorrelation(unittest.TestCase):
    """`if_sid` narrows the input; `if_matched_sid` is a threshold."""

    def test_if_sid_goes_on_the_source_not_into_a_correlation(self):
        # Treating it as a correlation invents a threshold the rule does not
        # have.
        rule = lower(SSHD)
        self.assertEqual(first(rule, Read).selector, "if_sid=5700")
        self.assertFalse(
            [n for n in rule.pipeline if isinstance(n, Correlation)]
        )

    def test_if_matched_sid_becomes_a_correlation(self):
        # Treating it as a precondition drops the threshold and fires on a
        # single event.
        correlation = first(lower(BRUTE_FORCE), Correlation)
        self.assertEqual(correlation.frequency, 8)
        self.assertEqual(correlation.timeframe.seconds, Decimal(120))

    def test_if_group_is_carried_as_a_precondition(self):
        rule = lower(rule_xml("<if_group>authentication_failed</if_group>"
                              "<match>x</match>"))
        self.assertIn("group:authentication_failed", first(rule, Read).selector)

    def test_several_parents_are_all_kept(self):
        rule = lower(rule_xml("<if_sid>5700,5701</if_sid><match>x</match>"))
        self.assertIn("5700", first(rule, Read).selector)
        self.assertIn("5701", first(rule, Read).selector)


class CorrelationGrouping(unittest.TestCase):
    """Getting the group_by wrong changes the detection completely."""

    def test_same_source_ip_becomes_the_group_key(self):
        # Without it, five failures spread over five machines would fire a rule
        # that means five failures on ONE machine.
        correlation = first(lower(BRUTE_FORCE), Correlation)
        self.assertEqual([k.full for k in correlation.group_by], ["srcip"])

    def test_every_same_element_maps_to_a_field(self):
        for tag, field in sorted(SAME_ELEMENTS.items()):
            if tag == "same_field":
                continue
            with self.subTest(tag=tag):
                correlation = first(
                    lower(rule_xml(
                        f"<if_matched_sid>1</if_matched_sid><{tag} />",
                        'id="2" level="5" frequency="5" timeframe="60"',
                    )),
                    Correlation,
                )
                self.assertEqual(
                    [k.full for k in correlation.group_by], [field]
                )

    def test_same_field_uses_its_name(self):
        correlation = first(
            lower(rule_xml(
                '<if_matched_sid>1</if_matched_sid>'
                '<same_field name="win.eventdata.User" />',
                'id="2" level="5" frequency="5" timeframe="60"',
            )),
            Correlation,
        )
        self.assertEqual(correlation.group_by[0].name, "win")

    def test_a_correlation_with_no_group_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(rule_xml(
                "<if_matched_sid>1</if_matched_sid>",
                'id="2" level="5" frequency="5" timeframe="60"',
            ))
        self.assertEqual(caught.exception.code, "WAZUH_CORRELATION_NO_GROUP")

    def test_a_correlation_with_no_frequency_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(rule_xml(
                "<if_matched_sid>1</if_matched_sid><same_source_ip />",
                'id="2" level="5" timeframe="60"',
            ))
        self.assertEqual(
            caught.exception.code, "WAZUH_CORRELATION_NO_FREQUENCY"
        )

    def test_a_correlation_with_no_timeframe_is_refused(self):
        # A count with no window is not a threshold.
        with self.assertRaises(Refusal) as caught:
            lower(rule_xml(
                "<if_matched_sid>1</if_matched_sid><same_source_ip />",
                'id="2" level="5" frequency="5"',
            ))
        self.assertEqual(
            caught.exception.code, "WAZUH_CORRELATION_NO_TIMEFRAME"
        )

    def test_different_source_ip_is_refused_rather_than_inverted(self):
        # The IR groups rows that SHARE a key and has no inverse, so lowering
        # this as a normal group_by would invert what the rule counts.
        with self.assertRaises(Refusal) as caught:
            lower(rule_xml(
                "<if_matched_sid>1</if_matched_sid><different_source_ip />",
                'id="2" level="5" frequency="5" timeframe="60"',
            ))
        self.assertEqual(
            caught.exception.code, "WAZUH_DIFFERENT_NOT_SUPPORTED"
        )

    def test_same_elements_without_a_threshold_are_reported(self):
        _, diagnostics = lower_wazuh(
            rule_xml("<match>x</match><same_source_ip />")
        )
        self.assertIn(
            "WAZUH_SAME_WITHOUT_CORRELATION", [d.code for d in diagnostics]
        )


class MultipleRules(unittest.TestCase):
    TWO = """<group name="local,">
  <rule id="100" level="5"><match>first</match></rule>
  <rule id="200" level="7"><match>second</match></rule>
</group>"""

    def test_a_document_with_several_rules_is_refused_without_a_selection(self):
        # Lowering the first and discarding the rest hides detections, which is
        # the worst way for this to fail.
        with self.assertRaises(Refusal) as caught:
            lower_wazuh(self.TWO)
        self.assertEqual(caught.exception.code, "WAZUH_MULTIPLE_RULES")

    def test_the_refusal_names_the_ids_it_found(self):
        with self.assertRaises(Refusal) as caught:
            lower_wazuh(self.TWO)
        self.assertIn("100", caught.exception.message)
        self.assertIn("200", caught.exception.message)

    def test_a_rule_can_be_selected_by_id(self):
        self.assertEqual(lower(self.TWO, "200").rule_id, "200")
        self.assertIn(
            "second", render_expr(first(lower(self.TWO, "200"), Filter).condition)
        )


class Metadata(unittest.TestCase):
    def test_the_level_becomes_a_severity(self):
        self.assertEqual(lower(SSHD).annotations.severity, "low")
        self.assertEqual(lower(BRUTE_FORCE).annotations.severity, "high")

    def test_the_description_becomes_the_title(self):
        self.assertIn("authentication failed", lower(SSHD).annotations.title)

    def test_mitre_techniques_are_carried(self):
        # Wazuh names techniques and not tactics, so the tactic is left empty
        # rather than guessed -- the technique id is what a SOC pivots on.
        self.assertEqual(
            lower(SSHD).annotations.mitre_attack, (("", ("T1110",)),)
        )

    def test_the_rule_id_comes_from_the_xml(self):
        self.assertEqual(lower(SSHD).rule_id, "5710")

    def test_the_attributes_are_preserved_for_rendering(self):
        meta = lower(BRUTE_FORCE).metadata
        self.assertEqual(meta["wazuh.level"], "10")
        self.assertEqual(meta["wazuh.frequency"], "8")
        self.assertEqual(meta["wazuh.timeframe"], "120")

    def test_the_enclosing_group_is_kept_apart_from_the_rules_own(self):
        # Using one for the other on the way out silently rewrites both.
        meta = lower(SSHD).metadata
        self.assertEqual(meta["wazuh.ruleset_group"], "syslog,sshd")
        self.assertEqual(meta["wazuh.group"], "authentication_failed")

    def test_the_dialect_is_recorded(self):
        self.assertEqual(lower(SSHD).metadata["dialect"], DIALECT)
        self.assertEqual(lower(SSHD).metadata["language"], LANGUAGE)


class Rendering(unittest.TestCase):
    def test_a_simple_rule_round_trips(self):
        text = render_wazuh(lower(SSHD))
        self.assertIn('<rule id="5710" level="5">', text)
        self.assertIn("<if_sid>5700</if_sid>", text)
        self.assertIn("<match>Failed password</match>", text)
        self.assertIn("<description>", text)
        self.assertIn("<id>T1110</id>", text)

    def test_the_rendered_rule_lowers_again_to_the_same_condition(self):
        rule = lower(SSHD)
        again, _ = lower_wazuh(render_wazuh(rule))
        self.assertEqual(
            render_expr(first(again, Filter).condition),
            render_expr(first(rule, Filter).condition),
        )

    def test_rendering_is_stable_across_two_round_trips(self):
        text = render_wazuh(lower(SSHD))
        again, _ = lower_wazuh(text)
        self.assertEqual(render_wazuh(again), text)

    def test_a_correlation_round_trips(self):
        text = render_wazuh(lower(BRUTE_FORCE))
        self.assertIn('frequency="8"', text)
        self.assertIn('timeframe="120"', text)
        self.assertIn("<same_source_ip />", text)
        again, _ = lower_wazuh(text)
        self.assertEqual(first(again, Correlation).frequency, 8)

    def test_xml_special_characters_are_escaped(self):
        # An unescaped `<` in a value produces a document that will not parse,
        # and an unescaped `&` produces one that parses differently.
        text = render_wazuh(lower(rule_xml("<match>a &amp; b &lt; c</match>")))
        self.assertIn("&amp;", text)
        self.assertIn("&lt;", text)
        again, _ = lower_wazuh(text)
        self.assertIn("a & b < c", render_expr(first(again, Filter).condition))

    def test_an_or_is_refused_rather_than_flattened(self):
        # Sibling elements are ANDed. Emitting the branches of an OR as siblings
        # turns it into an AND -- a strictly narrower rule that silently stops
        # firing.
        rule = Rule(
            rule_id="1",
            pipeline=(
                Read(id="s", table="wazuh_alerts"),
                Filter(id="f", condition=BoolOp("or", (
                    Comparison("contains", FieldRef("full_log"), Literal("a")),
                    Comparison("contains", FieldRef("full_log"), Literal("b")),
                ))),
                Emit(id="o"),
            ),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_wazuh(rule)
        self.assertEqual(caught.exception.code, "WAZUH_RENDER_OR")

    def test_an_unrenderable_operator_is_refused(self):
        rule = Rule(
            rule_id="1",
            pipeline=(
                Read(id="s", table="wazuh_alerts"),
                Filter(id="f", condition=Comparison(
                    ">", FieldRef("srcport"), Literal(Decimal(1024)))),
                Emit(id="o"),
            ),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_wazuh(rule)
        self.assertEqual(caught.exception.code, "WAZUH_RENDER_OPERATOR")


if __name__ == "__main__":
    unittest.main()
