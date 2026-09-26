"""The user's real YARA-L 2.0 rule, as an acceptance test.

Pasted verbatim from their request. It is the hardest of the five for this engine
in one specific way: it contains a CROSS-EVENT comparison, which is the easiest
thing in the world to misread as a same-row comparison and have the rule fire on
every logon regardless of whether any credential access happened.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from ruleforge.dialects.yaral import parse_yaral  # noqa: E402
from ruleforge.dialects.yaral_ir import lower, render  # noqa: E402
from ruleforge.engine import (  # noqa: E402
    Pattern,
    Refusal,
    Verdict,
    evaluate,
    validate_graph,
)
from ruleforge.engine.ir import Call  # noqa: E402

USER_YARAL_RULE = """
rule CredentialAccess_NTLM_LateralMovement {

  meta:
    author = "SOC Detection Engineering"
    description = "Detects LSASS credential access followed by NTLM lateral movement"
    severity = "HIGH"
    mitre_attack_tactic = "Credential Access, Lateral Movement"
    mitre_attack_technique = "T1003.001, T1021.002"

  events:

    $lsass.metadata.event_type = "PROCESS_ACCESS"
    $lsass.target.process.file.full_path = /\\\\lsass\\.exe$/ nocase
    $lsass.principal.hostname = $host

    $login.metadata.event_type = "USER_LOGIN"
    $login.extensions.auth.type = "NTLM"
    $login.principal.hostname = $host

    $lsass.metadata.event_timestamp <=
      $login.metadata.event_timestamp

  match:
    $host over 10m

  condition:
    $lsass and $login
}
"""


class ParsingTests(unittest.TestCase):

    def setUp(self):
        self.parsed = parse_yaral(USER_YARAL_RULE)

    def test_the_rule_name_and_metadata_come_through(self):
        self.assertEqual(self.parsed.name, "CredentialAccess_NTLM_LateralMovement")
        self.assertEqual(self.parsed.meta["severity"], "HIGH")
        self.assertEqual(self.parsed.meta["mitre_attack_technique"],
                         "T1003.001, T1021.002")

    def test_the_event_lines_are_parsed_and_the_cross_event_one_is_separated(self):
        """4 predicates, 2 grouping bindings, and the cross-event comparison
        lifted out of the event list entirely.

        The cross-event line is NOT an event. It orders two events, and leaving it
        in the list would make it a same-row comparison -- comparing the login's
        timestamp to itself, which is always true, so the rule would fire on every
        NTLM logon regardless of whether any credential access happened.
        """
        predicates = [e for e in self.parsed.events if not e.is_placeholder]
        bindings = [e for e in self.parsed.events if e.is_placeholder]
        self.assertEqual(len(predicates), 4,
                         "2 for $lsass (event_type, file path), 2 for $login")
        self.assertEqual(len(bindings), 2,
                         "$host is bound from both events, and a binding is not a "
                         "predicate")
        self.assertEqual(len(self.parsed.cross_event_order), 1,
                         "the timestamp comparison is not an event line")
        self.assertTrue(all("event_timestamp" not in e.field for e in predicates),
                        "no predicate may be the cross-event comparison")

    def test_the_window_is_ten_minutes(self):
        self.assertEqual(self.parsed.match.window_seconds, 600)
        self.assertEqual(self.parsed.match.keys, ("$host",))

    def test_the_nocase_modifier_is_recorded_not_dropped(self):
        regex_events = [e for e in self.parsed.events if e.is_regex]
        self.assertTrue(regex_events, "the /regex/ literal should be recognised")
        self.assertTrue(regex_events[0].nocase,
                        "nocase must be recorded on the node, not discarded")

    def test_the_dotted_udm_paths_survive_intact(self):
        fields = {e.field for e in self.parsed.events}
        self.assertIn("target.process.file.full_path", fields)
        self.assertIn("extensions.auth.type", fields)
        self.assertIn("metadata.event_type", fields)

    def test_the_condition_names_both_events(self):
        self.assertEqual(self.parsed.condition.op, "and")
        self.assertEqual(len(self.parsed.condition.operands), 2)

    def test_the_cross_event_comparison_is_detected(self):
        self.assertEqual(len(self.parsed.cross_event_order), 1)
        left, right, operator = self.parsed.cross_event_order[0]
        self.assertTrue(left.endswith("metadata.event_timestamp"))
        self.assertTrue(right.endswith("metadata.event_timestamp"))
        self.assertEqual(operator, "<=")

    def test_the_wrapped_comparison_was_joined_not_split(self):
        """The rule wraps the timestamp comparison across two lines. Treating
        those as two statements would produce two half-comparisons."""
        self.assertEqual(len(self.parsed.cross_event_order), 1)

    def test_there_are_no_unexpected_diagnostics(self):
        blockers = [d for d in self.parsed.diagnostics if d.severity == "refusal"]
        self.assertEqual(blockers, [], f"unexpected refusals: {blockers}")


class LoweringTests(unittest.TestCase):

    def setUp(self):
        self.parsed = parse_yaral(USER_YARAL_RULE)

    def test_it_produces_a_runnable_graph(self):
        ir, _ = lower(self.parsed)
        validate_graph(ir)
        self.assertEqual(ir.output, "out")

    def test_the_window_becomes_a_pattern_window(self):
        ir, _ = lower(self.parsed)
        patterns = [n for n in ir.nodes if isinstance(n, Pattern)]
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0].within.seconds, 600)

    def test_the_pattern_declares_its_time_field(self):
        """Pattern REQUIRES time_field. It is taken from the rule's own
        cross-event comparison, never guessed from a column that looks like a
        time."""
        ir, _ = lower(self.parsed)
        pattern = next(n for n in ir.nodes if isinstance(n, Pattern))
        self.assertEqual(pattern.time_field, "metadata.event_timestamp")

    def test_the_cross_event_comparison_becomes_a_stage_order(self):
        """THE TEST THAT MATTERS.

        Lowered as a same-row comparison it would compare the LOGIN's timestamp to
        the LOGIN's timestamp, which is always true, so the rule would fire on
        every NTLM logon regardless of whether any credential access occurred.
        """
        ir, diagnostics = lower(self.parsed)
        warnings = [d for d in diagnostics
                    if d.code == "YARAL_CROSS_EVENT_BECAME_STAGE_ORDER"]
        self.assertTrue(warnings,
                        "the cross-event reading must be disclosed, not silent")
        self.assertIn("would compare the logon's timestamp to itself",
                      warnings[0].message)

        pattern = next(n for n in ir.nodes if isinstance(n, Pattern))
        self.assertGreaterEqual(len(pattern.stages), 2,
                                "two events means at least two ordered stages")

    def test_the_grouping_key_comes_from_the_placeholder(self):
        ir, _ = lower(self.parsed)
        pattern = next(n for n in ir.nodes if isinstance(n, Pattern))
        self.assertTrue(pattern.key, "the match key must survive lowering")
        self.assertIn("principal.hostname", {k.name for k in pattern.key})


class RefusalTests(unittest.TestCase):

    def test_a_nocase_regex_LOWERS_with_a_diagnostic_and_refuses_only_at_runtime(self):
        """The rule must stay OPENABLE and RENDERABLE.

        An earlier version refused at lower time, which made the user's own rule
        impossible to open, edit, understand or render in a tool whose job is
        exactly that. A case-insensitive regex is representable EXACTLY -- the
        pattern plus a `nocase` flag -- so it lowers, renders back as
        `/pattern/ nocase`, and only a LOCAL RUN is impossible because the dialect
        is PCRE and this engine has no PCRE engine.
        """
        rule = """
        rule R {
          events:
            $e.target.process.file.full_path = /lsass/ nocase
          condition:
            $e
        }
        """
        ir, diagnostics = lower(parse_yaral(rule))
        validate_graph(ir)
        codes = [d.code for d in diagnostics]
        self.assertIn("YARAL_REGEX_NOT_EXECUTABLE_LOCALLY", codes)
        self.assertIn("nocase", render(ir),
                      "the modifier must survive into the rendered rule")

    def test_a_nocase_COMPARISON_still_refuses_because_it_is_not_representable(self):
        """`nocase` on a plain comparison has no faithful home. `contains` folds
        case but is a DIFFERENT and BROADER test, and the render would quietly
        differ from the rule written. This one refuses at lower time, because a
        faithful render is impossible."""
        rule = """
        rule R {
          events:
            $e.process.name = "LSASS.EXE" nocase
          condition:
            $e
        }
        """
        with self.assertRaises(Refusal) as caught:
            lower(parse_yaral(rule))
        self.assertEqual(caught.exception.code,
                         "YARAL_UNSUPPORTED_NOCASE_COMPARISON")
        self.assertIn("broader test than the rule states", caught.exception.message)

    def test_a_sliding_pivot_window_is_refused_rather_than_approximated(self):
        rule = """
        rule R {
          events:
            $a.event_type = "A"
            $a.host = $h
            $b.event_type = "B"
          match:
            $h over 10m after $a
          condition:
            $a and $b
        }
        """
        parsed = parse_yaral(rule)
        codes = [d.code for d in parsed.diagnostics]
        self.assertIn("YARAL_UNSUPPORTED_SLIDING_PIVOT", codes)

    def test_a_window_outside_one_minute_to_48_hours_is_refused(self):
        rule = """
        rule R {
          events:
            $a.event_type = "A"
            $a.host = $h
          match:
            $h over 30s
          condition:
            $a
        }
        """
        with self.assertRaises(Refusal) as caught:
            parse_yaral(rule)
        self.assertEqual(caught.exception.code, "YARAL_WINDOW_OUT_OF_RANGE")

    def test_a_bare_field_event_is_refused(self):
        """`$e.event_type` with no comparison matches every event that has the
        field, which is never what an author meant."""
        rule = """
        rule R {
          events:
            $e.event_type
          condition:
            $e
        }
        """
        with self.assertRaises(Refusal):
            parse_yaral(rule)

    def test_a_rule_with_no_condition_is_refused(self):
        rule = """
        rule R {
          events:
            $e.event_type = "A"
        }
        """
        parsed = parse_yaral(rule)
        self.assertIn("YARAL_NO_CONDITION", [d.code for d in parsed.diagnostics])

    def test_text_that_is_not_a_rule_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_yaral("this is just a sentence")
        self.assertEqual(caught.exception.code, "YARAL_NO_RULE_HEADER")


class RenderingTests(unittest.TestCase):

    def test_the_render_keeps_the_nocase_modifier(self):
        """The pattern text is emitted EXACTLY as given. Baking `(?i)` into it
        would preserve the matched language but change the analyst's bytes and
        break the diff against the rule they pasted."""
        rule = """
        rule R {
          events:
            $e.target.process.file.full_path = /lsass\\.exe$/ nocase
          condition:
            $e
        }
        """
        ir, _ = lower(parse_yaral(rule)) if False else (None, None)
        # a nocase regex is refused on lower, so render from a hand-built IR
        from ruleforge.engine import (Emit, FieldExpr, FieldRef, Read, RuleIR,
                                      SourceSelector)
        condition = Call("matches_regex",
                         (FieldExpr(FieldRef("target.process.file.full_path")),
                          __import__("ruleforge.engine", fromlist=["Literal"]
                                     ).Literal(r"lsass\.exe$")),
                         dialect="pcre", flags=frozenset({"nocase"}))
        ir = RuleIR(rule_id="R", title="R", nodes=(
            Read(id="read", selector=SourceSelector(name="udm_events")),
            __import__("ruleforge.engine", fromlist=["Filter"]).Filter(
                id="flt", input="read", condition=condition),
            Emit(id="out", input="flt"),
        ), output="out")
        text = render(ir)
        self.assertIn("/lsass\\.exe$/ nocase", text)
        self.assertNotIn("(?i)", text, "the pattern must not be rewritten")

    def test_a_single_event_rule_round_trips(self):
        rule = """
        rule Simple {
          events:
            $e.metadata.event_type = "PROCESS_ACCESS"
            $e.target.process.file.full_path = "lsass.exe"
          condition:
            $e
        }
        """
        ir, _ = lower(parse_yaral(rule))
        text = render(ir)
        self.assertIn("rule Simple", text)
        self.assertIn("metadata.event_type", text)
        self.assertIn("lsass.exe", text)
        self.assertIn("condition:", text)

    def test_a_correlation_rule_round_trips_its_window(self):
        ir, _ = lower(parse_yaral(USER_YARAL_RULE))
        text = render(ir)
        self.assertIn("match:", text)
        self.assertIn("over 10m", text)


class ExecutionTests(unittest.TestCase):
    """The rendered rule's SEMANTICS, checked against sample UDM rows."""

    def _rows(self, with_second_event: bool):
        rows = [
            {"metadata.event_type": "PROCESS_ACCESS",
             "target.process.file.full_path": r"C:\Windows\lsass.exe",
             "principal.hostname": "host-a",
             "metadata.event_timestamp": 100},
        ]
        if with_second_event:
            rows.append({"metadata.event_type": "USER_LOGIN",
                         "extensions.auth.type": "NTLM",
                         "principal.hostname": "host-a",
                         "metadata.event_timestamp": 200})
        return rows

    def test_a_pcre_regex_rule_refuses_to_run_rather_than_guessing(self):
        """The rule is preserved and renders correctly; QRadar... SecOps will run
        it correctly. This engine has no PCRE engine, so a local run must say so."""
        ir, _ = lower(parse_yaral(USER_YARAL_RULE))
        result = evaluate(ir, self._rows(with_second_event=True))
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED,
                      "a PCRE rule must not report a local verdict")
        self.assertIsNotNone(result.reason)

    def test_the_placeholder_binds_the_correlation_key_not_a_predicate(self):
        """`$lsass.principal.hostname = $host` is a GROUPING BINDING.

        Lowered as a comparison it would resolve `$host` as a field name that
        exists in no row, so every row would go undecidable and the rule could
        never match. The binding belongs on the Pattern's key.
        """
        rule = """
        rule HostMatch {
          events:
            $a.event_type = "PROCESS_ACCESS"
            $a.principal.hostname = $h
            $a.metadata.event_timestamp <= $b.metadata.event_timestamp
            $b.event_type = "USER_LOGIN"
            $b.principal.hostname = $h
          match:
            $h over 10m
          condition:
            $a and $b
        }
        """
        ir, _ = lower(parse_yaral(rule))
        validate_graph(ir)
        pattern = next(n for n in ir.nodes if isinstance(n, Pattern))
        self.assertEqual([k.name for k in pattern.key], ["principal.hostname"])
        self.assertEqual(pattern.time_field, "metadata.event_timestamp")
        for stage in pattern.stages:
            for condition in stage:
                self.assertNotIn("$h", str(condition),
                                 "the placeholder must not appear as a field")

    def test_a_correlation_rule_with_no_timestamp_is_refused(self):
        """A pattern cannot be ordered without a time field, and picking a column
        that merely looks like a timestamp would change which events count as
        'then'. So a window with no stated time field refuses."""
        rule = """
        rule NoTime {
          events:
            $a.event_type = "A"
            $a.principal.hostname = $h
            $b.event_type = "B"
            $b.principal.hostname = $h
          match:
            $h over 10m
          condition:
            $a and $b
        }
        """
        with self.assertRaises(Refusal) as caught:
            lower(parse_yaral(rule))
        self.assertEqual(caught.exception.code, "PATTERN_REQUIRES_TIME_FIELD")


if __name__ == "__main__":
    unittest.main()
