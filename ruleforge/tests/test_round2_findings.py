"""Tests for the defects the SECOND review round found, after the first fixes.

Both reviewers independently found the two worst of these. That is worth noting:
376 green tests plus a clean ruff did not catch a rule that rendered with OR
replaced by AND, and two reviewers reading the same code did.
"""
from __future__ import annotations

import unittest

from ruleforge.dialects import render_aql, render_spl
from ruleforge.dialects.spl_ir import lower
from ruleforge.dialects.spl_render import _selector_value, render_literal
from ruleforge.engine import Verdict, evaluate
from ruleforge.engine.values import Refusal, presence, ABSENT


class AqlPresenceTests(unittest.TestCase):
    """`is_not_null` rendered as `IS NULL` -- the exact opposite.

    One op name had two meanings: the AQL parser gave `IS NULL` the name
    `is_not_null`, and the renderer compensated by mapping that name to
    `IS NULL`. A SPL bare term correctly means "exists and is not null", so a
    cross-dialect render produced `WHERE EventCode IS NULL` -- an INVERTED
    detection, in the module whose whole point is that null and absent differ.
    """

    def test_is_null_and_is_not_null_are_different_ops(self):
        self.assertFalse(presence(5, "is_null").value)
        self.assertTrue(presence(5, "is_not_null").value)
        self.assertTrue(presence(None, "is_null").value)
        self.assertFalse(presence(None, "is_not_null").value)

    def test_absent_is_neither_null_nor_not_null(self):
        self.assertFalse(presence(ABSENT, "is_null").value)
        self.assertFalse(presence(ABSENT, "is_not_null").value)
        self.assertFalse(presence(ABSENT, "exists").value)

    def test_a_bare_spl_term_does_not_render_as_is_null_in_aql(self):
        """THE REGRESSION."""
        from ruleforge.dialects.spl_ir import lower as lower_spl_
        ir = lower_spl_("index=main | search EventCode | stats count as c "
                        "by host")[0]
        rendered = render_aql(ir)
        self.assertNotIn("IS NULL", rendered,
                         "a bare term rendered as IS NULL, inverting the rule")
        self.assertIn("IS NOT NULL", rendered)


class SplOrTests(unittest.TestCase):
    """SPL `OR` was lowered as `AND`. Both reviewers found this one.

    `walk_terms` returned the leaves and discarded the connective, then
    `_all_of` rejoined them with "and". So `a="1" OR b="2"` became
    `and(a="1", b="2")` -- for a single-valued field, unsatisfiable, so the rule
    could NEVER fire; for a multi-valued one, a strict subset. The OR was not
    lost, it was replaced with the operator that changes what is detected.
    """

    def test_a_two_row_or_matches_either_row(self):
        ir = lower("index=w a=\"1\" OR b=\"2\" | stats count as c by host")[0]
        result = evaluate(ir, [{"index": "w", "a": "1", "h": "h"},
                               {"index": "w", "b": "2", "h": "h"}])
        self.assertIs(result.verdict, Verdict.MATCHED,
                      "OR was lowered as AND, so neither row matched")

    def test_a_conjunction_of_several_terms_still_needs_all_of_them(self):
        """`AND` is NOT a Splunk search keyword -- juxtaposition is -- so this
        is written as the parser accepts it.

        A row missing `b` is UNDECIDED, not False: the rule has not established
        that the row fails, only that it cannot tell. That distinction is the
        engine's core invariant and it holds here too.
        """
        ir = lower('index=w a="1" b="2" | stats count as c by h')[0]
        self.assertIs(evaluate(ir, [{"index": "w", "a": "1", "b": "2",
                                     "h": "h"}]).verdict, Verdict.MATCHED)
        self.assertIs(evaluate(ir, [{"index": "w", "a": "1",
                                     "h": "h"}]).verdict,
                         Verdict.NOT_EVALUATED)

    def test_or_survives_into_the_rendered_search(self):
        """The parser groups `index=w a="1"` as a conjunction under the `or`, so
        the rendered form legitimately contains an AND -- the point is that the
        OR is the TOP-LEVEL connective, not that AND is absent."""
        rendered = render_spl(lower(
            'index=w a="1" OR b="2" | stats count as c by h')[0])
        search_stage = rendered.split("| search")[-1]
        self.assertIn(" OR ", search_stage,
                      f"the OR was flattened away: {rendered}")
        self.assertNotIn(") AND b", search_stage)

    def test_a_three_way_or_matches(self):
        ir = lower('index=w a="1" OR b="2" OR c="3" | stats count as n by h')[0]
        self.assertIs(evaluate(ir, [{"index": "w", "c": "3", "h": "h"}]).verdict,
                         Verdict.MATCHED)

    def test_a_parenthesised_or_is_kept(self):
        ir = lower('index=w (a="1" OR b="2") | stats count as n by h')[0]
        self.assertIs(evaluate(ir, [{"index": "w", "b": "2", "h": "h"}]).verdict,
                         Verdict.MATCHED)

    def test_a_negated_head_term_is_refused_not_dropped(self):
        """`NOT user=admin` at the head was filtered out, widening the search."""
        with self.assertRaises(Refusal) as caught:
            lower("index=main NOT user=admin | stats count as c by host")
        self.assertEqual(caught.exception.code, "SPL_NEGATED_HEAD_TERM")


class SecondSelectorTests(unittest.TestCase):
    """A second all-selector filter was neither hoisted nor emitted -- gone.

    `selector_emitted` was a one-shot latch, so a later filter whose terms were
    all selectors produced neither a head term nor a `search`. The analyst got a
    search over the whole index, reported as success.
    """

    def test_a_second_selector_survives_as_a_filter(self):
        rendered = render_spl(lower(
            "index=main | search sourcetype=WinEventLog:Security")[0])
        self.assertIn("sourcetype", rendered)

    def test_a_mixed_second_filter_keeps_both_terms(self):
        rendered = render_spl(lower(
            "index=main | search sourcetype=Security EventCode=4625")[0])
        self.assertIn("sourcetype", rendered)
        self.assertIn("EventCode", rendered)

    def test_two_selector_stages_keep_both(self):
        rendered = render_spl(lower(
            "index=main | search sourcetype=Security "
            "| search EventCode=4625")[0])
        self.assertIn("sourcetype", rendered)
        self.assertIn("EventCode", rendered)


class RegexInjectionTests(unittest.TestCase):
    """A regex pattern was interpolated raw into the rendered SPL."""

    HOSTILE = 'index=w | search cmd matches_regex "x" | stats count by host; #"'

    def test_a_quote_in_a_pattern_cannot_add_a_stage(self):
        from ruleforge.dialects.spl import SplParseError
        try:
            ir = lower('index=w | search cmd matches_regex '
                       'x" | stats count by host; #"')[0]
            rendered = render_spl(ir)
        except SplParseError:
            return          # refusing the parse is also acceptable
        self.assertEqual(rendered.count("| stats"), 1,
                         "a regex pattern injected an extra pipeline stage")


class BackslashTests(unittest.TestCase):
    """Only `"` was escaped, so a value ending in `\\` never closed its literal."""

    def test_a_trailing_backslash_does_not_swallow_the_rest(self):
        rendered = render_literal("a\\")
        self.assertEqual(rendered.count('"') % 2, 0,
                         f"unterminated literal: {rendered}")

    def test_a_windows_path_round_trips(self):
        rendered = render_literal("C:\\Windows\\System32\\lsass.exe")
        self.assertEqual(rendered.count('"') % 2, 0)
        self.assertIn("\\\\", rendered)

    def test_escaping_comes_before_quoting(self):
        self.assertEqual(render_literal('a"b'), '"a\\"b"')


class SelectorQuotingTests(unittest.TestCase):
    def test_a_value_with_whitespace_is_quoted(self):
        self.assertTrue(_selector_value("a b").startswith('"'))

    def test_a_simple_value_is_bare(self):
        self.assertEqual(_selector_value("windows"), "windows")

    def test_a_trailing_newline_forces_quoting(self):
        """`$` matches before a trailing newline, so a bare-safe check using `$`
        would let one through unquoted."""
        self.assertTrue(_selector_value("abc\n").startswith('"'))


class MalformedPayloadTests(unittest.TestCase):
    """A malformed request is a named refusal, not a bare 500."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        from ruleforge import web
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.original = web.HISTORY_PATH
        web.HISTORY_PATH = Path(self.tmp.name) / "h.json"
        self.addCleanup(lambda: setattr(web, "HISTORY_PATH", self.original))
        self.client = web.create_app().test_client()

    def _post(self, raw, content_type="application/json"):
        return self.client.post("/api/author", data=raw,
                                content_type=content_type)

    def test_a_list_body_is_refused(self):
        data = self._post("[1,2,3]").get_json()
        self.assertEqual(data["refusal"]["code"], "PAYLOAD_NOT_AN_OBJECT")

    def test_a_numeric_rule_id_is_refused(self):
        data = self._post('{"dialect":"splunk","rule":"index=main","rule_id":7}'
                          ).get_json()
        self.assertEqual(data["refusal"]["code"], "PAYLOAD_FIELD_WRONG_TYPE")

    def test_a_list_dialect_is_refused(self):
        data = self._post('{"dialect":[],"rule":"index=main"}').get_json()
        self.assertEqual(data["refusal"]["code"], "PAYLOAD_FIELD_WRONG_TYPE")

    def test_a_numeric_fields_list_is_refused(self):
        data = self.client.post("/api/debug_logs_to_rule", json={
            "dialect": "splunk", "events": '[{"a":1}]', "fields": 5}).get_json()
        self.assertEqual(data["refusal"]["code"], "PAYLOAD_FIELD_WRONG_TYPE")

    def test_a_string_fields_list_is_refused(self):
        """A string is iterable, so it was silently iterated CHARACTER BY
        CHARACTER and reported as a field inventory of u, s, e, r."""
        data = self.client.post("/api/debug_logs_to_rule", json={
            "dialect": "splunk", "events": '[{"a":1}]',
            "fields": "user"}).get_json()
        self.assertEqual(data["refusal"]["code"], "PAYLOAD_FIELD_WRONG_TYPE")

    def test_malformed_json_is_refused(self):
        data = self._post("{not json").get_json()
        self.assertFalse(data["ok"])

    def test_an_unknown_job_is_still_404(self):
        self.assertEqual(self.client.post("/api/nonsense", json={}).status_code,
                         404)

    def test_a_normal_request_still_works(self):
        data = self._post('{"dialect":"splunk","rule":"index=main | stats '
                          'count BY host"}').get_json()
        self.assertTrue(data["ok"])


if __name__ == "__main__":
    unittest.main()
