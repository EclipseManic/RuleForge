"""Regression tests for the two-reviewer findings.

EVERY TEST HERE HAS A FAILING CASE THAT WAS OBSERVED, not a hypothetical. Each
docstring says what the bug did, because a regression test whose comment does not
say what it prevents tends to get deleted as "redundant" six months later.

The five in the CRITICAL group are all the same shape: an undecidable value
becoming a definitive answer, which is the one thing this engine exists to
prevent.
"""
from __future__ import annotations

import unittest
from decimal import Decimal

from ruleforge import jobs
from ruleforge.dialects import lower_aql, lower_kql, lower_spl, lower_wazuh
from ruleforge.dialects import parse_aql, parse_kql, parse_spl, parse_wazuh
from ruleforge.dialects import render_aql, render_spl
from ruleforge.dialects.wazuh_render import render as render_wazuh_xml
from ruleforge.engine import Verdict, evaluate
from ruleforge.engine.ir import (
    Aggregate,
    Call,
    Comparison,
    Duration,
    Emit,
    FieldExpr,
    FieldRef,
    Filter,
    Frame,
    Literal,
    Measure,
    Not,
    Package,
    Pattern,
    Read,
    RuleIR,
    SourceSelector,
    TimeRef,
)
from ruleforge.engine.validate import validate_graph
from ruleforge.engine.values import Refusal
from ruleforge.tests.test_kql import USER_SENTINEL_RULE
from ruleforge.tests.test_spl import CORPUS_SPL

SRC = SourceSelector(name="events")


def graph(*nodes, output="o"):
    return RuleIR(rule_id="t", nodes=nodes, output=output)


# ---------------------------------------------------------------------------
# CRITICAL
# ---------------------------------------------------------------------------


class TuneCrashTests(unittest.TestCase):
    """`tune` 500'd on the ORDINARY case.

    `result.reason` is a Refusal, which has `.code` and `.message`, not
    `.detail`. Any rule whose fields the sample does not carry produces
    `not_evaluated` -- which is the normal outcome, not an edge case -- so the
    behavioural half of a headline job was unreachable exactly when the
    invariant mattered most, and the JS then showed "Working..." forever.
    """

    def test_not_evaluated_does_not_raise(self):
        ir, _ = lower_spl("index=main EventCode=1 | stats count BY host")
        outcome = jobs.tune(ir, [{"unrelated": 1}])
        self.assertIsNotNone(outcome.result)
        self.assertEqual(outcome.result["verdict"], "not_evaluated")

    def test_the_reason_is_reported_as_text(self):
        ir, _ = lower_spl("index=main EventCode=1 | stats count BY host")
        outcome = jobs.tune(ir, [{"unrelated": 1}])
        self.assertIsInstance(outcome.result["reason_detail"], str)

    def test_a_matched_verdict_still_works(self):
        ir, _ = lower_spl("index=main | stats count BY host")
        outcome = jobs.tune(ir, [{"index": "main", "host": "h1"}])
        self.assertEqual(outcome.result["verdict"], "matched")


class PackageWindowTests(unittest.TestCase):
    """One untimed event used to produce THREE false alerts.

    The trailing-window loop stopped advancing the moment it met an unusable
    time, so `left` froze there and the window size went on counting rows from
    outside the timeframe. The caveat was recorded but the verdict still said
    matched, so a 3-in-100-seconds detector alerted on four events spread over an
    hour.
    """

    def _ir(self, frequency=3, span=100):
        # A Package with NEITHER parent nor children is refused as PACKAGE_EMPTY,
        # so the count subject needs a parent condition to count.
        parent = (Comparison("=", FieldExpr(ref=FieldRef("h")),
                             Literal(value="h1")),)
        package = Package(
            id="c", input="r", parent=parent, count_subject="parent",
            frequency=frequency, timeframe=Duration(span),
            same_fields=(FieldRef("h"),), time_field="t")
        return graph(Read(id="r", selector=SRC), package,
                     Emit(id="o", input="c"))

    def test_spread_past_the_timeframe_does_not_fire(self):
        rows = [{"t": Decimal(m * 1000), "h": "h1"}
                for m in range(4)]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_one_untimed_event_does_not_make_them_fire(self):
        """THE REGRESSION. The same four events plus a row with no `t`.

        The verdict is `not_evaluated` rather than `no_match`, because the
        untimed row means the window genuinely cannot be established for every
        row. What matters is that it is NOT `matched` -- the bug produced three
        false alerts, and the default-deny caveat gate is what stops them.
        """
        rows = [{"t": Decimal(m * 1000), "h": "h1"} for m in range(4)]
        rows.insert(2, {"h": "h1"})
        result = evaluate(self._ir(), rows)
        self.assertIsNot(result.verdict, Verdict.MATCHED,
                         "an event with no timestamp made a 3-in-100s detector "
                         "report three false alerts")

    def test_the_untimed_row_is_reported(self):
        rows = [{"t": Decimal(0), "h": "h1"}, {"h": "h1"},
                {"t": Decimal(10), "h": "h1"}, {"t": Decimal(20), "h": "h1"},
                {"t": Decimal(30), "h": "h1"}]
        result = evaluate(self._ir(frequency=5, span=100), rows)
        self.assertIn("PACKAGE_UNDECIDABLE_TIME",
                      [c.code for c in result.caveats])

    def test_a_genuine_cluster_still_fires(self):
        rows = [{"t": Decimal(m * 10), "h": "h1"} for m in range(4)]
        self.assertIs(evaluate(self._ir(), rows).verdict, Verdict.MATCHED)


class WindowedAggregateTests(unittest.TestCase):
    """A windowed aggregate measured the WRONG ROWS.

    `_windows` partitions the list it is handed, which was the time-usable
    subset, but the resulting indices were applied to the FULL row list. So any
    row without a timestamp shifted every later index and `max` could be read
    from a row that had been excluded from the window and reported as being
    inside it.
    """

    def _ir(self, frame):
        return graph(
            Read(id="r", selector=SRC),
            Aggregate(id="a", input="r", frame=frame, keys=(),
                      measures=(Measure(name="m", function="max",
                                        field=FieldRef("v")),
                                Measure(name="n", function="count"))),
            Emit(id="o", input="a"))

    def test_an_untimed_row_does_not_become_the_maximum(self):
        """THE REGRESSION: the untimed row's value was reported as the window's
        maximum even though the row was excluded from the window."""
        frame = Frame(kind="tumbling", size=Duration(100),
                      time_ref=TimeRef(field_name="t"))
        rows = [{"t": Decimal(1), "v": "A"}, {"v": "MID"},
                {"t": Decimal(2), "v": "B"}]
        result = evaluate(self._ir(frame), rows)
        self.assertEqual(result.rows[0].get("m"), "B",
                         "the maximum was read from a row outside the window")

    def test_an_untimed_row_does_not_inflate_the_count(self):
        frame = Frame(kind="tumbling", size=Duration(100),
                      time_ref=TimeRef(field_name="t"))
        rows = [{"t": Decimal(1), "v": "A"}, {"v": "MID"},
                {"t": Decimal(2), "v": "B"}]
        result = evaluate(self._ir(frame), rows)
        self.assertEqual(result.rows[0].get("n"), 2)

    def test_the_untimed_row_is_reported(self):
        frame = Frame(kind="tumbling", size=Duration(100),
                      time_ref=TimeRef(field_name="t"))
        result = evaluate(self._ir(frame), [{"t": Decimal(1), "v": "A"},
                                            {"v": "MID"}])
        self.assertIn("ROWS_WITHOUT_TIME", [c.code for c in result.caveats])


class AqlRenderTests(unittest.TestCase):
    """The AQL renderer had no `else`, and that was the whole bug.

    A graph containing a `Package` -- a correlation, whose entire detection IS
    that node -- rendered as `SELECT * FROM events`. No refusal, no diagnostic,
    and the artifact still carried the "NOT a deployable QRadar rule" header, so
    it read as finished. The other four renderers all raised for this.
    """

    def _correlation(self):
        return graph(Read(id="r", selector=SRC),
                     Package(id="c", input="r",
                             parent=(Comparison("=", FieldExpr(
                                 ref=FieldRef("a")), Literal(value=1)),),
                             count_subject="parent",
                             frequency=5, timeframe=Duration(60),
                             same_fields=(FieldRef("h"),), time_field="t"),
                     Emit(id="o", input="c"))

    def test_a_correlation_is_refused_not_silently_dropped(self):
        with self.assertRaises(Refusal) as caught:
            render_aql(self._correlation())
        self.assertEqual(caught.exception.code, "AQL_NODE_NOT_RENDERABLE")

    def test_the_refusal_names_the_node(self):
        with self.assertRaises(Refusal) as caught:
            render_aql(self._correlation())
        self.assertIn("Package", caught.exception.message)

    def test_a_pattern_is_refused_too(self):
        rule = graph(Read(id="r", selector=SRC),
                     Pattern(id="p", input="r",
                             stages=((Comparison("=", FieldExpr(
                                 ref=FieldRef("a")), Literal(value=1)),),
                                     (Comparison("=", FieldExpr(
                                         ref=FieldRef("b")), Literal(value=2)),)),
                             within=Duration(60), time_field="t"),
                     Emit(id="o", input="p"))
        with self.assertRaises(Refusal) as caught:
            render_aql(rule)
        self.assertEqual(caught.exception.code, "AQL_NODE_NOT_RENDERABLE")

    def test_a_plain_rule_still_renders(self):
        """The refusal must not break the ordinary path."""
        from ruleforge.tests.test_aql import USER_QRADAR_RULE
        ir, _ = lower_aql(parse_aql(USER_QRADAR_RULE))
        self.assertIn("SELECT", render_aql(ir))


class InSetNullTests(unittest.TestCase):
    """`in_set` treated a NULL as a definite non-member.

    `compare()` already refuses a null for `=`, so `=` and `IN` disagreed about
    the same field, and `NOT (src in ("a","b"))` MATCHED every row whose `src`
    was null. Defect 26's nested-UNDECIDED guard was added; nested-NULL was not.
    """

    def _not_in(self):
        return graph(
            Read(id="r", selector=SRC),
            Filter(id="f", input="r", condition=Not(Call(
                function="in_set",
                args=(FieldExpr(ref=FieldRef("src")),
                      Literal(value=("a", "b")))))),
            Emit(id="o", input="f"))

    def test_a_null_field_does_not_satisfy_not_in(self):
        """THE REGRESSION: this matched."""
        result = evaluate(self._not_in(), [{"src": None}, {"src": "a"}])
        self.assertIsNot(result.verdict, Verdict.MATCHED)

    def test_a_real_non_member_still_satisfies_not_in(self):
        result = evaluate(self._not_in(), [{"src": "c"}])
        self.assertIs(result.verdict, Verdict.MATCHED)

    def test_a_member_does_not_satisfy_not_in(self):
        result = evaluate(self._not_in(), [{"src": "a"}])
        self.assertIs(result.verdict, Verdict.NO_MATCH)


# ---------------------------------------------------------------------------
# HIGH
# ---------------------------------------------------------------------------


class WazuhAttributeInjectionTests(unittest.TestCase):
    """A pasted field name could inject a Wazuh ATTRIBUTE and invert the match.

    `xml.sax.saxutils.escape` escapes only `&`, `<` and `>`. It does not escape
    `"`, and every attribute in a Wazuh rule is double-quoted -- so a name
    carrying `&quot;` re-parsed as a real quote and a real attribute. The result
    was a rule that alerted on everything EXCEPT the target.
    """

    HOSTILE = (
        '<group name="g,">'
        '<rule id="700" level="5">'
        '<field name="win.eventdata.newProcessName&quot; '
        'negate=&quot;yes">evil.exe</field>'
        '</rule></group>'
    )

    def test_the_injected_attribute_does_not_appear(self):
        ir, _ = lower_wazuh(self.HOSTILE, "700")
        rendered = render_wazuh_xml(ir)
        again = parse_wazuh(rendered)["700"]
        self.assertEqual(
            getattr(again.fields[0], "negate", False), False,
            "a pasted field name injected negate=yes, which INVERTS the match")

    def test_the_field_name_survives_intact(self):
        ir, _ = lower_wazuh(self.HOSTILE, "700")
        again = parse_wazuh(render_wazuh_xml(ir))["700"]
        self.assertIn("newProcessName", again.fields[0].name)

    def test_a_quote_in_a_rule_id_cannot_break_the_document(self):
        rule = ('<group name="g,"><rule id="700" level="5">'
                '<description>a &amp; b</description>'
                '<field name="a">x</field></rule></group>')
        ir, _ = lower_wazuh(rule, "700")
        again = parse_wazuh(render_wazuh_xml(ir))
        self.assertIn("700", again)


class SplSelectorInjectionTests(unittest.TestCase):
    """A selector value was emitted UNQUOTED, injecting a pipeline stage."""

    HOSTILE = 'index="a | stats count by host" EventCode=4625 | stats count BY host'

    def test_a_pipe_in_a_selector_value_cannot_add_a_stage(self):
        """THE REGRESSION: the value was emitted bare, so its `|` became a real
        pipeline separator. Quoted, it stays one value."""
        rendered = render_spl(lower_spl(self.HOSTILE)[0])
        self.assertIn('"a | stats count by host"', rendered)
        # The injected stage is inside the quotes, so the only REAL stage
        # separator is the one the analyst wrote.
        self.assertEqual(rendered.count("| stats count by host"), 1)

    def test_a_value_with_a_space_is_quoted(self):
        rendered = render_spl(lower_spl(
            'index="windows security" | stats count BY host')[0])
        self.assertIn('"windows security"', rendered)

    def test_a_simple_value_is_left_bare(self):
        """Faithfulness: rewriting the analyst's bytes for no reason makes the
        diff against what they pasted stop matching."""
        self.assertIn("index=windows", render_spl(lower_spl(
            "index=windows | stats count BY host")[0]))


class SplHeadTermTests(unittest.TestCase):
    """Non-selector head terms were dropped SILENTLY, losing the filter.

    `index=windows EventCode=4625 | stats count by host` kept only `index`, so
    the analyst got a count over ALL Security events instead of the failed
    logons, with `ok: true` and no findings. A search that was nothing but
    `EventCode=4625` rendered as an EMPTY query, still `ok: true`.
    """

    def test_a_non_selector_head_term_survives(self):
        rendered = render_spl(lower_spl(
            "index=windows EventCode=4625 | stats count BY host")[0])
        self.assertIn("EventCode", rendered)

    def test_a_search_of_only_a_non_selector_is_not_empty(self):
        rendered = render_spl(lower_spl("EventCode=4625 | stats count BY host")[0])
        self.assertIn("EventCode", rendered)
        self.assertNotEqual(rendered.strip(), "")

    def test_it_re_parses_with_the_filter_intact(self):
        """EventCode comes back as a `| search` stage, not a head term -- which
        is correct: it is a filter, not a selector. The point is that it is
        THERE at all."""
        rendered = render_spl(lower_spl(
            "index=windows EventCode=4625 | stats count BY host")[0])
        again = parse_spl(rendered)
        searches = [c.args for c in again.pipeline if c.name == "search"]
        self.assertTrue(any("EventCode" in s for s in searches),
                        f"the EventCode filter was lost: {rendered}")

    def test_the_round_trip_keeps_the_whole_rule(self):
        """The full corpus rule, which has a selector AND a bare term."""
        rendered = render_spl(lower_spl(CORPUS_SPL)[0])
        self.assertIn("EventCode", rendered)
        self.assertIn("index=windows", rendered)


class SplMeasureDropTests(unittest.TestCase):
    """A measure following a function call was silently dropped."""

    def test_a_trailing_bare_count_is_not_dropped(self):
        from ruleforge.dialects.spl import parse_stats
        stats = parse_stats("values(user) as u count as c BY host", "stats")
        self.assertEqual({m.alias for m in stats.measures}, {"u", "c"})

    def test_an_unreadable_measure_is_refused(self):
        from ruleforge.dialects.spl import parse_stats, SplParseError
        with self.assertRaises(SplParseError) as caught:
            parse_stats("values(user) as u ??? as x BY host", "stats")
        self.assertEqual(caught.exception.code, "SPL_STATS_MEASURE_UNPARSED")


class PackageValidationTests(unittest.TestCase):
    """`Package` was the one node whose conditions were never validated."""

    def test_a_non_predicate_parent_is_refused(self):
        rule = graph(Read(id="r", selector=SRC),
                     Package(id="c", input="r",
                             parent=(FieldExpr(ref=FieldRef("a")),),
                             count_subject="parent",
                             frequency=5, timeframe=Duration(60),
                             same_fields=(FieldRef("h"),), time_field="t"),
                     Emit(id="o", input="c"))
        with self.assertRaises(Refusal):
            validate_graph(rule)

    def test_a_valid_package_validates(self):
        rule = graph(Read(id="r", selector=SRC),
                     Package(id="c", input="r",
                             parent=(Comparison("=", FieldExpr(
                                 ref=FieldRef("h")), Literal(value="h1")),),
                             count_subject="parent",
                             frequency=5, timeframe=Duration(60),
                             same_fields=(FieldRef("h"),), time_field="t"),
                     Emit(id="o", input="c"))
        validate_graph(rule)


class WazuhAggregateTests(unittest.TestCase):
    """The `aggregate` parameter was accepted and IGNORED.

    A threshold on a computed column was emitted as a `numeric` field test
    against a column that only exists because the rule computed it -- so the rule
    could never fire and contained no detection.
    """

    def test_a_threshold_on_an_aggregate_is_refused(self):
        ir, _ = lower_kql(parse_kql(USER_SENTINEL_RULE))
        with self.assertRaises(Refusal) as caught:
            render_wazuh_xml(ir)
        self.assertIn(caught.exception.code,
                      ("WAZUH_RENDER_AGGREGATE_NOT_A_RULE",
                       "WAZUH_RENDER_CORRELATION_WITHOUT_PARENT"))


class RowResolverTests(unittest.TestCase):
    """`Row.get` was a second, flat-only field resolver.

    It was called for `time_field`, which is a dotted name for every vendor that
    uses one, so it returned ABSENT on a nested row -- the shape Wazuh's own
    decoder produces, and the exact divergence `resolve_field` was fixed for.
    """

    def test_a_dotted_name_resolves_on_a_nested_row(self):
        """`Row.get("a.b")` and `resolve_field` must AGREE.

        They used to disagree: `Row.get` only looked in the top level, so a
        dotted `time_field` came back ABSENT on a nested row while the
        expression layer read it fine. One row, two answers.
        """
        from ruleforge.engine.nodes import resolve_field
        from ruleforge.engine.run import Row
        row = Row({"win": {"system": {"eventID": "4624"}}})
        ref = FieldRef("win", ("system", "eventID"))
        self.assertEqual(resolve_field(row, ref), "4624")
        self.assertEqual(row.get("win.system.eventID"),
                         resolve_field(row, ref))

    def test_a_literal_dotted_key_still_works(self):
        """A field genuinely NAMED `a.b` is a top-level key, not a path."""
        from ruleforge.engine.run import Row
        self.assertEqual(Row({"a.b": 1}).get("a.b"), 1)

    def test_a_top_level_name_still_works(self):
        from ruleforge.engine.run import Row
        self.assertEqual(Row({"a": 1}).get("a"), 1)


class HistoryJobVocabularyTests(unittest.TestCase):
    """Neither debug job could ever be saved."""

    def test_the_two_vocabularies_agree(self):
        from ruleforge import history
        routes = {"author", "understand", "tune",
                  "debug_rule_to_logs", "debug_logs_to_rule"}
        mapped = {"debug_rule_to_logs": "debug",
                  "debug_logs_to_rule": "debug"}
        for route in routes:
            kind = mapped.get(route, route)
            self.assertIn(kind, history.JOBS,
                          f"route {route} maps to a kind History rejects")

    def test_both_debug_routes_can_save(self):
        import tempfile
        from pathlib import Path
        from ruleforge import history, web
        with tempfile.TemporaryDirectory() as tmp:
            original = web.HISTORY_PATH
            web.HISTORY_PATH = Path(tmp) / "h.json"
            try:
                client = web.create_app().test_client()
                for route, body in (
                        ("debug_rule_to_logs",
                         {"dialect": "splunk",
                          "rule": "index=main | stats count BY host",
                          "save": True}),
                        ("debug_logs_to_rule",
                         {"dialect": "splunk", "events": '[{"a":1}]',
                          "save": True})):
                    with self.subTest(route=route):
                        data = client.post(f"/api/{route}",
                                           json=body).get_json()
                        self.assertTrue(data["saved"],
                                        f"{route} could not be saved")
                self.assertEqual(len(history.load(web.HISTORY_PATH)), 2)
            finally:
                web.HISTORY_PATH = original


if __name__ == "__main__":
    unittest.main()
