"""Tests for pipeline execution.

The centre of gravity here is the correlation test: a rule that reads one event
stream, joins a second, and requires the second to fall inside a window opened
by the first. If that works, the tool models enterprise rules. If it does not,
nothing else here matters.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from engine.evaluate import Row
from engine.ir import (
    Aggregate,
    Arith,
    Binding,
    Comparison,
    Correlation,
    Derive,
    Distinct,
    Duration,
    Emit,
    FieldRef,
    Filter,
    Join,
    Limit,
    ListExpr,
    Literal,
    Measure,
    Not,
    Project,
    Read,
    Regex,
    Rule,
    Sort,
    Span,
    Window,
)
from engine.pipeline import Verdict, evaluate
from engine.values import ABSENT, UNDECIDED, Seq


def event(**values):
    return values


def lsass_rule() -> Rule:
    """The shape of the LSASS-then-logon correlation, as a graph."""
    return Rule(
        rule_id="cred_access_then_logon",
        bindings=(
            Binding(
                "lsass",
                (
                    Read(id="r1", table="process_access", time_field="TimeGenerated"),
                    Filter(id="f1", condition=Comparison(
                        "==", FieldRef("EventID"), Literal(10))),
                    Project(id="p1", renames=(
                        (FieldRef("TimeGenerated"), "LSASSTime"),
                        (FieldRef("Computer"), "Computer"),
                        (FieldRef("Account"), "Account"),
                    ), drops=(
                        FieldRef("EventID"), FieldRef("Image"),
                    )),
                ),
            ),
            Binding(
                "logon",
                (
                    Read(id="r2", table="logon", time_field="TimeGenerated"),
                    Filter(id="f2", condition=Comparison(
                        "==", FieldRef("EventID"), Literal(4624))),
                    Project(id="p2", renames=(
                        (FieldRef("TimeGenerated"), "LoginTime"),
                        (FieldRef("Computer"), "Computer"),
                        (FieldRef("Account"), "Account"),
                    ), drops=(FieldRef("EventID"),)),
                ),
            ),
        ),
        pipeline=(
            Read(id="stage", table="(joined)", time_field="TimeGenerated"),
            Join(
                id="correlate",
                left="lsass",
                right="logon",
                how="inner",
                on=(
                    (FieldRef("Computer"), FieldRef("Computer")),
                    (FieldRef("Account"), FieldRef("Account")),
                ),
                predicate=Span(
                    value=FieldRef("LoginTime", scope="right"),
                    low=FieldRef("LSASSTime", scope="left"),
                    high=Arith("+", FieldRef("LSASSTime", scope="left"),
                               Literal(Duration(Decimal(600)))),
                ),
            ),
            Aggregate(id="agg", measures=(Measure("count", "Hits"),),
                      keys=(FieldRef("Computer"), FieldRef("Account"))),
            Emit(id="out", keeps=(FieldRef("Computer"), FieldRef("Account"))),
        ),
    )


class CrossEventCorrelation(unittest.TestCase):
    """The capability that separates this from a filter builder."""

    def _events(self):
        return [
            # LSASS access at t=1000
            event(TimeGenerated=1000, EventID=10, Computer="WS1",
                  Account="svc", Image=r"c:\lsass.exe"),
            # NTLM logon 5 minutes later, same host and account
            event(TimeGenerated=1300, EventID=4624, Computer="WS1",
                  Account="svc", LogonType=3),
        ]

    def test_logon_inside_the_window_matches(self):
        result = evaluate(lsass_rule(), self._events())
        self.assertEqual(result.verdict, Verdict.MATCHED, result.caveats)
        self.assertEqual(len(result.rows), 1)

    def test_logon_outside_the_window_does_not_match(self):
        events = [
            event(TimeGenerated=1000, EventID=10, Computer="WS1", Account="svc"),
            event(TimeGenerated=100000, EventID=4624, Computer="WS1", Account="svc"),
        ]
        result = evaluate(lsass_rule(), events)
        self.assertEqual(result.verdict, Verdict.NO_MATCH)
        self.assertEqual(result.rows, [])

    def test_different_account_does_not_match(self):
        events = [
            event(TimeGenerated=1000, EventID=10, Computer="WS1", Account="svc"),
            event(TimeGenerated=1100, EventID=4624, Computer="WS1",
                  Account="other"),
        ]
        result = evaluate(lsass_rule(), events)
        self.assertEqual(result.verdict, Verdict.NO_MATCH)

    def test_only_the_lsass_event_alone_does_not_match(self):
        # A correlation rule must not fire on half its evidence.
        events = [event(TimeGenerated=1000, EventID=10, Computer="WS1",
                        Account="svc")]
        result = evaluate(lsass_rule(), events)
        self.assertEqual(result.verdict, Verdict.NO_MATCH)

    def test_join_prefixes_keep_both_sides(self):
        # A self-join would otherwise have the right side overwrite the left.
        events = [
            event(TimeGenerated=1000, EventID=10, Computer="WS1", Account="svc"),
            event(TimeGenerated=1100, EventID=4624, Computer="WS1", Account="svc"),
        ]
        result = evaluate(lsass_rule(), events)
        merged = result.trace
        self.assertTrue(any(t.stage == "correlate" and t.rows_out == 1
                            for t in merged), merged)

    def test_projection_drops_the_renamed_source(self):
        # add-then-drop vs drop-then-add are different rules.
        rule = Rule(
            rule_id="rename",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Project(id="p", renames=((FieldRef("Image"), "Proc"),),
                        drops=(FieldRef("Image"),)),
                Emit(id="o", keeps=(FieldRef("Proc"),)),
            ),
        )
        result = evaluate(rule, [event(ts=1, Image="lsass.exe", Other="x")])
        self.assertEqual(result.verdict, Verdict.MATCHED)
        self.assertIn("Proc", result.rows[0].values)
        self.assertNotIn("Image", result.rows[0].values)


class UndecidedIsNotFalse(unittest.TestCase):
    """A rule that cannot decide must not report a clean no-match."""

    def _rule(self, condition):
        return Rule(
            rule_id="r",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Filter(id="f", condition=condition),
                Emit(id="o"),
            ),
        )

    def test_absent_field_yields_not_evaluated(self):
        rule = self._rule(Comparison("==", FieldRef("EventID"), Literal(4624)))
        result = evaluate(rule, [event(ts=1, Other="x")])
        self.assertEqual(result.verdict, Verdict.NOT_EVALUATED)
        self.assertIsNone(result.refusal)

    def test_absent_field_still_reports_the_reason(self):
        rule = self._rule(Comparison("==", FieldRef("EventID"), Literal(4624)))
        result = evaluate(rule, [event(ts=1, Other="x")])
        codes = {c.code for c in result.caveats}
        self.assertIn("COMPARISON_UNDECIDABLE", codes)

    def test_present_field_yields_no_match(self):
        rule = self._rule(Comparison("==", FieldRef("EventID"), Literal(4624)))
        result = evaluate(rule, [event(ts=1, EventID=1)])
        self.assertEqual(result.verdict, Verdict.NO_MATCH)

    def test_a_caveat_names_the_rule_field(self):
        rule = self._rule(
            Comparison("==", FieldRef("win.eventdata.Image"), Literal("lsass"))
        )
        result = evaluate(rule, [event(ts=1)])
        text = " ".join(c.message for c in result.caveats)
        self.assertIn("win.eventdata.Image", text)

    def test_not_of_an_undecidable_is_still_undecidable(self):
        # NOT (undecided) must not become a match, or a rule matches every event
        # that is missing the field.
        rule = self._rule(Not(Comparison("==", FieldRef("EventID"), Literal(4624))))
        result = evaluate(rule, [event(ts=1, Other="x")])
        self.assertNotEqual(result.verdict, Verdict.MATCHED)


class CorrelationThreshold(unittest.TestCase):
    """`frequency` / `timeframe`, as Wazuh expresses it."""

    def _rule(self, frequency, timeframe_seconds):
        return Rule(
            rule_id="threshold",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Correlation(id="c", parent="r", frequency=frequency,
                            timeframe=Duration(Decimal(timeframe_seconds)),
                            group_by=(FieldRef("srcip"),)),
                Emit(id="o"),
            ),
        )

    def test_fires_when_the_count_is_reached_inside_the_window(self):
        events = [event(ts=i * 10, srcip="1.2.3.4") for i in range(3)]
        result = evaluate(self._rule(3, 300), events)
        self.assertEqual(result.verdict, Verdict.MATCHED)

    def test_does_not_fire_below_the_threshold(self):
        events = [event(ts=i * 10, srcip="1.2.3.4") for i in range(2)]
        result = evaluate(self._rule(3, 300), events)
        self.assertEqual(result.verdict, Verdict.NO_MATCH)

    def test_the_window_trails_the_event(self):
        # A forward-looking window never fires on a spray of exactly N, which is
        # how a threshold rule gets deployed and never triggers.
        events = [event(ts=i * 10, srcip="1.2.3.4") for i in range(3)]
        result = evaluate(self._rule(2, 25), events)
        self.assertEqual(result.verdict, Verdict.MATCHED)

    def test_spray_far_apart_does_not_fire(self):
        events = [event(ts=i * 10_000, srcip="1.2.3.4") for i in range(5)]
        result = evaluate(self._rule(3, 300), events)
        self.assertEqual(result.verdict, Verdict.NO_MATCH)

    def test_frequency_below_one_is_refused_at_construction(self):
        from engine.values import Refusal
        with self.assertRaises(Refusal) as caught:
            self._rule(0, 300)
        self.assertEqual(caught.exception.code, "CORRELATION_FREQUENCY_INVALID")

    def test_no_group_by_is_refused(self):
        from engine.values import Refusal
        with self.assertRaises(Refusal) as caught:
            Rule(
                rule_id="c",
                pipeline=(
                    Read(id="r", table="t", time_field="ts"),
                    Correlation(id="c", parent="r", frequency=2,
                                timeframe=Duration(Decimal(60))),
                    Emit(id="o"),
                ),
            )
        self.assertEqual(caught.exception.code, "CORRELATION_NO_GROUP")


class TheCountIsPerGroup(unittest.TestCase):
    """`group_by` was accepted and then ignored.

    Every test in `CorrelationThreshold` uses a single `srcip`, which is why
    this survived: with one group, grouped and ungrouped counting agree.

    `ir.Correlation` REFUSES an empty `group_by` because "the count is
    'anywhere in the log', which is almost never the intent" -- and the
    evaluator then counted anywhere in the log regardless. A brute-force rule
    written as "eight failures from the same source IP" fired on eight
    failures from eight different hosts, which is ordinary background noise on
    any estate of size. The model insisted on the group and the engine dropped
    it, so the refusal guarded nothing.
    """

    def _rule(self, frequency=3, timeframe_seconds=300):
        return Rule(
            rule_id="threshold",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Correlation(id="c", parent="r", frequency=frequency,
                            timeframe=Duration(Decimal(timeframe_seconds)),
                            group_by=(FieldRef("srcip"),)),
                Emit(id="o"),
            ),
        )

    def test_events_from_different_sources_do_not_add_up(self):
        # Three events, three sources. Ungrouped this is three and fires.
        events = [event(ts=i * 10, srcip=f"10.0.0.{i}") for i in range(3)]
        self.assertEqual(
            evaluate(self._rule(), events).verdict, Verdict.NO_MATCH
        )

    def test_one_source_crossing_the_threshold_fires_among_noise(self):
        events = [event(ts=i * 10, srcip="1.2.3.4") for i in range(3)]
        events += [event(ts=i * 10, srcip=f"10.0.0.{i}") for i in range(5)]
        self.assertEqual(
            evaluate(self._rule(), events).verdict, Verdict.MATCHED
        )

    def test_the_window_is_measured_inside_the_group(self):
        # Two groups interleaved in time. A global window sees six events
        # close together; per group each has three spread far apart.
        events = []
        for index in range(3):
            events.append(event(ts=index * 10_000, srcip="A"))
            events.append(event(ts=index * 10_000 + 1, srcip="B"))
        self.assertEqual(
            evaluate(self._rule(), events).verdict, Verdict.NO_MATCH
        )

    def test_only_the_group_that_crossed_is_reported(self):
        events = [event(ts=i * 10, srcip="1.2.3.4") for i in range(3)]
        events += [event(ts=i * 10, srcip="9.9.9.9") for i in range(2)]
        result = evaluate(self._rule(), events)
        self.assertTrue(
            all(row.get("srcip") == "1.2.3.4" for row in result.rows),
            "the group below the threshold must not appear in the output",
        )

    def test_a_row_missing_the_group_key_is_not_counted_as_its_own_group(self):
        # Lumping every absence together would count unrelated events as one
        # actor, which is the failure the grouping exists to prevent.
        #
        # The verdict is `not_evaluated` rather than `no_match`: rows without
        # the group key genuinely cannot be counted, so "I cannot tell you" is
        # the honest answer. What matters is that it does not FIRE.
        events = [event(ts=i * 10) for i in range(5)]
        result = evaluate(self._rule(), events)
        self.assertNotEqual(result.verdict, Verdict.MATCHED)
        self.assertIn(
            "CORRELATION_GROUP_KEY_ABSENT", [c.code for c in result.caveats]
        )

    def test_a_row_with_no_timestamp_is_reported_rather_than_dropped(self):
        # Each untimed row lowers the count towards a false no_match.
        events = [event(ts=i * 10, srcip="1.2.3.4") for i in range(2)]
        events.append(Row({"srcip": "1.2.3.4"}, None, ""))
        result = evaluate(self._rule(), events)
        self.assertIn(
            "CORRELATION_ROW_UNTIMED", [c.code for c in result.caveats]
        )

    def test_the_reported_row_is_the_one_that_closed_the_window(self):
        # `times` was sorted and then used to index the UNSORTED rows, so the
        # row reported as closing the window was whichever sat at that
        # position -- an arbitrary event in any out-of-order sample.
        events = [
            event(ts=300, srcip="1.2.3.4", tag="third"),
            event(ts=100, srcip="1.2.3.4", tag="first"),
            event(ts=200, srcip="1.2.3.4", tag="second"),
        ]
        result = evaluate(self._rule(3, 1000), events)
        self.assertEqual(result.verdict, Verdict.MATCHED)
        self.assertEqual(
            [row.get("tag") for row in result.rows], ["third"],
            "the window closes on the latest event in the group",
        )

    def test_two_group_keys_are_both_required_to_match(self):
        rule = Rule(
            rule_id="threshold",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Correlation(id="c", parent="r", frequency=3,
                            timeframe=Duration(Decimal(300)),
                            group_by=(FieldRef("srcip"), FieldRef("user"))),
                Emit(id="o"),
            ),
        )
        same = [
            event(ts=i * 10, srcip="1.2.3.4", user="bob") for i in range(3)
        ]
        self.assertEqual(evaluate(rule, same).verdict, Verdict.MATCHED)
        split = [
            event(ts=i * 10, srcip="1.2.3.4", user=f"u{i}") for i in range(3)
        ]
        self.assertEqual(evaluate(rule, split).verdict, Verdict.NO_MATCH)


class Aggregation(unittest.TestCase):
    def _grouped(self, measure):
        return Rule(
            rule_id="agg",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Aggregate(id="a", measures=(measure,),
                          keys=(FieldRef("host"),),
                          window=Window("tumbling", Duration(Decimal(300)))),
                Emit(id="o"),
            ),
        )

    def test_count_per_group(self):
        rule = self._grouped(Measure("count", "n"))
        result = evaluate(rule, [
            event(ts=1, host="a"), event(ts=2, host="a"), event(ts=3, host="b"),
        ])
        self.assertEqual(result.verdict, Verdict.MATCHED)
        counts = {r.get("host"): r.get("n") for r in result.rows}
        self.assertEqual(counts["a"], Decimal(2))
        self.assertEqual(counts["b"], Decimal(1))

    def test_values_keeps_a_collection(self):
        # Collapsing this to a scalar loses the evidence the rule is on.
        rule = self._grouped(
            Measure("values", "procs", FieldRef("proc"), distinct=True)
        )
        result = evaluate(rule, [
            event(ts=1, host="a", proc="cmd.exe"),
            event(ts=2, host="a", proc="cmd.exe"),
            event(ts=3, host="a", proc="rundll32.exe"),
        ])
        row = result.rows[0]
        self.assertIsInstance(row.get("procs"), Seq)
        self.assertEqual(len(row.get("procs")), 2)

    def test_absent_key_and_null_key_are_different_groups(self):
        rule = self._grouped(Measure("count", "n"))
        result = evaluate(rule, [
            event(ts=1, host="a"),
            event(ts=2, other="x"),
            event(ts=3, host=None),
        ])
        self.assertEqual(len(result.rows), 3, "absent and null merged into one bucket")

    def test_min_and_max(self):
        rule = self._grouped(Measure("max", "latest", FieldRef("ts")))
        result = evaluate(rule, [event(ts=1, host="a"), event(ts=9, host="a")])
        self.assertEqual(result.rows[0].get("latest"), Decimal(9))

    def test_aggregate_with_no_measure_is_refused(self):
        from engine.values import Refusal
        with self.assertRaises(Refusal) as caught:
            Rule(
                rule_id="a",
                pipeline=(
                    Read(id="r", table="t", time_field="ts"),
                    Aggregate(id="a", keys=(FieldRef("host"),)),
                    Emit(id="o"),
                ),
            )
        self.assertEqual(caught.exception.code, "AGGREGATE_NO_MEASURE")

    def test_sliding_window_without_a_step_is_refused(self):
        from engine.values import Refusal
        with self.assertRaises(Refusal) as caught:
            Window("sliding", Duration(Decimal(300)))
        self.assertEqual(caught.exception.code, "WINDOW_REQUIRES_STEP")

    def test_step_on_a_tumbling_window_is_refused(self):
        from engine.values import Refusal
        with self.assertRaises(Refusal) as caught:
            Window("tumbling", Duration(Decimal(300)), Duration(Decimal(60)))
        self.assertEqual(caught.exception.code, "WINDOW_STEP_NOT_APPLICABLE")


class PostAggregateFilter(unittest.TestCase):
    """`HAVING` / `| where count >= 2` -- filtering AFTER a summarize."""

    def test_threshold_after_aggregation(self):
        rule = Rule(
            rule_id="having",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Aggregate(id="a", measures=(Measure("count", "n"),),
                          keys=(FieldRef("user"),)),
                Filter(id="having", condition=Comparison(
                    ">=", FieldRef("n"), Literal(2))),
                Emit(id="o"),
            ),
        )
        result = evaluate(rule, [
            event(ts=1, user="a"), event(ts=2, user="a"), event(ts=3, user="b"),
        ])
        self.assertEqual(len(result.rows), 1)
        self.assertEqual(result.rows[0].get("user"), "a")


class DeriveAndDistinct(unittest.TestCase):
    def test_derive_computes_a_column(self):
        rule = Rule(
            rule_id="d",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Derive(id="d", assignments=(("risk", Arith(
                    "*", FieldRef("score"), Literal(Decimal(2)))),)),
                Emit(id="o"),
            ),
        )
        result = evaluate(rule, [event(ts=1, score=45)])
        self.assertEqual(result.rows[0].get("risk"), Decimal(90))

    def test_derive_on_an_absent_field_is_absent_not_null(self):
        rule = Rule(
            rule_id="d",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Derive(id="d", assignments=(("risk", Arith(
                    "*", FieldRef("score"), Literal(Decimal(2)))),)),
                Emit(id="o"),
            ),
        )
        result = evaluate(rule, [event(ts=1)])
        self.assertIs(result.rows[0].get("risk"), ABSENT)

    def test_distinct_collapses_duplicates(self):
        rule = Rule(
            rule_id="x",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Distinct(id="d", keys=(FieldRef("user"),)),
                Emit(id="o"),
            ),
        )
        result = evaluate(rule, [
            event(ts=1, user="a"), event(ts=2, user="a"), event(ts=3, user="b"),
        ])
        self.assertEqual(len(result.rows), 2)


class SortAndLimit(unittest.TestCase):
    def test_sort_descending_then_limit(self):
        rule = Rule(
            rule_id="s",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Aggregate(id="a", measures=(Measure("count", "n"),),
                          keys=(FieldRef("user"),)),
                Sort(id="s", keys=((FieldRef("n"), True),)),
                Limit(id="l", count=1),
                Emit(id="o"),
            ),
        )
        result = evaluate(rule, [
            event(ts=1, user="a"), event(ts=2, user="a"), event(ts=3, user="b"),
        ])
        self.assertEqual(len(result.rows), 1)
        self.assertEqual(result.rows[0].get("n"), Decimal(2))

    def test_mixed_type_sort_does_not_crash(self):
        # Python cannot order a str against a Decimal. It must produce SOME
        # total order rather than losing the whole result to a TypeError.
        rule = Rule(
            rule_id="s",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Sort(id="s", keys=((FieldRef("v"), False),)),
                Emit(id="o"),
            ),
        )
        result = evaluate(rule, [event(ts=1, v=5), event(ts=2, v="abc")])
        self.assertEqual(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 2)


class StructuralRefusals(unittest.TestCase):
    def test_a_dangling_join_reference_is_refused(self):
        from engine.values import Refusal
        with self.assertRaises(Refusal) as caught:
            Rule(
                rule_id="r",
                pipeline=(
                    Read(id="a", table="t"),
                    Join(id="j", left="a", right="nowhere", how="inner",
                         on=((FieldRef("k"), FieldRef("k")),)),
                    Emit(id="o"),
                ),
            )
        self.assertEqual(caught.exception.code, "BINDING_UNKNOWN")

    def test_a_join_with_no_condition_is_refused(self):
        from engine.values import Refusal
        with self.assertRaises(Refusal) as caught:
            Rule(
                rule_id="r",
                pipeline=(
                    Read(id="a", table="t"),
                    Join(id="j", left="a", right="b", how="inner"),
                    Emit(id="o"),
                ),
            )
        self.assertEqual(caught.exception.code, "JOIN_HAS_NO_CONDITION")

    def test_colliding_join_prefixes_are_refused(self):
        from engine.values import Refusal
        with self.assertRaises(Refusal) as caught:
            Rule(
                rule_id="r",
                pipeline=(
                    Read(id="a", table="t"),
                    Read(id="b", table="t"),
                    Join(id="j", left="a", right="b", how="inner",
                         on=((FieldRef("k"), FieldRef("k")),),
                         left_prefix="X.", right_prefix="X."),
                    Emit(id="o"),
                ),
            )
        self.assertEqual(caught.exception.code, "JOIN_PREFIX_COLLISION")

    def test_a_rule_with_no_emit_is_refused(self):
        from engine.values import Refusal
        with self.assertRaises(Refusal) as caught:
            Rule(rule_id="r", pipeline=(Read(id="a", table="t"),))
        self.assertEqual(caught.exception.code, "RULE_HAS_NO_EMIT")

    def test_a_dangling_stage_reference_is_refused(self):
        # `evaluate` never raises: it returns NOT_EVALUATED with the refusal
        # attached. An analyst pasting a rule must never see a stack trace, so
        # the refusal travels in the result rather than as an exception.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Filter(id="f", condition=Comparison(
                    "==", FieldRef("a"), Literal(1))),
                Emit(id="o"),
            ),
        )
        result = evaluate(rule, [event(ts=1)])
        self.assertEqual(result.verdict, Verdict.NOT_EVALUATED)
        self.assertIsNotNone(result.refusal)
        self.assertEqual(result.refusal.code, "STAGE_HAS_NO_INPUT")


class Tracing(unittest.TestCase):
    def test_every_stage_is_traced(self):
        result = evaluate(lsass_rule(), [
            event(TimeGenerated=1000, EventID=10, Computer="WS1", Account="svc"),
            event(TimeGenerated=1100, EventID=4624, Computer="WS1", Account="svc"),
        ])
        stages = {t.stage for t in result.trace}
        self.assertIn("correlate", stages)
        self.assertIn("agg", stages)
        self.assertIn("out", stages)

    def test_undecided_rows_are_counted_at_the_filter(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="r", table="t", time_field="ts"),
                Filter(id="f", condition=Comparison(
                    "==", FieldRef("EventID"), Literal(4624))),
                Emit(id="o"),
            ),
        )
        result = evaluate(rule, [event(ts=1), event(ts=2), event(ts=3, EventID=4624)])
        filter_trace = next(t for t in result.trace if t.stage == "f")
        self.assertEqual(filter_trace.undecided, 2)
        self.assertEqual(filter_trace.rows_out, 1)


class DistinctCountIsDistinct(unittest.TestCase):
    """`dc` has to mean what every vendor means by it.

    It was grouped with `count` and `count_if` in the measure dispatch, so it
    returned the number of ROWS rather than the number of distinct values. The
    direction of the error is the dangerous one: `stats dc(user) by host` with a
    threshold of 5 fired on one user retrying five times, which is a password
    spray rule that alerts on a forgotten password. Nothing warned, because an
    aggregate that returns a number looks like it worked.

    No test covered `dc` at all, which is how it survived. Hence this class.
    """

    def counted(self, function: str, rows: list[dict]):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="T"),
                Aggregate(
                    id="agg",
                    measures=(Measure(function, "n", FieldRef("user")),),
                    keys=(FieldRef("host"),),
                ),
                Emit(id="out"),
            ),
        )
        result = evaluate(rule, rows)
        self.assertTrue(result.rows, f"{function} produced no rows")
        return result.rows[0].get("n")

    def test_dc_counts_distinct_values_not_rows(self):
        rows = [event(host="H1", user="bob") for _ in range(5)]
        self.assertEqual(self.counted("dc", rows), Decimal(1))

    def test_count_still_counts_rows(self):
        # The fix must not drag `count` along with it.
        rows = [event(host="H1", user="bob") for _ in range(5)]
        self.assertEqual(self.counted("count", rows), Decimal(5))

    def test_every_spelling_of_distinct_count_agrees(self):
        rows = [
            event(host="H1", user=name)
            for name in ("bob", "amy", "cat", "bob", "amy")
        ]
        for function in ("dc", "dcount", "distinct_count"):
            with self.subTest(function=function):
                self.assertEqual(self.counted(function, rows), Decimal(3))

    def test_a_null_contributes_no_distinct_value(self):
        # Null is not a value: `dc()` in Splunk and `dcount()` in KQL both
        # ignore it, and counting it would inflate every threshold by one on any
        # field that is sometimes empty.
        rows = [
            event(host="H1", user="bob"),
            event(host="H1", user=None),
            event(host="H1", user=None),
        ]
        self.assertEqual(self.counted("dc", rows), Decimal(1))

    def test_an_absent_field_contributes_no_distinct_value(self):
        rows = [event(host="H1", user="bob"), event(host="H1")]
        self.assertEqual(self.counted("dc", rows), Decimal(1))

    def test_a_distinct_count_threshold_does_not_fire_on_one_repeating_value(self):
        # The end-to-end shape of the defect: a port-scan rule reading
        # `dc(dest_port) >= 5` must not fire on five hits to one port.
        rule = Rule(
            rule_id="port_scan",
            pipeline=(
                Read(id="src", table="firewall"),
                Aggregate(
                    id="agg",
                    measures=(Measure("dc", "ports", FieldRef("dest_port")),),
                    keys=(FieldRef("src_ip"),),
                ),
                Filter(id="thresh", condition=Comparison(
                    ">=", FieldRef("ports"), Literal(Decimal(5)))),
                Emit(id="out"),
            ),
        )
        one_port = [event(src_ip="10.0.0.1", dest_port=445) for _ in range(9)]
        self.assertNotEqual(evaluate(rule, one_port).verdict, Verdict.MATCHED)

        many = [
            event(src_ip="10.0.0.1", dest_port=port)
            for port in (22, 80, 445, 3389, 8080)
        ]
        self.assertEqual(evaluate(rule, many).verdict, Verdict.MATCHED)

    def test_an_aggregate_this_engine_cannot_compute_is_reported(self):
        # The dispatch ends in a caveat rather than a zero, because a stage that
        # silently produced 0 would read as "nothing happened".
        rows = [event(host="H1", user="bob")]
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="T"),
                Aggregate(
                    id="agg",
                    measures=(Measure("mode", "n", FieldRef("user")),),
                    keys=(FieldRef("host"),),
                ),
                Emit(id="out"),
            ),
        )
        result = evaluate(rule, rows)
        self.assertIn("MEASURE_UNKNOWN", [c.code for c in result.caveats])


class SortLimitIsApplied(unittest.TestCase):
    """`Sort.limit` was declared on the node and never applied.

    A stage meaning "the top 2 by severity" returned every row, so an alert
    built on it fired on rows the author excluded -- and the stage trace
    reported the full count as though that were correct.
    """

    def rule(self, limit=None, descending=True):
        return Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="t", time_field="ts"),
                Sort(id="q", keys=((FieldRef("n"), descending),),
                     limit=limit),
                Emit(id="out"),
            ),
        )

    ROWS = [event(ts=i, n=i) for i in range(5)]

    def test_the_limit_is_honoured(self):
        result = evaluate(self.rule(limit=2), self.ROWS)
        self.assertEqual(len(result.rows), 2)

    def test_it_keeps_the_rows_the_ordering_chose(self):
        # The point of the field: the first N AFTER the sort, not an arbitrary
        # N. Descending by `n` over 0..4 must keep 4 and 3.
        result = evaluate(self.rule(limit=2), self.ROWS)
        self.assertEqual([r.get("n") for r in result.rows],
                         [Decimal(4), Decimal(3)])

    def test_ascending_keeps_the_other_end(self):
        result = evaluate(self.rule(limit=2, descending=False), self.ROWS)
        self.assertEqual([r.get("n") for r in result.rows],
                         [Decimal(0), Decimal(1)])

    def test_no_limit_keeps_everything(self):
        self.assertEqual(len(evaluate(self.rule(), self.ROWS).rows), 5)

    def test_a_limit_larger_than_the_input_is_not_an_error(self):
        self.assertEqual(len(evaluate(self.rule(limit=99), self.ROWS).rows), 5)

    def test_the_trace_reports_the_rows_it_actually_emitted(self):
        # The trace is how an analyst finds the stage that dropped their rows,
        # so it must not report the pre-limit count.
        result = evaluate(self.rule(limit=2), self.ROWS)
        entry = next(t for t in result.trace if t.stage == "q")
        self.assertEqual(entry.rows_out, 2)


class TheFourAggregatesThatUsedToReturnNothing(unittest.TestCase):
    """`percentile`, `stdev`, `arg_max` and `arg_min`.

    All four are reachable from the KQL spec and all four fell through to
    MEASURE_UNKNOWN. That reported a caveat, so it was not silent -- but
    `_verdict` returns MATCHED as soon as a row survives, so a rule reading
    `summarize p95 = percentile(Duration, 95)` came back `matched` with the
    column holding nothing at all.
    """

    ROWS = [event(ts=i, h="A", n=Decimal(v), who=f"u{i}")
            for i, v in enumerate([10, 20, 30, 40])]

    def measure(self, function, param=None, field="n", rows=None):
        measure = Measure(function=function, name="v",
                          field=FieldRef(field), param=param)
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="t", time_field="ts"),
                Aggregate(id="a", measures=(measure,), keys=(FieldRef("h"),)),
                Emit(id="out"),
            ),
        )
        return evaluate(rule, self.ROWS if rows is None else rows)

    def test_the_median_interpolates(self):
        # Nearest-rank over four samples would return 20 or 30; the median of
        # 10,20,30,40 is 25. A threshold set just above a nearest-rank value
        # never fires, because the statistic jumps a whole observation at a
        # time.
        self.assertEqual(self.measure("percentile", Decimal(50))
                         .rows[0].get("v"), Decimal("25.0"))

    def test_a_high_percentile_lands_between_neighbours(self):
        self.assertEqual(self.measure("percentile", Decimal(95))
                         .rows[0].get("v"), Decimal("38.50"))

    def test_the_extremes_are_the_extremes(self):
        self.assertEqual(self.measure("percentile", Decimal(0))
                         .rows[0].get("v"), Decimal(10))
        self.assertEqual(self.measure("percentile", Decimal(100))
                         .rows[0].get("v"), Decimal(40))

    def test_a_percentile_with_no_rank_is_reported_not_guessed(self):
        # Defaulting to the median would report a number the rule never asked
        # for.
        result = self.measure("percentile")
        self.assertIs(result.rows[0].get("v"), ABSENT)
        self.assertIn("MEASURE_PERCENTILE_RANK",
                      [c.code for c in result.caveats])

    def test_a_rank_outside_zero_to_a_hundred_is_reported(self):
        result = self.measure("percentile", Decimal(150))
        self.assertIn("MEASURE_PERCENTILE_RANK",
                      [c.code for c in result.caveats])

    def test_the_deviation_is_the_sample_form(self):
        # KQL's `stdev()` divides by n-1. The population form is smaller, so a
        # threshold tuned in Sentinel would fire later here than there.
        # sample sd of 10,20,30,40 = sqrt(500/3) = 12.9099...
        value = self.measure("stdev").rows[0].get("v")
        self.assertAlmostEqual(float(value), 12.909944, places=5)

    def test_one_value_has_no_deviation_rather_than_zero(self):
        # Zero reads as "perfectly consistent", which is a claim about data
        # that does not exist.
        result = self.measure("stdev", rows=self.ROWS[:1])
        self.assertIs(result.rows[0].get("v"), ABSENT)
        self.assertIn("MEASURE_STDEV_TOO_FEW",
                      [c.code for c in result.caveats])

    def test_arg_max_reports_the_row_that_won(self):
        self.assertEqual(
            self.measure("arg_max", "who").rows[0].get("v"), "u3"
        )

    def test_arg_min_reports_the_other_end(self):
        self.assertEqual(
            self.measure("arg_min", "who").rows[0].get("v"), "u0"
        )

    def test_arg_max_with_no_subject_is_reported(self):
        result = self.measure("arg_max")
        self.assertIs(result.rows[0].get("v"), ABSENT)
        self.assertIn("MEASURE_ARG_NO_SUBJECT",
                      [c.code for c in result.caveats])

    def test_a_tie_keeps_the_first_row_in_input_order(self):
        # Otherwise two runs over the same sample disagree about which row won.
        tied = [event(ts=0, h="A", n=Decimal(5), who="first"),
                event(ts=1, h="A", n=Decimal(5), who="second")]
        self.assertEqual(
            self.measure("arg_max", "who", rows=tied).rows[0].get("v"),
            "first",
        )

    def test_a_genuinely_unknown_aggregate_still_falls_through(self):
        # The fallthrough is the invariant: implementing four of them must not
        # remove the refusal for the fifth.
        result = self.measure("frobnicate")
        self.assertIn("MEASURE_UNKNOWN", [c.code for c in result.caveats])

    def test_every_aggregate_any_dialect_can_produce_is_computed(self):
        # The drift guard. A dialect spec that maps onto an aggregate this
        # engine does not compute produces a rule that imports, runs, reports
        # `matched`, and hands back an empty column.
        from engine import dialects

        aggregates = {
            "count", "count_if", "countif", "dcount", "distinct_count", "dc",
            "min", "max", "avg", "average", "sum", "total", "earliest",
            "latest", "values", "make_set", "make_list", "array_agg",
            "collect_set", "percentile", "percentiles", "percentile_cont",
            "stdev", "stdevp", "stddev", "arg_max", "arg_min",
        }
        wanted = set()
        for entry in dialects.ready_dialects():
            spec = getattr(dialects.load(entry.key), "SPEC", None)
            if spec is None:
                continue
            wanted |= {v for v in spec.functions.values() if v in aggregates}

        uncomputed = []
        for name in sorted(wanted):
            param = Decimal(50) if "percentile" in name else "who"
            result = self.measure(name, param)
            if "MEASURE_UNKNOWN" in [c.code for c in result.caveats]:
                uncomputed.append(name)
        self.assertEqual(
            uncomputed, [],
            f"a dialect maps onto these aggregates and the engine does not "
            f"compute them: {uncomputed}",
        )


class AnIndexFilterDoesNotBlockANonMatch(unittest.TestCase):
    """The verdict policy, and the one case that keeps the strict form.

    An index-time filter can only REMOVE rows from what the engine saw, so for
    a monotone rule it cannot create a match and a local `no_match` stays
    true. Treating it as blocking meant no rule carrying a selector could ever
    report a negative -- and every Sigma rule has a `logsource`.
    """

    def monotone(self):
        return Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="t", selector="index=main",
                     time_field="ts"),
                Filter(id="f", condition=Comparison(
                    "==", FieldRef("n"), Literal(Decimal(99)))),
                Emit(id="out"),
            ),
        )

    def test_a_genuine_non_match_is_confident(self):
        result = evaluate(self.monotone(), [event(ts=1, n=Decimal(1))])
        self.assertEqual(result.verdict, Verdict.NO_MATCH)

    def test_the_scope_limit_is_still_reported(self):
        # What changed is the verdict, not the disclosure.
        result = evaluate(self.monotone(), [event(ts=1, n=Decimal(1))])
        self.assertIn("INDEX_TIME_FILTER", [c.code for c in result.caveats])

    def test_a_real_uncertainty_still_blocks(self):
        # Relaxing one caveat must not relax the others.
        result = evaluate(self.monotone(), [event(ts=1)])
        self.assertEqual(result.verdict, Verdict.NOT_EVALUATED)

    def test_an_anti_join_keeps_the_strict_verdict(self):
        # The exception. An anti-join asks for rows with NO counterpart, so
        # taking rows away from the right-hand side makes left rows
        # unmatched: a rule that found nothing locally can fire once the index
        # has narrowed the input.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="t", selector="index=main",
                     time_field="ts"),
                Join(id="j", left="src", right="other", how="anti",
                     on=((FieldRef("h"), FieldRef("h", scope="right")),)),
                Emit(id="out"),
            ),
            bindings=(Binding(name="other", pipeline=(
                Read(id="o", table="u", time_field="ts"),
                Emit(id="oe"),
            )),),
        )
        result = evaluate(rule, [event(ts=1, h="A")])
        self.assertNotEqual(result.verdict, Verdict.NO_MATCH)

    def test_an_ordinary_join_does_not_keep_the_strict_verdict(self):
        # Only `anti` is non-monotone. An inner join is monotone, so it must
        # not be caught by the exception.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="t", selector="index=main",
                     time_field="ts"),
                Join(id="j", left="src", right="other", how="inner",
                     on=((FieldRef("h"), FieldRef("h", scope="right")),)),
                Emit(id="out"),
            ),
            bindings=(Binding(name="other", pipeline=(
                Read(id="o", table="u", time_field="ts"),
                Filter(id="bf", condition=Comparison(
                    "==", FieldRef("h"), Literal("nothing"))),
                Emit(id="oe"),
            )),),
        )
        result = evaluate(rule, [event(ts=1, h="A")])
        self.assertEqual(result.verdict, Verdict.NO_MATCH)


class ADeclaredOnlyStageIsNotRun(unittest.TestCase):
    """`pipeline.py` never looked at `node.capability`.

    The word appeared only as a string in `ADVISORY_CODES`. So a stage a
    dialect had modelled faithfully and marked NOT locally executable was
    executed anyway: `| tstats count by src_ip` reads an index-time
    acceleration summary that no sample of events carries, and the engine
    computed the count FROM the sample instead. The number was fabricated,
    the stage trace looked ordinary, and the verdict came back `matched`.

    The honest answer is `not_evaluated`: this rule cannot be decided here.
    """

    def declared_only_rule(self):
        from engine.ir import Capability

        return Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="t", time_field="ts"),
                Aggregate(
                    id="summary",
                    measures=(Measure(function="count", name="Hits"),),
                    keys=(FieldRef("h"),),
                    capability=Capability.DECLARED_ONLY,
                    note="reads an acceleration summary, not events",
                ),
                Emit(id="out"),
            ),
        )

    ROWS = [event(ts=i, h="A") for i in range(5)]

    def test_it_does_not_report_a_confident_verdict(self):
        result = evaluate(self.declared_only_rule(), self.ROWS)
        self.assertEqual(result.verdict, Verdict.NOT_EVALUATED)

    def test_it_says_which_stage_and_why(self):
        result = evaluate(self.declared_only_rule(), self.ROWS)
        note = next(
            c for c in result.caveats if c.code == "STAGE_DECLARED_ONLY"
        )
        self.assertIn("summary", note.message)
        self.assertIn("acceleration summary", note.message)

    def test_it_produces_no_fabricated_rows(self):
        # The specific harm: a count computed from the wrong source.
        result = evaluate(self.declared_only_rule(), self.ROWS)
        self.assertEqual(result.rows, [])

    def test_the_caveat_blocks_rather_than_advises(self):
        from engine.pipeline import ADVISORY_CODES, MONOTONE_ADVISORY_CODES

        self.assertNotIn("STAGE_DECLARED_ONLY", ADVISORY_CODES)
        self.assertNotIn("STAGE_DECLARED_ONLY", MONOTONE_ADVISORY_CODES)

    def test_the_trace_records_that_it_was_skipped(self):
        # The trace is how an analyst finds where rows went.
        result = evaluate(self.declared_only_rule(), self.ROWS)
        entry = next(t for t in result.trace if t.stage == "summary")
        self.assertEqual(entry.rows_out, 0)

    def test_an_ordinary_stage_is_unaffected(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="t", time_field="ts"),
                Aggregate(
                    id="summary",
                    measures=(Measure(function="count", name="Hits"),),
                    keys=(FieldRef("h"),),
                ),
                Emit(id="out"),
            ),
        )
        result = evaluate(rule, self.ROWS)
        self.assertEqual(result.verdict, Verdict.MATCHED)
        self.assertEqual(result.rows[0].get("Hits"), Decimal(5))

    def test_the_real_splunk_shape_is_covered(self):
        # The case that exposed it, end to end.
        from engine import dialects

        rule, _ = dialects.lower("splunk", "index=main | tstats count by src")
        result = evaluate(rule, [event(_time=1, src="1.2.3.4")])
        self.assertEqual(result.verdict, Verdict.NOT_EVALUATED)
        self.assertIn(
            "STAGE_DECLARED_ONLY", [c.code for c in result.caveats]
        )


class AJoinUsesBothKeys(unittest.TestCase):
    """`node.on` holds (LEFT key, RIGHT key) pairs and only the left was read.

    Both loops destructured it as `for ref, _ in node.on`, so the right-hand
    rows were hashed under the LEFT field's name. A join written
    `on src_ip == ip` indexed the right side by `src_ip`, which it does not
    have, so every probe missed and the join returned nothing -- a silent
    no_match on a rule that should fire.

    It worked whenever both sides spelled the key the same way, which is the
    common case in a test fixture and not in a real rule.
    """

    def rule(self, left_key: str, right_key: str, how: str = "inner"):
        # BOTH sides are filtered. Without a filter on the left the `Read`
        # takes every seed row, including the ones meant for the right side,
        # and the row count stops being about the join at all.
        return Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="a", time_field="ts"),
                Filter(id="lf", condition=Comparison(
                    "==", FieldRef("side"), Literal("L"))),
                Join(id="j", left="lf", right="R", how=how,
                     on=((FieldRef(left_key),
                          FieldRef(right_key, scope="right")),)),
                Emit(id="o"),
            ),
            bindings=(Binding(name="R", pipeline=(
                Read(id="RR", table="b", time_field="ts"),
                Filter(id="rf", condition=Comparison(
                    "==", FieldRef("side"), Literal("R"))),
                Emit(id="re"),
            )),),
        )

    ROWS = [
        event(ts=1, side="L", src_ip="1.2.3.4", host="WS-01"),
        event(ts=2, side="R", ip="1.2.3.4", threat="known-bad"),
        event(ts=3, side="R", ip="9.9.9.9", threat="other"),
    ]

    def test_differently_named_keys_still_join(self):
        result = evaluate(self.rule("src_ip", "ip"), self.ROWS)
        self.assertEqual(
            len(result.rows), 1,
            "a join between `src_ip` and `ip` found nothing, so the right "
            "side was indexed under the left key's name",
        )

    def test_the_joined_row_carries_both_sides(self):
        result = evaluate(self.rule("src_ip", "ip"), self.ROWS)
        values = result.rows[0].values
        self.assertIn("known-bad", str(values))
        self.assertIn("WS-01", str(values))

    def test_it_joins_only_the_matching_right_row(self):
        # The second right row has a different `ip` and must not pair.
        result = evaluate(self.rule("src_ip", "ip"), self.ROWS)
        self.assertNotIn("other", str(result.rows[0].values))

    def test_identically_named_keys_still_work(self):
        # The case that masked the bug must not regress.
        rows = [
            event(ts=1, side="L", host="WS-01"),
            event(ts=2, side="R", host="WS-01", threat="known-bad"),
        ]
        result = evaluate(self.rule("host", "host"), rows)
        self.assertEqual(len(result.rows), 1)

    def test_a_non_matching_key_produces_nothing(self):
        rows = [
            event(ts=1, side="L", src_ip="5.5.5.5"),
            event(ts=2, side="R", ip="1.2.3.4"),
        ]
        self.assertEqual(evaluate(self.rule("src_ip", "ip"), rows).rows, [])

    def test_an_anti_join_is_the_exact_complement(self):
        # The same key handling, inverted. If the index were built on the
        # wrong field an anti-join would match EVERYTHING instead of nothing.
        result = evaluate(self.rule("src_ip", "ip", how="anti"), self.ROWS)
        self.assertEqual(
            [r.get("src_ip") for r in result.rows], [],
            "the left row HAS a counterpart, so an anti-join must drop it",
        )


class DescendingSortActuallyDescends(unittest.TestCase):
    """`sort by X desc` returned ascending order for anything non-numeric.

    The descending branch appended a high sentinel and then rebuilt a
    three-tuple, discarding it, and negated only the NUMERIC component -- so
    the string component and the type tag stayed ascending. `| sort by Name
    desc` gave alphabetical order, and `| sort by Severity desc | take 1`
    returned the LOWEST severity: the opposite of the row the rule asked for.
    """

    def sorted_values(self, field: str, rows, descending: bool = True):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table="t", time_field="ts"),
                Sort(id="q", keys=((FieldRef(field), descending),)),
                Emit(id="o"),
            ),
        )
        return [r.get(field) for r in evaluate(rule, rows).rows]

    def test_strings_descend(self):
        rows = [event(ts=i, n=v) for i, v in
                enumerate(["bravo", "alpha", "charlie"])]
        self.assertEqual(
            self.sorted_values("n", rows), ["charlie", "bravo", "alpha"]
        )

    def test_strings_still_ascend_when_asked(self):
        rows = [event(ts=i, n=v) for i, v in
                enumerate(["bravo", "alpha", "charlie"])]
        self.assertEqual(
            self.sorted_values("n", rows, descending=False),
            ["alpha", "bravo", "charlie"],
        )

    def test_numbers_descend(self):
        rows = [event(ts=i, n=Decimal(v)) for i, v in enumerate([3, 1, 2])]
        self.assertEqual(
            self.sorted_values("n", rows),
            [Decimal(3), Decimal(2), Decimal(1)],
        )

    def test_the_top_row_is_the_top_row(self):
        # The consequence that matters: `sort desc | take 1` must give the
        # highest, and it was giving the lowest.
        rows = [event(ts=i, sev=v) for i, v in
                enumerate(["low", "critical", "medium"])]
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table="t", time_field="ts"),
                Sort(id="q", keys=((FieldRef("sev"), True),)),
                Limit(id="l", count=1),
                Emit(id="o"),
            ),
        )
        result = evaluate(rule, rows)
        self.assertEqual(result.rows[0].get("sev"), "medium")

    def test_mixed_types_stay_totally_ordered(self):
        # The tag exists so a mixed column cannot raise halfway through and
        # lose the whole result. Descending must invert the tag too.
        rows = [
            event(ts=0, n=Decimal(5)),
            event(ts=1, n="text"),
            event(ts=2),
            event(ts=3, n=None),
        ]
        values = self.sorted_values("n", rows)
        self.assertEqual(len(values), 4)
        self.assertEqual(values[-1], Decimal(5),
                         "numbers sort first ascending, so last descending")


if __name__ == "__main__":
    unittest.main()
