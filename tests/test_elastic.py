"""Elastic Security EQL, and the ordered-sequence IR node it needed.

`OrderIsTheWholePoint` is the class this module exists for. A sequence is an
ORDERED series of events, and nothing in the IR could carry order: `Join`
pairs streams without it and `Correlation` counts one repeated condition. So
`ir.Sequence` exists. Lowering a sequence to a join would double the matches
and half of them would be the benign direction -- `procdump` then `lsass` is
credential dumping, and the same two events reversed is somebody inspecting a
memory tool.

`ColonIsNotEquals` is second. EQL's `:` is a case-INSENSITIVE wildcard match
and `==` is exact. They look interchangeable; collapsing them silently narrows
every rule that used `:` and widens every rule that used `==`.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from engine import dialects
from engine.dialects.elastic import (
    CATEGORY_FIELD,
    DEFAULT_TABLE,
    DIALECT,
    MATCH_OPERATORS,
    PIPES,
    REGEX_DIALECT,
    lower_elastic,
    parse_elastic,
    render_elastic,
)
from engine.ir import (
    Annotations,
    Comparison,
    Distinct,
    Emit,
    Expand,
    FieldRef,
    Filter,
    Limit,
    Literal,
    Read,
    Regex,
    Rule,
    Sequence,
    SequenceStep,
    Sort,
    render_expr,
)
from engine.pipeline import evaluate
from engine.values import Duration, Refusal

SEQ = '''sequence by host.id with maxspan=5m
  [process where process.name == "procdump.exe"]
  [process where process.name : "LSASS*"]
until [process where event.type == "end"]'''

EVENT = (
    'process where process.name : "*.scr" '
    'and process.parent.name == "cmd.exe"'
)


def lower(text: str) -> Rule:
    rule, _ = lower_elastic(text)
    return rule


def first(rule: Rule, kind: type):
    return next(n for n in rule.pipeline if isinstance(n, kind))


def stages(rule: Rule) -> list[str]:
    return [type(n).__name__ for n in rule.pipeline]


def ev(ts, name, host="H1", etype="info", parent="x", category="process"):
    return {
        "@timestamp": ts,
        "event": {"category": category, "type": etype},
        "process": {"name": name, "parent": {"name": parent}},
        "host": {"id": host},
    }


class OrderIsTheWholePoint(unittest.TestCase):
    """Why `ir.Sequence` exists rather than reusing Join or Correlation."""

    def test_a_sequence_lowers_to_the_sequence_node(self):
        self.assertIn("Sequence", stages(lower(SEQ)))

    def test_the_steps_keep_their_order(self):
        steps = first(lower(SEQ), Sequence).steps
        self.assertIn("procdump.exe", render_expr(steps[0].condition))
        self.assertIn("LSASS", render_expr(steps[1].condition))

    def test_the_forward_order_matches(self):
        rule = lower(SEQ)
        self.assertTrue(
            evaluate(rule, [ev(1, "procdump.exe"), ev(2, "lsass.exe")]).matched
        )

    def test_the_reverse_order_does_not(self):
        # This is the assertion a Join could not make. `lsass` then `procdump`
        # is somebody inspecting a memory tool, not credential dumping.
        rule = lower(SEQ)
        self.assertFalse(
            evaluate(rule, [ev(1, "lsass.exe"), ev(2, "procdump.exe")]).matched
        )

    def test_unrelated_events_between_the_steps_do_not_break_it(self):
        # Real attack chains have ordinary traffic between their steps.
        rule = lower(SEQ)
        self.assertTrue(evaluate(rule, [
            ev(1, "procdump.exe"), ev(2, "chrome.exe"), ev(3, "lsass.exe"),
        ]).matched)

    def test_a_false_start_does_not_consume_the_real_one(self):
        # Anchoring once and giving up made the second attempt invisible.
        rule = lower(SEQ)
        self.assertTrue(evaluate(rule, [
            ev(1, "procdump.exe"), ev(2, "procdump.exe"), ev(3, "lsass.exe"),
        ]).matched)

    def test_out_of_order_input_is_still_matched(self):
        # The rows are sorted per key before matching, so a sample that did
        # not arrive in time order is still read in time order.
        rule = lower(SEQ)
        self.assertTrue(
            evaluate(rule, [ev(5, "lsass.exe"), ev(1, "procdump.exe")]).matched
        )

    def test_the_completing_row_carries_every_step(self):
        rule = lower(SEQ)
        result = evaluate(rule, [ev(1, "procdump.exe"), ev(2, "lsass.exe")])
        self.assertEqual(result.rows[0].values["sequence_steps"], Decimal(2))


class TheJoinKeyAndTheWindow(unittest.TestCase):
    def test_the_steps_must_agree_on_the_by_field(self):
        # Without this, `procdump` on one machine and `lsass` access on
        # another are the same finding.
        rule = lower(SEQ)
        self.assertFalse(evaluate(rule, [
            ev(1, "procdump.exe", "A"), ev(2, "lsass.exe", "B"),
        ]).matched)

    def test_maxspan_is_measured_first_to_last(self):
        rule = lower(SEQ)
        self.assertTrue(
            evaluate(rule, [ev(1, "procdump.exe"), ev(200, "lsass.exe")]).matched
        )
        self.assertFalse(
            evaluate(rule, [ev(1, "procdump.exe"), ev(999, "lsass.exe")]).matched
        )

    def test_the_window_is_read_from_the_query(self):
        self.assertEqual(
            first(lower(SEQ), Sequence).maxspan, Duration(Decimal(300))
        )

    def test_a_sequence_without_a_window_is_reported(self):
        # Unbounded, an attack chain and two unrelated events a year apart are
        # the same finding.
        _, diagnostics = lower_elastic(
            'sequence by host.id\n'
            '  [process where process.name == "a"]\n'
            '  [process where process.name == "b"]'
        )
        self.assertIn(
            "EQL_SEQUENCE_NO_MAXSPAN", [d.code for d in diagnostics]
        )

    def test_a_sequence_without_a_by_is_refused(self):
        # Any first event would pair with any later one anywhere in the
        # estate.
        with self.assertRaises(Refusal) as caught:
            lower('sequence\n  [process where process.name == "a"]\n'
                  '  [process where process.name == "b"]')
        self.assertEqual(caught.exception.code, "EQL_SEQUENCE_NO_BY")

    def test_a_one_step_sequence_is_refused(self):
        # One step is an ordinary filter, and writing it as a sequence implies
        # an ordering the rule does not require.
        with self.assertRaises(Refusal) as caught:
            lower('sequence by host.id\n  [process where process.name == "a"]')
        self.assertEqual(caught.exception.code, "EQL_SEQUENCE_TOO_SHORT")

    def test_a_row_without_the_join_key_is_reported(self):
        rule = lower(SEQ)
        broken = ev(1, "procdump.exe")
        del broken["host"]
        result = evaluate(rule, [broken, ev(2, "lsass.exe")])
        self.assertIn(
            "SEQUENCE_JOIN_KEY_ABSENT", [c.code for c in result.caveats]
        )

    def test_a_row_without_a_timestamp_is_reported(self):
        rule = lower(SEQ)
        broken = ev(1, "procdump.exe")
        del broken["@timestamp"]
        result = evaluate(rule, [broken, ev(2, "lsass.exe")])
        self.assertIn(
            "SEQUENCE_ROW_UNTIMED", [c.code for c in result.caveats]
        )


class UntilCancelsTheChain(unittest.TestCase):
    def test_the_terminator_is_read(self):
        self.assertIsNotNone(first(lower(SEQ), Sequence).until)

    def test_it_is_not_counted_as_a_step(self):
        # Counted as a step, the rule would require the cancellation to happen
        # before it could fire.
        self.assertEqual(len(first(lower(SEQ), Sequence).steps), 2)

    def test_a_cancelled_chain_does_not_fire(self):
        rule = lower(SEQ)
        self.assertFalse(evaluate(rule, [
            ev(1, "procdump.exe"),
            ev(2, "anything", etype="end"),
            ev(3, "lsass.exe"),
        ]).matched)

    def test_the_same_chain_without_the_cancellation_fires(self):
        rule = lower(SEQ)
        self.assertTrue(evaluate(rule, [
            ev(1, "procdump.exe"), ev(3, "lsass.exe"),
        ]).matched)

    def test_until_with_no_bracket_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower('sequence by host.id\n'
                  '  [process where process.name == "a"]\n'
                  '  [process where process.name == "b"]\nuntil')
        self.assertEqual(caught.exception.code, "EQL_UNTIL_NO_STEP")


class RunsRequiresRepeats(unittest.TestCase):
    QUERY = (
        'sequence by host.id with maxspan=5m\n'
        '  [process where process.name == "fail"] with runs=3\n'
        '  [process where process.name == "ok"]'
    )

    def test_the_count_is_read(self):
        self.assertEqual(first(lower(self.QUERY), Sequence).steps[0].runs, 3)

    def test_it_needs_that_many(self):
        rule = lower(self.QUERY)
        enough = [ev(i, "fail") for i in range(3)] + [ev(9, "ok")]
        self.assertTrue(evaluate(rule, enough).matched)
        short = [ev(i, "fail") for i in range(2)] + [ev(9, "ok")]
        self.assertFalse(evaluate(rule, short).matched)

    def test_it_round_trips(self):
        self.assertIn("with runs=3", render_elastic(lower(self.QUERY)))

    def test_runs_below_one_is_refused_by_the_node(self):
        with self.assertRaises(Refusal) as caught:
            SequenceStep(condition=Literal(True), runs=0)
        self.assertEqual(caught.exception.code, "SEQUENCE_RUNS_INVALID")


class ColonIsNotEquals(unittest.TestCase):
    """`:` is a case-insensitive wildcard match and `==` is exact."""

    def test_the_two_are_kept_apart_as_data(self):
        self.assertEqual(MATCH_OPERATORS["=="], "==")
        self.assertEqual(MATCH_OPERATORS[":"], "ilike")

    def test_colon_lowers_to_a_case_insensitive_match(self):
        condition = first(lower(EVENT), Filter).condition
        colon = condition.operands[1].operands[0]
        self.assertEqual(colon.op, "ilike")

    def test_the_wildcard_is_translated_not_left_literal(self):
        # Left as literal text, `*.scr` stops matching the events the rule was
        # written for.
        condition = first(lower(EVENT), Filter).condition
        colon = condition.operands[1].operands[0]
        self.assertEqual(colon.right.value, "%.scr")

    def test_colon_matches_case_insensitively_when_it_runs(self):
        rule = lower('process where process.name : "LSASS*"')
        self.assertTrue(evaluate(rule, [ev(1, "lsass.exe")]).matched)

    def test_equals_stays_exact(self):
        rule = lower('process where process.name == "LSASS.EXE"')
        self.assertFalse(evaluate(rule, [ev(1, "lsass.exe")]).matched)

    def test_colon_comes_back_as_a_colon(self):
        # Rendered as `==` the rule silently narrows; rendered as `like` it
        # loses the case-insensitivity.
        self.assertIn(': "LSASS*"', render_elastic(lower(SEQ)))

    def test_equals_comes_back_as_equals(self):
        self.assertIn('== "procdump.exe"', render_elastic(lower(SEQ)))

    def test_a_wildcard_call_becomes_a_match(self):
        rule = lower('process where wildcard(process.name, "*.scr")')
        self.assertTrue(evaluate(rule, [ev(1, "evil.scr")]).matched)
        self.assertFalse(evaluate(rule, [ev(1, "evil.exe")]).matched)

    def test_a_multi_pattern_wildcard_is_an_or_not_just_the_first(self):
        # Keeping only the first pattern silently narrows the rule.
        rule = lower('process where wildcard(process.name, "*.scr", "*.pif")')
        self.assertTrue(evaluate(rule, [ev(1, "a.scr")]).matched)
        self.assertTrue(evaluate(rule, [ev(1, "a.pif")]).matched)
        self.assertFalse(evaluate(rule, [ev(1, "a.exe")]).matched)

    def test_negated_membership_round_trips_as_a_negated_group(self):
        rule = lower('any where not (FileName in ("trusted.exe", "safe.exe"))')
        text = render_elastic(rule)
        self.assertIn("not FileName in", text)
        self.assertEqual(render_elastic(lower(text)), text)


class TheCategoryIsAPredicate(unittest.TestCase):
    """`process where ...` filters a field; it does not name an index."""

    def test_it_becomes_a_condition_on_the_category_field(self):
        condition = first(lower(EVENT), Filter).condition
        self.assertEqual(condition.operands[0].left.full, CATEGORY_FIELD)
        self.assertEqual(condition.operands[0].right.value, "process")

    def test_the_table_is_the_data_stream_not_the_category(self):
        # Named as the table, `any` would be an index that does not exist.
        self.assertEqual(first(lower(EVENT), Read).table, DEFAULT_TABLE)

    def test_any_constrains_nothing(self):
        # Modelled as a comparison against the string "any" it would match no
        # event at all.
        rule = lower('any where process.name == "x"')
        rendered = render_expr(first(rule, Filter).condition)
        self.assertNotIn(CATEGORY_FIELD, rendered)

    def test_the_category_filters_when_it_runs(self):
        rule = lower('process where process.name == "a"')
        self.assertTrue(evaluate(rule, [ev(1, "a")]).matched)
        self.assertFalse(
            evaluate(rule, [ev(1, "a", category="network")]).matched
        )

    def test_it_comes_back_as_a_category_not_a_condition(self):
        # Left in the condition this renders as
        # `any where event.category == "process" and ...`, which runs and
        # means the same thing but is not the query the analyst pasted.
        text = render_elastic(lower(EVENT))
        self.assertTrue(text.startswith("process where"))
        self.assertNotIn(CATEGORY_FIELD, text)

    def test_a_bare_true_condition_keeps_its_category(self):
        rule = lower("process where true")
        self.assertEqual(render_elastic(rule), "process where true")


class Pipes(unittest.TestCase):
    def test_head_becomes_a_limit(self):
        rule = lower(EVENT + "\n| head 5")
        self.assertEqual(first(rule, Limit).count, 5)

    def test_tail_is_recorded_as_keeping_the_last(self):
        # The model's Limit keeps the FIRST rows, so turning a tail into a
        # head quietly returns a different five.
        rule, diagnostics = lower_elastic(EVENT + "\n| tail 5")
        self.assertTrue(first(rule, Limit).keep_last)
        self.assertIn("EQL_TAIL_IS_A_HEAD", [d.code for d in diagnostics])

    def test_sort_and_unique_lower(self):
        rule = lower(EVENT + "\n| sort process.name\n| unique host.id")
        self.assertEqual(first(rule, Sort).keys[0][0].full, "process.name")
        self.assertEqual(first(rule, Distinct).keys[0].full, "host.id")

    def test_filter_becomes_a_second_filter_not_a_replacement(self):
        rule = lower(EVENT + '\n| filter host.id == "H1"')
        self.assertEqual(
            len([n for n in rule.pipeline if isinstance(n, Filter)]), 2
        )

    def test_an_aggregating_pipe_is_refused_rather_than_dropped(self):
        with self.assertRaises(Refusal) as caught:
            lower(EVENT + "\n| count")
        self.assertEqual(
            caught.exception.code, "EQL_PIPE_COUNT_UNSUPPORTED"
        )

    def test_an_unknown_pipe_is_refused_by_name(self):
        with self.assertRaises(Refusal) as caught:
            lower(EVENT + "\n| frobnicate")
        self.assertEqual(caught.exception.code, "EQL_PIPE_UNKNOWN")

    def test_every_modelled_pipe_has_a_handling(self):
        for name, handling in PIPES.items():
            with self.subTest(pipe=name):
                self.assertIn(
                    handling,
                    ("limit", "sort", "distinct", "filter", "unsupported"),
                )

    def test_the_pipes_round_trip(self):
        rule = lower(EVENT + "\n| head 5")
        self.assertIn("| head 5", render_elastic(rule))


class RegexIsNotExecutable(unittest.TestCase):
    def test_a_regex_test_is_tagged_with_the_elastic_flavour(self):
        rule = lower('process where process.name regex "lsa.*"')
        condition = first(rule, Filter).condition
        pattern = condition.operands[1]
        self.assertIsInstance(pattern.right, Regex)
        self.assertEqual(pattern.right.dialect, REGEX_DIALECT)

    def test_it_refuses_to_run_rather_than_guessing(self):
        rule = lower('process where process.name regex "lsa.*"')
        self.assertFalse(evaluate(rule, [ev(1, "lsass.exe")]).matched)

    def test_a_foreign_regex_dialect_is_refused_on_render(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table=DEFAULT_TABLE),
                Filter(id="f", condition=Comparison(
                    "matches", FieldRef(name="a"), Regex("x", "re2")
                )),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_elastic(rule)
        self.assertEqual(
            caught.exception.code, "EQL_RENDER_REGEX_DIALECT"
        )


class Parsing(unittest.TestCase):
    def test_a_sequence_is_recognised(self):
        self.assertEqual(parse_elastic(SEQ).kind, "sequence")
        self.assertEqual(parse_elastic(EVENT).kind, "event")

    def test_the_by_and_maxspan_are_split_out(self):
        parsed = parse_elastic(SEQ)
        self.assertEqual(parsed.by, ("host.id",))
        self.assertEqual(parsed.maxspan, "5m")

    def test_empty_text_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_elastic("   ")
        self.assertEqual(caught.exception.code, "EQL_EMPTY")

    def test_a_query_with_no_where_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_elastic('process process.name == "x"')
        self.assertEqual(caught.exception.code, "EQL_STEP_NO_WHERE")

    def test_an_empty_condition_is_refused(self):
        # An empty condition passes every event in the category.
        with self.assertRaises(Refusal) as caught:
            parse_elastic("process where ")
        self.assertIn(
            caught.exception.code,
            ("EQL_STEP_NO_CONDITION", "EQL_STEP_NO_WHERE"),
        )

    def test_an_unbalanced_bracket_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_elastic('sequence by host.id\n  [process where true')
        self.assertEqual(caught.exception.code, "EQL_UNBALANCED_BRACKET")

    def test_a_sample_query_is_refused_rather_than_mislowered(self):
        # A sample groups unordered events. Lowered as a sequence it would
        # claim an ordering it does not have.
        with self.assertRaises(Refusal) as caught:
            parse_elastic("sample by host.id [process where true]")
        self.assertEqual(caught.exception.code, "EQL_SAMPLE_UNSUPPORTED")

    def test_a_pipe_inside_a_string_does_not_split_the_query(self):
        parsed = parse_elastic('process where process.args : "a|b"')
        self.assertEqual(parsed.pipes, ())

    def test_a_partially_read_condition_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower('process where process.name == "a" frobnicate 2')
        self.assertEqual(caught.exception.code, "EQL_CONDITION_TRAILING")


class Rendering(unittest.TestCase):
    def test_a_sequence_round_trips(self):
        text = render_elastic(lower(SEQ))
        self.assertIn("sequence by host.id with maxspan=5m", text)
        self.assertIn("until [process where", text)

    def test_rendering_is_stable_across_two_round_trips(self):
        for query in (SEQ, EVENT):
            with self.subTest(query=query.splitlines()[0]):
                text = render_elastic(lower(query))
                self.assertEqual(
                    render_elastic(lower(text)), text,
                    "an unstable renderer makes every save look like a change",
                )

    def test_an_unrenderable_stage_is_refused_rather_than_dropped(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table=DEFAULT_TABLE),
                Filter(id="f", condition=Comparison(
                    "==", FieldRef(name="a"), Literal(1)
                )),
                Expand(id="e", field=FieldRef(name="a"), into="b"),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_elastic(rule)
        self.assertEqual(caught.exception.code, "EQL_RENDER_STAGE")

    def test_a_rule_with_no_body_is_refused(self):
        rule = Rule(
            rule_id="r",
            pipeline=(Read(id="s", table=DEFAULT_TABLE), Emit(id="o")),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_elastic(rule)
        self.assertEqual(caught.exception.code, "EQL_RENDER_NO_BODY")


class SequenceNodeInvariants(unittest.TestCase):
    """`ir.Sequence` refuses what EQL allows but nobody means."""

    def step(self, value):
        return SequenceStep(condition=Comparison(
            "==", FieldRef(name="a"), Literal(value)
        ))

    def test_fewer_than_two_steps_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            Sequence(id="q", steps=(self.step(1),),
                     by=(FieldRef(name="h"),))
        self.assertEqual(caught.exception.code, "SEQUENCE_TOO_SHORT")

    def test_no_join_key_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            Sequence(id="q", steps=(self.step(1), self.step(2)))
        self.assertEqual(caught.exception.code, "SEQUENCE_NO_JOIN_KEY")

    def test_a_sound_sequence_is_accepted(self):
        node = Sequence(
            id="q", steps=(self.step(1), self.step(2)),
            by=(FieldRef(name="h"),), maxspan=Duration(Decimal(60)),
        )
        self.assertEqual(len(node.steps), 2)


class RegistryIntegration(unittest.TestCase):
    def test_it_is_registered_and_ready(self):
        entry = dialects.get("elastic")
        self.assertTrue(entry.can_parse)
        self.assertTrue(entry.can_render)

    def test_it_round_trips_through_the_registry(self):
        rule, _ = dialects.lower("elastic", SEQ)
        text, notes = dialects.render("elastic", rule)
        self.assertEqual(notes, [])
        again, _ = dialects.lower("elastic", text)
        self.assertEqual(stages(again), stages(rule))

    def test_a_sequence_is_refused_by_the_dialects_that_cannot_order(self):
        # Every other dialect's render dispatch ends in a refusal, so a
        # Sequence cannot be silently dropped into a rule that looks complete.
        rule, _ = dialects.lower("elastic", SEQ)
        for key in ("sentinel", "splunk", "sigma", "wazuh", "qradar",
                    "chronicle", "crowdstrike"):
            with self.subTest(target=key):
                with self.assertRaises(Refusal):
                    dialects.render(key, rule)

    def test_an_event_query_still_crosses_into_other_dialects(self):
        rule, _ = dialects.lower("elastic", EVENT)
        text, _ = dialects.render("sentinel", rule)
        self.assertIn("where", text)


if __name__ == "__main__":
    unittest.main()
