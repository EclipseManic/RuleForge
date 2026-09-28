"""Elastic EQL, slice 1: a single event query, honestly.

A single `[ category where condition ]` is genuinely just a filter, and lowers
onto nodes that already exist: `Read` -> `Filter` -> `Emit`. That is the whole
of what this file claims, and it is stated up front because the value of EQL is
overwhelmingly its sequences -- every real detection written in it is a
`sequence` or a `sample` -- so parsing one event while refusing the rest is the
easy 5% and must say so.

`sequence`, `sample`, the `:` wildcard, `like`, `in` and every function are
recognised and refused BY NAME with the missing piece, not left to a generic
"unknown syntax". The IR already has `Pattern` for sequences, so those refusals
are "not yet lowered" rather than "cannot be expressed".
"""

import unittest

import jobs
from dialects.eql import parse_eql
from dialects.eql_ir import lower as lower_eql
from engine.values import Refusal


def _round_trip(source: str) -> str:
    outcome = jobs.author("elastic", source, "r1")
    assert outcome.ok, f"{source} should lower: {outcome.refusal}"
    return outcome.rendered


class SingleEventLowers(unittest.TestCase):
    def test_a_process_event_round_trips(self):
        self.assertEqual(
            _round_trip('[ process where process.name == "regsvr32.exe" ]'),
            '[process where process.name == "regsvr32.exe"]')

    def test_a_file_event_round_trips(self):
        self.assertEqual(
            _round_trip('[ file where file.extension == "exe" ]'),
            '[file where file.extension == "exe"]')

    def test_an_authentication_event_round_trips(self):
        self.assertEqual(
            _round_trip('[ authentication where event.code == "4624" ]'),
            '[authentication where event.code == "4624"]')

    def test_any_category_round_trips(self):
        self.assertEqual(_round_trip('[ any where uptime > 0 ]'),
                         '[any where uptime > 0]')

    def test_numbers_and_booleans_lower(self):
        self.assertEqual(_round_trip('[ any where port > 100 ]'),
                         '[any where port > 100]')


class BooleanStructureIsCorrect(unittest.TestCase):
    """NOT > AND > OR, parens honoured, quoted separators left alone -- the
    same three properties the SPL `where` fix established, because the same
    one-line-split bug would produce the same false negative here."""

    def test_or_with_and_is_or_outermost(self):
        self.assertEqual(
            _round_trip('[ any where a == 1 or b == 2 and c == 3 ]'),
            '[any where (a == 1 or (b == 2 and c == 3))]')

    def test_parentheses_are_honoured(self):
        self.assertEqual(
            _round_trip('[ any where a == 1 or (b == 2 and c == 3) ]'),
            '[any where (a == 1 or (b == 2 and c == 3))]')

    def test_a_quoted_and_is_not_split(self):
        self.assertEqual(
            _round_trip('[ any where msg == "x and y" ]'),
            '[any where msg == "x and y"]')

    def test_not_binds_tightest(self):
        self.assertEqual(
            _round_trip('[ any where not a == 1 and b == 2 ]'),
            '[any where (not a == 1 and b == 2)]')


class SequencesLowerOntoPattern(unittest.TestCase):
    """Slice 2. `sequence` lowers onto the IR's `Pattern` node -- stages,
    `within` from `maxspan`, `key` from `sequence by`, and `until` with
    `until_scope="between"` which is EQL's rule."""

    def test_a_plain_sequence_round_trips(self):
        self.assertEqual(
            _round_trip('sequence with maxspan=15m\n'
                        '  [ file where file.extension == "exe" ]\n'
                        '  [ process where true ]'),
            'sequence with maxspan=15m\n'
            '  [file where file.extension == "exe"]\n'
            '  [process where true]')

    def test_a_sequence_with_by_and_until_round_trips(self):
        self.assertEqual(
            _round_trip('sequence by user.name with maxspan=15m\n'
                        '  [ file where file.extension == "exe" ]\n'
                        '  [ process where true ]\n'
                        '  until [ process where event.type == "termination" ]'),
            'sequence by user.name with maxspan=15m\n'
            '  [file where file.extension == "exe"]\n'
            '  [process where true]\n'
            '  until [process where event.type == "termination"]')

    def test_step_categories_survive_the_round_trip(self):
        """The category is folded into each stage as `event.category == ...`
        at lowering time and read back out at render time. Rendering a step as
        `[any where ...]` would silently widen it."""
        rendered = _round_trip(
            'sequence with maxspan=15m\n'
            '  [ file where file.extension == "exe" ]\n'
            '  [ network where true ]')
        self.assertIn("[file where", rendered)
        self.assertIn("[network where", rendered)
        self.assertNotIn("[any where", rendered)

    def test_a_bracket_inside_a_string_does_not_end_the_step(self):
        """THE BUG. The splitter found blocks quote-aware, but the closer took
        `body.index("]")` -- the first one, even inside a string. So a condition
        ending in `"]"` truncated there and the rest misread as a `by` trailer,
        refusing with EQL_PER_STEP_BY_NOT_LOWERED for a rule with no `by`."""
        self.assertEqual(
            _round_trip('sequence with maxspan=15m\n'
                        '  [ file where name == "]" ]\n'
                        '  [ process where true ]'),
            'sequence with maxspan=15m\n'
            '  [file where name == "]"]\n'
            '  [process where true]')

    def test_a_pipe_is_refused_by_name_not_generically(self):
        """`[file where true] | head 5` starts with `[`, so the first-word
        keyword check never fires. The top-level `|` check names it."""
        with self.assertRaises(Refusal) as caught:
            parse_eql('[ file where true ] | head 5')
        self.assertEqual(caught.exception.code, "EQL_PIPE_NOT_LOWERED")

    def test_a_pipe_inside_a_string_is_not_a_pipe(self):
        self.assertEqual(
            _round_trip('sequence with maxspan=15m\n'
                        '  [ file where name == "a|b" ]\n'
                        '  [ process where true ]'),
            'sequence with maxspan=15m\n'
            '  [file where name == "a|b"]\n'
            '  [process where true]')

    def test_a_leading_until_is_refused_by_name(self):
        with self.assertRaises(Refusal) as caught:
            parse_eql('until [ process where true ]')
        self.assertEqual(caught.exception.code, "EQL_UNTIL_WITHOUT_SEQUENCE")

    def test_an_until_missing_event_is_refused(self):
        """GAP-7 CLOSED. `until ![ ... ]` negates the expiry, which the IR
        cannot express. The branch fired correctly when probed, but no test
        pinned it -- flipping `allow_bang` kept the suite green. Now pinned."""
        with self.assertRaises(Refusal) as caught:
            parse_eql('sequence with maxspan=15m\n'
                      '  [ file where true ]\n'
                      '  [ process where true ]\n'
                      '  until ![ process where true ]')
        self.assertEqual(caught.exception.code, "EQL_UNTIL_MISSING_EVENT")

    def test_a_sequence_without_maxspan_is_refused_at_lowering(self):
        """`Pattern.within` is required and there is no unbounded spelling.
        Using 0 for "no bound" would mean "same timestamp", which is a
        different rule. Parsed fine; refused when lowering."""
        from dialects.eql_ir import lower as lower_eql
        with self.assertRaises(Refusal) as caught:
            lower_eql(parse_eql(
                'sequence\n'
                '  [ file where file.extension == "exe" ]\n'
                '  [ process where true ]'))
        self.assertEqual(caught.exception.code, "EQL_SEQUENCE_NEEDS_MAXSPAN")


class SequencesExecuteWithEqlUntilSemantics(unittest.TestCase):
    """The scope is not decoration. `until_scope="between"` is EQL's rule --
    an expiry after the match leaves it standing -- and this executes a lowered
    sequence to prove it. Changing the scope to `"window"` must fail here."""

    def _rows(self):
        def R(cat, ts, **kw):
            d = {"event.category": cat, "@timestamp": ts}
            d.update(kw)
            return d
        return [
            R("file", 0, **{"file.extension": "exe"}),
            R("process", 100),
            R("process", 200, **{"event.type": "termination"}),
        ]

    def test_an_expiry_after_the_match_leaves_it_standing(self):
        """THE DISCRIMINATING CASE, from Elastic's own example. The expiry at
        t=200 comes after the file->process sequence completed at t=100, so
        under EQL the sequence matches. Under the "window" scope it would not
        -- which is exactly what the mutation changes, and why this test
        exists."""
        from engine import Verdict, evaluate
        ir, _ = lower_eql(parse_eql(
            'sequence with maxspan=15m\n'
            '  [ file where file.extension == "exe" ]\n'
            '  [ process where true ]\n'
            '  until [ process where event.type == "termination" ]'))
        result = evaluate(ir, self._rows())
        self.assertIs(result.verdict, Verdict.MATCHED,
                      "the expiry comes after the sequence completed, so "
                      "under EQL the match stands")

    def test_an_expiry_between_the_matches_expires_it(self):
        """The second stage names only the LATER process row, so the expiry
        row sits strictly between the two matched rows. A `where true` stage
        would match the first process row it sees and leave nothing between --
        which is correct EQL, not a test bug, but it cannot discriminate the
        scopes."""
        from engine import Verdict, evaluate
        ir, _ = lower_eql(parse_eql(
            'sequence with maxspan=15m\n'
            '  [ file where file.extension == "exe" ]\n'
            '  [ process where host == "h2" ]\n'
            '  until [ process where event.type == "termination" ]'))
        rows = [
            {"event.category": "file", "file.extension": "exe",
             "@timestamp": 0},
            {"event.category": "process", "host": "h1",
             "event.type": "termination", "@timestamp": 50},
            {"event.category": "process", "host": "h2", "@timestamp": 100},
        ]
        result = evaluate(ir, rows)
        self.assertIsNot(result.verdict, Verdict.MATCHED,
                         "the expiry falls between the matched events")


class EverythingElseIsRefusedByName(unittest.TestCase):
    def test_runs_is_refused_at_parse_time(self):
        """`with runs=N` needs N consecutive repeats and `Pattern` has no
        repeat count. Recognised in the parser and refused there, with the
        missing piece named."""
        with self.assertRaises(Refusal) as caught:
            parse_eql('sequence with runs=3\n'
                      '  [ file where true ]\n'
                      '  [ process where true ]')
        self.assertEqual(caught.exception.code, "EQL_RUNS_NOT_LOWERED")

    def test_runs_one_lowers_exactly(self):
        """`with runs=1` MEANS "MATCH ONCE", WHICH IS THE PATTERN ITSELF. One
        run needs no repeat semantics, so it lowers exactly and renders
        without the clause -- which is semantically identical, not a silent
        drop like the other cases in this project. Only 2+ is refused."""
        for source in ('sequence with maxspan=15m with runs=1\n'
                       '  [ file where file.extension == "exe" ]\n'
                       '  [ process where true ]',
                       'sequence with runs=1 with maxspan=15m\n'
                       '  [ file where file.extension == "exe" ]\n'
                       '  [ process where true ]'):
            with self.subTest(source=source[:40]):
                self.assertEqual(
                    _round_trip(source),
                    'sequence with maxspan=15m\n'
                    '  [file where file.extension == "exe"]\n'
                    '  [process where true]')

    def test_runs_zero_and_non_integer_are_refused(self):
        """A repeat count that is not a positive integer is not a count."""
        for source in ('sequence with runs=0\n'
                       '  [ file where true ]\n'
                       '  [ process where true ]',
                       'sequence with runs=many\n'
                       '  [ file where true ]\n'
                       '  [ process where true ]'):
            with self.subTest(source=source[:30]):
                with self.assertRaises(Refusal) as caught:
                    parse_eql(source)
                self.assertEqual(caught.exception.code,
                                 "EQL_RUNS_NOT_A_COUNT")

    def test_double_maxspan_is_refused(self):
        """Two `with maxspan=` clauses join nothing new; the second is refused
        rather than silently kept alongside the first."""
        with self.assertRaises(Refusal) as caught:
            parse_eql('sequence with maxspan=15m with maxspan=1h\n'
                      '  [ file where true ]\n'
                      '  [ process where true ]')
        self.assertEqual(caught.exception.code, "EQL_MAXSPAN_TWICE")

    def test_a_missing_event_step_is_refused(self):
        """`![ ... ]` matches an absence. Dropping it would invert the rule."""
        with self.assertRaises(Refusal) as caught:
            parse_eql('sequence with maxspan=1h\n'
                      '  [ file where true ]\n'
                      '  ![ process where true ]')
        self.assertEqual(caught.exception.code,
                         "EQL_MISSING_EVENT_NOT_LOWERED")

    def test_a_per_step_by_is_refused(self):
        """`Pattern.key` is global; EQL allows different fields per step."""
        with self.assertRaises(Refusal) as caught:
            parse_eql('sequence with maxspan=1h\n'
                      '  [ file where true ] by file.path\n'
                      '  [ process where true ]')
        self.assertEqual(caught.exception.code,
                         "EQL_PER_STEP_BY_NOT_LOWERED")

class SamplesLowerOntoUnorderedPatterns(unittest.TestCase):
    """`sample by keys steps...` is an unordered, windowless, key-grouped set
    of events -- which is `Pattern` with `ordered=False`, `within=None`, and
    `key` from `by`. No `maxspan` (samples take none), no `until` (not
    allowed), no `time_field` (unordered needs none, and guessing one would
    order the match by an unrelated column)."""

    def test_a_sample_round_trips(self):
        self.assertEqual(
            _round_trip('sample by host\n'
                        '  [ file where file.extension == "exe" ]\n'
                        '  [ process where true ]'),
            'sample by host\n'
            '  [file where file.extension == "exe"]\n'
            '  [process where true]')

    def test_multiple_keys_round_trip(self):
        self.assertEqual(
            _round_trip('sample by host, os\n'
                        '  [ file where file.extension == "exe" ]\n'
                        '  [ process where true ]'),
            'sample by host, os\n'
            '  [file where file.extension == "exe"]\n'
            '  [process where true]')

    def test_step_categories_survive(self):
        rendered = _round_trip(
            'sample by host\n'
            '  [ file where file.extension == "exe" ]\n'
            '  [ network where true ]')
        self.assertIn("[file where", rendered)
        self.assertIn("[network where", rendered)
        self.assertNotIn("[any where", rendered)

    def test_sample_without_by_is_refused(self):
        """Without shared keys a sample is unrelated events -- a no-op."""
        with self.assertRaises(Refusal) as caught:
            parse_eql('sample\n'
                      '  [ file where true ]')
        self.assertEqual(caught.exception.code, "EQL_SAMPLE_NEEDS_BY")

    def test_more_than_five_filters_is_refused(self):
        """EQL caps samples at 5 filters; the 6th would silently not filter."""
        with self.assertRaises(Refusal) as caught:
            parse_eql('sample by host\n'
                      '  [ file where true ]\n'
                      '  [ process where true ]\n'
                      '  [ network where true ]\n'
                      '  [ dns where true ]\n'
                      '  [ registry where true ]\n'
                      '  [ library where true ]')
        self.assertEqual(caught.exception.code,
                         "EQL_SAMPLE_TOO_MANY_FILTERS")

    def test_sample_executes_unordered(self):
        """Order-independent: the same events in reverse chronological order
        still match, because a sample has no order to violate."""
        from engine import Verdict, evaluate
        ir, _ = lower_eql(parse_eql(
            'sample by host\n'
            '  [ file where file.extension == "exe" ]\n'
            '  [ process where true ]'))
        rows = [
            {"event.category": "process", "host": "h1", "@timestamp": 100},
            {"event.category": "file", "file.extension": "exe",
             "host": "h1", "@timestamp": 0},
        ]
        result = evaluate(ir, rows)
        self.assertIs(result.verdict, Verdict.MATCHED,
                      "a sample matches regardless of event order")

    def test_the_wildcard_operator_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower_eql(parse_eql('[ file where file.extension : "exe" ]'))
        self.assertEqual(caught.exception.code, "EQL_WILDCARD_NOT_LOWERED")

    def test_functions_are_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower_eql(parse_eql('[ file where stringContains(file.name, "x") ]'))
        self.assertEqual(caught.exception.code, "EQL_FUNCTION_NOT_LOWERED")

    def test_an_unknown_category_is_refused_not_treated_as_any(self):
        """Matching every category is a different rule."""
        with self.assertRaises(Refusal) as caught:
            parse_eql('[ banana where true ]')
        self.assertEqual(caught.exception.code, "EQL_UNKNOWN_CATEGORY")

    def test_a_sequence_produces_an_artifact_now(self):
        """Sequences lower since slice 2. A test asserting they do not would be
        certifying a refusal that no longer exists -- the same failure mode as
        the old `sort count desc` assertion."""
        outcome = jobs.author(
            "elastic", "sequence with maxspan=15m\n"
            '  [ file where file.extension == "exe" ]\n'
            '  [ process where true ]', "r1")
        self.assertTrue(outcome.ok)
        self.assertIn("sequence with maxspan=15m", outcome.rendered)

    def test_the_rendered_output_says_which_dialect_this_is(self):
        """The label must not claim full EQL support."""
        import jobs as _jobs
        self.assertIn("single event", _jobs.DIALECTS["elastic"]["label"].lower(),
                      "the dialect label must say this is the single-event "
                      "slice, or the UI claims a dialect that is 5% done")


class TheGraphIsJustAFilter(unittest.TestCase):
    def test_lower_produces_read_filter_emit(self):
        ir, _ = lower_eql(parse_eql('[ process where process.name == "x" ]'))
        self.assertEqual([type(n).__name__ for n in ir.nodes],
                         ["Read", "Filter", "Emit"])
        self.assertEqual(ir.nodes[0].selector.name, "process")

    def test_render_refuses_a_graph_with_an_aggregate(self):
        """A graph with an aggregation in it is not a single event, and
        rendering it as one would drop the aggregation."""
        from dialects.eql_render import render
        from engine.ir import (
            Derive, Emit, FieldRef, Filter, Literal, Read,
            RuleIR, SourceSelector,
        )
        from engine.ir import Comparison, FieldExpr
        graph = RuleIR(
            rule_id="r",
            nodes=(Read(id="r", selector=SourceSelector(name="process")),
                   Filter(id="f", input="r",
                          condition=Comparison(
                              "=", FieldExpr(FieldRef("a")), Literal("x"))),
                   Derive(id="d", input="f",
                          assignments=(("x", Literal("y")),), kind="eval"),
                   Emit(id="o", input="d")),
            output="o", metadata={"dialect": "eql"})
        with self.assertRaises(Refusal) as caught:
            render(graph)
        self.assertEqual(caught.exception.code,
                         "EQL_RENDER_NODE_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
