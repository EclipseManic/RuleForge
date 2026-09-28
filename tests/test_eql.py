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
from engine import Duration, Verdict, evaluate
from engine.ir import Literal
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

    def test_an_UNORDERED_pattern_does_not_early_exit_the_until_veto(self):
        """MED-4, and the case that makes it observable.

        The `until` veto used to `return False` the moment it saw a row whose
        timestamp was past the window end. That early exit is only valid if the
        group's rows are in TIME order. An unordered pattern's rows are in
        ARRIVAL order, so a row past the window sitting in the middle of the
        array would abort the scan while a matching row still sat behind it --
        and a rule reading "and no logout in that window" would fire anyway.

        The rows below are deliberately out of time order: t=50 is past the
        10-second window end, and the logout that must veto is at t=20, sitting
        AFTER it in the array. With the early exit the veto is never reached;
        with `continue` it is. Same rows, same rule, opposite answers, and only
        an unordered pattern distinguishes them -- an ordered group would sort
        itself first and hide the bug entirely.
        """
        from engine import Verdict, evaluate
        from engine.ir import (Comparison, Duration, Emit, FieldExpr, FieldRef,
                               Literal, Pattern, Read, RuleIR, SourceSelector)
        veto = Comparison("=", FieldExpr(FieldRef("kind")), Literal("logout"))
        node = Pattern(
            id="p", input="r",
            stages=((Comparison("=", FieldExpr(FieldRef("kind")),
                                Literal("open")),),
                    (Comparison("=", FieldExpr(FieldRef("kind")),
                                Literal("close")),)),
            within=Duration(10), time_field="ts", ordered=False,
            until=veto, until_scope="window")
        ir = RuleIR(rule_id="t", nodes=(
            Read(id="r", selector=SourceSelector(name="any")),
            node, Emit(id="out", input="p")), output="out", title="t")
        # ARRIVAL order, and the timestamps are what make this bite: the window
        # is [0, 10]. t=50 is PAST it and sits early in the array; the logout at
        # t=8 is INSIDE it and sits after. An early exit at t=50 would decide the
        # veto before ever reaching t=8.
        unordered = [{"kind": "open", "ts": 0}, {"kind": "close", "ts": 50},
                     {"kind": "x", "ts": 3}, {"kind": "logout", "ts": 8},
                     {"kind": "close", "ts": 5}]
        result = evaluate(ir, unordered)
        self.assertIs(result.verdict, Verdict.NO_MATCH,
                      "a logout at t=8 is inside the 10s window from t=0, so "
                      "the sequence is vetoed; an early exit on the t=50 row "
                      "would have missed it and matched")

    def test_the_until_veto_still_fires_when_the_row_IS_out_of_window(self):
        """The other direction, so `continue` cannot become "never veto".

        A logout OUTSIDE the window must not veto: "no logout within 10 minutes"
        is not "no logout ever", and treating it as the latter would narrow the
        rule and hide real sequences.
        """
        from engine import Verdict, evaluate
        from engine.ir import (Comparison, Duration, Emit, FieldExpr, FieldRef,
                               Literal, Pattern, Read, RuleIR, SourceSelector)
        veto = Comparison("=", FieldExpr(FieldRef("kind")), Literal("logout"))
        node = Pattern(
            id="p", input="r",
            stages=((Comparison("=", FieldExpr(FieldRef("kind")),
                                Literal("open")),),
                    (Comparison("=", FieldExpr(FieldRef("kind")),
                                Literal("close")),)),
            within=Duration(10), time_field="ts", ordered=False,
            until=veto, until_scope="window")
        ir = RuleIR(rule_id="t", nodes=(
            Read(id="r", selector=SourceSelector(name="any")),
            node, Emit(id="out", input="p")), output="out", title="t")
        ordered_rows = [{"kind": "open", "ts": 0}, {"kind": "close", "ts": 5},
                        {"kind": "logout", "ts": 900}]
        self.assertIs(evaluate(ir, ordered_rows).verdict, Verdict.MATCHED,
                      "a logout at t=900 is far outside the 10s window, so it "
                      "must not veto")

    def test_the_between_scope_still_works_on_an_unordered_pattern(self):
        """The refusal must not be over-broad. `between` bounds the veto by the
        MATCHED EVENTS rather than the clock, so it needs no ordering, and it is
        the scope an unordered pattern should use. EQL `sample` has no `until`
        at all today, so this is the shape a future one would take."""
        from engine.ir import Comparison, FieldExpr, FieldRef, Pattern
        node = Pattern(id="p", input="r",
                       stages=((Literal(True),), (Literal(True),)),
                       within=None, ordered=False,
                       until=Comparison("=", FieldExpr(FieldRef("x")),
                                        Literal(1)),
                       until_scope="between")
        self.assertEqual(node.until_scope, "between")
        self.assertFalse(node.ordered)

    def test_a_sequence_is_EXECUTED_end_to_end_not_only_lowered(self):
        """The coverage hole that let a real bug through 869 green tests.

        Adding `runs=` to the `Pattern(...)` tuple dropped the trailing `Emit`
        node, so every sequence had a dangling `output` and evaluated to
        `NOT_EVALUATED` -- and the whole suite stayed green, because the EQL
        tests asserted the IR node LIST and the rendered text, and nothing
        between a lowerer and a renderer executes a rule.

        So this asserts a sequence actually produces rows, and that a failing
        sequence produces none. Without it, a dropped node, a wrong `output`, or
        an evaluator that returns nothing all look identical to "lowering
        succeeded".
        """
        from engine import Verdict, evaluate
        rows = [{"event.category": "file", "@timestamp": 0,
                 "file.extension": "exe"},
                {"event.category": "process", "@timestamp": 100}]

        matching, _ = lower_eql(parse_eql(
            'sequence with maxspan=15m\n'
            '  [ file where file.extension == "exe" ]\n'
            '  [ process where true ]'))
        result = evaluate(matching, [dict(r) for r in rows])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 1,
                         "the sequence must produce a row, and the IR must "
                         "name a node that exists to emit it")

        # And the negative, so a rule that matches everything cannot pass by
        # simply emitting: a sequence whose second stage cannot be satisfied
        # must produce NO ROWS. The assertion is on the row count rather than
        # the verdict, because the verdict taxonomy here is noisier than this
        # test's purpose -- a row carrying the engine's internal `_absent`
        # sentinel makes a decided non-match come back NOT_EVALUATED, which is
        # a separate question about caveat propagation.
        nonmatching, _ = lower_eql(parse_eql(
            'sequence with maxspan=15m\n'
            '  [ file where file.extension == "exe" ]\n'
            '  [ process where event.type == "creation" ]'))
        self.assertEqual(len(evaluate(nonmatching,
                                      [dict(r) for r in rows]).rows), 0,
                         "a sequence whose stages cannot all be satisfied must "
                         "not emit a row")

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
    def test_runs_ACTUALLY_REQUIRES_THAT_MANY_REPEATS(self):
        """`runs=N` is EXECUTED, not just carried through the IR.

        This is the third instance of this repo's worst bug shape -- a field a
        lowerer sets and the evaluator ignores. `Derive.projects` was one,
        `Aggregate.keys` was another, and both shipped green because every test
        compared text. So the assertion is on the EVENT COUNT, which is the only
        thing that can tell "happened once" from "happened twice":

          runs absent / 1, with TWO events of the pattern  -> matches
          runs=2,       with TWO events of the pattern       -> does NOT match
          runs=2,       with FOUR events (two repeats)      -> matches

        The middle line is the whole feature. The other two are the regression
        guards: the first proves the new default did not change the meaning of
        every existing rule, the third proves the count is not merely compared
        against 1.
        """
        one = "[process where true] [network where true]"

        def events(count):
            return [{"event.category": "process" if i % 2 == 0 else "network",
                     "@timestamp": 10 + i * 10, "host": "h1"}
                    for i in range(count)]

        def run(clause, count):
            source = f"sequence by host{clause} with maxspan=10m {one}"
            ir, _ = lower_eql(parse_eql(source))
            result = evaluate(ir, events(count))
            return result.verdict

        self.assertIs(run("", 2), Verdict.MATCHED,
                      "one repeat of a two-stage pattern is the default")
        self.assertIs(run(" with runs=1", 2), Verdict.MATCHED)
        self.assertIs(run(" with runs=2", 2), Verdict.NO_MATCH,
                      "TWO events is ONE repeat, so runs=2 must not match")
        self.assertIs(run(" with runs=2", 4), Verdict.MATCHED,
                      "four events is two complete repeats")

    def test_runs_is_a_count_of_repeats_NOT_a_window_multiplier(self):
        """`runs=2` with `maxspan=10m` needs the repeats INSIDE ten minutes.

        Reading N as a window multiplier instead -- "this took twice as long" --
        is the obvious wrong answer, and it is not a conservative one: it makes
        the rule MATCH MORE than the analyst wrote, on events spread over a
        wider span. Here both repeats fit in 30 seconds, so this test cannot
        tell the two readings apart, and the window case below can.
        """
        one = "[process where true] [network where true]"
        # Two repeats, but the second starts two hours after the first. Under a
        # correct reading the window rejects it; under "double the window" it
        # would pass.
        spread = [{"event.category": "process", "@timestamp": 0, "host": "h1"},
                  {"event.category": "network", "@timestamp": 10, "host": "h1"},
                  {"event.category": "process", "@timestamp": 7200, "host": "h1"},
                  {"event.category": "network", "@timestamp": 7210, "host": "h1"}]
        ir, _ = lower_eql(parse_eql(
            f"sequence by host with runs=2 with maxspan=10m {one}"))
        self.assertIs(evaluate(ir, spread).verdict, Verdict.NO_MATCH,
                      "the second repeat is outside maxspan, so runs=2 does not "
                      "hold; a window-multiplier reading would have matched")

    def test_runs_cannot_reuse_one_event_for_two_repeats(self):
        """The repeats must be DISJOINT.

        If the second repeat could start at the same event the first one ended
        on, two events would satisfy `runs=2` -- "happened twice" would become
        "happened once, counted twice", which matches strictly more than the
        analyst wrote.
        """
        one = "[process where true] [network where true]"
        two_events = [{"event.category": "process", "@timestamp": 0,
                       "host": "h1"},
                      {"event.category": "network", "@timestamp": 10,
                       "host": "h1"}]
        ir, _ = lower_eql(parse_eql(
            f"sequence by host with runs=2 with maxspan=10m {one}"))
        self.assertIs(evaluate(ir, two_events).verdict, Verdict.NO_MATCH,
                      "the same two events cannot serve as both repeats")

    def test_runs_round_trips_and_is_not_silently_dropped(self):
        """`with runs=2` is rendered BACK.

        Omitting it would emit a query that matches ONE occurrence where the
        analyst wrote two -- the same failure as rendering `eval` as `rename`,
        and equally invisible to a test that only compares the IR.
        """
        # The expectation is written out rather than assembled from the input,
        # because deriving it from the input would pass even if `runs` were
        # dropped on both sides. The renderer puts each step on its own line.
        self.assertEqual(
            _round_trip("sequence with runs=2 with maxspan=10m "
                        "[process where true] [network where true]"),
            "sequence with maxspan=10m with runs=2\n"
            "  [process where true]\n"
            "  [network where true]")
        # And runs=1 stays implicit, because `with runs=1` IS the pattern.
        self.assertNotIn("runs=1", _round_trip(
            "sequence with runs=1 with maxspan=10m "
            "[process where true] [network where true]"))

    def test_runs_is_no_longer_refused_but_only_a_REAL_COUNT_is_accepted(self):
        """`with runs=N` now lowers for any positive integer.

        What it will NOT accept is a non-count, because "how many times" with a
        non-number in it is not a number of times -- and `runs=0` would mean the
        pattern matches when it does NOT occur, which is an inverted rule rather
        than a weaker one. Both are refused, by code, at parse time.
        """
        for bad, code in (("runs=0", "EQL_RUNS_NOT_A_COUNT"),
                          ("runs=-1", "EQL_RUNS_NOT_A_COUNT"),
                          ("runs=two", "EQL_RUNS_NOT_A_COUNT"),
                          ("runs=2.5", "EQL_RUNS_NOT_A_COUNT"),
                          ("runs=", "EQL_RUNS_NOT_A_COUNT")):
            with self.assertRaises(Refusal) as caught:
                parse_eql(f'sequence with maxspan=15m with {bad}\n'
                          '  [ file where true ]\n'
                          '  [ process where true ]')
            self.assertEqual(caught.exception.code, code, bad)

    def test_a_runs_count_of_zero_is_refused_by_the_node_too(self):
        """Belt and braces: `Pattern(runs=0)` is refused by the IR as well, so
        a future lowerer cannot construct an inverted rule by accident. The
        parser check is the user-facing one; this is the invariant."""
        from engine.ir import Pattern
        with self.assertRaises(Refusal) as caught:
            Pattern(id="p", input="r", stages=((Literal(True),), (Literal(True),)),
                    within=Duration(60), time_field="ts", runs=0)
        self.assertEqual(caught.exception.code, "PATTERN_RUNS_INVALID")
        # And a negative count is refused the same way, so no producer can
        # construct a pattern that must repeat a negative number of times.
        with self.assertRaises(Refusal) as caught:
            Pattern(id="p", input="r", stages=((Literal(True),), (Literal(True),)),
                    within=Duration(60), time_field="ts", runs=-1)
        self.assertEqual(caught.exception.code, "PATTERN_RUNS_INVALID")

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

    def test_the_per_step_by_refusal_cites_the_vendor(self):
        """The refusal must state the REASON, not assert it.

        Elastic's EQL reference: "Use the `by` keyword in a sequence query to
        only match events that share the same values, EVEN IF THOSE VALUES ARE
        IN DIFFERENT FIELDS." That is what makes this refusal load-bearing
        rather than a shrug: `Pattern.key` is one global list of field names
        compared by NAME, so it can only ever say "same field everywhere". A
        rule joining `user.name` in one step to `user.id` in the next is a
        different rule, and faking it with a global key would over-match --
        matching on a field nobody asked about.

        So the message has to name the different-fields behaviour, or an
        analyst reads "not lowered" and assumes it is a missing feature rather
        than a rule the IR cannot state.
        """
        with self.assertRaises(Refusal) as caught:
            parse_eql('sequence with maxspan=1h\n'
                      '  [ file where true ] by file.path\n'
                      '  [ process where true ]')
        message = caught.exception.message
        self.assertIn("DIFFERENT fields", message)
        self.assertIn("global", message,
                      "the message must say Pattern.key is global, since that "
                      "is the constraint being hit")

    def test_both_per_step_by_shapes_are_refused_the_same_way(self):
        """A trailing `by` on the step, and a `by` the splitter left as its
        own segment, are the SAME construct and must not diverge. The dangling
        form once produced a message that named neither the reason nor the
        fields."""
        trailing = ('sequence with maxspan=1h\n'
                    '  [ file where true ] by file.path\n'
                    '  [ process where true ]')
        dangling = ('sequence with maxspan=1h\n'
                    '  [ file where true ]\n'
                    '  by file.path\n'
                    '  [ process where true ]')
        codes = set()
        for source in (trailing, dangling):
            with self.assertRaises(Refusal) as caught:
                parse_eql(source)
            codes.add(caught.exception.code)
        self.assertEqual(codes, {"EQL_PER_STEP_BY_NOT_LOWERED"},
                         "both shapes are the same construct and must refuse "
                         "under the same code")

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
