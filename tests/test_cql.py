"""CrowdStrike CQL (LogScale), slice 1: a filter plus `| table`, honestly.

CQL is a PIPELINE language: `filter | table a, b`. The filter uses `=`/`!=`
comparisons with `AND`/`OR`/`NOT`, `#tag` fields (indexed), `@meta` fields,
and bare event fields. This slice lowers the filter onto one `Filter` and
`| table a, b` onto `Derive(kind="fields")` -- both existing nodes, no
approximations.

THIS IS NOT FQL, and each refuses the other's shape by name. FQL's
`property:value` with a colon and no `=` is refused here as FQL; CQL pipe and
word-operator shapes are refused there as CQL. A combined grammar would accept
strings valid in neither language.

SHIPPED: a filter, plus the pipes `| table`, `| sort`, `| rename`, `| name :=`
(single operand: a field, quoted string, or number), `| count()` (nullary), and
`in()`. Pipes lower IN THE ORDER WRITTEN, each kind at most once.

Refused by name in this slice: wildcards, regex, functions, `field = *` (a
presence test needs a node this lowering does not build), `now()`, `join()` (a
LogScale FILTER function whose `include` fills missing fields with the empty
string), `count(field=)` and grouped `count(by=)`, an arithmetic or function RHS
to `:=`, a repeated pipe, an empty filter, and an empty `table`.
"""

import unittest
import jobs
from dialects.cql import parse_cql
from dialects.cql_ir import lower as lower_cql
from engine import evaluate
from engine.values import Refusal



def _round_trip(source: str) -> str:
    outcome = jobs.author("logscale", source, "r1")
    assert outcome.ok, f"{source} should lower: {outcome.refusal}"
    return outcome.rendered


class FilterAndTableLower(unittest.TestCase):
    def test_a_tag_filter_round_trips(self):
        self.assertEqual(
            _round_trip("#event_simpleName=ProcessRollup2"),
            "event_simpleName = ProcessRollup2")

    def test_a_field_filter_with_and_round_trips(self):
        """Quoted values that are single tokens render bare -- `"admin"` and
        `admin` mean the same in CQL, so the normalisation is exact, not a
        loss. A value with a space would stay quoted."""
        self.assertEqual(
            _round_trip('UserName = "admin" AND #event_simpleName=ProcessRollup2'),
            'UserName = admin AND event_simpleName = ProcessRollup2')

    def test_a_meta_field_filter_round_trips(self):
        self.assertEqual(_round_trip("@timestamp > 100"),
                         "@timestamp > 100")

    def test_a_table_pipe_round_trips(self):
        self.assertEqual(
            _round_trip("#event_simpleName=ProcessRollup2 "
                        "| table ComputerName, ImageFileName"),
            "event_simpleName = ProcessRollup2 | table ComputerName, "
            "ImageFileName")

    def test_comparison_operators_lower(self):
        for source, expected in (
            ("a != 1", "a != 1"),
            ("a >= 1", "a >= 1"),
            ("a <= 1", "a <= 1"),
            ("a > 1", "a > 1"),
            ("a < 1", "a < 1"),
        ):
            with self.subTest(source=source):
                self.assertEqual(_round_trip(source), expected)


class PrecedenceAndGrouping(unittest.TestCase):
    """NOT > AND > OR, parens honoured, quoted separators left alone -- the
    same three properties every other dialect in this project establishes,
    because the same one-line-split bug would produce the same false negative
    here."""

    def test_or_with_and_is_or_outermost(self):
        self.assertEqual(
            _round_trip("a = 1 OR b = 2 AND c = 3"),
            "a = 1 OR (b = 2 AND c = 3)")

    def test_parentheses_are_honoured(self):
        self.assertEqual(
            _round_trip("a = 1 OR (b = 2 AND c = 3)"),
            "a = 1 OR (b = 2 AND c = 3)")

    def test_a_quoted_and_is_not_split(self):
        self.assertEqual(_round_trip('msg = "x AND y"'),
                         'msg = "x AND y"')

    def test_not_binds_tightest(self):
        """`NOT =` normalises to `!=`, which is the same comparison -- not a
        dropped negation."""
        self.assertEqual(_round_trip("NOT a = 1 AND b = 2"),
                         "a != 1 AND b = 2")


class EverythingElseIsRefusedByName(unittest.TestCase):
    def test_fql_shapes_are_refused_as_fql(self):
        """`hostname:'x'` is FQL's `property:value`, not broken CQL."""
        with self.assertRaises(Refusal) as caught:
            parse_cql("hostname:'x'")
        self.assertEqual(caught.exception.code, "CQL_NOT_FQL")

    def test_wildcards_are_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower_cql(parse_cql('UserName = "admin*"'))
        self.assertEqual(caught.exception.code, "CQL_WILDCARD_NOT_LOWERED")

    def test_regex_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower_cql(parse_cql("CommandLine=/pattern/i"))
        self.assertEqual(caught.exception.code, "CQL_REGEX_NOT_LOWERED")

    def test_other_pipes_are_refused_by_name(self):
        with self.assertRaises(Refusal) as caught:
            parse_cql("#event_simpleName=ProcessRollup2 | join x")
        self.assertEqual(caught.exception.code, "CQL_PIPE_NOT_LOWERED")

    def test_double_table_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_cql("a = 1 | table a | table b")
        self.assertEqual(caught.exception.code, "CQL_TABLE_TWICE")


class SortAndRenameLower(unittest.TestCase):
    """`| sort(field[, limit=N])` and `| rename old as new` use existing
    nodes -- `Arrange` and `Derive(kind="rename")` -- so no new IR was needed.
    Stages lower in pipeline order, because reordering them returns different
    events."""

    def test_sort_round_trips(self):
        self.assertEqual(
            _round_trip("#event_simpleName=ProcessRollup2 | sort(UserName)"),
            "event_simpleName = ProcessRollup2 | sort(UserName)")

    def test_sort_with_limit_round_trips(self):
        self.assertEqual(
            _round_trip("#event_simpleName=ProcessRollup2 "
                        "| sort(UserName, limit=10)"),
            "event_simpleName = ProcessRollup2 | sort(UserName, limit=10)")

    def test_rename_round_trips_old_as_new(self):
        """The order is `rename <old> as <new>` -- asserted, because the SPL
        main loop and subpipeline once disagreed about this in opposite
        directions."""
        self.assertEqual(
            _round_trip("#event_simpleName=ProcessRollup2 | rename a as b"),
            "event_simpleName = ProcessRollup2 | rename a as b")

    def test_stages_keep_pipeline_order(self):
        """`sort` then `table` sorts full rows and projects the sorted ones;
        the reverse would sort one-column rows. The order written is the order
        lowered."""
        self.assertEqual(
            _round_trip("#event_simpleName=ProcessRollup2 | sort(UserName) "
                        "| table a, b"),
            "event_simpleName = ProcessRollup2 | sort(UserName) "
            "| table a, b")

    def test_sort_with_unknown_arg_is_refused(self):
        """A direction keyword this parser does not know would be silently
        defaulted to ascending -- so it is refused instead."""
        with self.assertRaises(Refusal) as caught:
            parse_cql("a = 1 | sort(x, order=desc)")
        self.assertEqual(caught.exception.code, "CQL_SORT_ARG_UNKNOWN")

    def test_sort_with_non_positive_limit_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_cql("a = 1 | sort(x, limit=0)")
        self.assertEqual(caught.exception.code,
                         "CQL_SORT_LIMIT_NOT_POSITIVE")

    def test_rename_without_as_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_cql("a = 1 | rename a b")
        self.assertEqual(caught.exception.code, "CQL_RENAME_NOT_A_PAIR")

    def test_double_sort_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_cql("a = 1 | sort(x) | sort(y)")
        self.assertEqual(caught.exception.code, "CQL_SORT_TWICE")

    def test_double_rename_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_cql("a = 1 | rename a as b | rename c as d")
        self.assertEqual(caught.exception.code, "CQL_RENAME_TWICE")

    def test_an_unclosed_paren_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_cql("a = 1 | sort(x")
        self.assertEqual(caught.exception.code, "CQL_PIPE_MALFORMED")

    def test_exists_check_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower_cql(parse_cql("a = *"))
        self.assertEqual(caught.exception.code, "CQL_EXISTS_NOT_LOWERED")

    def test_no_artifact_is_produced_for_a_sort_pipe(self):
        outcome = jobs.author("logscale", "a = 1 | sort x", "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"], "CQL_PIPE_NOT_LOWERED")


class AssignLowersAsEval(unittest.TestCase):
    """`| name := operand` ADDS a column and keeps the rest -- `eval`
    semantics, not `rename`. Getting these backwards drops the original
    column, which is the exact bug the SPL renderer once shipped."""

    def test_field_copy_round_trips(self):
        self.assertEqual(_round_trip("a = 1 | x := b"), "a = 1 | x := b")

    def test_string_constant_stays_quoted(self):
        """`x := lit` copies FIELD lit; `x := "lit"` assigns the CONSTANT.
        Rendering the constant bare would turn a fixed value into a field
        read -- a different rule that fails open where the field is absent."""
        self.assertEqual(_round_trip('a = 1 | x := "lit"'),
                         'a = 1 | x := "lit"')

    def test_number_round_trips(self):
        self.assertEqual(_round_trip("a = 1 | x := 5"), "a = 1 | x := 5")

    def test_assign_is_eval_not_rename(self):
        """Structural: the node must say `eval`, because `rename` REMOVES the
        original column and `eval` KEEPS it. A later term reading the original
        works under one and finds nothing under the other."""
        from engine.ir import Derive
        ir, _ = lower_cql(parse_cql("a = 1 | x := b"))
        derives = [n for n in ir.nodes if isinstance(n, Derive)]
        self.assertEqual(len(derives), 1)
        self.assertEqual(derives[0].kind, "eval")

    def test_arithmetic_rhs_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_cql("a = 1 | x := a + b")
        # `a + b` contains no paren/quote issue; the refusal comes from the
        # operand check. Either code below names the real reason.
        self.assertIn(caught.exception.code,
                      ("CQL_ASSIGN_EXPRESSION_NOT_LOWERED",))

    def test_function_rhs_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_cql("a = 1 | x := f(y)")
        self.assertIn(caught.exception.code,
                      ("CQL_ASSIGN_EXPRESSION_NOT_LOWERED",
                       "CQL_PIPE_NOT_LOWERED"))

    def test_double_assign_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_cql("a = 1 | x := 1 | y := 2")
        self.assertEqual(caught.exception.code, "CQL_ASSIGN_TWICE")

    def test_a_paren_inside_a_string_does_not_misroute(self):
        """`x := "a(b"` has a paren inside the value. The `(` branch is not
        quote-aware, so `:=` is checked first -- otherwise the string's paren
        misreads as a function call."""
        self.assertEqual(_round_trip('a = 1 | x := "a(b"'),
                         'a = 1 | x := "a(b"')

    def test_no_artifact_is_produced_for_an_expression_rhs(self):
        outcome = jobs.author("logscale", "a = 1 | x := a + b", "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"],
                         "CQL_ASSIGN_EXPRESSION_NOT_LOWERED")


class StageOrderIsTheWritersOrder(unittest.TestCase):
    """Pipes lower IN WRITTEN ORDER, because each transforms the previous one's
    output.

    This is a regression for a real shipped bug. The query model held one
    optional slot per pipe kind and the lowerer emitted them in a fixed order,
    so `| table a,b | sort(x)` -- project, then order by a column that SURVIVED
    the projection -- rendered as `| sort(x) | table a,b`, a different rule that
    can order by a column the analyst's own query had already dropped. The
    parser docstring even claimed order was preserved while the code did the
    opposite, which is worse than an undocumented bug: a false claim about an
    invariant.

    The discriminating test is the one whose output CHANGES with the order, not
    one that happens to render the same either way.
    """

    def test_project_then_sort_keeps_that_order(self):
        self.assertEqual(_round_trip("a = 1 | table a,b | sort(x)"),
                         "a = 1 | table a, b | sort(x)")

    def test_sort_then_project_keeps_that_order_too(self):
        self.assertEqual(_round_trip("a = 1 | sort(x) | table a,b"),
                         "a = 1 | sort(x) | table a, b")

    def test_node_order_matches_written_order(self):
        """Structural, not just textual: the IR must chain in the written
        order too, because a renderer that only looks right while the graph is
        wrong still returns different rows."""
        from engine.ir import Arrange, Derive
        ir, _ = lower_cql(parse_cql("a = 1 | table a,b | sort(x)"))
        self.assertLess([n.id for n in ir.nodes].index("derive1"),
                        [n.id for n in ir.nodes].index("arrange2"))
        stages = {n.id: n for n in ir.nodes}
        self.assertIsInstance(stages["derive1"], Derive)
        self.assertIsInstance(stages["arrange2"], Arrange)
        # And the arrange must CONSUME the projection, not run beside it.
        self.assertEqual(stages["arrange2"].input, "derive1")

    def test_four_stage_order_is_preserved(self):
        self.assertEqual(
            _round_trip("a = 1 | table a,b | x := 1 | sort(a) | rename b as c"),
            "a = 1 | table a, b | x := 1 | sort(a) | rename b as c")

    def test_assign_before_table_keeps_the_assigned_column(self):
        """`x := 1 | table a,x` keeps `x`; the reverse projects a column that
        does not exist yet and is a different query."""
        self.assertEqual(_round_trip("a = 1 | x := 1 | table a,x"),
                         "a = 1 | x := 1 | table a, x")

    def test_repeated_pipe_of_a_kind_is_still_refused(self):
        """The refactor from slots to a list must not have quietly widened
        what is accepted: a second `| sort` still rewrites the first."""
        for source, code in (("a = 1 | sort(x) | sort(y)", "CQL_SORT_TWICE"),
                             ("a = 1 | table a | table b", "CQL_TABLE_TWICE"),
                             ("a = 1 | rename a as b | rename b as c",
                              "CQL_RENAME_TWICE"),
                             ("a = 1 | x := 1 | y := 2",
                              "CQL_ASSIGN_TWICE")):
            with self.assertRaises(Refusal) as caught:
                parse_cql(source)
            self.assertEqual(caught.exception.code, code, source)

    def test_no_artifact_is_produced_when_order_would_be_rewritten(self):
        """The refusal must survive the rewrite: a rule whose pipes come back
        in a different order is worse than a refusal."""
        outcome = jobs.author("logscale", "a = 1 | sort(x) | sort(y)", "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"], "CQL_SORT_TWICE")


class TableActuallyProjectsAtEvaluation(unittest.TestCase):
    """`| table a,b` must DROP the other columns WHEN THE RULE RUNS.

    A regression for an engine defect, not a CQL one. `Derive.projects` is the
    flag that says "replace the row, do not extend it", and three renderers
    already believed it -- `spl_render`, `kql_render`, and `wazuh_render` each
    read it to decide whether to write a `<fields>` list. `eval_derive` did not.
    So `| table a,b` rendered as a projection and EXECUTED as a pass-through:
    every other column survived to the output, and the round trip looked
    perfect the whole way.

    It is invisible to a text-level test because nothing between a lowerer and a
    renderer executes the rule. A rule that says "show me these four fields" and
    returns twenty is a rule whose result nobody can trust, so these tests
    evaluate, and they assert the dropped column is gone.
    """

    ROWS = [{"a": "1", "b": "2", "SECRET": "must-not-be-emitted"}]

    def _values(self, source):
        ir, _ = lower_cql(parse_cql(source))
        return [dict(row.values) for row in evaluate(ir, list(self.ROWS)).rows]

    def test_table_drops_every_column_it_did_not_name(self):
        self.assertEqual(self._values("a = 1 | table a,b"),
                         [{"a": "1", "b": "2"}])

    def test_table_keeps_the_writers_column_order(self):
        """`| table b,a` is a DIFFERENT OUTPUT from `| table a,b`, so the
        projection preserves the order the analyst wrote rather than the row's."""
        self.assertEqual([list(row) for row in
                          self._values("a = 1 | table b,a")], [["b", "a"]])

    def test_a_field_the_row_lacks_stays_absent_not_null(self):
        """`| table a,nope` must not invent a null for `nope`. ABSENT is the
        honest value for "not in this event"; a fabricated null is the same
        fabrication `eval_derive` refuses elsewhere, and it would read as data."""
        self.assertEqual(self._values("a = 1 | table a,nope"), [{"a": "1"}])

    def test_rename_does_not_project(self):
        """The other half of the flag: `rename` EXTENDS. Getting this backwards
        is the exact bug the SPL renderer once shipped, so both directions are
        asserted -- a fix that made every Derive project would pass a
        table-only test."""
        self.assertEqual(self._values('a = 1 | rename b as c'),
                         [{"a": "1", "b": "2", "SECRET": "must-not-be-emitted",
                           "c": "2"}])

    def test_assign_does_not_project(self):
        self.assertEqual(self._values("a = 1 | x := 9"),
                         [{"a": "1", "b": "2", "SECRET": "must-not-be-emitted",
                           "x": 9}])


class HashPrefixIsOneRuleEverywhere(unittest.TestCase):
    """`#foo` AND `foo` NAME THE SAME FIELD, so one query must not spell it
    three different ways.

    A leading `#` is an indexing hint, not part of the name. It was stripped
    for `| sort`, `| rename`'s source, and the `:=` RHS -- and KEPT for `| table`
    and `| rename`'s target, so `#tag = 1 | table #tag, x | sort(#tag)` named
    `tag` in the filter, `#tag` in the projection, and `tag` in the sort. The
    projected column was literally NAMED `#tag`, so it was always absent: the
    rule rendered back perfectly and evaluated to a column the analyst never
    asked for.
    """

    def _round_trip(self, source):
        return _round_trip(source)

    def test_table_strips_the_hash(self):
        self.assertEqual(self._round_trip("#tag = 1 | table #tag, x"),
                         "tag = 1 | table tag, x")

    def test_one_query_spells_a_field_the_same_way_throughout(self):
        self.assertEqual(
            self._round_trip("#tag = 1 | table #tag, x | sort(#tag)"),
            "tag = 1 | table tag, x | sort(tag)")

    def test_rename_target_strips_the_hash_too(self):
        self.assertEqual(self._round_trip("#tag = 1 | rename a as #b"),
                         "tag = 1 | rename a as b")

    def test_assign_rhs_strips_the_hash(self):
        self.assertEqual(self._round_trip("#tag = 1 | x := #tag"),
                         "tag = 1 | x := tag")

    def test_count_executes_to_the_number_of_matching_rows(self):
        """`| count()` must COUNT, not merely render. A nullary `count` reads no
        field -- it is the number of rows that reached the stage, which is a
        different question from `count(field=x)`."""
        from engine import evaluate
        ir, _ = lower_cql(parse_cql("a = 1 | count()"))
        rows = [{"a": "1"}, {"a": "1"}, {"a": "2"}]
        self.assertEqual([dict(r.values) for r in evaluate(ir, rows).rows],
                         [{"count": 2}])

    def test_count_position_changes_the_answer_not_just_the_text(self):
        """`| count() | sort(a)` sorts ONE row; `| sort(a) | count()` sorts first.
        The aggregate collapses the rowset, so its position is semantics -- which
        is why `count` is a stage in the ordered list rather than a property."""
        self.assertEqual(_round_trip("a = 1 | count() | sort(a)"),
                         "a = 1 | count() | sort(a)")
        self.assertEqual(_round_trip("a = 1 | sort(a) | count()"),
                         "a = 1 | sort(a) | count()")
        from engine.ir import Aggregate, Arrange
        before = lower_cql(parse_cql("a = 1 | count() | sort(a)"))[0]
        self.assertLess([n.id for n in before.nodes].index("count1"),
                        [n.id for n in before.nodes].index("arrange2"))
        after = lower_cql(parse_cql("a = 1 | sort(a) | count()"))[0]
        self.assertLess([n.id for n in after.nodes].index("arrange1"),
                        [n.id for n in after.nodes].index("count2"))
        self.assertIsInstance(
            next(n for n in after.nodes if n.id == "count2"), Aggregate)
        self.assertIsInstance(
            next(n for n in after.nodes if n.id == "arrange1"), Arrange)

    def test_a_projection_after_a_count_is_refused_not_silently_emptied(self):
        """`| count() | table a` must NOT return a row with zero columns.

        A count collapses the rowset to one row carrying only `count`, so every
        event field is gone. Projecting `a` after it names a column that cannot
        exist, and the row came back as `{}` -- the count the rule just computed,
        silently destroyed, with no caveat and no refusal. To an analyst that
        looks identical to "no events matched", which is the worst possible
        shape for a wrong answer.

        It is decidable at lower time because the columns an Aggregate produces
        are its measure names, so there is nothing to discover later. A refusal
        beats a caveat here: the query is almost certainly a mistake, and a
        caveat on an empty row reads as data, not as an error.
        """
        for source in ("a = 1 | count() | table a",
                       "a = 1 | count() | table a, count"):
            with self.assertRaises(Refusal) as caught:
                lower_cql(parse_cql(source))
            self.assertEqual(caught.exception.code,
                             "CQL_TABLE_AFTER_AGGREGATE", source)
            self.assertIn("count", caught.exception.message,
                          "the refusal must name the one column that survives")

    def test_a_projection_of_the_measure_itself_still_works(self):
        """`table count` names the column that DOES survive, so it lowers --
        the refusal has to be about the missing field, not about being after a
        count at all."""
        from engine import evaluate
        ir, _ = lower_cql(parse_cql("a = 1 | count() | table count"))
        rows = [{"a": "1"}, {"a": "1"}]
        self.assertEqual([dict(r.values) for r in evaluate(ir, rows).rows],
                         [{"count": 2}])

    def test_a_count_after_a_projection_is_unaffected(self):
        """`| table a | count()` counts the projected rows -- the other order,
        and it must not inherit the refusal above."""
        from engine import evaluate
        ir, _ = lower_cql(parse_cql("a = 1 | table a | count()"))
        rows = [{"a": "1", "b": "x"}, {"a": "1", "b": "y"}]
        self.assertEqual([dict(r.values) for r in evaluate(ir, rows).rows],
                         [{"count": 2}])

    def test_count_uses_the_whole_input_frame(self):
        """A `tumbling` frame would emit ONE ROW PER WINDOW, so `| count()` would
        return several numbers where the rule asks for one. `per_event` is the
        whole-input frame, and is the same one SPL's spanless `stats` uses."""
        from engine.ir import Aggregate
        ir, _ = lower_cql(parse_cql("a = 1 | count()"))
        node = next(n for n in ir.nodes if isinstance(n, Aggregate))
        self.assertEqual(node.frame.kind, "per_event")
        self.assertIsNone(node.frame.size)

    def test_count_field_is_refused_rather_than_counted_unfielded(self):
        """`count(field=a)` counts rows where a is PRESENT. Reading it as
        `count()` returns a different number, and "different number" is exactly
        what a detection rule cannot be allowed to do."""
        for source, code in (
                ("a = 1 | count(field=a)", "CQL_COUNT_FIELD_NOT_LOWERED"),
                ("a = 1 | count(as x)", "CQL_COUNT_NOT_NULLARY"),
                ("a = 1 | count(by=a)", "CQL_COUNT_BY_NOT_LOWERED")):
            with self.assertRaises(Refusal) as caught:
                parse_cql(source)
            self.assertEqual(caught.exception.code, code, source)

    def test_join_is_refused_with_the_specific_reason(self):
        """`join()` is a LogScale FILTER function, not a stage, and its defaults
        are load-bearing: `mode` decides which rows survive, `max=1` takes one
        subquery row per key, and `include=[...]` fills a missing field with THE
        EMPTY STRING. This engine keeps absent and empty distinct, so the
        refusal has to name all of it -- "not implemented" would suggest a
        `Join` node is one commit away when the node has no field for a
        per-key fan-in limit."""
        for source in ('a = 1 | join(query={b=2}, field=c, key=d)',
                       "a = 1 | join(query={b=2}, mode=left)",
                       "a = 1 | join()"):
            with self.assertRaises(Refusal) as caught:
                parse_cql(source)
            self.assertEqual(caught.exception.code, "CQL_JOIN_NOT_LOWERED")
        message = caught.exception.message
        self.assertIn("EMPTY STRING", message,
                      "the refusal must name the include-fills-empty-string "
                      "behaviour, which is the one that would break this "
                      "engine's absent/empty distinction")
        self.assertIn("max=1", message,
                      "the refusal must name the per-key fan-in limit, which "
                      "the IR's Join node has nowhere to record")

    def test_no_artifact_is_produced_for_a_join(self):
        outcome = jobs.author("logscale",
                              "a = 1 | join(query={b=2}, field=c)", "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"], "CQL_JOIN_NOT_LOWERED")

    def test_a_hashed_column_is_actually_present_after_projection(self):
        """The point of stripping: the projected column must now resolve
        against a real field rather than being named after a hash."""
        from engine import evaluate
        ir, _ = lower_cql(parse_cql("#tag = 1 | table #tag"))
        rows = [{"tag": "1", "other": "x"}]
        self.assertEqual([dict(r.values) for r in evaluate(ir, rows).rows],
                         [{"tag": "1"}])


class MembershipLowersAsDisjunction(unittest.TestCase):
    """`in(field, [...])` IS a disjunction -- `field` equal to any one of the
    values -- so it lowers exactly onto `BoolOp("or", ...)` with no new node
    and no approximation."""

    def test_membership_round_trips_as_or(self):
        self.assertEqual(
            _round_trip('in(host, ["a", "b"])'),
            "host = a OR host = b")

    def test_values_keyword_form_round_trips(self):
        self.assertEqual(
            _round_trip('in(host, values=["a", "b", "c"])'),
            "host = a OR host = b OR host = c")

    def test_single_value_membership_is_bare_equality(self):
        """One value needs no `or` node -- and the renderer must not invent
        parens around a single comparison."""
        self.assertEqual(
            _round_trip('in(host, ["a"]) AND b = 1'),
            "host = a AND b = 1")

    def test_empty_list_is_refused(self):
        """`in(host, [])` matches nothing, so the rule could never fire.
        Refused rather than rendered, the way `head 0` is."""
        with self.assertRaises(Refusal) as caught:
            lower_cql(parse_cql("in(host, [])"))
        self.assertEqual(caught.exception.code, "CQL_IN_EMPTY")

    def test_malformed_membership_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower_cql(parse_cql("in(host)"))
        self.assertEqual(caught.exception.code, "CQL_IN_MALFORMED")

    def test_no_artifact_is_produced_for_an_empty_list(self):
        outcome = jobs.author("logscale", "in(host, [])", "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"], "CQL_IN_EMPTY")

    def test_the_label_says_which_slice_this_is(self):
        """Every shipped pipe is named, not just `table`.

        Asserting `"table" in label` passed against the ORIGINAL
        "filter + table" label too, so it could not fail: it was a test of
        nothing. The label is the contract the UI shows an analyst, so it must
        name each thing that actually works -- a label that understates the tool
        sends someone hunting for refusals that do not exist, and one that
        overstates it promises rules the tool will refuse.
        """
        import jobs as _jobs
        label = _jobs.DIALECTS["logscale"]["label"].lower()
        for shipped in ("table", "sort", "rename", ":=", "in", "count()"):
            self.assertIn(shipped, label,
                          f"the logscale label does not name `{shipped}`, which "
                          f"the slice accepts; label is {label!r}")


if __name__ == "__main__":
    unittest.main()
