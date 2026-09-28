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

Refused by name in this slice: wildcards, regex, functions, `in()`, `:=`,
`field = *` (a presence test needs a node this lowering does not build), every
pipe except `table`, an empty filter, and an empty `table`.
"""

import unittest

import jobs
from dialects.cql import parse_cql
from dialects.cql_ir import lower as lower_cql
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
        import jobs as _jobs
        self.assertIn("table",
                      _jobs.DIALECTS["logscale"]["label"].lower(),
                      "the dialect label must say this is the filter+table "
                      "slice, or the UI claims a language that is 5% done")


if __name__ == "__main__":
    unittest.main()
