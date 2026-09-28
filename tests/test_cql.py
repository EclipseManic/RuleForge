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

    def test_the_label_says_which_slice_this_is(self):
        import jobs as _jobs
        self.assertIn("table",
                      _jobs.DIALECTS["logscale"]["label"].lower(),
                      "the dialect label must say this is the filter+table "
                      "slice, or the UI claims a language that is 5% done")


if __name__ == "__main__":
    unittest.main()
