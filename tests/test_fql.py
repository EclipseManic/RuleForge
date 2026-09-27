"""CrowdStrike FQL, slice 1: a flat API filter, honestly.

FQL is `property:[operator]value` with `+` for AND, `,` for OR, `(...)` for
grouping. It lowers to a single `Filter` and nothing else -- it cannot be
half-done, because it is either a filter or a refusal.

THIS IS NOT CQL, and the parser enforces that. CQL's `field = "value"`, its
pipes, and its word operators are refused here with the confusion named: a
combined grammar would accept strings valid in neither language, and misread
strings valid in one as the other.

Values by shape: single-quoted strings, `[ 'exact' ]` (case-sensitive),
single-quoted UTC dates, lowercase `true`/`false`, unquoted integers, and
`null` -- which the IR distinguishes from ABSENT, so equality against it lowers
exactly. `*` wildcards and `~` text-matches are refused by name: a literal
equality would match almost nothing where the wildcard was meant to catch, and
the IR's regex neither tokenises nor ignores case.

At most 20 properties per statement, enforced and counted here, because the
21st would silently not filter server-side.
"""

import unittest

import jobs
from dialects.fql import parse_fql
from dialects.fql_ir import MAX_PROPERTIES, count_terms, lower as lower_fql
from engine.values import Refusal


def _round_trip(source: str) -> str:
    outcome = jobs.author("falcon", source, "r1")
    assert outcome.ok, f"{source} should lower: {outcome.refusal}"
    return outcome.rendered


class FlatFiltersLower(unittest.TestCase):
    def test_a_hostname_filter_round_trips(self):
        self.assertEqual(_round_trip("hostname:'g'"), "hostname:'g'")

    def test_an_and_filter_round_trips(self):
        self.assertEqual(
            _round_trip("hostname:'a'+platform_name:'Windows'"),
            "hostname:'a'+platform_name:'Windows'")

    def test_an_or_filter_with_groups_round_trips(self):
        """A nested `BoolOp` is always parenthesised; the top level never is.
        Parens mark nesting, not count, so this is stable regardless of how
        many terms each side holds."""
        self.assertEqual(
            _round_trip("(hostname:'a'),(hostname:'b'+platform_name:'Linux')"),
            "hostname:'a',(hostname:'b'+platform_name:'Linux')")

    def test_integers_booleans_and_dates_lower(self):
        self.assertEqual(_round_trip("posts.count:>10"), "posts.count:>10")
        self.assertEqual(_round_trip("featured:true"), "featured:true")
        self.assertEqual(
            _round_trip("last_seen:<='2021-08-31T12:00:00Z'"),
            "last_seen:<='2021-08-31T12:00:00Z'")

    def test_exact_match_brackets_lower_as_equality(self):
        """`[ 'value' ]` forces an exact, case-sensitive match -- which is what
        a plain equality already is here, so it lowers exactly rather than
        growing a new node for no behavioural difference."""
        self.assertEqual(_round_trip("hostname:['exact']"), "hostname:'exact'")

    def test_null_lowers_exactly(self):
        self.assertEqual(_round_trip("field:null"), "field:null")


class PrecedenceAndGrouping(unittest.TestCase):
    """`+` (AND) binds tighter than `,` (OR), and parens group -- verified as
    structure, because the SPL `where` fix proved a tuple-order bug here is a
    false negative."""

    def test_and_binds_tighter_than_or(self):
        from engine.ir import BoolOp
        ir, _ = lower_fql(parse_fql("a:'1',b:'2'+c:'3'"))
        root = next(n for n in ir.nodes
                    if type(n).__name__ == "Filter").condition
        self.assertIsInstance(root, BoolOp)
        self.assertEqual(root.op, "or")
        self.assertEqual(root.operands[1].op, "and")

    def test_a_quoted_plus_is_not_split(self):
        """`hostname:'a+b'` is one term whose value contains the separator."""
        self.assertEqual(_round_trip("hostname:'a+b'"), "hostname:'a+b'")


class EverythingElseIsRefusedByName(unittest.TestCase):
    def test_cql_pipes_are_refused_as_cql(self):
        with self.assertRaises(Refusal) as caught:
            parse_fql('hostname:"x" | table a')
        self.assertEqual(caught.exception.code, "FQL_NOT_CQL")

    def test_cql_word_operators_are_refused_as_cql(self):
        with self.assertRaises(Refusal) as caught:
            parse_fql("hostname:'x' AND platform:'y'")
        self.assertEqual(caught.exception.code, "FQL_NOT_CQL")

    def test_cql_equals_without_colon_is_refused_as_cql(self):
        with self.assertRaises(Refusal) as caught:
            parse_fql('hostname = "x"')
        self.assertEqual(caught.exception.code, "FQL_NOT_CQL")

    def test_wildcards_are_refused_not_read_as_literals(self):
        with self.assertRaises(Refusal) as caught:
            lower_fql(parse_fql("hostname:'g*'"))
        self.assertEqual(caught.exception.code, "FQL_WILDCARD_NOT_LOWERED")

    def test_text_match_is_refused_not_read_as_regex(self):
        """`field:~value` is a tokenising, case-insensitive match. The `~`
        without a colon is not valid FQL shape at all, so the operator form is
        what is tested."""
        with self.assertRaises(Refusal) as caught:
            lower_fql(parse_fql("field:~value"))
        self.assertEqual(caught.exception.code, "FQL_TEXT_MATCH_NOT_LOWERED")

    def test_more_than_twenty_properties_is_refused(self):
        text = "+".join(f"f{i}:'v'" for i in range(MAX_PROPERTIES + 1))
        self.assertEqual(count_terms(text), MAX_PROPERTIES + 1)
        with self.assertRaises(Refusal) as caught:
            lower_fql(parse_fql(text))
        self.assertEqual(caught.exception.code, "FQL_TOO_MANY_PROPERTIES")

    def test_exactly_twenty_properties_still_works(self):
        text = "+".join(f"f{i}:'v'" for i in range(MAX_PROPERTIES))
        self.assertEqual(
            jobs.author("falcon", text, "r1").rendered.replace("'", "'"), text)

    def test_no_artifact_is_produced_for_cql_input(self):
        outcome = jobs.author("falcon", 'hostname = "x"', "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"], "FQL_NOT_CQL")

    def test_the_label_says_which_slice_this_is(self):
        import jobs as _jobs
        self.assertIn("flat filter",
                      _jobs.DIALECTS["falcon"]["label"].lower(),
                      "the dialect label must say this is the flat-filter "
                      "slice, or the UI claims a language that is 5% done")


if __name__ == "__main__":
    unittest.main()
