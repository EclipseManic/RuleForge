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


class EverythingElseIsRefusedByName(unittest.TestCase):
    def test_sequence_is_refused_with_the_missing_piece_named(self):
        with self.assertRaises(Refusal) as caught:
            parse_eql("sequence by process.pid with maxspan=1h\n"
                      '  [ process where process.name == "regsvr32.exe" ]')
        self.assertEqual(caught.exception.code, "EQL_SEQUENCE_NOT_LOWERED")

    def test_sample_is_refused_with_the_missing_piece_named(self):
        with self.assertRaises(Refusal) as caught:
            parse_eql("sample by host\n"
                      '  [ file where file.extension == "exe" ]')
        self.assertEqual(caught.exception.code, "EQL_SAMPLE_NOT_LOWERED")

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

    def test_no_artifact_is_produced_for_a_sequence(self):
        outcome = jobs.author(
            "elastic", "sequence by process.pid with maxspan=1h\n"
            '  [ process where process.name == "regsvr32.exe" ]', "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"], "EQL_SEQUENCE_NOT_LOWERED")

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
