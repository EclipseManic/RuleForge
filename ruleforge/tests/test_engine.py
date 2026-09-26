"""Tests for the RuleForge engine.

The tests that matter most are the negative ones: a filter on an absent field must
NOT report a clean non-match. That single property is the difference between a tool
an analyst can trust and one that will eventually lie to them about their own data.
"""

from __future__ import annotations

import pathlib
import sys
import unittest
from decimal import Decimal

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from ruleforge.engine import (  # noqa: E402
    ABSENT,
    UNDECIDED,
    Aggregate,
    Comparison,
    Duration,
    Emit,
    FieldExpr,
    FieldRef,
    Filter,
    Frame,
    Literal,
    Measure,
    Read,
    Refusal,
    RuleIR,
    SourceSelector,
    TimeRef,
    Verdict,
    and_,
    compare,
    evaluate,
    not_,
    or_,
    presence,
)

SRC = SourceSelector(name="events")


def read(node_id="r"):
    return Read(id=node_id, selector=SRC)


def emit(source, node_id="o"):
    return Emit(id=node_id, input=source)


def field(name):
    return FieldExpr(FieldRef(name))


def eq(name, value):
    return Comparison("=", field(name), Literal(value))


class ValueModelTests(unittest.TestCase):
    def test_absent_null_and_empty_are_three_different_things(self):
        from ruleforge.engine import has_value
        # ABSENT and NULL carry no information, so they fail. The empty string
        # DOES carry information: a field that is present and empty is a real,
        # observable fact about the event, and a rule that could not see it would
        # treat "logged in with an empty username" as "no username field at all".
        self.assertFalse(has_value(ABSENT))
        self.assertFalse(has_value(None))
        self.assertTrue(has_value(""))
        self.assertTrue(has_value(0))
        self.assertTrue(has_value(False))

    def test_absent_null_and_empty_are_not_interchangeable(self):
        """The distinction has to survive comparison, not just a helper."""
        self.assertIs(compare(ABSENT, "", "=").value, UNDECIDED)
        self.assertIs(compare(None, "", "=").value, UNDECIDED)
        self.assertIs(compare("", "", "=").value, True)

    def test_an_absent_field_cannot_be_ordered(self):
        result = compare(ABSENT, 5, "<")
        self.assertIs(result.value, UNDECIDED)
        self.assertIn("absent", result.reason)

    def test_a_null_field_cannot_be_ordered_either(self):
        self.assertIs(compare(None, 5, "<").value, UNDECIDED)

    def test_not_undecided_is_never_true(self):
        """The single most important line in the value model.

        NOT UNDECIDED returning True would turn every undecidable row into a
        match, which is the worst possible failure: a rule that fires on data it
        never actually examined.
        """
        self.assertIs(not_(UNDECIDED), UNDECIDED)
        self.assertIs(not_(True), False)
        self.assertIs(not_(False), True)

    def test_and_with_one_false_is_false(self):
        self.assertIs(and_(True, False, UNDECIDED), False)

    def test_and_of_all_undecided_is_undecided(self):
        self.assertIs(and_(UNDECIDED, UNDECIDED), UNDECIDED)

    def test_or_with_one_true_is_true(self):
        self.assertIs(or_(False, True, UNDECIDED), True)

    def test_string_number_comparison_is_undecided(self):
        self.assertIs(compare("abc", 5, "<").value, UNDECIDED)

    def test_numeric_strings_compare_as_numbers(self):
        self.assertIs(compare("10", "9", ">").value, True)

    def test_presence_asks_about_the_field(self):
        self.assertIs(presence("x", "exists").value, True)
        self.assertIs(presence(ABSENT, "exists").value, False)
        self.assertIs(presence(None, "is_not_null").value, False)
        self.assertIs(presence("x", "is_not_null").value, True)


class FilterHonestyTests(unittest.TestCase):
    """The property the whole engine exists to guarantee."""

    def test_a_filter_on_an_absent_field_does_not_claim_a_clean_no_match(self):
        ir = RuleIR(rule_id="t", nodes=(
            read(),
            Filter(id="f", input="r", condition=eq("granted_access", "0x1fffff")),
            emit("f"),
        ), output="o")
        result = evaluate(ir, [{"event_id": 10}, {"event_id": 11}])

        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        codes = [c.code for c in result.caveats]
        self.assertIn("FILTER_UNDECIDABLE_ROWS", codes)
        self.assertIn("NOTHING_DECIDED", [result.reason.code] if result.reason else [])

    def test_a_filter_that_really_does_not_match_says_no_match(self):
        """The counterpart, so the refusal above cannot be a blanket cop-out."""
        ir = RuleIR(rule_id="t", nodes=(
            read(),
            Filter(id="f", input="r", condition=eq("event_id", 10)),
            emit("f"),
        ), output="o")
        result = evaluate(ir, [{"event_id": 4624}, {"event_id": 4625}])
        self.assertIs(result.verdict, Verdict.NO_MATCH)
        self.assertEqual(result.rows, ())

    def test_a_filter_that_matches_reports_matched(self):
        ir = RuleIR(rule_id="t", nodes=(
            read(),
            Filter(id="f", input="r", condition=eq("event_id", 10)),
            emit("f"),
        ), output="o")
        result = evaluate(ir, [{"event_id": 10}, {"event_id": 4624}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 1)

    def test_mixed_present_and_absent_rows_still_match_what_they_can(self):
        ir = RuleIR(rule_id="t", nodes=(
            read(),
            Filter(id="f", input="r", condition=eq("event_id", 10)),
            emit("f"),
        ), output="o")
        result = evaluate(ir, [{"event_id": 10}, {"other": 1}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 1)
        codes = [c.code for c in result.caveats]
        self.assertIn("FILTER_UNDECIDABLE_ROWS", codes)


class FrameConstructionTests(unittest.TestCase):
    """Impossible frames cannot be built. That is the design."""

    def test_a_sliding_frame_needs_a_step(self):
        with self.assertRaises(Refusal) as caught:
            Frame(kind="sliding", size=Duration(600), time_ref=TimeRef("t"))
        self.assertEqual(caught.exception.code, "FRAME_REQUIRES_STEP")

    def test_a_step_on_a_tumbling_frame_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            Frame(kind="tumbling", size=Duration(600), step=Duration(60),
                  time_ref=TimeRef("t"))
        self.assertEqual(caught.exception.code, "FRAME_STEP_NOT_APPLICABLE")

    def test_explicit_alignment_needs_an_anchor(self):
        with self.assertRaises(Refusal) as caught:
            Frame(kind="tumbling", size=Duration(600), alignment="explicit",
                  time_ref=TimeRef("t"))
        self.assertEqual(caught.exception.code, "FRAME_REQUIRES_ANCHOR")

    def test_an_anchor_on_an_epoch_frame_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            Frame(kind="tumbling", size=Duration(600), anchor=FieldRef("t"),
                  time_ref=TimeRef("t"))
        self.assertEqual(caught.exception.code, "FRAME_ANCHOR_NOT_APPLICABLE")

    def test_a_window_needs_a_time_field(self):
        with self.assertRaises(Refusal) as caught:
            Frame(kind="tumbling", size=Duration(600))
        self.assertEqual(caught.exception.code, "FRAME_REQUIRES_TIME_REF")

    def test_a_duration_must_not_be_negative(self):
        from ruleforge.engine.values import Refusal as R
        with self.assertRaises(R) as caught:
            Duration(Decimal(-1))
        self.assertEqual(caught.exception.code, "DURATION_NEGATIVE")

    def test_a_zero_duration_is_allowed_for_a_temporal_lower_bound(self):
        """`a logon from 0 to 10 minutes after the access` is the ordinary reading.
        Refusing zero forced it to be written as 1 second, an off-by-one that
        shifted a boundary invisibly."""
        self.assertEqual(Duration(0).seconds, 0)
        self.assertFalse(Duration(0).is_positive)

    def test_a_zero_length_window_is_refused(self):
        """Zero is fine for a bound but not for a window: a zero-length window
        contains no events, so every count over it is zero."""
        with self.assertRaises(Refusal) as caught:
            Frame(kind="tumbling", size=Duration(0), time_ref=TimeRef("t"))
        self.assertEqual(caught.exception.code, "FRAME_SIZE_NOT_POSITIVE")

    def test_durations_parse_the_way_vendors_write_them(self):
        self.assertEqual(Duration.parse("5m").seconds, 300)
        self.assertEqual(Duration.parse("2h").seconds, 7200)
        self.assertEqual(Duration.parse("300").seconds, 300)
        self.assertEqual(str(Duration.parse("300")), "5m")


class MeasureConstructionTests(unittest.TestCase):

    def test_arg_max_needs_two_fields(self):
        with self.assertRaises(Refusal) as caught:
            Measure("v", "arg_max", field=FieldRef("val"))
        self.assertEqual(caught.exception.code, "ARG_EXTREME_REQUIRES_TWO_FIELDS")

    def test_arg_max_accepts_two_fields(self):
        m = Measure("v", "arg_max", field=FieldRef("val"), by=FieldRef("score"))
        self.assertEqual(m.by.name, "score")

    def test_an_ordering_field_on_count_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            Measure("n", "count", by=FieldRef("score"))
        self.assertEqual(caught.exception.code, "ORDERING_FIELD_NOT_APPLICABLE")

    def test_two_measures_cannot_share_an_output_name(self):
        with self.assertRaises(Refusal) as caught:
            Aggregate(id="a", input="r", measures=(
                Measure("n", "count"), Measure("n", "count_distinct",
                                               field=FieldRef("u"))),
                frame=Frame(kind="per_event"))
        self.assertEqual(caught.exception.code, "AGGREGATE_DUPLICATE_MEASURE")


class WindowingTests(unittest.TestCase):

    def _aggregate(self, frame):
        return Aggregate(id="a", input="r",
                         measures=(Measure("n", "count"),), frame=frame)

    def test_tumbling_produces_one_bucket_per_grid_position(self):
        ir = RuleIR(rule_id="t", nodes=(
            read(), self._aggregate(Frame(kind="tumbling", size=Duration(300),
                                          time_ref=TimeRef("t"))),
            emit("a"),
        ), output="o")
        result = evaluate(ir, [{"t": 0}, {"t": 100}, {"t": 400}], time_field="t")
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 2)
        self.assertEqual(sorted(dict(r.values)["n"] for r in result.rows), [1, 2])

    def test_sliding_produces_overlapping_windows_not_fewer_ones(self):
        """THE TEST THAT MATTERS for sliding.

        A tumbling window over this data gives 2 buckets. A 300s window on a 60s
        grid over the same span gives ~6 overlapping windows. If sliding silently
        returned tumbling results, this count would be 2 and the rule would report
        the right number for the wrong time range.
        """
        ir = RuleIR(rule_id="t", nodes=(
            read(), self._aggregate(Frame(kind="sliding", size=Duration(300),
                                          step=Duration(60), time_ref=TimeRef("t"))),
            emit("a"),
        ), output="o")
        sliding = evaluate(ir, [{"t": 0}, {"t": 100}, {"t": 400}], time_field="t")
        self.assertIs(sliding.verdict, Verdict.MATCHED)
        self.assertGreater(len(sliding.rows), 2,
                           "a sliding grid must emit more windows than tumbling")

    def test_rows_without_a_timestamp_are_reported_not_dropped_silently(self):
        ir = RuleIR(rule_id="t", nodes=(
            read(), self._aggregate(Frame(kind="tumbling", size=Duration(300),
                                          time_ref=TimeRef("t"))),
            emit("a"),
        ), output="o")
        result = evaluate(ir, [{"t": 0}, {"no_time_here": True}], time_field="t")
        codes = [c.code for c in result.caveats]
        self.assertIn("ROWS_WITHOUT_TIME", codes)


class GraphValidationTests(unittest.TestCase):

    def test_a_dangling_input_is_refused(self):
        ir = RuleIR(rule_id="t", nodes=(
            read(), Filter(id="f", input="missing", condition=eq("a", 1)),
            emit("f"),
        ), output="o")
        result = evaluate(ir, [{"a": 1}])
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.code, "DANGLING_INPUT")

    def test_a_cycle_is_refused(self):
        # f1 reads f2 which reads f1, so no topological order exists.
        ir = RuleIR(rule_id="t", nodes=(
            Filter(id="f1", input="f2", condition=eq("a", 1)),
            Filter(id="f2", input="f1", condition=eq("a", 1)),
            emit("f1"),
        ), output="o")
        result = evaluate(ir, [{"a": 1}])
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.code, "GRAPH_CYCLE")

    def test_the_output_must_be_an_emit(self):
        ir = RuleIR(rule_id="t", nodes=(read(),), output="r")
        result = evaluate(ir, [{"a": 1}])
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.code, "OUTPUT_NOT_AN_EMIT")

    def test_an_unreachable_node_is_refused(self):
        ir = RuleIR(rule_id="t", nodes=(
            read(), Filter(id="f", input="r", condition=eq("a", 1)),
            Filter(id="orphan", input="r", condition=eq("a", 2)),
            emit("f"),
        ), output="o")
        result = evaluate(ir, [{"a": 1}])
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.code, "UNREACHABLE_NODES")

    def test_a_bare_field_is_not_accepted_as_a_predicate(self):
        """A bare field is truthy for any non-empty string, so accepting one would
        match nearly every row instead of failing."""
        ir = RuleIR(rule_id="t", nodes=(
            read(), Filter(id="f", input="r", condition=field("anything")),
            emit("f"),
        ), output="o")
        result = evaluate(ir, [{"a": 1}])
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.code, "PREDICATE_INCOMPLETE")


class RegexTests(unittest.TestCase):

    def test_a_posix_extended_pattern_runs(self):
        """A regex is a PREDICATE, so it stands alone as the filter condition.

        Wrapping it in a Comparison would ask "is this string equal to the boolean
        result", which is undecidable on every row -- so the rule would quietly
        match nothing instead of erroring.
        """
        from ruleforge.engine import Call
        ir = RuleIR(rule_id="t", nodes=(
            read(),
            Filter(id="f", input="r", condition=Call(
                "matches_regex", (field("a"), Literal("^x")),
                dialect="posix_extended")),
            emit("f"),
        ), output="o")
        self.assertIs(evaluate(ir, [{"a": "xyz"}]).verdict, Verdict.MATCHED)
        self.assertIs(evaluate(ir, [{"a": "abc"}]).verdict, Verdict.NO_MATCH)

    def test_wrapping_a_predicate_in_a_comparison_is_not_a_predicate(self):
        from ruleforge.engine import Call
        ir = RuleIR(rule_id="t", nodes=(
            read(),
            Filter(id="f", input="r", condition=Comparison(
                "=", field("a"),
                Call("matches_regex", (field("a"), Literal("^x")),
                     dialect="posix_extended"))),
            emit("f"),
        ), output="o")
        result = evaluate(ir, [{"a": "xyz"}])
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)

    def test_a_regex_without_a_dialect_cannot_be_built(self):
        from ruleforge.engine import Call
        from ruleforge.engine.values import Refusal as R
        with self.assertRaises(R) as caught:
            Call("matches_regex", (field("a"), Literal("x")))
        self.assertEqual(caught.exception.code, "DIALECT_REQUIRED")

    def test_pcre_is_declared_but_never_executed(self):
        """Declaring PCRE is fine and loses nothing. Executing it is not possible
        here, and `compile_pattern` must say so rather than reach for `re`."""
        from ruleforge.engine import Call
        call = Call("matches_regex", (field("a"), Literal("^x")), dialect="pcre")
        self.assertEqual(call.dialect, "pcre")
        from ruleforge.engine.regex import EXECUTABLE_DIALECTS
        self.assertNotIn("pcre", EXECUTABLE_DIALECTS)

    def test_a_dialect_specific_construct_is_refused_by_name(self):
        """`\\d` means different things in different dialects, so evaluating it with
        Python's re and calling it POSIX would be a false claim."""
        from ruleforge.engine.regex import compile_pattern
        from ruleforge.engine.values import Refusal as R
        with self.assertRaises(R) as caught:
            compile_pattern("posix_extended", r"^\d+$")
        self.assertEqual(caught.exception.code, "REGEX_DIALECT_SPECIFIC")

    def test_pcre_cannot_be_compiled_at_all(self):
        from ruleforge.engine.regex import compile_pattern
        from ruleforge.engine.values import Refusal as R
        with self.assertRaises(R) as caught:
            compile_pattern("pcre", "^abc$")
        self.assertEqual(caught.exception.code, "REGEX_NOT_EXECUTABLE")

    def test_a_pattern_needs_a_dialect(self):
        from ruleforge.engine import Call
        from ruleforge.engine.values import Refusal as R
        with self.assertRaises(R) as caught:
            Call("matches_regex", (field("a"), Literal("x")))
        self.assertEqual(caught.exception.code, "DIALECT_REQUIRED")

    def test_a_dialect_on_a_plain_function_is_refused(self):
        from ruleforge.engine import Call
        from ruleforge.engine.values import Refusal as R
        with self.assertRaises(R) as caught:
            Call("lower", (field("a"),), dialect="pcre")
        self.assertEqual(caught.exception.code, "DIALECT_NOT_APPLICABLE")


class SerialisationTests(unittest.TestCase):

    def test_a_rule_serialises_with_its_node_types(self):
        from ruleforge.engine import RuleIR as R
        ir = R(rule_id="t", title="x", nodes=(
            read(), Filter(id="f", input="r", condition=eq("a", 1)), emit("f"),
        ), output="o")
        payload = ir.to_dict()
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual([n["__type__"] for n in payload["nodes"]],
                         ["Read", "Filter", "Emit"])

    def test_a_round_tripped_rule_refuses_loudly_rather_than_being_dead(self):
        """An earlier version handed raw dicts to the constructor, so a
        round-tripped rule looked complete and then failed every evaluation with
        NODE_TYPE_UNKNOWN. Cached and history-loaded rules were dead on arrival.
        It must now refuse AT LOAD TIME with a reason, not at run time."""
        from ruleforge.engine import RuleIR as R
        from ruleforge.engine.values import Refusal as Rf
        ir = R(rule_id="t", nodes=(read(), emit("r")), output="o")
        with self.assertRaises(Rf) as caught:
            R.from_dict(ir.to_dict())
        self.assertEqual(caught.exception.code, "ROUND_TRIP_NOT_IMPLEMENTED")
        self.assertIn("looks complete but refuses to run", caught.exception.message)

    def test_a_wrong_schema_version_is_refused(self):
        from ruleforge.engine import RuleIR as R
        from ruleforge.engine.values import Refusal as Rf
        with self.assertRaises(Rf) as caught:
            R.from_dict({"schema_version": "99.0", "rule_id": "t",
                         "nodes": [], "output": "o"})
        self.assertEqual(caught.exception.code, "SCHEMA_VERSION_MISMATCH")


class StandaloneTests(unittest.TestCase):
    """This tool must not depend on the project it sits inside."""

    def test_the_engine_imports_nothing_from_the_parent_project(self):
        import ast
        engine_dir = pathlib.Path(__file__).resolve().parent.parent / "engine"
        banned = {"rule_engine", "correlation", "pipeline", "detection_model",
                  "app", "explainer", "validators", "sigma_compiler",
                  "models", "kernel", "models.rule_ir", "kernel.eval"}
        for path in engine_dir.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and not node.level:
                    names = [node.module or ""]
                for name in names:
                    root = name.split(".")[0]
                    self.assertNotIn(
                        root, banned,
                        f"{path.name} imports {name}; RuleForge is standalone")

    def test_the_engine_never_widens_the_import_path(self):
        """Guard against a future 'just import the parent's helpers' shortcut.

        Matches `sys.path` specifically rather than any attribute ending in
        `path`, because `FieldRef.path` is a legitimate field-nesting attribute
        and flagging it would make this test useless.
        """
        import ast
        engine_dir = pathlib.Path(__file__).resolve().parent.parent / "engine"
        for path in engine_dir.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Attribute):
                    continue
                if node.attr != "path":
                    continue
                owner = node.value
                if isinstance(owner, ast.Name) and owner.id == "sys":
                    self.fail(f"{path.name} touches sys.path at line {node.lineno}; "
                              f"RuleForge is standalone and has no business widening "
                              f"the import path")


if __name__ == "__main__":
    unittest.main()
