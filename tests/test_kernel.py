"""Contract tests for the Phase 3A semantic execution kernel.

Ships DARK. Nothing in the application imports `kernel/` yet, and ShadowModeTests asserts that.

The project's history is a history of green tests over fabricated behaviour, so the bias here
is toward assertions with EXACT expected values and tests that would fail if a semantic rule
were reverted. A test that restates the implementation proves nothing; these pin behaviour.
"""

import unittest
from pathlib import Path

from kernel.eval import evaluate_ir
from kernel.eval_errors import KERNEL_EVAL_CODES, EvaluationRefusal
from kernel.eval_expr import k_and, k_not, k_or
from kernel.eval_nodes import Sample
from kernel.eval_types import (EvalState, EvaluationResult, Row, Verdict,
                               canonical, primitive_of, row_key)
from models.rule_ir import (Aggregate, Arrange, BoolOp, Call, Comparison, Derive, Duration, Emit,
                            FieldExpr, FieldRef, Filter, Frame, InList, Join, Literal, Measure,
                            MeasureExpr, Pattern, Read, RuleIR, SetOp, SourceSelector, Stage,
                            TimeRef)

SRC = SourceSelector(name="events")


def sample(rows, read_id="r"):
    return Sample({read_id: rows})


def graph(*nodes, output="o", rule_id="t"):
    return RuleIR(rule_id=rule_id, nodes=tuple(nodes), output=output)


def read(node_id="r"):
    return Read(id=node_id, selector=SRC)


def emit(source, node_id="o"):
    return Emit(id=node_id, input=source)


def passthrough(rows, read_id="r"):
    return graph(read(read_id), emit(read_id), rows=rows)


def evaluate(rows, *nodes, output="o", read_id="r"):
    ir = graph(*nodes, output=output)
    return evaluate_ir(ir, sample(rows, read_id))


class StateInvariantTests(unittest.TestCase):
    """`not_evaluated` must be structurally unable to carry output."""

    def test_an_unevaluated_result_cannot_carry_rows(self):
        with self.assertRaises(ValueError):
            EvaluationResult(state=EvalState.NOT_EVALUATED, reason=object(),
                             rows=(Row(values={"a": 1}, index=0),))

    def test_an_unevaluated_result_cannot_carry_columns(self):
        with self.assertRaises(ValueError):
            EvaluationResult(state=EvalState.NOT_EVALUATED, reason=object(), columns=("a",))

    def test_an_unevaluated_result_must_name_its_reason(self):
        with self.assertRaises(ValueError):
            EvaluationResult(state=EvalState.NOT_EVALUATED)

    def test_no_vocabulary_field_can_say_would_fire(self):
        """The plan forbids displaying not_evaluated as a firing verdict."""
        for name in dir(EvaluationResult):
            self.assertNotIn("would_fire", name)
            self.assertNotIn("fires", name)

    def test_verdict_is_derived_not_stored(self):
        result = EvaluationResult(state=EvalState.EVALUATED, rows=(), columns=())
        self.assertIs(result.verdict, Verdict.NO_MATCH)
        self.assertIn("nothing", result.verdict_label.lower())


class KleeneTests(unittest.TestCase):
    """Three-valued logic, table by table."""

    def test_and_table(self):
        self.assertIs(k_and([True, True]), True)
        self.assertIs(k_and([True, False]), False)
        self.assertIs(k_and([True, None]), None)
        self.assertIs(k_and([False, None]), False, "a decisive falsifier settles a conjunction")
        self.assertIs(k_and([None, None]), None)

    def test_or_table(self):
        self.assertIs(k_or([True, True]), True)
        self.assertIs(k_or([True, False]), True)
        self.assertIs(k_or([True, None]), True)
        self.assertIs(k_or([False, None]), None)
        self.assertIs(k_or([None, None]), None)

    def test_not_table(self):
        self.assertIs(k_not(True), False)
        self.assertIs(k_not(False), True)
        self.assertIs(k_not(None), None, "not unknown is unknown, never true")


class FilterTruthTests(unittest.TestCase):
    """A Filter keeps a row only on TRUE. UNKNOWN drops it, and is counted separately."""

    def _filter_on(self, condition, rows):
        return evaluate(rows, read(), Filter(id="f", input="r", condition=condition),
                        emit("f"))

    def test_a_true_predicate_keeps_the_row(self):
        result = self._filter_on(
            Comparison("=", FieldExpr(FieldRef("u")), Literal("alice")),
            [{"u": "alice"}, {"u": "bob"}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual([dict(r.values) for r in result.rows], [{"u": "alice"}])

    def test_a_false_predicate_drops_the_row_and_is_counted_as_false(self):
        result = self._filter_on(
            Comparison("=", FieldExpr(FieldRef("u")), Literal("alice")),
            [{"u": "bob"}])
        self.assertIs(result.verdict, Verdict.NO_MATCH)
        self.assertEqual(result.counts.rows_predicate_false, 1)
        self.assertEqual(result.counts.rows_predicate_unknown, 0)

    def test_a_missing_field_drops_the_row_and_is_counted_as_UNKNOWN_not_false(self):
        result = self._filter_on(
            Comparison("=", FieldExpr(FieldRef("u")), Literal("alice")),
            [{"other": 1}])
        self.assertIs(result.verdict, Verdict.NO_MATCH)
        self.assertEqual(result.counts.rows_predicate_unknown, 1)
        self.assertEqual(result.counts.rows_predicate_false, 0,
                         "absence of evidence must not be counted as evidence of absence")

    def test_false_and_unknown_is_false(self):
        result = self._filter_on(
            BoolOp("and", (Comparison("=", FieldExpr(FieldRef("u")), Literal("alice")),
                           Comparison("=", FieldExpr(FieldRef("v")), Literal("x")))),
            [{"u": "bob"}])
        self.assertEqual(result.counts.rows_predicate_false, 1)

    def test_true_and_unknown_is_unknown(self):
        result = self._filter_on(
            BoolOp("and", (Comparison("=", FieldExpr(FieldRef("u")), Literal("alice")),
                           Comparison("=", FieldExpr(FieldRef("v")), Literal("x")))),
            [{"u": "alice"}])
        self.assertEqual(result.counts.rows_predicate_unknown, 1)


class AggregationTests(unittest.TestCase):
    """Exact values, because the sum/avg asymmetry is the classic silent-misfire bug."""

    def _grouped(self, rows, measures, group_by=(FieldRef("u"),), **frame_kw):
        node = Aggregate(id="a", input="r", measures=measures, group_by=group_by, **frame_kw)
        return evaluate(rows, read(), node, emit("a"))

    def test_count_with_no_field_counts_rows(self):
        result = self._grouped([{"u": "a"}, {"u": "a"}, {"u": "b"}],
                               (Measure("n", "count"),))
        got = {dict(r.values)["u"]: dict(r.values)["n"] for r in result.rows}
        self.assertEqual(got, {"a": 2, "b": 1})

    def test_count_with_a_field_counts_present_non_null_values(self):
        result = self._grouped([{"u": "a", "ip": "1"}, {"u": "a", "ip": None}, {"u": "a"}],
                               (Measure("n", "count", field=FieldRef("ip")),))
        self.assertEqual(dict(result.rows[0].values)["n"], 1,
                         "count(field) counts values; count() counts rows")

    def test_sum_of_an_empty_group_is_zero_but_avg_is_null(self):
        """The asymmetry that makes a rule fire at threshold 1 on an empty group."""
        agg = Aggregate(id="a", input="r", group_by=(FieldRef("missing"),),
                        measures=(Measure("s", "sum", field=FieldRef("v")),
                                  Measure("m", "avg", field=FieldRef("v"))))
        result = evaluate([{"u": "a"}], read(), agg, emit("a"))
        values = dict(result.rows[0].values)
        self.assertEqual(values["s"], 0)
        self.assertIsNone(values["m"])

    def test_dcount_excludes_nulls(self):
        result = self._grouped([{"u": "a", "v": 1}, {"u": "a", "v": 1}, {"u": "a", "v": None}],
                               (Measure("n", "dcount", field=FieldRef("v")),))
        self.assertEqual(dict(result.rows[0].values)["n"], 1,
                         "nulls are excluded, so {1, 1, None} is one distinct value")

    def test_a_measure_where_clause_admits_only_true_rows(self):
        """A Measure's `where` obeys the same three-valued rule a Filter does.

        A row whose predicate is UNKNOWN must not silently feed the measure; it is counted
        separately so absence of evidence stays visible.
        """
        rows = [{"u": "a", "v": 1, "ok": True}, {"u": "a", "v": 2}, {"u": "a", "v": 3,
                                                                     "ok": False}]
        measure = Measure("n", "count", field=FieldRef("v"),
                          where=Comparison("=", FieldExpr(FieldRef("ok")), Literal(True)))
        result = self._grouped(rows, (measure,))
        values = dict(result.rows[0].values)
        self.assertEqual(values["n"], 1, "only the row that is affirmatively true is counted")
        self.assertEqual(result.counts.measure_where_unknown, 1,
                         "the row with no `ok` value is counted as unknown, not as false")

    def test_values_preserves_input_order(self):
        result = self._grouped([{"u": "a", "v": 3}, {"u": "a", "v": 1}, {"u": "a", "v": 2}],
                               (Measure("vs", "values", field=FieldRef("v")),))
        self.assertEqual(dict(result.rows[0].values)["vs"], [3, 1, 2])

    def test_a_threshold_after_an_aggregate_keeps_only_the_heavy_group(self):
        """The canonical rule shape: Aggregate, then a Filter over MeasureExpr."""
        result = evaluate(
            [{"u": "alice"}, {"u": "alice"}, {"u": "alice"}, {"u": "bob"}],
            read(),
            Aggregate(id="a", input="r", measures=(Measure("Hits", "count"),),
                      group_by=(FieldRef("u"),)),
            Filter(id="f", input="a",
                   condition=Comparison(">=", MeasureExpr("Hits"), Literal(2))),
            emit("f"))
        self.assertEqual([dict(r.values) for r in result.rows], [{"u": "alice", "Hits": 3}])

    def test_arg_max_is_refused_rather_than_guessed(self):
        result = self._grouped([{"u": "a", "v": 1}],
                               (Measure("x", "arg_max", field=FieldRef("v")),))
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.code, "MEASURE_ARG_EXTREME_UNDER_SPECIFIED")

    def test_an_unknown_measure_reference_is_refused(self):
        result = evaluate([{"u": "a"}], read(),
                          Aggregate(id="a", input="r", measures=(Measure("Hits", "count"),)),
                          Filter(id="f", input="a",
                                 condition=Comparison(">", MeasureExpr("Nope"), Literal(0))),
                          emit("f"))
        self.assertEqual(result.reason.code, "UNKNOWN_MEASURE_REFERENCE")


class WindowTests(unittest.TestCase):
    def _tumbling(self, rows, size, offset=0, kind="tumbling", field="t"):
        frame = Frame(kind=kind, size=Duration(size) if size else None,
                      offset_seconds=offset, time_ref=TimeRef(field_name=field))
        agg = Aggregate(id="a", input="r", measures=(Measure("n", "count"),), frame=frame)
        return evaluate(rows, read(), agg, emit("a"), read_id="r")

    def test_a_tumbling_frame_partitions_by_size(self):
        result = self._tumbling([{"t": 0}, {"t": 1}, {"t": 10}, {"t": 11}], 10)
        self.assertEqual(result.counts.windows, 2)
        self.assertEqual(sorted(r.values["n"] for r in result.rows), [2, 2])

    def test_an_event_exactly_on_a_boundary_belongs_to_the_later_window(self):
        """Half-open [start, end): the boundary case most often got wrong."""
        result = self._tumbling([{"t": 0}, {"t": 10}, {"t": 20}], 10)
        self.assertEqual(result.counts.windows, 3, "0, 10 and 20 are three windows, not two")

    def test_the_first_window_is_left_closed(self):
        result = self._tumbling([{"t": 0}, {"t": 5}], 10)
        self.assertEqual(result.counts.windows, 1)

    def test_a_sliding_frame_is_refused_because_it_has_no_step(self):
        result = self._tumbling([{"t": 0}], 10, kind="sliding")
        self.assertEqual(result.reason.code, "FRAME_SLIDING_STEP_UNDECLARED")

    def test_explicit_alignment_is_refused_because_it_has_no_anchor(self):
        frame = Frame(kind="tumbling", size=Duration(10), alignment="explicit",
                      time_ref=TimeRef(field_name="t"))
        agg = Aggregate(id="a", input="r", measures=(Measure("n", "count"),), frame=frame)
        result = evaluate([{"t": 0}], read(), agg, emit("a"))
        self.assertEqual(result.reason.code, "FRAME_ALIGNMENT_UNANCHORED")

    def test_an_unresolvable_time_field_is_never_guessed(self):
        frame = Frame(kind="tumbling", size=Duration(10))
        agg = Aggregate(id="a", input="r", measures=(Measure("n", "count"),), frame=frame)
        result = evaluate([{"t": 0}], read(), agg, emit("a"))
        self.assertEqual(result.reason.code, "TIME_FIELD_UNRESOLVED")
        self.assertIn("will not assume", result.reason.message)

    def test_a_time_field_on_the_frame_is_authoritative(self):
        frame = Frame(kind="tumbling", size=Duration(10), time_ref=TimeRef(field_name="t"))
        agg = Aggregate(id="a", input="r", measures=(Measure("n", "count"),), frame=frame)
        result = evaluate_ir(graph(read(), agg, emit("a")),
                             sample([{"t": 0}, {"t": 1}, {"t": 11}]))
        self.assertEqual(result.counts.windows, 2)

    def test_a_conflicting_time_binding_is_refused_not_preferred(self):
        frame = Frame(kind="tumbling", size=Duration(10), time_ref=TimeRef(field_name="declared"))
        agg = Aggregate(id="a", input="r", measures=(Measure("n", "count"),), frame=frame)
        bound = Sample({"r": [{"declared": 0}]}, time_bindings={"r": "other"})
        result = evaluate_ir(graph(read(), agg, emit("a")), bound)
        self.assertEqual(result.reason.code, "TIME_BINDING_CONFLICT")

    def test_no_usable_times_under_a_frame_is_not_evaluated_not_an_empty_match(self):
        """Returning 'matched nothing' here would be the most dangerous possible output."""
        frame = Frame(kind="tumbling", size=Duration(10), time_ref=TimeRef(field_name="t"))
        agg = Aggregate(id="a", input="r", measures=(Measure("n", "count"),), frame=frame)
        result = evaluate([{"other": 1}], read(), agg, emit("a"))
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.code, "TIME_UNRESOLVED_ON_ALL_ROWS")

    def test_tumbling_declares_that_its_buckets_look_complete(self):
        frame = Frame(kind="tumbling", size=Duration(10), time_ref=TimeRef(field_name="t"))
        agg = Aggregate(id="a", input="r", measures=(Measure("n", "count"),), frame=frame)
        result = evaluate_ir(graph(read(), agg, emit("a")), sample([{"t": 0}]))
        self.assertIn("TUMBLING_BUCKETS_FULLY_FORMED", result.caveat_codes())


class ArrangeTests(unittest.TestCase):
    def _arranged(self, rows, order_by, **kw):
        return evaluate(rows, read(), Arrange(id="s", input="r", order_by=order_by, **kw),
                        emit("s"))

    def test_rows_sort_by_a_key(self):
        result = self._arranged([{"n": 3}, {"n": 1}, {"n": 2}],
                                ((FieldExpr(FieldRef("n")), True),))
        self.assertEqual([dict(r.values)["n"] for r in result.rows], [1, 2, 3])

    def test_descending_reverses_the_order(self):
        result = self._arranged([{"n": 1}, {"n": 3}],
                                ((FieldExpr(FieldRef("n")), False),))
        self.assertEqual([dict(r.values)["n"] for r in result.rows], [3, 1])

    def test_an_unknown_order_key_sorts_last_in_BOTH_directions(self):
        """Nulls-first would silently promote unmeasurable rows to the top of a limit N."""
        for ascending in (True, False):
            result = self._arranged([{"n": 1}, {"other": 0}, {"n": 2}],
                                    ((FieldExpr(FieldRef("n")), ascending),))
            self.assertEqual([dict(r.values) for r in result.rows][-1], {"other": 0},
                             f"ascending={ascending}")
            self.assertEqual(result.counts.rows_with_unknown_order_key, 1)

    def test_limit_and_offset_apply_after_distinct(self):
        result = self._arranged([{"n": 1}, {"n": 2}, {"n": 3}],
                                ((FieldExpr(FieldRef("n")), True),), limit=2, offset=1)
        self.assertEqual([dict(r.values)["n"] for r in result.rows], [2, 3])

    def test_an_offset_past_the_end_is_empty_not_an_error(self):
        result = self._arranged([{"n": 1}], ((FieldExpr(FieldRef("n")), True),), offset=5)
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_a_negative_offset_is_refused_rather_than_clamped(self):
        result = self._arranged([{"n": 1}], (), offset=-1)
        self.assertEqual(result.reason.code, "ARRANGE_NEGATIVE_OFFSET")


class DeriveTests(unittest.TestCase):
    def test_derive_adds_a_field(self):
        result = evaluate([{"a": 1}], read(),
                          Derive(id="d", input="r",
                                 assignments=((FieldRef("b"), Literal(9)),)),
                          emit("d"))
        self.assertEqual(dict(result.rows[0].values), {"a": 1, "b": 9})

    def test_a_field_collision_is_refused_under_the_error_policy(self):
        result = evaluate([{"a": 1}], read(),
                          Derive(id="d", input="r",
                                 assignments=((FieldRef("a"), Literal(9)),)),
                          emit("d"))
        self.assertEqual(result.reason.code, "EVAL_DERIVE_FIELD_COLLISION")


class EmitTests(unittest.TestCase):
    def test_a_projection_naming_an_absent_column_yields_absent_not_null(self):
        result = evaluate([{"a": 1}], read(), Emit(id="o", input="r", columns=("a", "nope")),
                          output="o")
        self.assertEqual(dict(result.rows[0].values), {"a": 1, "nope": None})
        self.assertEqual(result.counts.emit_column_absent, 1,
                         "a silent None reads as 'the value was null'")

    def test_cooldown_is_refused_as_a_stateful_counter(self):
        result = evaluate([{"a": 1}], read(),
                          Emit(id="o", input="r", cooldown=Duration(300)), output="o")
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.deferred_to, "3C")


class SetOpTests(unittest.TestCase):
    def _setop(self, op, left, right, all_=False):
        return evaluate_ir(
            graph(read("l"), read("r"), SetOp(id="u", left="l", right="r", op=op, all=all_),
                  emit("u")),
            Sample({"l": left, "r": right}))

    def test_union_of_disjoint_rows_keeps_both(self):
        result = self._setop("union", [{"a": 1}], [{"a": 2}])
        self.assertEqual(len(result.rows), 2)

    def test_union_is_distinct_by_default(self):
        result = self._setop("union", [{"a": 1}], [{"a": 1}])
        self.assertEqual(len(result.rows), 1)

    def test_intersect_keeps_only_shared_rows(self):
        result = self._setop("intersect", [{"a": 1}, {"a": 2}], [{"a": 2}])
        self.assertEqual(len(result.rows), 1)

    def test_except_removes_the_right_side(self):
        result = self._setop("except", [{"a": 1}, {"a": 2}], [{"a": 2}])
        self.assertEqual(len(result.rows), 1)

    def test_append_concatenates_regardless_of_all(self):
        self.assertEqual(len(self._setop("append", [{"a": 1}], [{"a": 1}]).rows), 2)
        self.assertEqual(len(self._setop("append", [{"a": 1}], [{"a": 1}], True).rows), 2)

    def test_the_integer_one_and_the_boolean_true_are_different_rows(self):
        """Python says 1 == True. A set operation must not."""
        self.assertNotEqual(canonical(1), canonical(True))
        result = self._setop("union", [{"a": 1}], [{"a": True}])
        self.assertEqual(len(result.rows), 2)

    def test_absent_and_null_are_different_rows(self):
        self.assertNotEqual(row_key(Row(values={}, index=0)),
                            row_key(Row(values={"a": None}, index=0)))


class RefusalTests(unittest.TestCase):
    """3B and 3C constructs are refused BY NAME at pre-flight."""

    def _with(self, *nodes, output="o"):
        return evaluate_ir(graph(*nodes, output=output), sample([{"a": 1}], "r"))

    def test_a_join_is_deferred_to_3b(self):
        node = Join(id="j", left="r", right="r", on=Comparison("=", FieldExpr(FieldRef("a")),
                                                               Literal(1)))
        result = self._with(read(), node, emit("j"))
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.code, "EVAL_PHASE_NOT_IMPLEMENTED")
        self.assertEqual(result.reason.deferred_to, "3B")

    def test_a_pattern_is_deferred_to_3c(self):
        node = Pattern(id="p", stages=(Stage(id="s1", input="r"),), max_span=Duration(60))
        result = self._with(read(), node, emit("p"))
        self.assertEqual(result.reason.deferred_to, "3C")

    def test_a_deferred_rule_costs_no_row_walk(self):
        node = Join(id="j", left="r", right="r", on=Comparison("=", FieldExpr(FieldRef("a")),
                                                               Literal(1)))
        result = self._with(read(), node, emit("j"))
        self.assertEqual(result.counts.rows_in, 0)

    def test_an_unresolved_source_is_refused(self):
        ir = graph(Read(id="r", selector=SourceSelector(name=None, confidence="unverified")),
                   emit("r"))
        result = evaluate_ir(ir, sample([{"a": 1}], "r"))
        self.assertEqual(result.reason.code, "UNRESOLVED_SOURCE")
        self.assertIn("will not invent", result.reason.message)

    def test_an_unverified_field_reference_refuses_the_whole_graph(self):
        result = evaluate([{"a": 1}], read(),
                          Filter(id="f", input="r",
                                 condition=Comparison("=",
                                                      FieldExpr(FieldRef("q",
                                                                         confidence="unverified")),
                                                      Literal(1))),
                          emit("f"))
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.code, "UNVERIFIED_FIELD_REFERENCE")

    def test_no_sample_for_a_read_is_refused_rather_than_read_as_empty(self):
        ir = graph(read("r"), emit("r"))
        result = evaluate_ir(ir, Sample({}))
        self.assertEqual(result.reason.code, "EVAL_INPUT_SOURCE_NOT_PROVIDED")

    def test_a_lookalike_node_class_is_not_a_kernel_node(self):
        class Read2:
            id = "r"
            selector = SRC
        ir = graph(Read2(), emit("r"))
        result = evaluate_ir(ir, sample([{"a": 1}], "r"))
        self.assertIsNone(primitive_of(Read2()))
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)


class CodeRegistryTests(unittest.TestCase):
    """The registry is enforced, not documented. This is the anti-rotation gate."""

    def test_every_raised_code_is_registered(self):
        """Grep the kernel for every literal handed to a refusal and check the registry."""
        import re
        pattern = re.compile(r'EvaluationRefusal\(\s*\n?\s*"([A-Z_]+)"')
        found = set()
        for path in Path("kernel").glob("*.py"):
            found |= set(pattern.findall(path.read_text(encoding="utf-8")))
        self.assertTrue(found, "the grep found no codes at all; the pattern is wrong")
        self.assertEqual(found - KERNEL_EVAL_CODES, set(),
                         "these codes are raised but not in the registry")

    def test_an_unregistered_code_cannot_be_raised(self):
        with self.assertRaises(AssertionError):
            EvaluationRefusal("MADE_UP_CODE", "nope")

    def test_deferred_to_is_only_meaningful_for_a_phase_gap(self):
        with self.assertRaises(AssertionError):
            EvaluationRefusal("TIME_FIELD_UNRESOLVED", "x", deferred_to="3B")

    def test_no_code_is_phrased_as_a_vendor_limitation(self):
        for code in KERNEL_EVAL_CODES:
            for word in ("QRADAR", "SPLUNK", "ELASTIC", "WAZUH", "SENTINEL", "FALCON", "VENDOR"):
                self.assertNotIn(word, code.upper())


class ExpressionTests(unittest.TestCase):
    def test_a_function_with_wrong_arity_is_refused(self):
        result = evaluate([{"a": "x"}], read(),
                          Filter(id="f", input="r",
                                 condition=Comparison("=", FieldExpr(FieldRef("a")),
                                                      Call("lower", ()))),
                          emit("f"))
        self.assertEqual(result.reason.code, "FUNCTION_ARITY_VIOLATION")

    def test_matches_regex_is_refused_because_no_dialect_can_be_declared(self):
        result = evaluate([{"a": "x"}], read(),
                          Filter(id="f", input="r",
                                 condition=Comparison("=", FieldExpr(FieldRef("a")),
                                                      Call("matches_regex",
                                                           (FieldExpr(FieldRef("a")),
                                                            Literal("^x"))))),
                          emit("f"))
        self.assertEqual(result.reason.code, "FUNCTION_DIALECT_UNDECLARED")

    def test_contains_is_case_insensitive_but_starts_with_is_not(self):
        """The contracts differ: only `contains` declares a case rule."""
        lower_result = evaluate([{"a": "ADMIN"}], read(),
                                Filter(id="f", input="r",
                                       condition=Call("contains", (FieldExpr(FieldRef("a")),
                                                                  Literal("admin")))),
                                emit("f"))
        starts_result = evaluate([{"a": "ADMIN"}], read(),
                                 Filter(id="f", input="r",
                                        condition=Call("starts_with", (FieldExpr(FieldRef("a")),
                                                                       Literal("admin")))),
                                 emit("f"))
        self.assertIs(lower_result.verdict, Verdict.MATCHED)
        self.assertIs(starts_result.verdict, Verdict.NO_MATCH)

    def test_dividing_by_zero_is_unknown_not_infinity(self):
        from models.rule_ir import Arith
        result = evaluate([{"a": 1}], read(),
                          Filter(id="f", input="r",
                                 condition=Comparison(">", Arith("/", FieldExpr(FieldRef("a")),
                                                             Literal(0)),
                                                      Literal(-1))),
                          emit("f"))
        self.assertIs(result.verdict, Verdict.NO_MATCH)
        self.assertGreaterEqual(result.counts.arithmetic_unknown, 1)

    def test_string_concatenation_via_arith_is_refused_not_guessed(self):
        from models.rule_ir import Arith
        result = evaluate([{"a": "x"}], read(),
                          Filter(id="f", input="r",
                                 condition=Comparison("=", Arith("+", FieldExpr(FieldRef("a")),
                                                                 Literal("y")),
                                                      Literal("xy"))),
                          emit("f"))
        self.assertEqual(result.reason.code, "ARITH_STRING_CONCAT_UNSUPPORTED")

    def test_an_empty_inlist_matches_nothing_rather_than_everything(self):
        result = evaluate([{"a": "x"}], read(),
                          Filter(id="f", input="r",
                                 condition=InList(FieldExpr(FieldRef("a")), ())),
                          emit("f"))
        self.assertIs(result.verdict, Verdict.NO_MATCH)


class TraceTests(unittest.TestCase):
    def test_the_trace_covers_every_node_in_execution_order(self):
        result = evaluate([{"u": "a"}], read(),
                          Derive(id="d", input="r",
                                 assignments=((FieldRef("x"), Literal(1)),)),
                          emit("d"))
        self.assertEqual([t.node_id for t in result.trace], ["r", "d", "o"])

    def test_a_trace_never_contains_row_content(self):
        result = evaluate([{"secret": "hunter2"}], read(),
                          Filter(id="f", input="r",
                                 condition=Comparison("=", FieldExpr(FieldRef("secret")),
                                                      Literal("x"))),
                          emit("f"))
        for trace in result.trace:
            self.assertNotIn("hunter2", str(trace.detail))
            self.assertNotIn("hunter2", str(trace.samples))

    def test_row_samples_are_indices_not_rows(self):
        result = evaluate([{"u": "a"}, {"u": "b"}], read(), emit("r"))
        emit_trace = [t for t in result.trace if t.node_id == "o"][0]
        self.assertTrue(all(isinstance(i, int) for i in emit_trace.samples))


class ShadowModeTests(unittest.TestCase):
    def test_nothing_in_the_application_imports_the_kernel(self):
        for module in ("app.py", "rule_engine.py", "compiler/pipeline.py",
                       "compiler/sigma_compiler.py", "static/app.js", "templates/index.html"):
            text = Path(module).read_text(encoding="utf-8")
            self.assertNotIn("kernel.eval", text, f"{module} already imports the v2 kernel")
            self.assertNotIn("from kernel", text, f"{module} already imports the v2 kernel")

    def test_the_kernel_imports_nothing_from_the_application(self):
        """The dependency runs one way only, or the dark module is not really dark."""
        for path in Path("kernel").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("import app", text)
            self.assertNotIn("from app", text)
            self.assertNotIn("import rule_engine", text)
            self.assertNotIn("from rule_engine", text)


if __name__ == "__main__":
    unittest.main()
