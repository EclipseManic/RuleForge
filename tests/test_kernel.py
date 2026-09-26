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
                            Arith, FieldExpr, EventExpr, Expand, FieldRef, Filter, Frame, InList, Join, Literal, Measure,
                            MeasureExpr, Pattern, Read, RuleIR, SetOp, SourceSelector, Stage, TimeExpr,
                            TimeRef)

SRC = SourceSelector(name="events")


def sample(rows, read_id="r", time_bindings=None):
    return Sample({read_id: rows}, time_bindings=time_bindings)


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

    def test_an_iterate_is_refused_and_says_why(self):
        """`Iterate.step` is a graph NODE, so a fixed point needs sub-graph execution the
        single-input executor does not have. Reported rather than approximated."""
        from models.rule_ir import Iterate
        node = Iterate(id="it", input="r", step=Derive(id="s", input="r",
                                                      assignments=((FieldRef("x"),
                                                                    Literal(1)),)),
                       until=Literal(True), max_iterations=3)
        result = self._with(read(), node, emit("it"))
        self.assertEqual(result.reason.deferred_to, "3C")

    def test_a_deferred_rule_costs_no_row_walk(self):
        from models.rule_ir import Iterate
        node = Iterate(id="it", input="r", step=Derive(id="s", input="r",
                                                      assignments=((FieldRef("x"),
                                                                    Literal(1)),)),
                       until=Literal(True), max_iterations=3)
        result = self._with(read(), node, emit("it"))
        self.assertEqual(result.counts.rows_in, 0)

    def test_a_rule_package_is_refused_because_its_unit_schema_is_unknown(self):
        """`RulePackage.units` is `tuple[dict[str, Any]]` and the only field the model reads
        is `id`, so there is nothing linking a unit to a graph. Evaluating one would mean
        inventing that schema."""
        from models.rule_ir import RulePackage
        pkg = RulePackage(rule_id="bundle", units=({"id": "a"}, {"id": "b"}),
                          dependencies=(("a", "b"),))
        plain = RuleIR(rule_id="p", nodes=(read(), emit("r")), output="r", package=pkg)
        packaged = evaluate_ir(plain, sample([{"a": 1}], "r"))
        unpackaged = evaluate_ir(graph(read(), emit("r")), sample([{"a": 1}], "r"))
        self.assertIs(packaged.verdict, Verdict.NOT_EVALUATED)
        self.assertIs(unpackaged.verdict, Verdict.MATCHED,
                      "the same graph WITHOUT a package evaluates, so the package is the cause")

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


class JoinTests(unittest.TestCase):
    """Two-input execution. Exact expected values, because a join is where a rule can
    silently match the wrong events and still look plausible."""

    LEFT = [{"host": "a", "t": 0}, {"host": "b", "t": 100}]
    RIGHT = [{"host": "a", "ip": "10.0.0.1"}, {"host": "a", "ip": "10.0.0.2"}]

    def _join(self, left_rows=None, right_rows=None, **kw):
        node = Join(id="j", left="l", right="r",
                    on=Comparison("=", EventExpr("left", None, FieldRef("host")),
                                  EventExpr("right", None, FieldRef("host"))),
                    **kw)
        ir = graph(read("l"), read("r"), node, emit("j"))
        return evaluate_ir(ir, Sample({"l": self.LEFT if left_rows is None else left_rows,
                                       "r": self.RIGHT if right_rows is None else right_rows}))

    def test_an_inner_join_keeps_only_matching_rows(self):
        result = self._join()
        self.assertEqual([dict(r.values) for r in result.rows],
                         [{"host": "a", "t": 0, "ip": "10.0.0.1"},
                          {"host": "a", "t": 0, "ip": "10.0.0.2"}])

    def test_the_declared_one_to_many_cardinality_duplicates_the_left_row(self):
        """Two right rows for one left row produce two output rows - the default, not a bug."""
        result = self._join(cardinality="one_to_many")
        self.assertEqual(len(result.rows), 2)

    def test_a_one_to_one_declaration_that_matches_twice_is_refused(self):
        """Keeping the first would be a guess; keeping both would contradict the declaration."""
        result = self._join(cardinality="one_to_one")
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.code, "JOIN_CARDINALITY_VIOLATION")

    def test_a_left_join_preserves_an_unmatched_left_row(self):
        result = self._join(kind="left", unmatched="preserve_left")
        self.assertEqual(len(result.rows), 3, "two matches plus the unmatched host b")
        self.assertEqual(dict(result.rows[-1].values), {"host": "b", "t": 100})

    def test_a_left_anti_join_emits_only_the_rows_with_no_match(self):
        result = self._join(kind="left_anti", unmatched="drop")
        self.assertEqual([dict(r.values) for r in result.rows], [{"host": "b", "t": 100}])

    def test_a_right_anti_join_emits_only_the_unmatched_right_rows(self):
        result = self._join(right_rows=[{"host": "z", "ip": "1"}], kind="right_anti",
                            unmatched="drop")
        self.assertEqual([dict(r.values) for r in result.rows], [{"host": "z", "ip": "1"}])

    def test_a_full_outer_join_is_refused_because_unmatched_cannot_express_both(self):
        result = self._join(kind="full")
        self.assertEqual(result.reason.code, "JOIN_KIND_INEXPRESSIBLE")
        self.assertIn("preserve unmatched rows from BOTH sides", result.reason.message)

    def test_a_contradictory_kind_and_unmatched_pairing_is_refused(self):
        result = self._join(kind="left", unmatched="drop")
        self.assertEqual(result.reason.code, "JOIN_KIND_UNMATCHED_CONTRADICTION")
        self.assertIn("will not honour one field", result.reason.message)

    def test_a_shared_name_with_equal_values_is_not_a_collision(self):
        """The field a join is keyed on is on BOTH sides by definition.

        Treating that as a collision would make the default `error` policy refuse essentially
        every join, firing on the normal case rather than the exceptional one.
        """
        result = self._join(collision="error")
        self.assertEqual(result.state, EvalState.EVALUATED, result.reason)

    def test_a_shared_name_with_differing_values_is_a_collision(self):
        result = self._join(left_rows=[{"host": "a", "v": 1}],
                            right_rows=[{"host": "a", "v": 2}], collision="error")
        self.assertEqual(result.reason.code, "JOIN_FIELD_COLLISION")
        self.assertIn("DIFFERENT values", result.reason.message)

    def test_keep_left_resolves_a_collision_by_keeping_the_left_value(self):
        result = self._join(left_rows=[{"host": "a", "v": 1}],
                            right_rows=[{"host": "a", "v": 2}], collision="keep_left")
        self.assertEqual(dict(result.rows[0].values)["v"], 1)

    def test_a_shared_name_not_referenced_by_the_predicate_is_merged_when_equal(self):
        """The equal-values rule, isolated from the side-scoped rule.

        `env` appears on both rows but is not referenced in `on`, so it is not side-scoped.
        Equal values merge; differing values are a real conflict. Without this, the
        equal-values branch is unreachable for any field the predicate does not mention.
        """
        equal = self._join(left_rows=[{"host": "a", "env": "prod"}],
                           right_rows=[{"host": "a", "env": "prod"}], collision="error")
        self.assertEqual(equal.state, EvalState.EVALUATED, equal.reason)
        self.assertEqual(dict(equal.rows[0].values)["env"], "prod")

        differing = self._join(left_rows=[{"host": "a", "env": "prod"}],
                               right_rows=[{"host": "a", "env": "dev"}], collision="error")
        self.assertEqual(differing.reason.code, "JOIN_FIELD_COLLISION")

    def test_a_temporal_window_without_a_temporal_predicate_is_refused(self):
        """Symmetric and asymmetric are different rules, so the kernel will not imply one."""
        result = self._join(match_window=Duration(600))
        self.assertEqual(result.reason.code, "JOIN_TEMPORAL_WINDOW_WITHOUT_PREDICATE")
        self.assertIn("different rules", result.reason.message)

    def test_a_temporal_window_with_a_temporal_predicate_is_accepted_and_declared(self):
        """The explicit form: each side's clock named through EventExpr.

        A BARE TimeRef is refused as ambiguous when both sides carry the field, because
        left.t <= right.t + W is undecidable without knowing which clock is which.
        """
        def side_time(which):
            return EventExpr(which, None, FieldRef("t"))

        node = Join(id="j", left="l", right="r",
                    on=BoolOp("and", (
                        Comparison("=", EventExpr("left", None, FieldRef("host")),
                                   EventExpr("right", None, FieldRef("host"))),
                        # left.t <= right.t <= left.t + 600. Writing ONLY the upper bound
                        # would also match a right event that happened long BEFORE the left
                        # one, which is a different rule entirely.
                        Comparison(">=", side_time("right"), side_time("left")),
                        Comparison("<=", side_time("right"),
                                   Arith("+", side_time("left"), Literal(600))))),
                    match_window=Duration(600))
        ir = graph(read("l"), read("r"), node, emit("j"))
        result = evaluate_ir(ir, Sample({
            "l": [{"host": "a", "t": 0}, {"host": "a", "t": 10_000}],
            "r": [{"host": "a", "t": 5}, {"host": "a", "t": 9_000}]},
            time_bindings={"l": "t", "r": "t"}))
        self.assertEqual(result.state, EvalState.EVALUATED, result.reason)
        self.assertIn("JOIN_TEMPORAL_WINDOW_DECLARED_NOT_ENFORCED", result.caveat_codes())
        self.assertEqual(len(result.rows), 1, "only the 0/5 pair satisfies `on`")
        self.assertIn("JOIN_SIDE_SCOPED_FIELDS_NOT_MERGED", result.caveat_codes())

    def test_a_merged_row_keeps_both_sides_addressable(self):
        """EventExpr must resolve to a NAMED side, not to whichever side had the field."""
        result = self._join(left_rows=[{"host": "a", "marker": "LEFT"}],
                            right_rows=[{"host": "a", "marker": "RIGHT"}],
                            collision="keep_left")
        row = result.rows[0]
        self.assertEqual(row.side("left")["marker"], "LEFT")
        self.assertEqual(row.side("right")["marker"], "RIGHT")
        self.assertEqual(row.values["marker"], "LEFT", "the merged view follows collision")

    def test_a_bare_time_reference_ambiguous_across_sides_is_refused(self):
        node = Join(id="j", left="l", right="r",
                    on=Comparison("=", TimeExpr(TimeRef(field_name="t")),
                                  TimeExpr(TimeRef(field_name="t"))))
        ir = graph(read("l"), read("r"), node, emit("j"))
        result = evaluate_ir(ir, Sample({"l": [{"t": 1}], "r": [{"t": 1}]}))
        self.assertEqual(result.reason.code, "TIME_SIDE_AMBIGUOUS")

    def test_an_event_scoped_reference_outside_a_two_input_node_is_refused(self):
        """The kernel validator catches this first, and its code is the more specific one."""
        node = Filter(id="f", input="r",
                      condition=Comparison("=", EventExpr("left", None, FieldRef("host")),
                                           Literal("a")))
        result = evaluate([{"host": "a"}], read(), node, emit("f"))
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.code, "EVENT_REF_OUT_OF_SCOPE")


class ExpandTests(unittest.TestCase):
    def _expand(self, rows, mode="unnest", field="ips"):
        node = Expand(id="x", input="r", field=FieldRef(field), mode=mode)
        return evaluate(rows, read(), node, emit("x"))

    def test_unnest_produces_one_row_per_element(self):
        result = self._expand([{"u": "a", "ips": ["1", "2", "3"]}])
        self.assertEqual([r.values["ips"] for r in result.rows], ["1", "2", "3"])

    def test_an_absent_list_produces_no_rows_and_is_counted(self):
        result = self._expand([{"u": "a"}])
        self.assertIs(result.verdict, Verdict.NO_MATCH)
        self.assertEqual(result.counts.emit_column_absent, 1)

    def test_an_empty_list_produces_no_rows(self):
        result = self._expand([{"u": "a", "ips": []}])
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_a_scalar_where_a_list_was_expected_is_refused_not_wrapped(self):
        """Treating a scalar as a one-element list would invent a row that never existed."""
        result = self._expand([{"u": "a", "ips": "10.0.0.1"}])
        self.assertEqual(result.reason.code, "EXPAND_VALUE_NOT_A_SEQUENCE")

    def test_cross_is_refused_because_expand_has_no_second_operand(self):
        result = self._expand([{"ips": ["1"]}], mode="cross")
        self.assertEqual(result.reason.code, "EXPAND_MODE_INEXPRESSIBLE")
        self.assertIn("no second operand", result.reason.message)

    def test_generate_is_refused_because_expand_has_nothing_to_generate_from(self):
        result = self._expand([{"ips": ["1"]}], mode="generate")
        self.assertEqual(result.reason.code, "EXPAND_MODE_INEXPRESSIBLE")

    def test_an_alias_redirects_the_expanded_column(self):
        node = Expand(id="x", input="r", field=FieldRef("ips"), alias="ip")
        result = evaluate([{"ips": ["1"]}], read(), node, emit("x"))
        self.assertEqual(dict(result.rows[0].values)["ip"], "1")
        self.assertNotIn("ips", result.rows[0].values)


class ReviewRegressionTests(unittest.TestCase):
    """Regressions for defects found by independent review of 3A/3B.

    Each of these shipped in a green suite. That is the point: the suite was not evidence, so
    the regression is pinned deliberately rather than assumed.
    """

    # --- C1/A4: InList could never return True, and identity was used as equality ----
    def test_an_inlist_predicate_actually_matches(self):
        """This is the single worst defect in the three commits.

        `InList.options` holds unevaluated expressions. Comparing the raw tuple made
        `canonical(Literal('a'))` -> ('other', "Literal(value='a')"), which can never equal
        ('str','a'), so EVERY membership test returned False. The v1 adapter emits exactly this
        shape for every list-valued Sigma predicate, so a whole common rule family silently
        matched nothing and was counted as rows_predicate_false - a definitive wrong negative.
        """
        result = evaluate([{"u": "a"}, {"u": "b"}, {"u": "z"}], read(),
                          Filter(id="f", input="r",
                                 condition=InList(FieldExpr(FieldRef("u")),
                                                  (Literal("a"), Literal("b")))),
                          emit("f"))
        self.assertEqual([dict(r.values)["u"] for r in result.rows], ["a", "b"])

    def test_an_inlist_match_is_counted_as_true_not_false(self):
        result = evaluate([{"u": "a"}, {"u": "z"}], read(),
                          Filter(id="f", input="r",
                                 condition=InList(FieldExpr(FieldRef("u")), (Literal("a"),))),
                          emit("f"))
        self.assertEqual(result.counts.rows_predicate_true, 1)
        self.assertEqual(result.counts.rows_predicate_false, 1)

    def test_a_json_float_equals_an_integer_literal(self):
        """`canonical()` is identity, where 1 == True must not collapse. Reusing it for `=`
        meant 1024.0 never equalled 1024 - a silent definitive wrong negative for every numeric
        comparison against a float field."""
        result = evaluate([{"b": 1024.0}], read(),
                          Filter(id="f", input="r",
                                 condition=Comparison("=", FieldExpr(FieldRef("b")),
                                                      Literal(1024))),
                          emit("f"))
        self.assertIs(result.verdict, Verdict.MATCHED)

    def test_a_boolean_is_still_distinct_from_a_number_in_equality(self):
        result = evaluate([{"n": 1}], read(),
                          Filter(id="f", input="r",
                                 condition=Comparison("=", FieldExpr(FieldRef("n")),
                                                      Literal(True))),
                          emit("f"))
        self.assertIs(result.verdict, Verdict.NO_MATCH, "1 must not equal True")

    # --- C2/A1/A2: match_window was broken in both directions ---
    def test_a_declared_window_is_not_silently_used_to_narrow_the_join(self):
        """`on` is authoritative. The old pre-filter discarded pairs `on` accepted, turning a
        real match into NO_MATCH with no refusal and no counter."""
        def bounded(window):
            node = Join(id="j", left="l", right="r",
                        on=BoolOp("and", (
                            Comparison("=", EventExpr("left", None, FieldRef("host")),
                                       EventExpr("right", None, FieldRef("host"))),
                            Comparison(">=", EventExpr("right", None, FieldRef("t")),
                                       EventExpr("left", None, FieldRef("t"))),
                            Comparison("<=", EventExpr("right", None, FieldRef("t")),
                                       Arith("+", EventExpr("left", None, FieldRef("t")),
                                             Literal(600))))),
                        match_window=window)
            return evaluate_ir(graph(read("l"), read("r"), node, emit("j")),
                               Sample({"l": [{"host": "a", "t": 0}],
                                       "r": [{"host": "a", "t": 300}]},
                                      time_bindings={"l": "t", "r": "t"}))

        without = bounded(None)
        with_window = bounded(Duration(60))
        self.assertEqual(without.verdict, Verdict.MATCHED)
        self.assertEqual(with_window.verdict, Verdict.MATCHED,
                         "a 60s window must not delete a pair that `on` accepts")

    def test_a_window_that_cannot_be_enforced_says_so(self):
        """A caveat that claims a boundary was applied when it was not is worse than none."""
        node = Join(id="j", left="l", right="r",
                    on=BoolOp("and", (
                        Comparison("=", EventExpr("left", None, FieldRef("host")),
                                   EventExpr("right", None, FieldRef("host"))),
                        Comparison(">=", EventExpr("right", None, FieldRef("t")),
                                   EventExpr("left", None, FieldRef("t"))))),
                    match_window=Duration(60))
        result = evaluate_ir(graph(read("l"), read("r"), node, emit("j")),
                             Sample({"l": [{"host": "a", "t": 0}],
                                     "r": [{"host": "a", "t": 36_000}]},
                                    time_bindings={"l": "t", "r": "t"}))
        codes = result.caveat_codes()
        self.assertIn("JOIN_TEMPORAL_WINDOW_DECLARED_NOT_ENFORCED", codes)
        self.assertIn("JOIN_WINDOW_NOT_ENFORCED_NO_CLOCK", codes)
        self.assertNotIn("JOIN_TEMPORAL_BOUNDARY_INCLUSIVE", codes)

    # --- C3: count() ignored where ---
    def test_a_count_with_a_where_clause_honours_it(self):
        """`Measure('Failed','count', where=ok==False)` counted EVERY row."""
        rows = [{"u": "a", "ok": False}, {"u": "a", "ok": False}, {"u": "a", "ok": True},
                {"u": "b", "ok": True}]
        measure = Measure("Failed", "count",
                          where=Comparison("=", FieldExpr(FieldRef("ok")), Literal(False)))
        result = self._grouped_for(rows, (measure,))
        got = {dict(r.values)["u"]: dict(r.values)["Failed"] for r in result.rows}
        self.assertEqual(got, {"a": 2, "b": 0})

    def _grouped_for(self, rows, measures):
        agg = Aggregate(id="a", input="r", measures=measures, group_by=(FieldRef("u"),))
        return evaluate(rows, read(), agg, emit("a"))

    # --- H1: matched_right keyed on Row.index, which is only unique per Read ---
    def test_a_right_anti_join_keeps_unmatched_rows_from_a_non_read_input(self):
        """A SetOp right input numbers each side from 0, so a matched sibling marked its
        unmatched sibling as matched - and `kind='right'`, whose only purpose is to KEEP those
        rows, dropped them. Two matching left rows are needed to distinguish the correct
        ordinal-keyed set from an index-keyed one."""
        node = Join(id="j", left="l", right="u",
                    on=Comparison("=", EventExpr("left", None, FieldRef("host")),
                                  EventExpr("right", None, FieldRef("host"))),
                    kind="right", unmatched="preserve_right", cardinality="many_to_many")
        ir = graph(read("l"), read("r1"), read("r2"),
                   SetOp(id="u", left="r1", right="r2", op="append"), node, emit("j"))
        result = evaluate_ir(ir, Sample({
            "l": [{"host": "a"}, {"host": "a"}],
            "r1": [{"host": "a"}],
            "r2": [{"host": "zz"}, {"host": "yy"}]}))
        self.assertEqual(result.state, EvalState.EVALUATED, result.reason)
        kept = {r.values.get("host") for r in result.rows}
        self.assertEqual(kept, {"a", "zz", "yy"},
                         "both unmatched right rows must survive a right outer join")
        self.assertEqual(len(result.rows), 4, "two matches plus the two unmatched right rows")

    # --- H2/A3: Row.side fabricated a value for a side that does not exist ---
    def test_an_unmatched_row_has_no_value_for_the_side_that_never_matched(self):
        result = evaluate_ir(
            graph(read("l"), read("r"),
                  Join(id="j", left="l", right="r",
                       on=Comparison("=", EventExpr("left", None, FieldRef("host")),
                                     EventExpr("right", None, FieldRef("host"))),
                       kind="left", unmatched="preserve_left"),
                  Derive(id="d", input="j",
                         assignments=((FieldRef("right_host"),
                                       EventExpr("right", None, FieldRef("host"))),)),
                  emit("d")),
            Sample({"l": [{"host": "LEFT-ONLY"}], "r": [{"host": "other"}]}))
        self.assertEqual(result.state, EvalState.EVALUATED, result.reason)
        self.assertEqual(dict(result.rows[0].values).get("right_host"), None,
                         "the right side did not match, so its value is absent, not the left's")

    def test_side_scoping_survives_more_than_one_node(self):
        result = evaluate_ir(
            graph(read("l"), read("r"),
                  Join(id="j", left="l", right="r",
                       on=Comparison("=", EventExpr("left", None, FieldRef("host")),
                                     EventExpr("right", None, FieldRef("host")))),
                  Derive(id="d1", input="j",
                         assignments=((FieldRef("x"), Literal(1)),)),
                  Derive(id="d2", input="d1",
                         assignments=((FieldRef("h"), EventExpr("left", None,
                                                               FieldRef("host"))),)),
                  emit("d2")),
            Sample({"l": [{"host": "a"}], "r": [{"host": "a"}]}))
        self.assertEqual(result.state, EvalState.EVALUATED, result.reason)
        self.assertEqual(dict(result.rows[0].values)["h"], "a")

    # --- H4: Arith operator unvalidated ---
    def test_an_unknown_arithmetic_operator_is_refused_not_evaluated_as_modulo(self):
        """`Arith('^', 7, 3) > 0` silently evaluated 7 % 3 and MATCHED."""
        result = evaluate([{"a": 7}], read(),
                          Filter(id="f", input="r",
                                 condition=Comparison(">", Arith("^", FieldExpr(FieldRef("a")),
                                                                Literal(3)), Literal(0))),
                          emit("f"))
        self.assertEqual(result.reason.code, "UNKNOWN_ARITHMETIC_OPERATOR")

    def test_an_unknown_operator_does_not_escape_as_a_zero_division(self):
        result = evaluate([{"a": 7}], read(),
                          Filter(id="f", input="r",
                                 condition=Comparison(">", Arith("^", FieldExpr(FieldRef("a")),
                                                                Literal(0)), Literal(0))),
                          emit("f"))
        self.assertIsNotNone(result.reason, "evaluate_ir must return a refusal, never raise")

    # --- B2: Expand output was uncapped ---
    def test_an_enormous_expand_is_refused_rather_than_exhausting_memory(self):
        """One sample row holding a long array is ONE input row, so MAX_INPUT_ROWS gave no
        protection at all. 374 MB was reachable from a single JSON array."""
        node = Expand(id="x", input="r", field=FieldRef("ips"))
        result = evaluate([{"ips": list(range(300_000))}], read(), node, emit("x"))
        self.assertEqual(result.reason.code, "EXPAND_OUTPUT_TOO_LARGE")

    # --- B1: join work was O(left x right) with no bound ---
    def test_a_join_refuses_work_beyond_its_pair_budget(self):
        node = Join(id="j", left="l", right="r",
                    on=Comparison("=", EventExpr("left", None, FieldRef("k")),
                                  EventExpr("right", None, FieldRef("k"))),
                    cardinality="many_to_many")
        rows = [{"k": i} for i in range(2000)]
        result = evaluate_ir(graph(read("l"), read("r"), node, emit("j")),
                             Sample({"l": rows, "r": rows}))
        self.assertEqual(result.reason.code, "EVAL_JOIN_WORK_EXCEEDED")

    # --- probe 6: a refusal message leaked sample VALUES ---
    def test_no_refusal_message_contains_sample_content(self):
        secret = "P@ssw0rd-Do-Not-Log"
        node = Join(id="j", left="l", right="r",
                    on=Comparison("=", EventExpr("left", None, FieldRef("host")),
                                  EventExpr("right", None, FieldRef("host"))),
                    collision="error")
        result = evaluate_ir(graph(read("l"), read("r"), node, emit("j")),
                             Sample({"l": [{"host": "a", "pw": secret}],
                                     "r": [{"host": "a", "pw": "other"}]}))
        self.assertEqual(result.reason.code, "JOIN_FIELD_COLLISION")
        self.assertNotIn(secret, result.reason.message)
        self.assertNotIn(secret, str(result.to_dict()))

    # --- C3: a blank source name was accepted ---
    def test_a_blank_source_name_is_refused_like_an_unresolved_one(self):
        for name in ("   ", "\t\n"):
            ir = graph(Read(id="r", selector=SourceSelector(name=name)), emit("r"))
            result = evaluate_ir(ir, sample([{"a": 1}], "r"))
            self.assertEqual(result.reason.code, "UNRESOLVED_SOURCE", repr(name))

    # --- C1 (security): the invariant used truthiness ---
    def test_the_not_evaluated_invariant_cannot_be_defeated_by_a_bool_override(self):
        class LyingTuple(tuple):
            def __bool__(self):
                return False

        with self.assertRaises(ValueError):
            EvaluationResult(state=EvalState.NOT_EVALUATED, reason=object(),
                             rows=LyingTuple((Row(values={"a": 1}, index=0),)))

    # --- B3: RecursionError escaped evaluate_ir ---
    def test_a_very_deep_expression_is_refused_not_crashed(self):
        expr = Literal(True)
        for _ in range(5000):
            expr = BoolOp("not", (expr,))
        result = evaluate([{"a": 1}], read(),
                          Filter(id="f", input="r", condition=expr), emit("f"))
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)


class OrderingAndLabellingTests(unittest.TestCase):
    """Fixes for the open items left after the review pass.

    These are the same defect class as the reviewed ones - a confident answer that is quietly
    wrong - and they were left open deliberately rather than half-fixed.
    """

    def test_multiple_order_keys_sort_lexicographically(self):
        """The last declared key used to win outright.

        `order_by=((a asc),(b asc))` over (2,1),(1,2),(1,1) returned [(1,1),(2,1),(1,2)]
        instead of [(1,1),(1,2),(2,1)] - wrong rows for exactly the top-N-per-group shape
        Arrange exists to express, with no refusal and no caveat.
        """
        rows = [{"a": 2, "b": 1}, {"a": 1, "b": 2}, {"a": 1, "b": 1}]
        result = evaluate(rows, read(),
                          Arrange(id="s", input="r",
                                  order_by=((FieldExpr(FieldRef("a")), True),
                                             (FieldExpr(FieldRef("b")), True))),
                          emit("s"))
        self.assertEqual([(r.values["a"], r.values["b"]) for r in result.rows],
                         [(1, 1), (1, 2), (2, 1)])

    def test_mixed_direction_keys_each_honour_their_own_direction(self):
        rows = [{"a": 1, "b": 1}, {"a": 1, "b": 2}, {"a": 2, "b": 1}]
        result = evaluate(rows, read(),
                          Arrange(id="s", input="r",
                                  order_by=((FieldExpr(FieldRef("a")), True),
                                             (FieldExpr(FieldRef("b")), False))),
                          emit("s"))
        self.assertEqual([(r.values["a"], r.values["b"]) for r in result.rows],
                         [(1, 2), (1, 1), (2, 1)])

    def test_top_n_per_group_uses_all_keys_before_the_limit(self):
        """The shape the node is justified by: order by a, then b, then limit."""
        rows = [{"u": "a", "n": 1, "t": 9}, {"u": "a", "n": 2, "t": 8},
                {"u": "a", "n": 3, "t": 7}, {"u": "b", "n": 1, "t": 6}]
        result = evaluate(rows, read(),
                          Arrange(id="s", input="r",
                                  order_by=((FieldExpr(FieldRef("u")), True),
                                             (FieldExpr(FieldRef("n")), False)),
                                  limit=2),
                          emit("s"))
        self.assertEqual([(r.values["u"], r.values["n"]) for r in result.rows],
                         [("a", 3), ("a", 2)])

    def test_an_unknown_key_still_sorts_last_with_several_keys(self):
        rows = [{"a": 1, "b": 1}, {"a": 1}, {"a": 0, "b": 9}]
        result = evaluate(rows, read(),
                          Arrange(id="s", input="r",
                                  order_by=((FieldExpr(FieldRef("a")), True),
                                             (FieldExpr(FieldRef("b")), True))),
                          emit("s"))
        self.assertEqual(result.rows[-1].values.get("b"), None,
                         "the row missing the second key must sort last")

    def test_emit_order_by_is_applied_rather_than_silently_dropped(self):
        """The model declares Emit.order_by and an earlier version ignored it entirely, so a
        declared alert ordering vanished with no refusal and no caveat - the same 'silently
        drop a declared parameter' pattern 3A refuses for Frame.offset_seconds."""
        result = evaluate([{"n": 3}, {"n": 1}, {"n": 2}], read(),
                          Emit(id="o", input="r",
                               order_by=((FieldExpr(FieldRef("n")), True),)), output="o")
        self.assertEqual([r.values["n"] for r in result.rows], [1, 2, 3])
        self.assertIn("EMIT_ORDER_BY_APPLIED", result.caveat_codes())

    def test_an_all_undecidable_filter_does_not_assert_a_negative_it_does_not_have(self):
        """Every row lacked the field, so the kernel holds zero evidence either way, yet the
        verdict label was about to say 'Matched nothing in the sample'."""
        result = evaluate([{"other": 1}, {"other": 2}], read(),
                          Filter(id="f", input="r",
                                 condition=Comparison("=", FieldExpr(FieldRef("event_category")),
                                                      Literal("authentication"))),
                          emit("f"))
        self.assertIs(result.verdict, Verdict.NO_MATCH)
        self.assertEqual(result.counts.rows_predicate_unknown, 2)
        self.assertIn("NO_EVIDENCE_ROWS_WERE_ALL_UNDECIDABLE", result.caveat_codes())

    def test_a_filter_that_decisively_rejects_everything_gets_no_such_caveat(self):
        """The caveat must not fire when rows were genuinely FALSE - that would dilute it."""
        result = evaluate([{"c": "a"}, {"c": "b"}], read(),
                          Filter(id="f", input="r",
                                 condition=Comparison("=", FieldExpr(FieldRef("c")),
                                                      Literal("z"))),
                          emit("f"))
        self.assertIs(result.verdict, Verdict.NO_MATCH)
        self.assertNotIn("NO_EVIDENCE_ROWS_WERE_ALL_UNDECIDABLE", result.caveat_codes())

    def test_a_refused_node_marks_everything_after_it_as_skipped(self):
        """`skipped_from` used to be assigned and then returned past, so no result could ever
        contain a `skipped` entry and the module docstring's claim was false."""
        from models.rule_ir import Join
        result = evaluate_ir(
            graph(read(),
                  Join(id="j", left="r", right="r", kind="full",
                       on=Comparison("=", FieldExpr(FieldRef("a")), Literal(1))),
                  Derive(id="d", input="j",
                         assignments=((FieldRef("x"), Literal(1)),)),
                  emit("d")),
            sample([{"a": 1}], "r"))
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        statuses = {t.node_id: t.status for t in result.trace}
        self.assertEqual(statuses.get("j"), "refused")
        self.assertEqual(statuses.get("d"), "skipped")
        self.assertEqual(statuses.get("o"), "skipped")

    def test_a_non_mapping_sample_row_is_a_named_refusal_not_a_crash(self):
        """EVAL_INPUT_INVALID was registered and never raised, so a string row escaped as an
        uncaught TypeError from inside a row builder."""
        for bad in ("notadict", None, 42, ["a"]):
            result = evaluate_ir(graph(read(), emit("r")), Sample({"r": [bad]}))
            self.assertEqual(result.reason.code, "EVAL_INPUT_INVALID", repr(bad))
            self.assertIs(result.verdict, Verdict.NOT_EVALUATED)

    def test_an_unknown_counter_name_is_an_obvious_mistake_not_a_new_attribute(self):
        from kernel.eval_expr import EvalContext
        from kernel.eval_types import EvalCounts
        ctx = EvalContext(counts=EvalCounts(), unmodelled=[])
        with self.assertRaises(AttributeError):
            ctx.unknown("nonexistent_bucket")
        self.assertFalse(hasattr(ctx.counts, "nonexistent_bucket"))


class PatternTests(unittest.TestCase):
    """Sequence matching. The `until` negative twin comes FIRST, deliberately.

    `until` exists to produce silence. A pattern that reports a match when the stop condition
    fired fires on exactly the behaviour it was written to exclude, and nothing in the result
    would say so. It is the most expensive bug this module could have, so it is pinned before
    any positive case.
    """

    def _pattern(self, stages, mode="ordered", rows=None, read_id="r", **kw):
        node = Pattern(id="p", stages=tuple(stages), mode=mode,
                       max_span=Duration(600), **kw)
        return evaluate_ir(graph(Read(id=read_id, selector=SRC), node, emit("p")),
                           sample(rows if rows is not None else [], read_id),
                           time_bindings={read_id: "t"})

    def _until_graph(self, rows):
        """A, B, C each behind its own Filter.

        A Stage carries no predicate of its own - it reads the node named by `stage.input` -
        so the ONLY way to make stages distinguishable is to give each one a different
        filtered input. With all stages on one input they are indistinguishable, every suffix
        is also a candidate, and `until` becomes meaningless.
        """
        def only(event):
            return Filter(id=f"f{event}", input="r",
                          condition=Comparison("=", FieldExpr(FieldRef("e")),
                                               Literal(event)))
        stages = (Stage(id="sA", input="fA"), Stage(id="sB", input="fB"),
                  Stage(id="sC", input="fC", quantifier="none"))
        node = Pattern(id="p", stages=stages, mode="until", max_span=Duration(600),
                       terminal="any")
        return evaluate_ir(graph(Read(id="r", selector=SRC), only("A"), only("B"), only("C"),
                                 node, emit("p")),
                           sample(rows, "r", time_bindings={"r": "t"}))

    def test_until_does_not_match_when_the_stop_condition_fires(self):
        """THE negative twin. A then B then C - and C happened."""
        result = self._until_graph([{"e": "A", "t": 0}, {"e": "B", "t": 1},
                                    {"e": "C", "t": 2}])
        self.assertIs(result.verdict, Verdict.NO_MATCH,
                      "until fired, so this must NOT be a match")

    def test_until_matches_when_the_stop_condition_never_fires(self):
        result = self._until_graph([{"e": "A", "t": 0}, {"e": "B", "t": 1}])
        self.assertIs(result.verdict, Verdict.MATCHED)

    def test_until_with_no_stop_stage_is_refused(self):
        node = Pattern(id="p", stages=(Stage(id="s1", input="r"),), mode="until",
                       max_span=Duration(600))
        result = evaluate_ir(graph(Read(id="r", selector=SRC), node, emit("p")),
                             sample([{"e": "A", "t": 0}], "r", time_bindings={"r": "t"}))
        self.assertEqual(result.reason.code, "PATTERN_UNTIL_NEEDS_A_STOP_STAGE")

    def test_an_incompatible_stage_quantifier_is_refused(self):
        """`all` in `missing` mode contradicts itself: the point is non-occurrence."""
        node = Pattern(id="p", stages=(Stage(id="s1", input="r", quantifier="all"),),
                       mode="missing", max_span=Duration(600))
        result = evaluate_ir(graph(Read(id="r", selector=SRC), node, emit("p")),
                             sample([{"a": 1}], "r", time_bindings={"r": "a"}))
        self.assertEqual(result.reason.code, "INCOMPATIBLE_STAGE_QUANTIFIER")

    def test_an_ordered_pattern_without_a_span_is_refused(self):
        """Without a span, "ordered" has no time relationship at all."""
        node = Pattern(id="p", stages=(Stage(id="s1", input="r"),), mode="ordered")
        result = evaluate_ir(graph(Read(id="r", selector=SRC), node, emit("p")),
                             sample([{"a": 1}], "r"))
        self.assertEqual(result.reason.code, "PATTERN_SPAN_NOT_DECLARED")

    def _two_stage_graph(self, mode="ordered", rows=None, **kw):
        """A then B, each behind its own Filter.

        A Stage carries no predicate of its own - it reads the node named by `stage.input` -
        and may only consume rows from THAT node. With both stages on one input they would be
        indistinguishable and the sequence would be meaningless.
        """
        def only(event):
            return Filter(id=f"f{event}", input="r",
                          condition=Comparison("=", FieldExpr(FieldRef("e")), Literal(event)))
        stages = (Stage(id="sA", input="fA"), Stage(id="sB", input="fB"))
        if mode == "until":
            stages = stages + (Stage(id="sC", input="fC", quantifier="none"),)
        node = Pattern(id="p", stages=stages, mode=mode, max_span=Duration(600),
                       **({"terminal": "any"} | kw))
        return evaluate_ir(graph(Read(id="r", selector=SRC), only("A"), only("B"), only("C"),
                                 node, emit("p")),
                           sample(rows if rows is not None else [], "r",
                                   time_bindings={"r": "t"}))

    def test_ordered_stages_need_a_time_relationship(self):
        result = self._two_stage_graph(rows=[{"e": "A", "t": 0}, {"e": "B", "t": 1}])
        self.assertIs(result.verdict, Verdict.MATCHED)

    def test_a_stage_may_not_consume_another_stages_rows(self):
        """The regression that made `until` fire on the behaviour it excludes.

        Only A and B exist. There is no C row at all, so nothing may satisfy the stop stage,
        and the match must survive. Before the fix the matcher ignored `stage.input` and drew
        from a merged pool, so it could consume A's row as if it satisfied the C stage.
        """
        result = self._two_stage_graph(mode="until",
                                       rows=[{"e": "A", "t": 0}, {"e": "B", "t": 1}])
        self.assertIs(result.verdict, Verdict.MATCHED)

    def test_the_terminal_policy_is_declared_as_an_assumption(self):
        result = self._two_stage_graph(rows=[{"e": "A", "t": 0}, {"e": "B", "t": 1}],
                                       terminal="any")
        self.assertIn("PATTERN_TERMINAL_POLICY_ANY_ASSUMED", result.caveat_codes())

    def test_the_max_span_actually_excludes_a_distant_match(self):
        """Without this, the span check is untested: dropping it changed nothing.

        A at t=0 and B at t=10000 are four hours apart, and the span is 600 seconds. The
        matcher must refuse, rather than treating "ordered" as merely "both stages appeared".
        """
        result = self._two_stage_graph(rows=[{"e": "A", "t": 0}, {"e": "B", "t": 10_000}])
        self.assertIs(result.verdict, Verdict.NO_MATCH,
                      "a match four hours apart must not satisfy a 600s span")

    def test_the_max_span_admits_a_near_match(self):
        result = self._two_stage_graph(rows=[{"e": "A", "t": 0}, {"e": "B", "t": 300}])
        self.assertIs(result.verdict, Verdict.MATCHED)

    def test_a_span_that_cannot_be_enforced_is_refused_rather_than_ignored(self):
        """`Row.time` is set only by an Aggregate frame, so a Pattern's stages have no clock.

        With no declared binding the span comparison is inert and `ordered` degrades into
        "both stages appeared somewhere" - the exact thing PATTERN_SPAN_NOT_DECLARED exists to
        prevent. It must refuse, not quietly match.
        """
        node = Pattern(id="p", stages=(Stage(id="sA", input="fA"), Stage(id="sB", input="fB")),
                       mode="ordered", max_span=Duration(600))

        def only(event):
            return Filter(id=f"f{event}", input="r",
                          condition=Comparison("=", FieldExpr(FieldRef("e")), Literal(event)))
        result = evaluate_ir(graph(Read(id="r", selector=SRC), only("A"), only("B"),
                                   node, emit("p")),
                             sample([{"e": "A"}, {"e": "B"}], "r"))
        self.assertEqual(result.reason.code, "TIME_FIELD_UNRESOLVED")
        self.assertIn("degrade into", result.reason.message)

    def test_a_match_reaching_the_end_of_the_sample_says_so(self):
        """A static sample cannot know the event that would have continued the sequence."""
        result = self._two_stage_graph(rows=[{"e": "A", "t": 0}, {"e": "B", "t": 1}])
        self.assertIn("SEQUENCE_MATCH_REACHES_END_OF_SAMPLE", result.caveat_codes())

    def test_a_pattern_with_no_stages_is_refused(self):
        """The model refuses to even CONSTRUCT one, which is stronger than a kernel refusal."""
        from models.rule_ir import RuleIRValidationError
        with self.assertRaises(RuleIRValidationError) as caught:
            self._pattern((), rows=[{"a": 1}])
        self.assertEqual(caught.exception.code, "PATTERN_REQUIRES_STAGES")

    def test_a_runaway_search_refuses_rather_than_running_forever(self):
        """The step budget is decremented BEFORE the work, so a combinatorially bad pattern
        refuses rather than spending minutes and then answering confidently."""
        import kernel.eval_stateful as stateful
        stages = tuple(Stage(id=f"s{i}", input="r") for i in range(6))
        node = Pattern(id="p", stages=stages, mode="ordered", max_span=Duration(10_000))
        original = stateful.MAX_SEQUENCE_STEPS
        stateful.MAX_SEQUENCE_STEPS = 50
        try:
            result = evaluate_ir(graph(Read(id="r", selector=SRC), node, emit("p")),
                             sample([{"a": 1, "t": i} for i in range(300)], "r",
                                    time_bindings={"r": "t"}))
        finally:
            stateful.MAX_SEQUENCE_STEPS = original
        self.assertEqual(result.reason.code, "EVAL_SEQUENCE_SEARCH_EXCEEDED")


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
