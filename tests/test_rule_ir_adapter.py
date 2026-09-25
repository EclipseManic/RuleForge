"""Contract tests for the v1 -> RuleIR adapter.

Phase 2 of docs/ruleforge-redesign-plan.md. Ships DARK; `ShadowModeTests` asserts nothing
in the app calls it.

The adapter's defining promise is that it REFUSES rather than GUESSES, because the v1
model is a bag of unordered lists. These tests therefore assert two distinct things:

  1. unambiguous v1 state converts exactly, with the right shape and no invented name;
  2. ambiguous v1 state produces a `must` loss, never a plausible-looking guess.

The `must` loss is the safety mechanism. It blocks `exact` and blocks cross-target
compilation, which is correct: when v1 does not record what a window MEANS, this tool does
not know, and saying so is the whole point.
"""

import unittest
from dataclasses import dataclass
from dataclasses import field as dc_field

from models.correlation import (Aggregation, CorrelationModel, Join, LogicNode, Lookup,
                                Predicate, Sequence, SequenceStage)
from models.rule_ir import FieldRef, RuleIRValidationError, validate_ir
from models.rule_ir_adapter import (correlation_to_ir, ir_to_correlation, parse_duration,
                                    request_to_ir)

SHADOW = "DARK-NOT-IN-APP"


@dataclass
class FakeRequest:
    """A stand-in with the same surface as the real v1 RuleRequest."""
    title: str = "t"
    description: str = "d"
    severity: str = "high"
    technique: str = "custom"
    field: str = "a"
    operator: str = "equals"
    value: str = "1"
    threshold: int | None = 1
    timeframe: str = "5m"
    group_by: str = "host.name"
    data_source: str = "*"
    wazuh_rule_id: int = 100100
    wazuh_parent_rule: str = ""
    siems: list = dc_field(default_factory=lambda: ["splunk"])
    conditions: list = dc_field(default_factory=list)
    condition_logic: str = "all"
    exclude_conditions: list = dc_field(default_factory=list)
    sequences: list = dc_field(default_factory=list)
    joins: list = dc_field(default_factory=list)
    aggregations: list = dc_field(default_factory=list)
    lookups: list = dc_field(default_factory=list)
    strict: bool = False


def kinds(ir):
    return [n.__class__.__name__ for n in ir.nodes]


def losses(ir, severity="must"):
    return [loss.code for loss in ir.parse_diagnostics if loss.severity == severity]


def single(**overrides):
    base = dict(logic=Predicate("process.command_line", "contains", "-enc"),
                source="*", window="5m", threshold=1)
    base.update(overrides)
    return CorrelationModel(**base)


class DurationTests(unittest.TestCase):
    def test_every_v1_unit_converts_exactly(self):
        self.assertEqual(parse_duration("30s").seconds, 30)
        self.assertEqual(parse_duration("5m").seconds, 300)
        self.assertEqual(parse_duration("2h").seconds, 7200)
        self.assertEqual(parse_duration("1d").seconds, 86400)

    def test_unparseable_windows_return_none_rather_than_raising(self):
        for bad in ("", "soon", "5x", "0m", "-3m", "5"):
            self.assertIsNone(parse_duration(bad), bad)


class UnambiguousConversionTests(unittest.TestCase):
    """v1 state that DOES determine a pipeline must convert cleanly."""

    def test_a_single_event_rule_becomes_read_filter_emit(self):
        ir = correlation_to_ir(single(source="logs-*"))
        validate_ir(ir)
        self.assertEqual(kinds(ir), ["Read", "Filter", "Emit"])
        self.assertEqual([n for n in ir.nodes if n.__class__.__name__ == "Read"][0].selector.name,
                         "logs-*")
        self.assertNotIn("UNRESOLVED_SOURCE", losses(ir))

    def test_a_named_source_is_recorded_as_parsed_not_authored(self):
        ir = correlation_to_ir(single(source="SigninLogs"))
        selector = [n for n in ir.nodes if n.__class__.__name__ == "Read"][0].selector
        self.assertEqual(selector.confidence, "parsed",
                         "a source that came from a parser is not analyst-authored")

    def test_boolean_structure_is_preserved_not_flattened(self):
        logic = LogicNode(op="or", children=(
            Predicate("a", "equals", "1"),
            LogicNode(op="and", children=(Predicate("b", "equals", "2"),
                                         Predicate("c", "equals", "3")))))
        ir = correlation_to_ir(single(logic=logic, source="logs-*"))
        validate_ir(ir)
        condition = [n for n in ir.nodes if n.__class__.__name__ == "Filter"][0].condition
        self.assertEqual(condition.op, "or", "the OR must survive as an OR")
        self.assertEqual(len(condition.children), 2)

    def test_exclusions_become_individual_negations_not_one_wide_not(self):
        """A set-wide NOT would invert ANDed exclusions.

        `not (a and b)` is true when neither holds, which is the opposite of excluding both.
        """
        ir = correlation_to_ir(single(source="logs-*", exclusions=[
            Predicate("user", "equals", "svc"), Predicate("host", "equals", "build")]))
        validate_ir(ir)
        condition = [n for n in ir.nodes if n.__class__.__name__ == "Filter"][0].condition
        self.assertEqual(condition.op, "and")
        nots = [c for c in condition.children if c.__class__.__name__ == "BoolOp"
                and c.op == "not"]
        self.assertEqual(len(nots), 2, "each exclusion is negated independently")

    def test_v1_not_with_several_children_fans_out_rather_than_dropping(self):
        logic = LogicNode(op="not", children=(Predicate("a", "equals", "1"),
                                              Predicate("b", "equals", "2")))
        ir = correlation_to_ir(single(logic=logic, source="logs-*"))
        condition = [n for n in ir.nodes if n.__class__.__name__ == "Filter"][0].condition
        self.assertEqual(condition.op, "and")
        self.assertEqual(len(condition.children), 2, "no child may be silently discarded")

    def test_a_count_threshold_becomes_a_measure_then_a_filter(self):
        ir = correlation_to_ir(single(source="logs-*", threshold=5, group_by=["user.name"]))
        validate_ir(ir)
        self.assertEqual(kinds(ir), ["Read", "Filter", "Aggregate", "Filter", "Emit"])
        aggregate = [n for n in ir.nodes if n.__class__.__name__ == "Aggregate"][0]
        self.assertEqual([m.name for m in aggregate.measures], ["EventCount"])
        threshold_filter = [n for n in ir.nodes if n.__class__.__name__ == "Filter"][1]
        self.assertEqual(threshold_filter.input, "aggregate",
                         "the threshold must be a filter AFTER the aggregate")

    def test_a_threshold_is_never_a_property_of_a_measure(self):
        """The v1 `Aggregation.threshold` defect in structural form.

        If a future edit put the threshold back on the measure, a filter could never be
        placed after the aggregate and the whole reason the kernel exists disappears.
        """
        ir = correlation_to_ir(single(source="logs-*", aggregations=[
            Aggregation("count", "", "Hits", 3)]))
        validate_ir(ir)
        measures = [n for n in ir.nodes if n.__class__.__name__ == "Aggregate"][0].measures
        for measure in measures:
            self.assertFalse(hasattr(measure, "threshold"),
                             "a threshold is a following filter, not a measure attribute")
        after = [n for n in ir.nodes if n.__class__.__name__ == "Filter" and n.input == "aggregate"]
        self.assertEqual(len(after), 1, "the aggregation threshold must survive as a filter")

    def test_multiple_aggregations_become_multiple_named_measures(self):
        ir = correlation_to_ir(single(source="logs-*", aggregations=[
            Aggregation("dc", "user.name", "UniqueUsers"),
            Aggregation("make_set", "source.ip", "SourceIPs")]))
        validate_ir(ir)
        aggregate = [n for n in ir.nodes if n.__class__.__name__ == "Aggregate"][0]
        self.assertEqual([(m.name, m.function) for m in aggregate.measures],
                         [("UniqueUsers", "dcount"), ("SourceIPs", "make_set")])

    def test_dc_maps_to_dcount_with_distinct_set(self):
        ir = correlation_to_ir(single(source="logs-*",
                                      aggregations=[Aggregation("dc", "user.name", "U")]))
        measure = [n for n in ir.nodes if n.__class__.__name__ == "Aggregate"][0].measures[0]
        self.assertEqual(measure.function, "dcount")
        self.assertTrue(measure.distinct)

    def test_in_list_becomes_a_typed_list_not_a_flattened_or(self):
        ir = correlation_to_ir(single(source="logs-*",
                                      logic=Predicate("user", "in_list", ["a", "b"])))
        validate_ir(ir)
        condition = [n for n in ir.nodes if n.__class__.__name__ == "Filter"][0].condition
        self.assertEqual(condition.__class__.__name__, "InList")
        self.assertEqual(len(condition.options), 2, "an OR of list members stays one node")


class RefusalTests(unittest.TestCase):
    """Ambiguous v1 state must refuse, not guess."""

    def test_a_wildcard_source_never_becomes_a_table_name(self):
        for wildcard in ("*", "", "   "):
            ir = correlation_to_ir(single(source=wildcard))
            read = [n for n in ir.nodes if n.__class__.__name__ == "Read"][0]
            self.assertIsNone(read.selector.name,
                              f"source {wildcard!r} must stay unresolved, never become a table")
            self.assertIn("UNRESOLVED_SOURCE", losses(ir))

    def test_an_ambiguous_window_refuses_to_choose_its_kind(self):
        """v1 has one `window` string; v2 has five distinct meanings for it.

        Emitting any one of them would be a guess, and guessing here is the
        `span=5m is not a correlation window` bug. So the duration is measured but the
        KIND is refused.
        """
        ir = correlation_to_ir(single(source="logs-*", threshold=5, group_by=["user"]))
        self.assertIn("AMBIGUOUS_WINDOW_KIND", losses(ir))
        aggregate = [n for n in ir.nodes if n.__class__.__name__ == "Aggregate"][0]
        self.assertIsNone(aggregate.frame, "no frame may be invented from an ambiguous window")
        with self.assertRaises(RuleIRValidationError) as raised:
            validate_ir(ir, target="splunk")
        self.assertEqual(raised.exception.code, "MUST_LOSS")

    def test_an_opaque_sequence_stage_is_preserved_not_parsed_into_fields(self):
        """A free-text stage condition must not be mined for a field name.

        This is the never-invent rule applied to parsing: the text is retained, and no
        predicate is fabricated from it.
        """
        raw = "from win.event.channel:Microsoft-Windows-Sysmon/Operational"
        ir = correlation_to_ir(single(source="logs-*", sequences=[
            Sequence(join_by="host.name", maxspan="5m",
                     stages=[SequenceStage(event="a", condition=raw)])]))
        self.assertIn("OPAQUE_SEQUENCE_STAGE", losses(ir))
        rendered = repr(ir.parse_diagnostics)
        self.assertIn(raw, rendered, "the original stage text must be preserved verbatim")

    def test_a_join_with_unresolved_endpoints_is_refused(self):
        ir = correlation_to_ir(single(source="logs-*", joins=[
            Join(kind="inner", left="native_left", right="native_right", on="DeviceId")]))
        self.assertIn("UNRESOLVED_JOIN_ENDPOINTS", losses(ir))
        selectors = {n.selector.name for n in ir.nodes if n.__class__.__name__ == "Read"}
        for name in ("native_left", "native_right"):
            self.assertNotIn(name, selectors,
                             f"{name} must not have been turned into a source")
        # The names ARE preserved in the loss, because losing them would hide what the
        # analyst has to resolve by hand.
        self.assertIn("native_left", repr(ir.parse_diagnostics))

    def test_an_opaque_join_predicate_is_preserved_not_parsed(self):
        ir = correlation_to_ir(single(source="logs-*", event_streams=[
            {"name": "processes", "source": "DeviceProcessEvents"},
            {"name": "network", "source": "DeviceNetworkEvents"}], joins=[
            Join(kind="inner", left="processes", right="network", on="DeviceId")]))
        self.assertIn("OPAQUE_JOIN_PREDICATE", losses(ir))
        self.assertIn("DeviceId", repr(ir.parse_diagnostics))

    def test_a_lookup_is_refused_because_v1_has_no_typed_contract(self):
        ir = correlation_to_ir(single(source="logs-*",
                                      lookups=[Lookup(name="privileged", arguments="user OUTPUT p")]))
        self.assertIn("UNREPRESENTABLE_LOOKUP", losses(ir))
        self.assertIn("privileged", repr(ir.parse_diagnostics))

    def test_an_unmappable_aggregate_function_is_refused_not_coerced_to_count(self):
        ir = correlation_to_ir(single(source="logs-*", aggregations=[
            Aggregation("percentile", "latency", "P99")]))
        self.assertIn("UNREPRESENTABLE_AGGREGATE", losses(ir))

    def test_a_group_by_with_no_aggregate_is_refused(self):
        ir = correlation_to_ir(single(source="logs-*", threshold=1, group_by=["user.name"]))
        self.assertIn("GROUP_BY_WITHOUT_AGGREGATE", losses(ir),
                      "v1 does not say what a group_by groups when there is no aggregate")

    def test_a_model_with_no_logic_refuses_rather_than_inventing_one(self):
        ir = correlation_to_ir(CorrelationModel(logic=None, source="logs-*"))
        self.assertIn("NO_LOGIC", losses(ir))
        rendered = repr(ir)
        for phantom in ("example.exe", "process.name"):
            self.assertNotIn(phantom, rendered,
                             f"a model with no logic must not acquire {phantom}")


class RequestTests(unittest.TestCase):
    """The form path is genuinely ordered, so it converts far more cleanly."""

    def test_a_normal_form_request_converts_with_only_a_source_loss(self):
        request = FakeRequest(data_source="SecurityEvent",
                              conditions=[{"field": "EventID", "operator": "equals", "value": "4625"}],
                              threshold=1, group_by="")
        ir = request_to_ir(request)
        validate_ir(ir)
        self.assertEqual(kinds(ir), ["Read", "Filter", "Emit"])
        self.assertEqual(losses(ir), [], "an explicit source and a single condition need no loss")

    def test_the_placeholder_data_source_is_unresolved(self):
        ir = request_to_ir(FakeRequest(data_source="*",
                                       conditions=[{"field": "a", "operator": "equals", "value": "1"}]))
        read = [n for n in ir.nodes if n.__class__.__name__ == "Read"][0]
        self.assertIsNone(read.selector.name)
        self.assertIn("UNRESOLVED_SOURCE", losses(ir))

    def test_structured_conditions_win_over_the_duplicated_top_level_triple(self):
        """RuleRequest carries field/operator/value AND conditions[]. They can disagree.

        The structured list is the analyst's real input, so it must win; trusting the
        top-level triple is how a stale default value survives an edit.
        """
        request = FakeRequest(data_source="logs", field="stale", operator="equals", value="stale",
                              conditions=[{"field": "EventID", "operator": "equals", "value": "4625"}])
        ir = request_to_ir(request)
        condition = [n for n in ir.nodes if n.__class__.__name__ == "Filter"][0].condition
        self.assertEqual(condition.left.ref.name, "EventID")

    def test_condition_logic_any_becomes_an_or(self):
        request = FakeRequest(data_source="logs", condition_logic="any", conditions=[
            {"field": "a", "operator": "equals", "value": "1"},
            {"field": "b", "operator": "equals", "value": "2"}])
        ir = request_to_ir(request)
        condition = [n for n in ir.nodes if n.__class__.__name__ == "Filter"][0].condition
        self.assertEqual(condition.op, "or")

    def test_exclude_conditions_become_negations(self):
        request = FakeRequest(data_source="logs",
                              conditions=[{"field": "a", "operator": "equals", "value": "1"}],
                              exclude_conditions=[{"field": "u", "operator": "equals", "value": "svc"}])
        ir = request_to_ir(request)
        condition = [n for n in ir.nodes if n.__class__.__name__ == "Filter"][0].condition
        self.assertEqual(condition.op, "and")
        self.assertTrue(any(c.op == "not" for c in condition.children))

    def test_a_count_request_produces_a_measure_and_a_threshold_filter(self):
        request = FakeRequest(data_source="logs", threshold=5, group_by="user.name",
                              conditions=[{"field": "a", "operator": "equals", "value": "1"}])
        ir = request_to_ir(request)
        self.assertEqual(kinds(ir), ["Read", "Filter", "Aggregate", "Filter", "Emit"])
        self.assertIn("AMBIGUOUS_WINDOW_KIND", losses(ir),
                      "even the form cannot say which kind of window its timeframe is")

    def test_no_conditions_refuses_rather_than_filling_in_a_default(self):
        ir = request_to_ir(FakeRequest(data_source="logs", conditions=[]))
        self.assertIn("NO_LOGIC", losses(ir))
        self.assertNotIn("example.exe", repr(ir))


class RoundTripTests(unittest.TestCase):
    def test_v1_round_trips_for_representable_graphs(self):
        model = single(source="logs-*", logic=Predicate("user", "equals", "alice"))
        restored = ir_to_correlation(correlation_to_ir(model))
        self.assertEqual(restored.source, "logs-*")
        self.assertEqual(restored.logic.field, "user")
        self.assertEqual(restored.logic.operator, "equals")
        self.assertEqual(restored.logic.value, "alice")

    def test_a_threshold_model_refuses_the_round_trip_because_its_window_is_ambiguous(self):
        """Honest consequence, asserted rather than worked around.

        Any v1 model with a count has one `window` string whose KIND v2 must know. Since the
        projection refuses graphs carrying a must-loss, and the window is one, a threshold
        model cannot be projected back to v1. That is the conservative direction: refusing
        a conversion is reversible, emitting a v1 rule built from a guessed window is not.
        """
        ir = correlation_to_ir(single(source="logs-*", threshold=7, group_by=["user.name"]))
        with self.assertRaises(RuleIRValidationError) as raised:
            ir_to_correlation(ir)
        self.assertEqual(raised.exception.code, "IR_HAS_MUST_LOSS")
        self.assertIn("AMBIGUOUS_WINDOW_KIND", raised.exception.message)

    def test_an_aggregate_model_also_refuses_because_v1_always_carries_one_window(self):
        """Even without a threshold, a v1 aggregate has the same single ambiguous `window`.

        Recording that is more honest than special-casing aggregates to look convertible.
        """
        ir = correlation_to_ir(single(source="logs-*", aggregations=[
            Aggregation("dc", "user.name", "UniqueUsers")]))
        with self.assertRaises(RuleIRValidationError) as raised:
            ir_to_correlation(ir)
        self.assertEqual(raised.exception.code, "IR_HAS_MUST_LOSS")

    def test_measures_survive_projection_when_the_graph_has_no_ambiguity(self):
        """The measure mapping itself is exercised by building the IR directly, with no v1
        window in the picture, so this tests ir_to_correlation rather than the v1 adapter."""
        from models.rule_ir import (Aggregate, Comparison, Emit, FieldExpr, Filter, Literal,
                                    Measure, Read, RuleIR, SourceSelector)
        ir = RuleIR(rule_id="x", nodes=(
            Read(id="r", selector=SourceSelector(name="logs")),
            Filter(id="f", input="r",
                   condition=Comparison("=", FieldExpr(FieldRef("a")), Literal("1"))),
            Aggregate(id="agg", input="f",
                      measures=(Measure("UniqueUsers", "dcount", field=FieldRef("user.name")),)),
            Emit(id="out", input="agg"),
        ), output="out")
        validate_ir(ir)
        restored = ir_to_correlation(ir)
        self.assertEqual([a.alias for a in restored.aggregations], ["UniqueUsers"])
        self.assertEqual(restored.aggregations[0].function, "dc",
                         "dcount must project back to v1's dc")
        self.assertEqual(restored.source, "logs")

    def test_projection_refuses_when_v1_cannot_represent_the_graph(self):
        """A lossy projection is the bug this redesign exists to remove.

        If a Pattern or Join were flattened into a v1 condition list, the stage or the join
        would vanish and the v1 caller would never know. So the projection refuses.
        """
        ir = correlation_to_ir(single(source="logs-*", lookups=[Lookup(name="p", arguments="x")]))
        with self.assertRaises(RuleIRValidationError) as raised:
            ir_to_correlation(ir)
        self.assertEqual(raised.exception.code, "IR_HAS_MUST_LOSS")

    def test_projection_refuses_an_ir_containing_a_pattern(self):
        from models.rule_ir import Emit, Pattern, Read, RuleIR, SourceSelector, Stage
        ir = RuleIR(rule_id="p", nodes=(
            Read(id="r", selector=SourceSelector(name="logs")),
            Read(id="r2", selector=SourceSelector(name="logs")),
            Pattern(id="pat", stages=(Stage(id="s1", input="r"), Stage(id="s2", input="r2"))),
            Emit(id="out", input="pat"),
        ), output="out")
        validate_ir(ir)
        with self.assertRaises(RuleIRValidationError) as raised:
            ir_to_correlation(ir)
        self.assertEqual(raised.exception.code, "IR_NOT_V1_REPRESENTABLE")


class ShadowModeTests(unittest.TestCase):
    def test_nothing_in_the_app_calls_the_adapter(self):
        from pathlib import Path
        for module in ("app.py", "rule_engine.py", "compiler/pipeline.py",
                       "compiler/sigma_compiler.py", "static/app.js", "templates/index.html"):
            self.assertNotIn("rule_ir_adapter", Path(module).read_text(encoding="utf-8"),
                             f"{module} already calls the adapter")

    def test_the_v1_model_is_not_mutated_by_a_conversion(self):
        model = single(source="logs-*", threshold=3, group_by=["user.name"])
        before = repr(model)
        correlation_to_ir(model)
        self.assertEqual(repr(model), before, "conversion must not mutate its input")

    def test_the_v1_request_is_not_mutated_by_a_conversion(self):
        request = FakeRequest(data_source="logs", threshold=3,
                              conditions=[{"field": "a", "operator": "equals", "value": "1"}])
        before = repr(request)
        request_to_ir(request)
        self.assertEqual(repr(request), before, "conversion must not mutate its input")


if __name__ == "__main__":
    unittest.main()
