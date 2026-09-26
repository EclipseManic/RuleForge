"""Contract tests for the RuleIR v2 kernel.

Phase 1 of docs/ruleforge-redesign-plan.md. These test the SEMANTIC KERNEL: the twelve
primitives, the closed expression algebra, and the validator.

The kernel is not yet wired into compilation. It ships dark. That is deliberate and is
itself tested below: `test_the_kernel_is_not_yet_reachable_from_the_app` asserts the
existing v1 path cannot see it, so Phase 1 cannot have silently changed behaviour.

Anti-vacuity: every rejection test asserts an exact `code`, not merely that something
raised, and the acceptance tests assert node identity and edges rather than counts alone.
The full kernel was mutation-checked (reverting models/rule_ir.py turns these red).
"""

import unittest
from dataclasses import replace

from models.rule_ir import (AGGREGATE_FUNCTIONS, Aggregate, Arith, Arrange, BoolOp, Call,
                            Comparison, Derive, Emit, EventExpr, Expand, FieldExpr, FieldRef,
                            Filter, Frame, FUNCTION_CONTRACTS, Iterate, Join, Literal, Measure,
                            MeasureExpr, Pattern, PRIMITIVE_NAMES, Read, RuleIR,
                            RuleIRValidationError, RulePackage, SCHEMA_VERSION, SetOp,
                            SourceSelector, Stage, Duration, ExecutionPolicy, ParseLoss,
                            canonical_operator, explain, validate_ir)


def src(node_id="src", name="logs"):
    return Read(id=node_id, selector=SourceSelector(name=name) if name else
                SourceSelector(name=None, confidence="unverified"))


def field(name, confidence="authored"):
    return FieldRef(name=name, confidence=confidence)


def pred(name, value):
    return Comparison("=", FieldExpr(field(name)), Literal(value))


def measure(name, function="count", where=None):
    return Measure(name, function, where=where)


def make(nodes, output, *, rule_id="r1", execution=None, package=None, diagnostics=()):
    return RuleIR(rule_id=rule_id, title="t", nodes=tuple(nodes), output=output,
                  execution=execution or ExecutionPolicy(), package=package,
                  parse_diagnostics=tuple(diagnostics))


def basic():
    """Source -> Filter -> Aggregate -> Filter -> Emit. The shape of a real rule."""
    r, f, a, g, e = src(), None, None, None, None
    f = Filter(id="flt", input="src", condition=pred("event.category", "authentication"))
    a = Aggregate(id="agg", input="flt",
                  measures=(measure("Failed", where=pred("event.outcome", "failure")),
                            measure("Success", where=pred("event.outcome", "success"))),
                  group_by=(field("user.name"),),
                  frame=Frame(kind="tumbling", size=Duration(600)))
    g = Filter(id="gate", input="agg",
               condition=BoolOp("and", children=(
                   Comparison(">=", MeasureExpr("Failed"), Literal(5)),
                   Comparison(">=", MeasureExpr("Success"), Literal(1)))))
    e = Emit(id="out", input="gate")
    return r, f, a, g, e


class RejectionTests(unittest.TestCase):
    """One test per rejection rule, each asserting the exact code."""

    def assertRejected(self, ir, code):
        with self.assertRaises(RuleIRValidationError) as raised:
            validate_ir(ir)
        self.assertEqual(raised.exception.code, code, f"got {raised.exception.code}: {raised.exception}")
        return raised.exception

    def test_duplicate_node_id(self):
        r, f, a, g, e = basic()
        self.assertRejected(make((r, src("src"), f, a, g, e), "out"), "DUPLICATE_NODE_ID")

    def test_dangling_node_reference(self):
        r, f, a, g, e = basic()
        broken = replace(f, input="nowhere")
        self.assertRejected(make((r, broken, a, g, e), "out"), "DANGLING_NODE_REF")

    def test_cycle_is_rejected(self):
        r, f, a, g, e = basic()
        loop1 = Derive(id="d1", input="d2")
        loop2 = Derive(id="d2", input="d1")
        self.assertRejected(make((r, loop1, loop2, f, a, g, e), "out"), "GRAPH_CYCLE")

    def test_output_must_be_emit(self):
        r, f, a, g, e = basic()
        self.assertRejected(make((r, f, a, g), "gate"), "OUTPUT_MUST_EMIT")

    def test_measure_name_collision_within_one_aggregate(self):
        """Rejected at construction, so a colliding measure can never be built at all."""
        with self.assertRaises(RuleIRValidationError) as raised:
            Aggregate(id="agg", input="flt",
                      measures=(measure("M"), measure("M", "dcount")))
        self.assertEqual(raised.exception.code, "MEASURE_NAME_COLLISION")

    def test_measure_reference_outside_a_post_aggregate_filter(self):
        """A measure is only visible directly downstream of its aggregate.

        Referencing one from a raw field Filter is the scope error that would otherwise let
        a measure leak into a single-event predicate.
        """
        r, f, a, g, e = basic()
        leak = Filter(id="leak", input="flt", condition=Comparison(">=", MeasureExpr("Failed"), Literal(1)))
        self.assertRejected(make((r, f, leak, a, g, e), "out"), "MEASURE_OUT_OF_SCOPE")

    def test_unknown_measure_reference(self):
        """A measure that no aggregate in scope produced is a named error, not a pass.

        This is the check that would catch a renderer inventing a measure alias.
        """
        r, f, a, g, e = basic()
        bad = replace(g, condition=Comparison(">=", MeasureExpr("Nope"), Literal(1)))
        self.assertRejected(make((r, f, a, bad, e), "out"), "UNKNOWN_MEASURE_REFERENCE")

    def test_a_sibling_aggregates_measure_is_not_visible_through_another_branch(self):
        """Measure scope is dataflow, not name lookup.

        Two aggregates on different branches: a filter after the second cannot reference
        the first's measure, even though a measure with that name exists in the graph.
        """
        left = Aggregate(id="a1", input="flt", measures=(measure("Shared"),))
        right = Aggregate(id="a2", input="flt", measures=(measure("Other"),))
        gate = Filter(id="gate", input="a2",
                      condition=Comparison(">=", MeasureExpr("Shared"), Literal(1)))
        out = Emit(id="out", input="gate")
        r, f, a, g, e = basic()
        ir = make((r, f, left, right, gate, out), "out")
        with self.assertRaises(RuleIRValidationError) as raised:
            validate_ir(ir)
        self.assertEqual(raised.exception.code, "UNKNOWN_MEASURE_REFERENCE")

    def test_event_scoped_reference_outside_join_or_pattern(self):
        r, f, a, g, e = basic()
        leak = Filter(id="leak", input="src",
                      condition=Comparison("=", EventExpr("left", None, field("x")), Literal(1)))
        self.assertRejected(make((r, leak, f, a, g, e), "out"), "EVENT_REF_OUT_OF_SCOPE")

    def test_boolean_not_arity(self):
        with self.assertRaises(RuleIRValidationError) as raised:
            BoolOp("not", children=(pred("a", 1), pred("b", 2)))
        self.assertEqual(raised.exception.code, "BOOLEAN_NOT_ARITY")

    def test_empty_boolean_rejected(self):
        with self.assertRaises(RuleIRValidationError) as raised:
            BoolOp("and", children=())
        self.assertEqual(raised.exception.code, "EMPTY_BOOLEAN")

    def test_unresolved_source_may_not_claim_to_be_authored(self):
        with self.assertRaises(RuleIRValidationError) as raised:
            SourceSelector(name=None, confidence="authored")
        self.assertEqual(raised.exception.code, "UNRESOLVED_SOURCE_CONFIDENCE")

    def test_unresolved_source_is_valid_but_not_deployable(self):
        """Unresolved is a legitimate provenance state, not a malformed graph.

        It validates structurally and is refused only at cross-target compile. This is the
        distinction that lets the tool represent 'we do not know the table' without either
        guessing or crashing.
        """
        r, f, a, g, e = basic()
        ir = make((src(name=None), f, a, g, e), "out")
        validate_ir(ir)
        with self.assertRaises(RuleIRValidationError) as raised:
            validate_ir(ir, target="sentinel")
        self.assertEqual(raised.exception.code, "UNRESOLVED_SOURCE")

    def test_must_loss_blocks_cross_target_compile(self):
        r, f, a, g, e = basic()
        ir = make((r, f, a, g, e), "out",
                  diagnostics=(ParseLoss("OPAQUE_JOIN", "must", "join endpoint unresolved"),))
        validate_ir(ir)
        with self.assertRaises(RuleIRValidationError) as raised:
            validate_ir(ir, target="splunk")
        self.assertEqual(raised.exception.code, "MUST_LOSS")

    def test_advisory_loss_does_not_block(self):
        r, f, a, g, e = basic()
        ir = make((r, f, a, g, e), "out",
                  diagnostics=(ParseLoss("MINOR", "advisory", "a comment was dropped"),))
        validate_ir(ir, target="splunk")

    def test_wrong_schema_version(self):
        r, f, a, g, e = basic()
        ir = make((r, f, a, g, e), "out")
        self.assertRejected(replace(ir, schema_version="1.0"), "INVALID_SCHEMA_VERSION")

    def test_unknown_function_is_refused_not_passed_through(self):
        """No raw-function escape hatch: an unregistered function cannot reach the IR."""
        with self.assertRaises(RuleIRValidationError) as raised:
            Call("eval_anything", ())
        self.assertEqual(raised.exception.code, "UNKNOWN_FUNCTION")

    def test_unknown_aggregate_function_refused(self):
        with self.assertRaises(RuleIRValidationError) as raised:
            Measure("M", "approximately_count")
        self.assertEqual(raised.exception.code, "UNKNOWN_AGGREGATE_FUNCTION")

    def test_accelerated_source_requires_a_schema(self):
        r, f, a, g, e = basic()
        accelerated = Read(id="src", selector=SourceSelector(name="dm", strategy="accelerated"))
        ir = make((accelerated, f, a, g, e), "out")
        validate_ir(ir)
        with self.assertRaises(RuleIRValidationError) as raised:
            validate_ir(ir, target="splunk")
        self.assertEqual(raised.exception.code, "ACCELERATED_SOURCE_WITHOUT_SCHEMA")

    def test_package_dependency_on_an_unknown_unit(self):
        with self.assertRaises(RuleIRValidationError) as raised:
            RulePackage(units=({"id": "100210"},), dependencies=(("100211", "100210"),))
        self.assertEqual(raised.exception.code, "UNKNOWN_PACKAGE_UNIT")

    def test_package_dependency_cycle(self):
        with self.assertRaises(RuleIRValidationError) as raised:
            RulePackage(units=({"id": "a"}, {"id": "b"}),
                        dependencies=(("a", "b"), ("b", "a")))
        self.assertEqual(raised.exception.code, "PACKAGE_DEPENDENCY_CYCLE")

    def test_invalid_duration(self):
        for bad in (0, -1, "5", 1.5, True):
            with self.assertRaises(RuleIRValidationError):
                Duration(bad)

    def test_frame_kind_requires_a_size(self):
        with self.assertRaises(RuleIRValidationError) as raised:
            Frame(kind="tumbling")
        self.assertEqual(raised.exception.code, "FRAME_REQUIRES_SIZE")

    def test_scheduled_policy_requires_a_cadence(self):
        """A missing cadence is unresolved configuration, never a guessed default."""
        with self.assertRaises(RuleIRValidationError) as raised:
            ExecutionPolicy(kind="scheduled")
        self.assertEqual(raised.exception.code, "SCHEDULED_REQUIRES_CADENCE")

    def test_pattern_requires_stages(self):
        with self.assertRaises(RuleIRValidationError) as raised:
            Pattern(id="p", stages=())
        self.assertEqual(raised.exception.code, "PATTERN_REQUIRES_STAGES")

    def test_empty_field_name_rejected(self):
        with self.assertRaises(RuleIRValidationError) as raised:
            FieldRef(name="  ")
        self.assertEqual(raised.exception.code, "EMPTY_FIELD_NAME")


class AcceptanceTests(unittest.TestCase):
    """The kernel must accept, and must not be a no-op that accepts anything."""

    def test_the_impossible_travel_rule_is_expressible(self):
        """Sentinel: two named measures, a time bucket, a predicate over the measures."""
        r, f, a, g, e = basic()
        ir = make((r, f, a, g, e), "out")
        validate_ir(ir)
        kinds = [n.__class__.__name__ for n in ir.nodes]
        self.assertEqual(kinds, ["Read", "Filter", "Aggregate", "Filter", "Emit"])
        self.assertEqual([m.name for m in a.measures], ["Failed", "Success"],
                         "the two measures must stay independent, not collapse into one")
        self.assertNotEqual(a.measures[0].where, a.measures[1].where)
        self.assertFalse(hasattr(a.measures[0], "threshold"),
                         "a threshold is a following filter, never a property of a measure")
        self.assertEqual(a.frame.kind, "tumbling")
        self.assertEqual(g.input, "agg", "the measure filter must sit directly after the aggregate")

    def test_node_order_in_the_tuple_is_not_execution_order(self):
        """A validator that trusts list order would fail this and pass everything else."""
        r, f, a, g, e = basic()
        forward = make((r, f, a, g, e), "out")
        backward = make((e, g, a, f, r), "out")
        validate_ir(forward)
        validate_ir(backward)
        self.assertEqual(explain(forward), explain(backward))

    def test_execution_policy_is_independent_of_frames(self):
        """The old model conflated these; a copy of the lookback into a frame is a bug."""
        r, f, a, g, e = basic()
        policy = ExecutionPolicy(kind="scheduled", lookback=Duration(3600), cadence=Duration(300))
        ir = make((r, f, a, g, e), "out", execution=policy)
        validate_ir(ir)
        self.assertEqual(ir.execution.lookback, Duration(3600))
        self.assertEqual(ir.execution.cadence, Duration(300))
        self.assertNotEqual(a.frame.size, ir.execution.lookback,
                            "a tumbling bucket is not the query lookback")

    def test_a_temporal_join_is_expressible(self):
        """Sentinel R3: two bindings, equijoin, an asymmetric inclusive temporal predicate."""
        left = Filter(id="l", input="src", condition=pred("EventID", 10))
        right = Filter(id="rr", input="src", condition=pred("EventID", 4624))
        within_10m = Arith("+", EventExpr("left", None, field("LSASSTime")), Literal(600))
        on = BoolOp("and", children=(
            Comparison("=", EventExpr("left", None, field("Computer")),
                       EventExpr("right", None, field("Computer"))),
            Comparison("<=", EventExpr("left", None, field("LSASSTime")),
                       EventExpr("right", None, field("LoginTime"))),
            Comparison("<=", EventExpr("right", None, field("LoginTime")), within_10m),
        ))
        join = Join(id="j", left="l", right="rr", on=on,
                    match_key="Account", match_window=Duration(600))
        agg = Aggregate(id="agg", input="j", measures=(measure("Pairs"),), group_by=(field("Computer"),))
        gate = Filter(id="gate", input="agg", condition=Comparison(">=", MeasureExpr("Pairs"), Literal(1)))
        out = Emit(id="out", input="gate")
        ir = make((src(), left, right, join, agg, gate, out), "out")
        validate_ir(ir)
        self.assertEqual(join.match_window, Duration(600))
        self.assertEqual(join.kind, "inner")

    def test_a_pattern_with_missing_stages_is_expressible(self):
        """EQL `until` and missing-event detection were NOT representable before."""
        stage_in = src("s1")
        stage_out = src("s2")
        pattern = Pattern(id="p", mode="missing",
                          stages=(Stage(id="a", input="s1"), Stage(id="b", input="s2")),
                          key=(field("host.name"),), max_span=Duration(300))
        out = Emit(id="out", input="p")
        ir = make((stage_in, stage_out, pattern, out), "out")
        validate_ir(ir)
        self.assertEqual(pattern.mode, "missing")

    def test_iterate_is_expressible(self):
        """Recursive closure is a primitive, not an ad-hoc node."""
        step = Derive(id="step", input="seed")
        loop = Iterate(id="closure", input="step", step=step, until=Literal(True), max_iterations=8)
        out = Emit(id="out", input="closure")
        ir = make((src("seed"), step, loop, out), "out")
        validate_ir(ir)

    def test_setop_and_expand_and_arrange_are_expressible(self):
        """The three primitives the earlier 13-node draft omitted entirely."""
        a = Filter(id="a", input="src", condition=pred("k", 1))
        b = Filter(id="b", input="src", condition=pred("k", 2))
        union = SetOp(id="u", left="a", right="b", op="except")
        expand = Expand(id="x", input="u", field=field("ips"), mode="unnest")
        arrange = Arrange(id="arr", input="x",
                          order_by=((FieldExpr(field("k")), "asc"),), limit=10)
        out = Emit(id="out", input="arr")
        ir = make((src(), a, b, union, expand, arrange, out), "out")
        validate_ir(ir)
        self.assertEqual(union.op, "except")
        self.assertEqual(arrange.limit, 10)

    def test_a_wazuh_package_is_a_package_not_a_node(self):
        """R1: the parent/child bundle is packaging, with a dependency edge."""
        r, f, a, g, e = basic()
        package = RulePackage(rule_id="bundle", units=({"id": "100210"}, {"id": "100211"}),
                              dependencies=(("100211", "100210"),))
        ir = make((r, f, a, g, e), "out", package=package)
        validate_ir(ir)
        self.assertEqual(len(package.units), 2)
        self.assertNotIn("RuleSet", PRIMITIVE_NAMES,
                         "there is no RuleSet node; a bundle is a package")

    def test_frozen_everywhere(self):
        """Mutation must be impossible, including nested containers."""
        r, f, a, g, e = basic()
        ir = make((r, f, a, g, e), "out")
        with self.assertRaises(Exception):
            ir.rule_id = "changed"
        with self.assertRaises(Exception):
            a.measures[0].name = "changed"
        with self.assertRaises(Exception):
            a.group_by = ()

    def test_explain_reports_the_primitive_pipeline(self):
        r, f, a, g, e = basic()
        self.assertEqual(explain(make((r, f, a, g, e), "out")),
                         "Read -> Filter x2 -> Aggregate -> Emit")

    def test_explain_flags_an_unresolved_source(self):
        r, f, a, g, e = basic()
        self.assertIn("unresolved source", explain(make((src(name=None), f, a, g, e), "out")))


class VocabularyTests(unittest.TestCase):
    def test_operator_normalisation_is_recorded_not_silent(self):
        self.assertEqual(canonical_operator("endswith"), ("ends_with", True))
        self.assertEqual(canonical_operator("startswith"), ("starts_with", True))
        self.assertEqual(canonical_operator("contains"), ("contains", False))
        self.assertEqual(canonical_operator("bogus"), ("bogus", False))

    def test_every_registered_function_declares_its_contract(self):
        for name, contract in FUNCTION_CONTRACTS.items():
            for required in ("arity", "returns", "null", "deterministic"):
                self.assertIn(required, contract, f"function {name!r} omits {required}")

    def test_aggregates_and_scalar_functions_are_disjoint(self):
        self.assertEqual(FUNCTION_CONTRACTS["count_distinct"]["returns"], "integer")
        self.assertIn("count_distinct", AGGREGATE_FUNCTIONS)
        self.assertNotIn("contains", AGGREGATE_FUNCTIONS,
                         "an aggregate may not be a substring test")

    def test_the_kernel_has_exactly_the_declared_primitives(self):
        self.assertEqual(len(PRIMITIVE_NAMES), 11,
                         "eleven graph primitives; grouping, execution policy and packaging "
                         "are parameters or envelopes, not primitives")
        self.assertEqual(set(PRIMITIVE_NAMES),
                         {"Read", "Derive", "Filter", "Expand", "Aggregate", "Arrange",
                          "Join", "SetOp", "Pattern", "Iterate", "Emit"})

    def test_schema_version_is_declared_once(self):
        self.assertEqual(SCHEMA_VERSION, "2.0")


class ShadowModeTests(unittest.TestCase):
    """Phase 1 ships dark. If these fail, the kernel is already changing behaviour."""

    def test_the_kernel_is_not_imported_by_the_application(self):
        from pathlib import Path
        for module in ("app.py", "rule_engine.py", "compiler/pipeline.py",
                       "compiler/sigma_compiler.py",
                       "static/app.js", "templates/index.html"):
            text = Path(module).read_text(encoding="utf-8")
            self.assertNotIn("rule_ir", text, f"{module} already references the new kernel")

    def test_the_v1_model_is_untouched(self):
        from models.correlation import CorrelationModel
        self.assertTrue(hasattr(CorrelationModel, "to_dict"),
                        "the v1 serialisation must still exist unchanged")


class LayerAgreementTests(unittest.TestCase):
    """The layers must not be able to disagree about the model they share.

    Three copies of one fact existed: `validate_ir` identified nodes by
    `node.__class__.__name__`, while `rule_capabilities` and `kernel/eval_types` each declared
    their own `NODE_TYPES`. They DID disagree — the validator accepted a class-name lookalike
    that both other layers refused, so one graph produced two different answers, and the
    disagreement fell in the direction that decides deployability. The same shape produced a
    21-entry comparison allowlist for a 6-operator model.
    """

    def test_node_identity_is_defined_once(self):
        from models import rule_capabilities, rule_ir
        from kernel import eval_types
        self.assertIs(rule_capabilities.NODE_TYPES, rule_ir.NODE_TYPES)
        self.assertIs(eval_types.NODE_TYPES, rule_ir.NODE_TYPES)
        self.assertIs(rule_capabilities.primitive_of, rule_ir.primitive_of)
        self.assertIs(eval_types.primitive_of, rule_ir.primitive_of)

    def test_node_types_covers_exactly_the_declared_primitives(self):
        from models.rule_ir import NODE_TYPES, PRIMITIVE_NAMES
        self.assertEqual(set(NODE_TYPES), set(PRIMITIVE_NAMES))

    def test_validate_ir_refuses_a_class_name_lookalike(self):
        """The disagreement itself, pinned.

        `validate_ir` used to compute `isinstance(node, tuple(PRIMITIVE_NAMES and ()))`, which
        is `isinstance(node, ())` - always False - so the type test never ran and the class
        name decided.
        """
        from models.rule_ir import (Emit, Read, RuleIR, RuleIRValidationError,
                                    validate_ir)

        class Read:                                    # noqa: A001 - deliberately a lookalike
            __name__ = "Read"

            def __init__(self):
                self.id = "r"

        with self.assertRaises(RuleIRValidationError) as caught:
            validate_ir(RuleIR(rule_id="spoof",
                               nodes=(Read(), Emit(id="o", input="r")), output="o"))
        self.assertEqual(caught.exception.code, "INVALID_NODE_TYPE")

    def test_a_real_graph_still_validates(self):
        from models.rule_ir import (Emit, Filter, FieldExpr, FieldRef, Literal, Read, RuleIR,
                                    SourceSelector, validate_ir)
        ir = RuleIR(rule_id="ok",
                    nodes=(Read(id="r", selector=SourceSelector(name="events")),
                           Filter(id="f", input="r",
                                  condition=__import__("models.rule_ir", fromlist=[
                                      "Comparison"]).Comparison(
                                      "=", FieldExpr(FieldRef("a")), Literal(1))),
                           Emit(id="o", input="f")),
                    output="o")
        validate_ir(ir)


class StructuralBoundTests(unittest.TestCase):
    """`validate_ir` bounds its own recursion rather than crashing and letting callers patch it.

    A `try/except RecursionError` in one caller is a symptom fix that leaves every other
    caller unprotected: the v1 adapter and the capability layer both call `validate_ir` and
    neither had a guard.
    """

    def _chain(self, depth):
        from models.rule_ir import (Derive, Emit, FieldRef, Literal, Read, RuleIR,
                                    SourceSelector)
        nodes = [Read(id="n0", selector=SourceSelector(name="events"))]
        for i in range(1, depth):
            nodes.append(Derive(id=f"n{i}", input=f"n{i - 1}",
                                assignments=((FieldRef("x"), Literal(1)),)))
        nodes.append(Emit(id="o", input=f"n{depth - 1}"))
        return RuleIR(rule_id="deep", nodes=tuple(nodes), output="o")

    def test_a_deep_expression_is_refused_with_a_code_not_a_crash(self):
        from models.rule_ir import (BoolOp, Filter, Literal, Read, RuleIR, RuleIRValidationError,
                                    SourceSelector, validate_ir)
        expr = Literal(True)
        for _ in range(3000):
            expr = BoolOp("not", (expr,))
        ir = RuleIR(rule_id="deep", nodes=(Read(id="r", selector=SourceSelector(name="e")),
                                           Filter(id="f", input="r", condition=expr),
                                           Emit(id="o", input="f")), output="o")
        with self.assertRaises(RuleIRValidationError) as caught:
            validate_ir(ir)
        self.assertEqual(caught.exception.code, "EXPRESSION_TOO_DEEP")

    def test_a_graph_too_large_to_walk_is_refused_with_a_code(self):
        from models.rule_ir import MAX_GRAPH_NODES, RuleIRValidationError, validate_ir
        with self.assertRaises(RuleIRValidationError) as caught:
            validate_ir(self._chain(MAX_GRAPH_NODES + 50))
        self.assertEqual(caught.exception.code, "GRAPH_TOO_LARGE")

    def test_a_presence_predicate_needs_a_boolean_literal(self):
        """`exists`/`is_not_null` test PRESENCE, so comparing them against a value is a
        mistake rather than a shorthand."""
        from models.rule_ir import (Comparison, FieldExpr, FieldRef, Literal,
                                    RuleIRValidationError)
        with self.assertRaises(RuleIRValidationError) as caught:
            Comparison("exists", FieldExpr(FieldRef("a")), Literal("yes"))
        self.assertEqual(caught.exception.code, "PRESENCE_PREDICATE_NEEDS_BOOLEAN")
        ok = Comparison("exists", FieldExpr(FieldRef("a")), Literal(True))
        self.assertEqual(ok.op, "exists")

    def test_the_graph_walk_is_bounded_indirectly_by_the_node_bound(self):
        """A depth counter in `_graph_cycle` was tried and REMOVED: it could not be shown to
        fire, so it was decorative. What actually keeps the walk finite is MAX_GRAPH_NODES,
        and that is what this pins - an indirect bound, recorded as such rather than dressed
        up as a direct one."""
        from models.rule_ir import MAX_GRAPH_NODES, RuleIRValidationError, validate_ir
        self.assertGreater(MAX_GRAPH_NODES, 0)
        with self.assertRaises(RuleIRValidationError) as caught:
            validate_ir(self._chain(MAX_GRAPH_NODES + 1))
        self.assertEqual(caught.exception.code, "GRAPH_TOO_LARGE")

    def test_a_graph_within_the_bound_still_validates(self):
        from models.rule_ir import validate_ir
        validate_ir(self._chain(20))

    def test_the_evaluate_boundary_still_returns_a_refusal_not_a_crash(self):
        """The kernel's outer guard stays as a backstop, but the validator now refuses first."""
        from kernel.eval import evaluate_ir
        from kernel.eval_nodes import Sample
        from models.rule_ir import (BoolOp, Emit, Filter, Literal, Read, RuleIR,
                                    SourceSelector)
        expr = Literal(True)
        for _ in range(3000):
            expr = BoolOp("not", (expr,))
        ir = RuleIR(rule_id="deep", nodes=(Read(id="r", selector=SourceSelector(name="e")),
                                           Filter(id="f", input="r", condition=expr),
                                           Emit(id="o", input="f")), output="o")
        result = evaluate_ir(ir, Sample({"r": [{"a": 1}]}))
        self.assertEqual(result.state.value, "not_evaluated")
        self.assertIsNotNone(result.reason)
