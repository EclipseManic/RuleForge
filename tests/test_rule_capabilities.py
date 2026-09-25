"""Contract tests for the vendor capability registry.

Phase 2b of docs/ruleforge-redesign-plan.md. Ships DARK.

The registry's job is to be the one place that answers "can this target do this?", and its
real test is whether it can LIE. So most of these tests are adversarial: they check that the
registry refuses when it should, and that the refusal never blames a vendor for a gap in
our own model.

The single most important fact about the current state: NO RENDERER EXISTS, so `EMITTERS` is
empty and EVERY target refuses EVERY graph. Several tests below therefore assert refusal
where an earlier draft asserted a successful emission. Those earlier assertions were wrong:
they passed because six `aql.*` strings had been registered as emitters, and nothing in the
repository lowered a RuleIR to AQL. A test that certifies a capability nobody implemented is
worse than no test, because it looks like evidence.
"""

import unittest
from dataclasses import replace

from models.rule_capabilities import (EMITTERS, EQUIVALENT, NATIVE, NODE_TYPES, OPERATORS,
                                      PLANNED_EMITTERS, PROFILES, REFUSED, audit, emitters_for,
                                      find_profile, lower, primitive_of, registered_dialects,
                                      resolve, resolve_for_product, vocabulary)
from models.rule_ir import (OPERATOR_ALIASES, Aggregate, Arith, Arrange, BoolOp, Call, Comparison,
                            Derive, Duration, Emit, EventExpr, Expand, FieldExpr, FieldRef,
                            Filter, Frame, InList, Join as IRJoin, Literal, Measure, MeasureExpr,
                            ParseLoss, Pattern, PRIMITIVE_NAMES, Read, RuleIR,
                            RuleIRValidationError, SetOp, SourceSelector, Stage as IRStage,
                            canonical_operator)
from rule_engine import CANONICAL_OPERATORS
from tests.corpus.rule_corpus import RULES
from tests.corpus.rule_matrix import all_cells

def AQL():
    """The QRadar AQL saved-search profile, looked up by its full key every time."""
    return find_profile("qradar", "aql", "saved_search")


def simple_graph(source="logs", *, extra=(), measures=(("Hits", "count"),), threshold=True,
                 confidence="authored"):
    """A minimal grouped-count graph. Every parameter is well-formed and resolved."""
    nodes = [Read(id="read", selector=SourceSelector(name=source, confidence=confidence))]
    current = "read"
    nodes.append(Filter(id="flt", input=current,
                        condition=Comparison("=", FieldExpr(FieldRef("a")), Literal("1"))))
    current = "flt"
    if measures:
        nodes.append(Aggregate(id="agg", input=current,
                               measures=tuple(Measure(n, f) for n, f in measures),
                               group_by=(FieldRef("u"),)))
        current = "agg"
    if threshold:
        nodes.append(Filter(id="gate", input=current,
                            condition=Comparison(">=", MeasureExpr("Hits"), Literal(1))))
        current = "gate"
    nodes.extend(extra)
    nodes.append(Emit(id="out", input=current))
    return RuleIR(rule_id="r", nodes=tuple(nodes), output="out")


def framed_graph():
    """A graph whose Aggregate carries a computed window - not a scan scope."""
    nodes = [Read(id="read", selector=SourceSelector(name="logs"))]
    nodes.append(Aggregate(id="agg", input="read", measures=(Measure("Hits", "count"),),
                           frame=Frame(kind="tumbling", size=Duration(600))))
    nodes.append(Emit(id="out", input="agg"))
    return RuleIR(rule_id="windowed", nodes=tuple(nodes), output="out")


class CatalogTests(unittest.TestCase):
    def test_every_primitive_has_an_operator_spec(self):
        for primitive in PRIMITIVE_NAMES:
            self.assertIn(primitive, OPERATORS, f"{primitive} has no operator spec")

    def test_no_operator_spec_invents_a_primitive(self):
        for primitive in OPERATORS:
            self.assertIn(primitive, PRIMITIVE_NAMES)

    def test_only_aggregate_produces_measures(self):
        producers = [p for p, s in OPERATORS.items() if s.produces_measures]
        self.assertEqual(producers, ["Aggregate"])

    def test_the_catalogs_do_not_contradict_the_kernel(self):
        self.assertEqual(audit(), [], "capability layer disagrees with the model it describes")

    def test_wazuh_and_qradar_are_always_marked_inferred(self):
        for profile in PROFILES:
            if profile.product in {"wazuh", "qradar"} and profile.grants_execution:
                self.assertTrue(profile.inferred_target,
                                f"{profile.profile_id} publishes no field schema and must say so")

    def test_sigma_grants_no_execution(self):
        sigma = find_profile("sigma", "yaml", "interchange")
        self.assertIsNotNone(sigma)
        self.assertFalse(sigma.grants_execution,
                         "Sigma is an interchange format with no execution semantics")

    def test_qradar_aql_and_cre_are_separate_artifact_kinds(self):
        """The R4 lesson: grouped historical AQL is not an event sequence."""
        aql = find_profile("qradar", "aql", "saved_search")
        cre = find_profile("qradar", "cre", "custom_rule_content")
        self.assertIsNotNone(aql)
        self.assertIsNotNone(cre)
        self.assertNotEqual(aql.profile_id, cre.profile_id)
        self.assertNotEqual(aql.dialect, cre.dialect)

    def test_elastic_esql_and_eql_are_separate_engines(self):
        esql = find_profile("elastic", "esql", "detection_rule")
        eql = find_profile("elastic", "eql", "detection_rule")
        self.assertIsNotNone(esql)
        self.assertIsNotNone(eql)
        self.assertNotEqual(esql.dialect, eql.dialect,
                            "EQL is a different engine, not a dialect of ES|QL")


class NoRendererExistsTests(unittest.TestCase):
    """The honest current state, asserted rather than assumed.

    This is the class an earlier draft of the suite was missing entirely, and its absence is
    why six fabricated emitter ids passed every test.
    """

    def test_no_emitter_is_registered_because_no_renderer_exists(self):
        self.assertEqual(EMITTERS, (),
                         "an emitter is registered, so a real lowering must now exist")

    def test_no_dialect_has_any_registered_emitter(self):
        self.assertEqual(registered_dialects(), frozenset())

    def test_every_target_refuses_a_well_formed_graph(self):
        for profile in PROFILES:
            result = resolve(simple_graph(), profile)
            self.assertFalse(result.resolvable, f"{profile.profile_id} claimed deployability")
            self.assertIn(result.refusal_code,
                          {"IR_UNSUPPORTED_EMITTER", "PROFILE_GRANTS_NO_EXECUTION"})

    def test_the_refusal_names_the_missing_renderer_not_a_missing_vendor_feature(self):
        result = resolve(simple_graph(), AQL())
        self.assertIn("cannot substitute for a renderer", result.reason)

    def test_planned_emitters_grant_nothing(self):
        """A TODO list must never be readable as a shipping feature list."""
        self.assertTrue(PLANNED_EMITTERS, "the plan for what to build should be recorded")
        from models.rule_capabilities import Emitter, PlannedEmitter
        for emitter in PLANNED_EMITTERS:
            self.assertNotIn(emitter, EMITTERS)
            self.assertNotIsInstance(emitter, Emitter,
                                     "a planned row must not be registerable as capability")
            self.assertIsInstance(emitter, PlannedEmitter)

    def test_a_planned_emitter_spliced_into_the_registry_grants_nothing(self):
        """Even a direct attempt to register the plan cannot produce capability."""
        import models.rule_capabilities as rc
        original = rc.EMITTERS
        rc.EMITTERS = PLANNED_EMITTERS
        self.addCleanup(lambda: setattr(rc, "EMITTERS", original))
        result = resolve(simple_graph(), AQL())
        self.assertFalse(result.resolvable,
                         "a planned emitter granted capability just by being listed")


class EmitterBindingTests(unittest.TestCase):
    """An emitter without a callable is a label, and a label is not proof."""

    def test_an_emitter_without_a_lowering_cannot_be_registered(self):
        from models.rule_capabilities import Emitter
        with self.assertRaises(RuleIRValidationError) as caught:
            Emitter(dialect="d", primitive="Filter", emitter_id="fake", lowering="aql.where")
        self.assertEqual(caught.exception.code, "EMITTER_WITHOUT_LOWERING")

    def test_audit_reports_a_callableless_emitter_if_one_is_forced_in(self):
        """Actually force the bad state; the previous version of this test asserted nothing."""
        import models.rule_capabilities as rc

        class Ghost:
            dialect = "qradar-aql"
            primitive = "Filter"
            emitter_id = "aql.where"
            exact = True
            forbids = ()
            version_min = None
            version_max = None

        original = rc.EMITTERS
        rc.EMITTERS = (Ghost(),)
        self.addCleanup(lambda: setattr(rc, "EMITTERS", original))
        problems = rc.audit()
        self.assertTrue(any("non-Emitter" in p for p in problems),
                        f"audit did not report a spliced non-Emitter: {problems}")

    def test_audit_reports_a_planned_row_spliced_into_the_registry(self):
        import models.rule_capabilities as rc
        original = rc.EMITTERS
        rc.EMITTERS = PLANNED_EMITTERS
        self.addCleanup(lambda: setattr(rc, "EMITTERS", original))
        problems = rc.audit()
        self.assertTrue(problems, "audit reported nothing for a corrupted registry")
        self.assertTrue(any("non-Emitter" in p for p in problems), problems)

    def test_registered_dialects_ignores_a_corrupted_registry(self):
        import models.rule_capabilities as rc
        original = rc.EMITTERS
        rc.EMITTERS = PLANNED_EMITTERS
        self.addCleanup(lambda: setattr(rc, "EMITTERS", original))
        self.assertEqual(rc.registered_dialects(), frozenset(),
                         "a planned dialect appeared registered")


class VersionGateTests(unittest.TestCase):
    """Version gating must FAIL CLOSED, and must be tested through resolve()."""

    def test_an_unknown_version_does_not_unlock_a_version_gated_emitter(self):
        emitter = next(e for e in PLANNED_EMITTERS if e.version_min == "7.4")
        self.assertFalse(emitter.supports_version(None),
                         "a missing version must not be read as 'newest'")

    def test_a_version_below_the_minimum_is_refused(self):
        emitter = next(e for e in PLANNED_EMITTERS if e.version_min == "7.4")
        self.assertFalse(emitter.supports_version("7.3"))
        self.assertTrue(emitter.supports_version("7.4"))

    def test_version_comparison_handles_multi_component_versions(self):
        emitter = next(e for e in PLANNED_EMITTERS if e.version_min == "7.4")
        self.assertFalse(emitter.supports_version("7.3.9"))
        self.assertTrue(emitter.supports_version("7.4.1"))
        self.assertTrue(emitter.supports_version("8.0"))

    def test_no_registered_emitter_is_version_gated_because_none_are_registered(self):
        self.assertEqual(emitters_for("qradar-aql", "Filter", "7.3"), ())


class ParameterGateTests(unittest.TestCase):
    """Capability depends on a primitive's PARAMETERS, not only on its type."""

    def test_a_plain_aggregate_is_not_denied_by_the_frame_rule(self):
        emitter = next(e for e in PLANNED_EMITTERS if e.primitive == "Aggregate")
        plain = Aggregate(id="a", input="r", measures=(Measure("Hits", "count"),),
                          group_by=(FieldRef("u"),))
        self.assertTrue(emitter.accepts(plain))

    def test_a_framed_aggregate_is_denied_by_the_frame_rule(self):
        emitter = next(e for e in PLANNED_EMITTERS if e.primitive == "Aggregate")
        self.assertFalse(emitter.accepts(framed_graph().nodes[1]))

    def test_denial_uses_presence_not_truthiness(self):
        """A malformed frame=0 is still a frame and must not slip through."""
        emitter = next(e for e in PLANNED_EMITTERS if e.primitive == "Aggregate")
        malformed = Aggregate(id="a", input="r", measures=(Measure("Hits", "count"),), frame=0)
        self.assertFalse(emitter.accepts(malformed),
                         "truthiness would let a falsy frame through")


class UnresolvedSourceTests(unittest.TestCase):
    """The first invariant: never invent a table or index.

    An earlier draft called `validate_ir(ir)` without a target, so an unresolved source was
    reported `resolvable` - the registry would have had to invent a table name downstream.
    """

    def test_an_unresolved_source_is_never_resolvable(self):
        for profile in PROFILES:
            ir = simple_graph(source=None, confidence="unverified")
            try:
                result = resolve(ir, profile)
            except RuleIRValidationError as exc:
                self.assertIn("UNRESOLVED", exc.code)
                continue
            self.assertFalse(result.resolvable, profile.profile_id)

    def test_an_unresolved_source_raises_rather_than_being_resolved(self):
        with self.assertRaises(RuleIRValidationError):
            resolve(simple_graph(source=None, confidence="unverified"), AQL())

    def test_a_resolved_source_still_reaches_the_capability_gate(self):
        result = resolve(simple_graph(source="logs"), AQL())
        self.assertEqual(result.refusal_code, "IR_UNSUPPORTED_EMITTER",
                         "a resolved source must not be refused for the wrong reason")


class PrimitiveIdentityTests(unittest.TestCase):
    """Primitive identity is decided by isinstance, not by class name."""

    def test_a_lookalike_class_is_not_a_kernel_node(self):
        class Read:
            id = "read"
            selector = SourceSelector(name="logs")

        self.assertIsNone(primitive_of(Read()))

    def test_a_lookalike_class_cannot_be_resolved_as_resolvable(self):
        class Read:
            id = "read"
            selector = SourceSelector(name="logs")

        class Emit:
            id = "out"
            input = "read"

        spoof = RuleIR(rule_id="fake", nodes=(Read(), Emit()), output="out")
        try:
            result = resolve(spoof, AQL())
        except RuleIRValidationError:
            return
        self.assertFalse(result.resolvable)

    def test_every_real_node_type_is_recognised_by_its_own_primitive_name(self):
        """Not `primitive_of(x) or name`, which is truthy for any string at all."""
        for name, cls in NODE_TYPES.items():
            self.assertIsNotNone(cls)
        graph = simple_graph()
        for node in graph.nodes:
            self.assertEqual(primitive_of(node), type(node).__name__)
        self.assertIsNone(primitive_of("not a node"))
        self.assertIsNone(primitive_of(None))

    def test_a_subclass_of_a_real_node_is_not_accepted_as_that_node(self):
        class SneakyRead(Read):
            pass

        self.assertIsNone(primitive_of(SneakyRead(id="r", selector=SourceSelector(name="logs"))))


class ProfileLookupTests(unittest.TestCase):
    """A product-only lookup must not silently choose between artifact kinds."""

    def test_a_product_with_several_profiles_is_never_guessed(self):
        for product in ("qradar", "elastic"):
            self.assertIsNone(find_profile(product),
                              f"{product} has several artifact kinds; guessing is the R4 bug")

    def test_a_partial_key_is_refused(self):
        self.assertIsNone(find_profile("qradar", "aql"))
        self.assertIsNone(find_profile("qradar", artifact_kind="saved_search"))

    def test_a_single_profile_product_resolves_by_product(self):
        for product in ("splunk", "sentinel", "wazuh", "falcon", "google_secops", "sigma"):
            self.assertIsNotNone(find_profile(product), product)

    def test_a_malformed_execution_flag_cannot_grant_execution(self):
        from models.rule_capabilities import TargetProfile
        with self.assertRaises(RuleIRValidationError) as caught:
            TargetProfile("x", "y", "z", "d", grants_execution="false")
        self.assertEqual(caught.exception.code, "MALFORMED_PROFILE")


class OurGapIsNotTheVendorsFaultTests(unittest.TestCase):
    def test_a_must_loss_is_refused_as_our_gap_not_a_vendor_limitation(self):
        """Target-aware validation raises MUST_LOSS before any capability question is asked.

        That ordering matters: our own parse gap must never be reported as a vendor
        limitation, because the analyst's next action is ours to fix, not theirs.
        """
        ir = replace(simple_graph(),
                     parse_diagnostics=(ParseLoss("OPAQUE_JOIN", "must", "join unresolved"),))
        with self.assertRaises(RuleIRValidationError) as caught:
            resolve(ir, AQL())
        self.assertEqual(caught.exception.code, "MUST_LOSS")
        self.assertNotIn("qradar", caught.exception.message.lower())

    def test_an_advisory_loss_does_not_block(self):
        ir = replace(simple_graph(),
                     parse_diagnostics=(ParseLoss("NOTE", "advisory", "a comment was dropped"),))
        self.assertEqual(resolve(ir, AQL()).refusal_code, "IR_UNSUPPORTED_EMITTER")


class ArtifactKindTests(unittest.TestCase):
    def test_an_ambiguous_product_refuses_rather_than_guessing(self):
        for product in ("qradar", "elastic"):
            result = resolve_for_product(simple_graph(), product)
            self.assertFalse(result.resolvable, product)
            self.assertEqual(result.refusal_code, "ARTIFACT_KIND_AMBIGUOUS")
            self.assertIn("not interchangeable", result.reason)

    def test_a_single_artifact_product_resolves_without_ambiguity(self):
        result = resolve_for_product(simple_graph(), "wazuh")
        self.assertNotEqual(result.refusal_code, "ARTIFACT_KIND_AMBIGUOUS")

    def test_an_unknown_product_is_refused(self):
        result = resolve_for_product(simple_graph(), "nonexistent-siem")
        self.assertFalse(result.resolvable)
        self.assertEqual(result.refusal_code, "UNKNOWN_PRODUCT")

    def test_a_non_executing_profile_always_refuses(self):
        result = resolve(simple_graph(), find_profile("sigma", "yaml", "interchange"))
        self.assertFalse(result.resolvable)
        self.assertEqual(result.refusal_code, "PROFILE_GRANTS_NO_EXECUTION")


class PackageTests(unittest.TestCase):
    """A rule that is one member of a bundle cannot be emitted on its own."""

    def _packaged(self):
        from models.rule_ir import RulePackage
        ir = simple_graph()
        pkg = RulePackage(rule_id="bundle",
                          units=({"id": ir.rule_id}, {"id": ir.rule_id + "-b"}),
                          dependencies=((ir.rule_id, ir.rule_id + "-b"),))
        return replace(ir, package=pkg)

    def test_a_bundled_rule_refuses(self):
        result = resolve(self._packaged(), AQL())
        self.assertFalse(result.resolvable)
        self.assertEqual(result.refusal_code, "BUNDLE_DEPENDENCY_NOT_EXPRESSIBLE")

    def test_the_refusal_explains_why_flattening_would_lose_semantics(self):
        self.assertIn("dependency", resolve(self._packaged(), AQL()).reason)

    def test_a_package_without_dependencies_is_not_claimed_to_lose_them(self):
        from models.rule_ir import RulePackage
        ir = replace(simple_graph(), package=RulePackage(rule_id="b", units=({"id": "r"},)))
        self.assertNotIn("dependency",
                         resolve(ir, AQL()).reason.lower().split("emitting")[0])

    def test_an_unpackaged_rule_is_unaffected(self):
        self.assertNotEqual(resolve(simple_graph(), AQL()).refusal_code,
                            "BUNDLE_DEPENDENCY_NOT_EXPRESSIBLE")


class MatrixAgreementTests(unittest.TestCase):
    """The registry and the frozen 70-cell matrix must not be able to disagree.

    The registry answers per GRAPH; the matrix is indexed per RULE. The bridge is the
    primitive list each corpus rule declares. Where a `frame` goes is load-bearing: a
    grouped historical search's frame is SCAN SCOPE on the Read (`LAST n MINUTES`); a
    correlation's frame is a COMPUTED window on the Aggregate. The kernel keeps those apart
    as `Read.bound` vs `Aggregate.frame`, and the corpus `shape` says which each rule means.
    """

    def _probe(self, rule_id):
        spec = RULES[rule_id]
        required = set(spec["primitives"])
        shape = spec.get("shape", "").lower()
        scan_scope_frame = "historical" in shape or "scan scope" in shape

        read = Read(id="read", selector=SourceSelector(name="logs"))
        if scan_scope_frame and "frame" in required:
            read = replace(read, bound=Frame(kind="per_event", size=Duration(600)))
        nodes = [read]
        current = "read"
        if "filter" in required:
            nodes.append(Filter(id="flt", input=current,
                                condition=Comparison("=", FieldExpr(FieldRef("a")),
                                                     Literal("1"))))
            current = "flt"
        if "expand" in required:
            nodes.append(Expand(id="exp", input=current, field=FieldRef("ips")))
            current = "exp"
        if "frame" in required and not scan_scope_frame:
            nodes.append(Aggregate(id="frame", input=current,
                                   measures=(Measure("Hits", "count"),),
                                   frame=Frame(kind="tumbling", size=Duration(600))))
            current = "frame"
        if "aggregate" in required:
            nodes.append(Aggregate(id="agg", input=current,
                                   measures=(Measure("Hits", "count"),
                                             Measure("Other", "dcount")),
                                   group_by=(FieldRef("u"),)))
            current = "agg"
        if "derive" in required:
            nodes.append(Derive(id="der", input=current,
                                assignments=((FieldRef("risk"), Literal(80)),)))
            current = "der"
        if "join" in required:
            nodes.append(Read(id="other", selector=SourceSelector(name="logs2")))
            on = BoolOp("and", children=(
                Comparison("=", EventExpr("left", None, FieldRef("host")),
                           EventExpr("right", None, FieldRef("host"))),
                Comparison("<=", EventExpr("right", None, FieldRef("t")),
                           Arith("+", EventExpr("left", None, FieldRef("t")),
                                 Literal(600)))))
            nodes.append(IRJoin(id="j", left=current, right="other", on=on,
                                match_window=Duration(600)))
            current = "j"
        if "pattern" in required:
            nodes.append(Read(id="stage2", selector=SourceSelector(name="logs")))
            nodes.append(Pattern(id="pat", max_span=Duration(300),
                                  stages=(IRStage(id="s1", input=current),
                                          IRStage(id="s2", input="stage2"))))
            current = "pat"
        if "set_op" in required:
            nodes.append(Read(id="other2", selector=SourceSelector(name="logs3")))
            nodes.append(SetOp(id="u", left=current, right="other2", op="except"))
            current = "u"
        nodes.append(Emit(id="out", input=current))
        return RuleIR(rule_id=rule_id, nodes=tuple(nodes), output="out")

    def test_every_frozen_matrix_cell_maps_to_a_registered_profile(self):
        unknown = set()
        for _rule_id, target, _value in all_cells():
            if find_profile(target) is None and len(
                    [p for p in PROFILES if p.product == target]) == 1:
                continue
            if target in {p.product for p in PROFILES}:
                continue
            unknown.add(target)
        self.assertEqual(unknown, set(), f"corpus names targets with no profile: {unknown}")

    def test_every_refused_matrix_cell_stays_refused(self):
        checked = 0
        for rule_id, target, (support, code, _note) in all_cells():
            if support != REFUSED:
                continue
            profiles = [p for p in PROFILES if p.product == target]
            for profile in profiles:
                result = resolve(self._probe(rule_id), profile)
                self.assertFalse(
                    result.resolvable,
                    f"{rule_id}/{target} is frozen as refused ({code}) but the registry "
                    f"emitted for the constructs that rule actually uses")
                checked += 1
        self.assertGreater(checked, 0, "no refused cell was actually checked")

    def test_the_registry_never_claims_more_than_the_matrix_allows(self):
        expected = {(r, t) for r, t, v in all_cells() if v[0] in {NATIVE, EQUIVALENT}}
        actual = set()
        for rule_id, target, (support, _code, _note) in all_cells():
            if support in {NATIVE, EQUIVALENT}:
                continue
            for profile in [p for p in PROFILES if p.product == target]:
                if resolve(self._probe(rule_id), profile).resolvable:
                    actual.add((rule_id, target))
        self.assertTrue(actual.issubset(expected),
                        f"registry claims capability the matrix refuses: "
                        f"{sorted(actual - expected)}")

    def test_no_matrix_cell_emits_at_this_phase(self):
        """Because no renderer exists, every cell refuses. Stated so it cannot drift."""
        for rule_id, target, _value in all_cells():
            for profile in [p for p in PROFILES if p.product == target]:
                self.assertFalse(resolve(self._probe(rule_id), profile).resolvable,
                                 f"{rule_id}/{target} emitted with no renderer registered")


class SupportLevelTests(unittest.TestCase):
    """Support is `native` only if EVERY lowering is native.

    An earlier draft said native if ANY node had an exact emitter, which mislabels a mixed
    graph the moment an equivalent emitter lands. Nothing caught that, because every emitter
    at the time was exact - so this test registers one of each to exercise the mix.
    """

    def _with_emitters(self, emitters):
        import models.rule_capabilities as rc
        original = rc.EMITTERS
        rc.EMITTERS = emitters
        self.addCleanup(lambda: setattr(rc, "EMITTERS", original))

    @staticmethod
    def _lowering(node):
        return f"rendered {node.id}"

    def _aql_filter(self, emitter_id, exact):
        from models.rule_capabilities import Emitter
        return Emitter(dialect="qradar-aql", primitive="Filter", emitter_id=emitter_id,
                       lowering=SupportLevelTests._lowering, exact=exact)

    def _pass_through(self, primitive, emitter_id, exact=True):
        from models.rule_capabilities import Emitter
        return Emitter(dialect="qradar-aql", primitive=primitive, emitter_id=emitter_id,
                       lowering=SupportLevelTests._lowering, exact=exact)

    def _mixed_graph(self):
        """Read (native) -> Derive (equivalent only) -> Filter -> Emit."""
        nodes = [Read(id="read", selector=SourceSelector(name="logs"))]
        nodes.append(Derive(id="der", input="read",
                            assignments=((FieldRef("risk"), Literal(80)),)))
        nodes.append(Filter(id="f1", input="der",
                            condition=Comparison("=", FieldExpr(FieldRef("a")), Literal("1"))))
        nodes.append(Emit(id="out", input="f1"))
        return RuleIR(rule_id="mix", nodes=tuple(nodes), output="out")

    def test_a_mixed_native_and_equivalent_graph_is_equivalent_not_native(self):
        self._with_emitters((self._pass_through("Read", "r"),
                             self._pass_through("Derive", "d", exact=False),
                             self._aql_filter("a", exact=True),
                             self._pass_through("Emit", "e")))
        result = resolve(self._mixed_graph(), AQL())
        self.assertTrue(result.resolvable, result.reason)
        self.assertEqual(result.support, EQUIVALENT,
                         "one equivalent lowering makes the whole graph equivalent")

    def test_an_all_native_graph_is_native(self):
        self._with_emitters((self._pass_through("Read", "r"),
                             self._pass_through("Derive", "d", exact=True),
                             self._aql_filter("a", exact=True),
                             self._pass_through("Emit", "e")))
        result = resolve(self._mixed_graph(), AQL())
        self.assertEqual(result.support, NATIVE)

    def test_competing_emitters_for_one_primitive_use_the_most_native_one(self):
        """Per node, if any applicable emitter is exact, the native lowering is chosen."""
        self._with_emitters((self._pass_through("Read", "r"),
                             self._aql_filter("a", exact=True),
                             self._aql_filter("b", exact=False),
                             self._pass_through("Emit", "e")))
        nodes = [Read(id="read", selector=SourceSelector(name="logs")),
                 Filter(id="f1", input="read",
                        condition=Comparison("=", FieldExpr(FieldRef("a")), Literal("1"))),
                 Emit(id="out", input="f1")]
        result = resolve(RuleIR(rule_id="c", nodes=tuple(nodes), output="out"), AQL())
        self.assertEqual(result.support, NATIVE)


class LoweringTests(unittest.TestCase):
    """Only `lower()` may produce an artifact, and only by actually running the lowerings.

    This is the separation that stops a catalog row from asserting deployability. A
    capability table says what is POSSIBLE; running a renderer says what was PRODUCED.
    """

    def _with_emitters(self, emitters):
        import models.rule_capabilities as rc
        original = rc.EMITTERS
        rc.EMITTERS = tuple(emitters)
        self.addCleanup(lambda: setattr(rc, "EMITTERS", original))

    def _emitter(self, primitive, emitter_id, body="ok", exact=True):
        from models.rule_capabilities import Emitter
        return Emitter(dialect="qradar-aql", primitive=primitive, emitter_id=emitter_id,
                       lowering=lambda node: body, exact=exact)

    def _read_emit_graph(self):
        nodes = [Read(id="read", selector=SourceSelector(name="logs")),
                 Emit(id="out", input="read")]
        return RuleIR(rule_id="tiny", nodes=tuple(nodes), output="out")

    def test_lowering_refuses_when_nothing_is_registered(self):
        with self.assertRaises(RuleIRValidationError) as caught:
            lower(self._read_emit_graph(), AQL())
        self.assertEqual(caught.exception.code, "IR_UNSUPPORTED_EMITTER")

    def test_lowering_actually_invokes_the_registered_lowering(self):
        calls = []

        def recording(node):
            calls.append(node.id)
            return f"-- {node.id}"

        from models.rule_capabilities import Emitter
        self._with_emitters((Emitter(dialect="qradar-aql", primitive="Read",
                                     emitter_id="r", lowering=recording),
                             self._emitter("Emit", "e", body="-- out")))
        artifact = lower(self._read_emit_graph(), AQL())
        self.assertEqual(calls, ["read"], "the lowering was never actually called")
        self.assertIn("-- read", artifact.text)
        self.assertIn("-- out", artifact.text)
        self.assertEqual(artifact.emitter_ids, ("r", "e"))

    def test_a_lowering_that_raises_fails_the_whole_artifact(self):
        from models.rule_capabilities import Emitter

        def boom(node):
            raise ValueError("renderer blew up")

        self._with_emitters((Emitter(dialect="qradar-aql", primitive="Read",
                                     emitter_id="r", lowering=boom),
                             self._emitter("Emit", "e")))
        with self.assertRaises(RuleIRValidationError) as caught:
            lower(self._read_emit_graph(), AQL())
        self.assertEqual(caught.exception.code, "EMITTER_FAILED")

    def test_a_lowering_that_returns_nothing_fails_rather_than_emitting_blank_text(self):
        self._with_emitters((self._emitter("Read", "r", body=""),
                             self._emitter("Emit", "e")))
        with self.assertRaises(RuleIRValidationError) as caught:
            lower(self._read_emit_graph(), AQL())
        self.assertEqual(caught.exception.code, "EMITTER_PRODUCED_NO_TEXT")

    def test_a_lowering_that_returns_a_non_string_fails(self):
        from models.rule_capabilities import Emitter
        self._with_emitters((Emitter(dialect="qradar-aql", primitive="Read", emitter_id="r",
                                     lowering=lambda node: 42),
                             self._emitter("Emit", "e")))
        with self.assertRaises(RuleIRValidationError) as caught:
            lower(self._read_emit_graph(), AQL())
        self.assertEqual(caught.exception.code, "EMITTER_PRODUCED_NO_TEXT")

    def test_a_partial_lowering_never_produces_a_partial_artifact(self):
        """One failing node must not yield half a rule that deploys and does not fire."""
        from models.rule_capabilities import Emitter
        self._with_emitters((self._emitter("Read", "r"),
                             Emitter(dialect="qradar-aql", primitive="Emit", emitter_id="e",
                                     lowering=lambda node: "")))
        with self.assertRaises(RuleIRValidationError):
            lower(self._read_emit_graph(), AQL())

    def test_resolution_alone_never_claims_an_artifact_was_produced(self):
        """`resolvable` is not `emitted`. The vocabulary itself must not blur."""
        self._with_emitters((self._emitter("Read", "r"), self._emitter("Emit", "e")))
        resolution = resolve(self._read_emit_graph(), AQL())
        self.assertTrue(resolution.resolvable)
        self.assertEqual(resolution.status, "resolvable")
        self.assertFalse(hasattr(resolution, "deployable"),
                         "a capability result must not expose a deployable flag")
        self.assertEqual(resolution.emitter_ids, ("r", "e"))


class SemanticPreflightTests(unittest.TestCase):
    """Checks `validate_ir` does not make, but a renderer would trip over."""

    def _with_emitters(self):
        import models.rule_capabilities as rc
        from models.rule_capabilities import Emitter
        original = rc.EMITTERS
        rc.EMITTERS = tuple(Emitter(dialect="qradar-aql", primitive=p, emitter_id=p.lower(),
                                    lowering=lambda node: "x")
                            for p in PRIMITIVE_NAMES)
        self.addCleanup(lambda: setattr(rc, "EMITTERS", original))

    def _code(self, ir):
        return resolve(ir, AQL()).refusal_code

    def test_a_blank_source_name_is_refused(self):
        self._with_emitters()
        self.assertEqual(self._code(simple_graph(source="   ")), "UNRESOLVED_SOURCE")

    def test_an_unknown_source_strategy_is_refused(self):
        self._with_emitters()
        nodes = [Read(id="read", selector=SourceSelector(name="logs", strategy="telepathy")),
                 Emit(id="out", input="read")]
        self.assertEqual(self._code(RuleIR(rule_id="s", nodes=tuple(nodes), output="out")),
                         "UNKNOWN_SOURCE_STRATEGY")

    def test_a_whitespace_schema_id_is_refused(self):
        self._with_emitters()
        nodes = [Read(id="read", selector=SourceSelector(name="logs", strategy="accelerated",
                                                         schema_id="   ")),
                 Emit(id="out", input="read")]
        self.assertEqual(self._code(RuleIR(rule_id="s", nodes=tuple(nodes), output="out")),
                         "ACCELERATED_SOURCE_WITHOUT_SCHEMA")

    def test_a_prior_emission_without_a_package_is_refused(self):
        self._with_emitters()
        nodes = [Read(id="read", selector=SourceSelector(name="out", strategy="prior_emission")),
                 Emit(id="out", input="read")]
        self.assertEqual(self._code(RuleIR(rule_id="s", nodes=tuple(nodes), output="out")),
                         "PRIOR_EMISSION_WITHOUT_PACKAGE")

    def test_an_unverified_field_reference_is_refused(self):
        self._with_emitters()
        ir = simple_graph()
        node = Filter(id="flt", input="read",
                      condition=Comparison("=", FieldExpr(FieldRef("a", confidence="unverified")),
                                           Literal("1")))
        nodes = tuple(node if n.id == "flt" else n for n in ir.nodes)
        self.assertEqual(self._code(replace(ir, nodes=nodes)), "UNVERIFIED_FIELD_REFERENCE")

    def test_a_function_call_with_bad_arity_is_refused(self):
        self._with_emitters()
        ir = simple_graph()
        node = Filter(id="flt", input="read", condition=Call("concat", ()))
        nodes = tuple(node if n.id == "flt" else n for n in ir.nodes)
        self.assertEqual(self._code(replace(ir, nodes=nodes)), "FUNCTION_ARITY_VIOLATION")

    def test_an_unknown_function_is_refused_by_the_kernel_before_the_preflight(self):
        """The kernel refuses unknown functions at construction, so this cannot be built."""
        with self.assertRaises(RuleIRValidationError) as caught:
            Call("teleport", (Literal(1),))
        self.assertEqual(caught.exception.code, "UNKNOWN_FUNCTION")

    def test_an_unknown_boolean_operator_is_refused(self):
        self._with_emitters()
        ir = simple_graph()
        node = Filter(id="flt", input="read", condition=BoolOp("xor", (Literal(True),)))
        nodes = tuple(node if n.id == "flt" else n for n in ir.nodes)
        self.assertEqual(self._code(replace(ir, nodes=nodes)), "UNKNOWN_BOOLEAN_OPERATOR")

    def test_a_well_formed_graph_still_passes_the_preflight(self):
        self._with_emitters()
        self.assertTrue(resolve(simple_graph(), AQL()).resolvable)


class StrictFlagTests(unittest.TestCase):
    def test_a_non_boolean_exact_flag_cannot_promote_an_equivalent_lowering(self):
        from models.rule_capabilities import Emitter
        with self.assertRaises(RuleIRValidationError) as caught:
            Emitter(dialect="d", primitive="Filter", emitter_id="e", lowering=lambda n: "x",
                    exact="false")
        self.assertEqual(caught.exception.code, "MALFORMED_EXACT_FLAG")

    def test_a_malformed_version_is_rejected_outright(self):
        from models.rule_capabilities import _version_tuple
        for bad in ("7.4junk", "7.4.0-beta", "not-a-version", "", "v7.4"):
            with self.assertRaises(RuleIRValidationError, msg=bad) as caught:
                _version_tuple(bad)
            self.assertEqual(caught.exception.code, "MALFORMED_VERSION")

    def test_a_well_formed_version_still_parses(self):
        from models.rule_capabilities import _version_tuple
        self.assertEqual(_version_tuple("7.4"), (7, 4))
        self.assertEqual(_version_tuple("7.4.1"), (7, 4, 1))


class UnregisteredProfileTests(unittest.TestCase):
    def test_a_forged_profile_is_refused(self):
        from models.rule_capabilities import TargetProfile
        forged = TargetProfile("evil", "engine", "artifact", "qradar-aql", "7.4")
        with self.assertRaises(RuleIRValidationError) as caught:
            resolve(simple_graph(), forged)
        self.assertEqual(caught.exception.code, "UNREGISTERED_PROFILE")

    def test_a_forged_profile_cannot_reach_lowering_either(self):
        from models.rule_capabilities import TargetProfile
        forged = TargetProfile("qradar", "aql", "saved_search", "qradar-aql", "9.9")
        with self.assertRaises(RuleIRValidationError):
            lower(simple_graph(), forged)


class PreflightCoverageTests(unittest.TestCase):
    """Every place a semantic problem can hide, not just `Filter.condition`.

    The preflight originally read only `node.condition`, so an unverified field hidden in
    `Join.on`, `Derive.assignments`, `Measure.where`, `InList`, `Expand.field`,
    `Arrange.order_by` or `Pattern.key` sailed through to a rendered artifact. These tests
    exist because a checker that only looks in one place looks like a checker.
    """

    def _with_emitters(self):
        import models.rule_capabilities as rc
        from models.rule_capabilities import Emitter
        original = rc.EMITTERS
        rc.EMITTERS = tuple(Emitter(dialect="qradar-aql", primitive=p, emitter_id=p.lower(),
                                    lowering=lambda node: "x")
                            for p in PRIMITIVE_NAMES)
        self.addCleanup(lambda: setattr(rc, "EMITTERS", original))

    def _swap(self, ir, node_id, replacement):
        nodes = tuple(replacement if n.id == node_id else n for n in ir.nodes)
        return replace(ir, nodes=nodes)

    def test_an_unverified_field_in_a_join_predicate_is_refused(self):
        self._with_emitters()
        nodes = [Read(id="read", selector=SourceSelector(name="logs")),
                 Read(id="other", selector=SourceSelector(name="logs2"))]
        on = BoolOp("and", children=(
            Comparison("=", EventExpr("left", None, FieldRef("host", confidence="unverified")),
                       EventExpr("right", None, FieldRef("host"))),))
        nodes.append(IRJoin(id="j", left="read", right="other", on=on))
        nodes.append(Emit(id="out", input="j"))
        ir = RuleIR(rule_id="j", nodes=tuple(nodes), output="out")
        self.assertEqual(resolve(ir, AQL()).refusal_code, "UNVERIFIED_FIELD_REFERENCE")

    def test_an_unverified_field_in_a_derive_assignment_is_refused(self):
        self._with_emitters()
        ir = simple_graph()
        node = Derive(id="flt", input="read",
                      assignments=((FieldRef("risk", confidence="unverified"), Literal(80)),))
        self.assertEqual(resolve(self._swap(ir, "flt", node), AQL()).refusal_code,
                         "UNVERIFIED_FIELD_REFERENCE")

    def test_a_bad_arity_call_in_a_derive_assignment_is_refused(self):
        self._with_emitters()
        ir = simple_graph()
        node = Derive(id="flt", input="read",
                      assignments=((FieldRef("risk"), Call("concat", ())),))
        self.assertEqual(resolve(self._swap(ir, "flt", node), AQL()).refusal_code,
                         "FUNCTION_ARITY_VIOLATION")

    def test_an_unverified_field_in_an_expand_is_refused(self):
        self._with_emitters()
        nodes = [Read(id="read", selector=SourceSelector(name="logs")),
                 Expand(id="exp", input="read", field=FieldRef("ips", confidence="inferred")),
                 Emit(id="out", input="exp")]
        ir = RuleIR(rule_id="e", nodes=tuple(nodes), output="out")
        self.assertEqual(resolve(ir, AQL()).refusal_code, "UNVERIFIED_FIELD_REFERENCE")

    def test_an_unverified_field_in_an_arrange_is_refused(self):
        self._with_emitters()
        nodes = [Read(id="read", selector=SourceSelector(name="logs")),
                 Arrange(id="arr", input="read", order_by=(FieldRef("t", confidence="unverified"),)),
                 Emit(id="out", input="arr")]
        ir = RuleIR(rule_id="a", nodes=tuple(nodes), output="out")
        self.assertEqual(resolve(ir, AQL()).refusal_code, "UNVERIFIED_FIELD_REFERENCE")

    def test_an_unverified_field_inside_an_inlist_is_refused(self):
        """`InList` is a standalone boolean expression, not a Comparison operator.

        The model has no `in` comparison - the vocabulary is six ops - so membership is
        expressed by making the InList itself the predicate.
        """
        self._with_emitters()
        ir = simple_graph()
        node = Filter(id="flt", input="read",
                      condition=InList(FieldRef("b", confidence="unverified"),
                                       (Literal(1), Literal(2))))
        self.assertEqual(resolve(self._swap(ir, "flt", node), AQL()).refusal_code,
                         "UNVERIFIED_FIELD_REFERENCE")

    def test_an_unknown_comparison_operator_is_refused(self):
        self._with_emitters()
        ir = simple_graph()
        node = Filter(id="flt", input="read",
                      condition=Comparison("approximately", FieldExpr(FieldRef("a")),
                                           Literal("1")))
        self.assertEqual(resolve(self._swap(ir, "flt", node), AQL()).refusal_code,
                         "UNKNOWN_COMPARISON_OPERATOR")

    def test_an_unverified_source_is_refused_even_when_named(self):
        self._with_emitters()
        nodes = [Read(id="read", selector=SourceSelector(name="logs", confidence="inferred")),
                 Emit(id="out", input="read")]
        ir = RuleIR(rule_id="s", nodes=tuple(nodes), output="out")
        self.assertEqual(resolve(ir, AQL()).refusal_code, "UNVERIFIED_SOURCE_REFERENCE")

    def test_a_regex_with_no_declarable_dialect_is_refused(self):
        """`matches_regex` demands a declared dialect, and `Call` has nowhere to declare one.

        That is a real gap in the expression algebra rather than a checker quirk, and the
        honest outcome is a refusal: an undeclared regex dialect is not portable, so
        guessing one would be exactly the fabrication this project forbids. The adapter's
        wildcard/windash/base64 mappings are consequently unusable and are recorded as an
        open item against the adapter, not papered over here.
        """
        self._with_emitters()
        ir = simple_graph()
        node = Filter(id="flt", input="read",
                      condition=Comparison("=", FieldExpr(FieldRef("a")),
                                           Call("matches_regex",
                                                (FieldExpr(FieldRef("payload")),
                                                 Literal("^a")))))
        result = resolve(self._swap(ir, "flt", node), AQL())
        self.assertEqual(result.refusal_code, "FUNCTION_DIALECT_UNDECLARED")

    def test_a_deep_expression_is_refused_rather_than_overflowing(self):
        self._with_emitters()
        ir = simple_graph()
        expr = Literal(True)
        for _ in range(200):
            expr = BoolOp("not", (expr,))
        node = Filter(id="flt", input="read", condition=expr)
        self.assertEqual(resolve(self._swap(ir, "flt", node), AQL()).refusal_code,
                         "EXPRESSION_TOO_DEEP")


class LoweringIntegrityTests(unittest.TestCase):
    """`lower()` must not misreport what it ran."""

    def _emitters(self, first_exact, second_exact):
        from models.rule_capabilities import Emitter
        return (Emitter(dialect="qradar-aql", primitive="Read", emitter_id="r",
                        lowering=lambda node: "r", exact=first_exact),
                Emitter(dialect="qradar-aql", primitive="Emit", emitter_id="e",
                        lowering=lambda node: "e", exact=second_exact))

    def _graph(self):
        nodes = [Read(id="read", selector=SourceSelector(name="logs")),
                 Emit(id="out", input="read")]
        return RuleIR(rule_id="tiny", nodes=tuple(nodes), output="out")

    def test_the_artifact_support_matches_the_emitters_that_actually_ran(self):
        import models.rule_capabilities as rc
        original = rc.EMITTERS
        rc.EMITTERS = self._emitters(True, False)
        self.addCleanup(lambda: setattr(rc, "EMITTERS", original))
        artifact = lower(self._graph(), AQL())
        self.assertEqual(artifact.support, EQUIVALENT)
        self.assertEqual(artifact.emitter_ids, ("r", "e"))

    def test_a_registry_swap_between_resolve_and_lower_cannot_change_the_artifact(self):
        """The emitter bound at resolution is the one that runs, even if EMITTERS changes."""
        import models.rule_capabilities as rc
        original = rc.EMITTERS
        calls = []

        def swapping(node):
            calls.append(node.id)
            rc.EMITTERS = self._emitters(True, False)
            return "original"

        from models.rule_capabilities import Emitter
        rc.EMITTERS = (Emitter(dialect="qradar-aql", primitive="Read", emitter_id="r",
                               lowering=swapping, exact=True),
                       Emitter(dialect="qradar-aql", primitive="Emit", emitter_id="e",
                               lowering=lambda node: "e", exact=True))
        self.addCleanup(lambda: setattr(rc, "EMITTERS", original))
        artifact = lower(self._graph(), AQL())
        self.assertEqual(artifact.support, NATIVE,
                         "support was taken from a registry that had already been replaced")
        self.assertEqual(artifact.emitter_ids, ("r", "e"))
        self.assertEqual(calls, ["read"])

    def test_whitespace_only_output_is_refused(self):
        import models.rule_capabilities as rc
        from models.rule_capabilities import Emitter
        original = rc.EMITTERS
        rc.EMITTERS = (Emitter(dialect="qradar-aql", primitive="Read", emitter_id="r",
                               lowering=lambda node: "   \n "),
                       Emitter(dialect="qradar-aql", primitive="Emit", emitter_id="e",
                               lowering=lambda node: "e"))
        self.addCleanup(lambda: setattr(rc, "EMITTERS", original))
        with self.assertRaises(RuleIRValidationError) as caught:
            lower(self._graph(), AQL())
        self.assertEqual(caught.exception.code, "EMITTER_PRODUCED_NO_TEXT")

    def test_a_renderer_exception_message_is_not_echoed_to_the_caller(self):
        """Renderer errors can carry paths or source text; the message must stay generic."""
        import models.rule_capabilities as rc
        from models.rule_capabilities import Emitter
        original = rc.EMITTERS
        secret = "C:\\secret\\path\\config.key"

        def boom(node):
            raise RuntimeError(f"failed reading {secret}")

        rc.EMITTERS = (Emitter(dialect="qradar-aql", primitive="Read", emitter_id="r",
                               lowering=boom),
                       Emitter(dialect="qradar-aql", primitive="Emit", emitter_id="e",
                               lowering=lambda node: "e"))
        self.addCleanup(lambda: setattr(rc, "EMITTERS", original))
        with self.assertRaises(RuleIRValidationError) as caught:
            lower(self._graph(), AQL())
        self.assertNotIn(secret, str(caught.exception))


class VocabularyTests(unittest.TestCase):
    """The preflight's vocabularies come from the model, not from a second hand-written copy.

    An earlier draft hard-coded 21 comparison operators including `exists`, `is_null`,
    `between` and `contains`. The IR permits six. The only effect of the extra fifteen was
    to wave unknown operators through a check built to refuse them.
    """

    def test_the_comparison_vocabulary_is_exactly_the_model_six(self):
        self.assertEqual(vocabulary()["comparison"],
                         frozenset({"=", "!=", "<", "<=", ">", ">="}))

    def test_no_vocabulary_resolves_empty(self):
        for name, allowed in vocabulary().items():
            self.assertTrue(allowed, f"vocabulary {name!r} is empty; the check would refuse "
                                     f"every value rather than every unknown one")

    def test_operators_the_model_cannot_express_are_not_accepted(self):
        for op in ("exists", "is_null", "between", "contains", "matches_regex", "approximately"):
            self.assertNotIn(op, vocabulary()["comparison"],
                             f"{op!r} is not a Comparison op but was being accepted")

    def test_the_boolean_and_setop_vocabularies_match_the_model(self):
        self.assertEqual(vocabulary()["boolean"], frozenset({"and", "or", "not"}))
        self.assertEqual(vocabulary()["set_op"],
                         frozenset({"union", "intersect", "except", "append", "except_both"}))

    def test_audit_fails_if_a_vocabulary_cannot_be_resolved(self):
        """An empty vocabulary must be a loud failure, not a strict-looking no-op."""
        import models.rule_capabilities as rc
        original = rc._COMPARISON_OPS
        rc._COMPARISON_OPS = frozenset()
        try:
            problems = rc.audit()
            self.assertTrue(any("EMPTY" in p for p in problems), problems)
        finally:
            rc._COMPARISON_OPS = original


class OperatorAliasTests(unittest.TestCase):
    """A synonym table may not alter meaning, not even in the message it produces."""

    def test_no_alias_widens_a_predicate(self):
        for source, target in OPERATOR_ALIASES.items():
            self.assertNotEqual((source, target), ("gt", "gte"),
                                "gt means strictly greater; mapping it to gte widens it")
            self.assertNotEqual(target, "gte", f"{source!r} widens into gte")

    def test_every_alias_is_a_truthful_synonym_in_the_v1_vocabulary(self):
        for source, target in OPERATOR_ALIASES.items():
            self.assertIn(target, CANONICAL_OPERATORS,
                          f"{source!r} maps to {target!r}, which is not a canonical operator")

    def test_gt_survives_normalisation_so_the_refusal_names_what_was_written(self):
        operator, changed = canonical_operator("gt")
        self.assertEqual(operator, "gt")
        self.assertFalse(changed, "gt must not be reported as a normalised operator")


class ShadowModeTests(unittest.TestCase):
    def test_nothing_in_the_app_calls_the_registry(self):
        from pathlib import Path
        for module in ("app.py", "rule_engine.py", "compiler/pipeline.py",
                       "compiler/sigma_compiler.py", "static/app.js", "templates/index.html"):
            self.assertNotIn("rule_capabilities", Path(module).read_text(encoding="utf-8"),
                             f"{module} already calls the capability registry")


if __name__ == "__main__":
    unittest.main()
