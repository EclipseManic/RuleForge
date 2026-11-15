"""The JSON codec: does a Rule survive leaving the process and coming back?

Most of these tests are about the four things JSON is bad at and this engine
depends on: exact decimals, the difference between ABSENT and null and "" and
UNDECIDED, tuples that stay tuples, and a type tag that cannot be guessed.

The reflection test at the bottom is the one that matters in a year. Everything
else checks the codec as it is today; that one fails when somebody adds an IR
node and forgets the codec, which is the failure that would otherwise reach a
user as a rule with a stage missing.
"""

from __future__ import annotations

import dataclasses
import json
import unittest
from decimal import Decimal

from engine import ir
from engine.codec import (
    KNOWN_TYPES,
    MAX_DEPTH,
    SCHEMA_VERSION,
    rule_from_dict,
    rule_from_json,
    rule_to_dict,
    rule_to_json,
)
from engine.dialects.kql import lower_kql
from engine.ir import (
    Aggregate,
    Annotations,
    Arith,
    Binding,
    BoolOp,
    Call,
    Comparison,
    Correlation,
    Derive,
    Distinct,
    Emit,
    Expand,
    FieldRef,
    Filter,
    Join,
    Limit,
    ListExpr,
    Literal,
    Measure,
    Not,
    Project,
    Read,
    Regex,
    Rule,
    Sort,
    Span,
    SubQuery,
    Window,
)
from engine.values import ABSENT, UNDECIDED, Capability, Duration, Refusal, Seq

#: The reference rule: two bindings, a join, a temporal span, a summarize and a
#: post-aggregate filter. Reused from the KQL suite so the round trip is proven
#: on something with every hard case in it rather than on `T | take 1`.
USER_RULE = """
let LSASSAccess =
SecurityEvent
| where EventID == 10
| where TargetImage endswith @"\\lsass.exe"
| project LSASSTime=TimeGenerated, Computer, Account, SourceImage, SourceIp;

let LateralMovement =
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| project LoginTime=TimeGenerated, Computer, Account, IpAddress;

LSASSAccess
| join kind=inner (LateralMovement) on Computer, Account
| where LoginTime between (LSASSTime .. LSASSTime + 10m)
| summarize Hits=count(), FirstSeen=min(LSASSTime), SourceIPs=make_set(SourceIp) by Computer, Account
| where Hits >= 1
| extend DetectionName="Credential Access Followed By NTLM Lateral Movement"
"""


def filter_rule(condition, **rule_kwargs) -> Rule:
    """The smallest valid rule carrying one condition."""
    return Rule(
        rule_id="r",
        pipeline=(
            Read(id="src", table="SecurityEvent"),
            Filter(id="f", condition=condition),
            Emit(id="out"),
        ),
        **rule_kwargs,
    )


def roundtrip(rule: Rule) -> Rule:
    return rule_from_dict(rule_to_dict(rule))


class TheReferenceRule(unittest.TestCase):
    def setUp(self):
        self.rule, _ = lower_kql(USER_RULE)

    def test_a_real_rule_survives_exactly(self):
        # Dataclass equality, not a string comparison: the IR is frozen
        # dataclasses, so this compares every field of every node.
        self.assertEqual(roundtrip(self.rule), self.rule)

    def test_it_survives_as_json_text(self):
        self.assertEqual(rule_from_json(rule_to_json(self.rule)), self.rule)

    def test_the_payload_is_actually_json(self):
        json.loads(rule_to_json(self.rule))

    def test_two_equal_rules_serialise_to_equal_bytes(self):
        # History and diffing both need a stable byte form, or every save looks
        # like a change.
        again, _ = lower_kql(USER_RULE)
        self.assertEqual(rule_to_json(self.rule), rule_to_json(again))

    def test_the_bindings_and_their_order_survive(self):
        back = roundtrip(self.rule)
        self.assertEqual(
            [b.name for b in back.bindings], ["LSASSAccess", "LateralMovement"]
        )

    def test_the_stage_sequence_survives(self):
        back = roundtrip(self.rule)
        self.assertEqual(
            [type(n).__name__ for n in back.pipeline],
            [type(n).__name__ for n in self.rule.pipeline],
        )

    def test_the_dialect_it_came_from_survives(self):
        self.assertEqual(roundtrip(self.rule).metadata["dialect"], "sentinel")

    def test_the_payload_names_its_schema_version(self):
        self.assertEqual(rule_to_dict(self.rule)["schema"], SCHEMA_VERSION)


class DecimalsAreExact(unittest.TestCase):
    """A threshold that changes value in transit is a different control."""

    def test_a_decimal_threshold_is_not_turned_into_a_float(self):
        rule = filter_rule(
            Comparison(">=", FieldRef("Hits"), Literal(Decimal("10.5")))
        )
        value = roundtrip(rule).pipeline[1].condition.right.value
        self.assertIsInstance(value, Decimal)
        self.assertEqual(value, Decimal("10.5"))

    def test_a_decimal_keeps_precision_a_float_would_lose(self):
        # 0.1 + 0.2 is the canonical float-noise case. Decimal is the reason
        # this engine can compare numbers at all.
        exact = Decimal("0.1000000000000000055511151231257827")
        rule = filter_rule(Comparison("==", FieldRef("x"), Literal(exact)))
        self.assertEqual(roundtrip(rule).pipeline[1].condition.right.value, exact)

    def test_a_decimal_keeps_its_trailing_zeros(self):
        # Decimal("1.50") != Decimal("1.5") in string form, and a renderer
        # writes the string form back into the rule.
        rule = filter_rule(Comparison("==", FieldRef("x"), Literal(Decimal("1.50"))))
        self.assertEqual(
            str(roundtrip(rule).pipeline[1].condition.right.value), "1.50"
        )

    def test_a_measure_param_decimal_survives(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="T"),
                Aggregate(
                    id="agg",
                    measures=(
                        Measure("percentile", "p95", FieldRef("dur"),
                                param=Decimal("95")),
                    ),
                    keys=(FieldRef("Computer"),),
                ),
                Emit(id="out"),
            ),
        )
        self.assertEqual(roundtrip(rule).pipeline[1].measures[0].param, Decimal("95"))


class FourWayNullDistinction(unittest.TestCase):
    """ABSENT, None, "" and UNDECIDED are four answers. JSON has one null."""

    def _literal_back(self, value):
        rule = filter_rule(Comparison("==", FieldRef("x"), Literal(value)))
        return roundtrip(rule).pipeline[1].condition.right.value

    def test_absent_comes_back_as_absent(self):
        self.assertIs(self._literal_back(ABSENT), ABSENT)

    def test_undecided_comes_back_as_undecided(self):
        self.assertIs(self._literal_back(UNDECIDED), UNDECIDED)

    def test_null_comes_back_as_none(self):
        self.assertIsNone(self._literal_back(None))

    def test_empty_string_comes_back_as_empty_string(self):
        back = self._literal_back("")
        self.assertEqual(back, "")
        self.assertIsInstance(back, str)

    def test_the_four_do_not_collapse_into_each_other(self):
        # The whole point. If any two of these encode the same way, a rule
        # testing for a missing field becomes a rule testing for an empty one.
        encoded = [
            json.dumps(rule_to_dict(filter_rule(
                Comparison("==", FieldRef("x"), Literal(v))
            )), sort_keys=True)
            for v in (ABSENT, UNDECIDED, None, "")
        ]
        self.assertEqual(len(set(encoded)), 4, encoded)

    def test_none_is_never_written_as_a_bare_json_null(self):
        # A bare null would be indistinguishable from a missing key, and a
        # missing key is how a decoder ends up filling in a default.
        payload = rule_to_dict(filter_rule(
            Comparison("==", FieldRef("x"), Literal(None))
        ))
        self.assertNotIn(": null", json.dumps(payload))


class BoolIsNotAnInt(unittest.TestCase):
    """`bool` subclasses `int`, so tag order in the encoder is load-bearing."""

    def test_true_does_not_come_back_as_one(self):
        rule = filter_rule(Comparison("==", FieldRef("x"), Literal(True)))
        back = roundtrip(rule).pipeline[1].condition.right.value
        self.assertIs(back, True)
        self.assertIsInstance(back, bool)

    def test_one_does_not_come_back_as_true(self):
        rule = filter_rule(Comparison("==", FieldRef("x"), Literal(1)))
        back = roundtrip(rule).pipeline[1].condition.right.value
        self.assertNotIsInstance(back, bool)
        self.assertEqual(back, 1)

    def test_a_negate_flag_survives(self):
        rule = filter_rule(
            Comparison("==", FieldRef("x"), Literal("a"), negate=True)
        )
        self.assertTrue(roundtrip(rule).pipeline[1].condition.negate)


class CapabilityIsNotAString(unittest.TestCase):
    """`Capability` subclasses `str`, the other tag-order trap."""

    def test_declared_only_survives_as_the_enum(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="T"),
                Filter(
                    id="f",
                    capability=Capability.DECLARED_ONLY,
                    note="runs on the appliance",
                    condition=Comparison(
                        "==", Call("qidname", (FieldRef("qid"),)), Literal("x")
                    ),
                ),
                Emit(id="out"),
            ),
        )
        back = roundtrip(rule).pipeline[1]
        self.assertIs(back.capability, Capability.DECLARED_ONLY)
        self.assertEqual(back.note, "runs on the appliance")


class TuplesStayTuples(unittest.TestCase):
    """The IR is tuples throughout and its dataclasses are frozen."""

    def test_a_field_path_comes_back_as_a_tuple(self):
        rule = filter_rule(
            Comparison(
                "==",
                FieldRef("win", ("eventdata", "Image"), "current"),
                Literal("x"),
            )
        )
        path = roundtrip(rule).pipeline[1].condition.left.path
        self.assertIsInstance(path, tuple)
        self.assertEqual(path, ("eventdata", "Image"))

    def test_bool_op_operands_come_back_as_a_tuple(self):
        rule = filter_rule(BoolOp("and", (
            Comparison("==", FieldRef("a"), Literal(1)),
            Comparison("==", FieldRef("b"), Literal(2)),
        )))
        operands = roundtrip(rule).pipeline[1].condition.operands
        self.assertIsInstance(operands, tuple)
        self.assertEqual(len(operands), 2)

    def test_a_list_value_stays_a_list_and_a_tuple_stays_a_tuple(self):
        # Different tags, because the IR means different things by them.
        rule = filter_rule(Comparison("==", FieldRef("x"), Literal(("a", "b"))))
        self.assertIsInstance(
            roundtrip(rule).pipeline[1].condition.right.value, tuple
        )
        rule = filter_rule(Comparison("==", FieldRef("x"), Literal(["a", "b"])))
        self.assertIsInstance(
            roundtrip(rule).pipeline[1].condition.right.value, list
        )

    def test_a_seq_keeps_its_distinct_flag(self):
        # values() de-duplicates and make_set() does not, and that difference
        # changes an alert.
        rule = filter_rule(
            Comparison("==", FieldRef("x"), Literal(Seq(("a", "b"), distinct=True)))
        )
        back = roundtrip(rule).pipeline[1].condition.right.value
        self.assertIsInstance(back, Seq)
        self.assertTrue(back.distinct)
        self.assertEqual(back.items, ("a", "b"))


class ScopedReferencesSurvive(unittest.TestCase):
    """Scope is the difference between a correlation and a filter."""

    def test_left_and_right_scopes_survive(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="T"),
                Join(
                    id="j",
                    left="src",
                    right="other",
                    predicate=Comparison(
                        "==",
                        FieldRef("Computer", (), "left"),
                        FieldRef("Computer", (), "right"),
                    ),
                ),
                Emit(id="out"),
            ),
            bindings=(
                Binding(name="other", pipeline=(Read(id="o", table="U"),)),
            ),
        )
        predicate = roundtrip(rule).pipeline[1].predicate
        self.assertEqual(predicate.left.scope, "left")
        self.assertEqual(predicate.right.scope, "right")

    def test_a_temporal_span_with_arithmetic_bounds_survives(self):
        # The canonical enterprise correlation predicate.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="T"),
                Join(
                    id="j",
                    left="src",
                    right="other",
                    on=((FieldRef("Computer"),
                         FieldRef("Computer", (), "right")),),
                    predicate=Span(
                        FieldRef("LoginTime", (), "right"),
                        FieldRef("LSASSTime", (), "left"),
                        Arith("+", FieldRef("LSASSTime", (), "left"),
                              Literal(Duration(Decimal(600)))),
                    ),
                ),
                Emit(id="out"),
            ),
            bindings=(
                Binding(name="other", pipeline=(Read(id="o", table="U"),)),
            ),
        )
        span = roundtrip(rule).pipeline[1].predicate
        self.assertIsInstance(span, Span)
        self.assertEqual(span.high.right.value.seconds, Decimal(600))
        self.assertEqual(span.value.scope, "right")

    def test_join_keys_and_prefixes_survive(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="T"),
                Join(
                    id="j", left="src", right="other", how="left",
                    on=((FieldRef("a"), FieldRef("b", (), "right")),),
                    left_prefix="L_", right_prefix="R_",
                ),
                Emit(id="out"),
            ),
            bindings=(
                Binding(name="other", pipeline=(Read(id="o", table="U"),)),
            ),
        )
        back = roundtrip(rule).pipeline[1]
        self.assertEqual(back.how, "left")
        self.assertEqual(back.left_prefix, "L_")
        self.assertEqual(back.on[0][0].name, "a")
        self.assertEqual(back.on[0][1].scope, "right")


class EveryWindowKindSurvives(unittest.TestCase):
    """A window that changes kind in transit produces different alerts."""

    def _rule_with(self, window: Window) -> Rule:
        return Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="T"),
                Aggregate(
                    id="agg",
                    measures=(Measure("count", "n"),),
                    keys=(FieldRef("Computer"),),
                    window=window,
                ),
                Emit(id="out"),
            ),
        )

    def test_all_five_kinds_round_trip(self):
        windows = (
            Window(kind="tumbling", size=Duration(Decimal(300))),
            Window(kind="sliding", size=Duration(Decimal(300)),
                   step=Duration(Decimal(60))),
            Window(kind="cumulative"),
            Window(kind="per_event"),
            Window(kind="session", gap=Duration(Decimal(900))),
        )
        for window in windows:
            with self.subTest(kind=window.kind):
                back = roundtrip(self._rule_with(window)).pipeline[1].window
                self.assertEqual(back, window)

    def test_a_window_with_no_size_keeps_its_none(self):
        # None here means "not specified", which is not the same as zero.
        back = roundtrip(self._rule_with(Window(kind="cumulative"))).pipeline[1]
        self.assertIsNone(back.window.size)


class EveryStageTypeSurvives(unittest.TestCase):
    def test_a_rule_using_every_stage_round_trips(self):
        rule = Rule(
            rule_id="everything",
            pipeline=(
                Read(id="src", table="SecurityEvent",
                     selector="index=main", time_field="TimeGenerated"),
                Filter(id="f", condition=Comparison(
                    "==", FieldRef("EventID"), Literal(4624))),
                Derive(id="d", assignments=(
                    ("Doubled", Arith("*", FieldRef("n"), Literal(Decimal(2)))),
                ), kind="add"),
                Project(id="p", renames=((FieldRef("TimeGenerated"), "ts"),),
                        keeps=(FieldRef("Computer"),)),
                Join(id="j", left="p", right="other",
                     on=((FieldRef("Computer"),
                          FieldRef("Computer", (), "right")),)),
                Aggregate(id="agg",
                          measures=(Measure("count", "n"),
                                    Measure("make_set", "ips", FieldRef("ip"))),
                          keys=(FieldRef("Computer"),)),
                Sort(id="s", keys=((FieldRef("n"), True),), limit=10),
                Distinct(id="dis", keys=(FieldRef("Computer"),)),
                Expand(id="e", field=FieldRef("ips"), into="ip"),
                Limit(id="l", count=5, keep_last=True),
                Emit(id="out", keeps=(FieldRef("Computer"),),
                     dedupe_by=(FieldRef("Computer"),)),
            ),
            bindings=(
                Binding(name="other", pipeline=(Read(id="o", table="U"),)),
            ),
        )
        self.assertEqual(roundtrip(rule), rule)

    def test_a_correlation_stage_round_trips(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="T"),
                Correlation(id="c", parent="src", frequency=5,
                            timeframe=Duration(Decimal(300)),
                            group_by=(FieldRef("srcip"),),
                            count_subject="parent"),
                Emit(id="out"),
            ),
        )
        back = roundtrip(rule).pipeline[1]
        self.assertEqual(back.frequency, 5)
        self.assertEqual(back.timeframe.seconds, Decimal(300))
        self.assertEqual(back.group_by[0].name, "srcip")

    def test_a_project_that_drops_round_trips(self):
        # keeps and drops cannot coexist, so the drop form needs its own test.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="T"),
                Project(id="p", drops=(FieldRef("secret"),)),
                Emit(id="out"),
            ),
        )
        self.assertEqual(roundtrip(rule).pipeline[1].drops[0].name, "secret")

    def test_a_subquery_operand_round_trips(self):
        rule = filter_rule(
            Comparison(
                "in",
                FieldRef("Computer"),
                SubQuery(pipeline=(Read(id="inner", table="U"),), alias="hosts"),
            )
        )
        back = roundtrip(rule).pipeline[1].condition.right
        self.assertIsInstance(back, SubQuery)
        self.assertEqual(back.alias, "hosts")
        self.assertEqual(back.pipeline[0].table, "U")


class EveryExpressionTypeSurvives(unittest.TestCase):
    def test_each_expression_node_round_trips(self):
        cases = {
            "Literal": Comparison("==", FieldRef("a"), Literal("x")),
            "FieldRef": Comparison("==", FieldRef("a", ("b",)), FieldRef("c")),
            "BoolOp": BoolOp("or", (
                Comparison("==", FieldRef("a"), Literal(1)),
                Comparison("==", FieldRef("b"), Literal(2)),
            )),
            "Not": Not(Comparison("==", FieldRef("a"), Literal(1))),
            "Arith": Comparison(
                ">", Arith("-", FieldRef("a"), Literal(Decimal(1))),
                Literal(Decimal(0))),
            "ListExpr": Comparison(
                "in", FieldRef("a"),
                ListExpr((Literal("x"), Literal("y")))),
            "Regex": Comparison(
                "matches", FieldRef("a"),
                Regex("lsass", dialect="posix_extended", nocase=True)),
            "Call": Comparison(
                "==", Call("lower", (FieldRef("a"),), ("ci",)), Literal("x")),
            "Span": Span(FieldRef("a"), Literal(Decimal(1)), Literal(Decimal(9)),
                         low_inclusive=False, high_inclusive=True),
        }
        for name, condition in cases.items():
            with self.subTest(expr=name):
                rule = filter_rule(condition)
                self.assertEqual(roundtrip(rule), rule)

    def test_a_regex_keeps_its_dialect_and_nocase(self):
        # The dialect decides whether the engine will execute it at all, so
        # losing it turns a refusal into a wrong answer.
        rule = filter_rule(
            Comparison("matches", FieldRef("a"),
                       Regex("lsass", dialect="pcre", nocase=True))
        )
        back = roundtrip(rule).pipeline[1].condition.right
        self.assertEqual(back.dialect, "pcre")
        self.assertTrue(back.nocase)


class AnnotationsAndMetadataSurvive(unittest.TestCase):
    def test_annotations_round_trip_including_mitre(self):
        annotations = Annotations(
            title="Credential Access",
            description="LSASS access then NTLM lateral movement",
            severity="high",
            author="soc",
            mitre_attack=(("credential-access", ("T1003", "T1003.001")),),
            references=("https://example.invalid/a",),
            false_positives=("backup agents",),
        )
        rule = filter_rule(
            Comparison("==", FieldRef("a"), Literal(1)), annotations=annotations
        )
        self.assertEqual(roundtrip(rule).annotations, annotations)

    def test_nested_mitre_tuples_stay_tuples(self):
        rule = filter_rule(
            Comparison("==", FieldRef("a"), Literal(1)),
            annotations=Annotations(mitre_attack=(("ta", ("T1", "T2")),)),
        )
        back = roundtrip(rule).annotations.mitre_attack
        self.assertIsInstance(back, tuple)
        self.assertIsInstance(back[0][1], tuple)

    def test_rule_metadata_round_trips(self):
        rule = filter_rule(
            Comparison("==", FieldRef("a"), Literal(1)),
            metadata={"dialect": "sentinel", "language": "KQL", "artifact": "rule"},
        )
        self.assertEqual(roundtrip(rule).metadata["artifact"], "rule")

    def test_an_empty_metadata_dict_stays_empty(self):
        rule = filter_rule(Comparison("==", FieldRef("a"), Literal(1)))
        self.assertEqual(roundtrip(rule).metadata, {})

    def test_a_binding_guard_round_trips(self):
        # A guard is the difference between a definition and a sub-search.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="T"),
                Join(id="j", left="src", right="other",
                     on=((FieldRef("a"),
                          FieldRef("a", (), "right")),)),
                Emit(id="out"),
            ),
            bindings=(
                Binding(
                    name="other",
                    pipeline=(Read(id="o", table="U"),),
                    guard=Comparison("==", FieldRef("ok"), Literal(True)),
                ),
            ),
        )
        self.assertIsNotNone(roundtrip(rule).bindings[0].guard)
        self.assertEqual(roundtrip(rule), rule)


class MalformedPayloadsRefuse(unittest.TestCase):
    """Untrusted input must refuse, never crash. A KeyError reaching the API
    is a 500 where a refusal with a reason belongs."""

    def setUp(self):
        self.rule, _ = lower_kql(USER_RULE)
        self.good = rule_to_dict(self.rule)

    def _refuses(self, payload, code=None):
        with self.assertRaises(Refusal) as caught:
            rule_from_dict(payload)
        if code is not None:
            self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_an_empty_object_is_refused(self):
        self._refuses({})

    def test_a_non_dict_is_refused(self):
        self._refuses([])
        self._refuses("not a rule")

    def test_a_missing_schema_version_is_refused(self):
        # Assuming "current" is how a v1 reader silently mis-reads a v2 rule.
        self._refuses({"rule": self.good["rule"]})

    def test_a_future_schema_version_is_refused_by_name(self):
        payload = dict(self.good)
        payload["schema"] = SCHEMA_VERSION + 1
        exc = self._refuses(payload, "CODEC_SCHEMA_UNSUPPORTED")
        self.assertIn(str(SCHEMA_VERSION), exc.message)

    def test_a_missing_rule_body_is_refused(self):
        self._refuses({"schema": SCHEMA_VERSION})

    def test_an_untagged_value_is_refused(self):
        self._refuses({"schema": SCHEMA_VERSION, "rule": {"rule_id": "x"}})

    def test_a_bare_scalar_where_a_node_belongs_is_refused(self):
        self._refuses({"schema": SCHEMA_VERSION, "rule": 5})

    def test_an_unknown_type_tag_is_refused_and_lists_what_is_known(self):
        exc = self._refuses(
            {"schema": SCHEMA_VERSION, "rule": {"@": "Backdoor"}},
            "CODEC_TYPE_UNKNOWN",
        )
        self.assertIn("Rule", exc.message)

    def test_a_node_missing_a_field_is_refused_rather_than_defaulted(self):
        # Constructing with defaults is how a decoded rule ends up missing a
        # predicate and matching everything.
        payload = json.loads(json.dumps(self.good))
        self.assertEqual(payload["rule"]["pipeline"]["v"][0]["@"], "Read")
        del payload["rule"]["pipeline"]["v"][0]["table"]
        exc = self._refuses(payload, "CODEC_MALFORMED")
        self.assertIn("table", exc.message)

    def test_a_node_with_an_extra_field_is_refused_rather_than_ignored(self):
        payload = json.loads(json.dumps(self.good))
        payload["rule"]["pipeline"]["v"][1]["smuggled"] = {"@": "int", "v": 1}
        self._refuses(payload, "CODEC_MALFORMED")

    def test_a_decimal_sent_as_a_json_number_is_refused(self):
        # By the time it is a JSON number the precision is already gone, so
        # accepting it would be accepting a different threshold.
        self._refuses(
            {"schema": SCHEMA_VERSION,
             "rule": {"@": "Duration", "seconds": {"@": "decimal", "v": 10.5}}},
        )

    def test_a_decimal_that_is_not_a_number_is_refused(self):
        self._refuses(
            {"schema": SCHEMA_VERSION,
             "rule": {"@": "Duration", "seconds": {"@": "decimal", "v": "ten"}}},
        )

    def test_an_unknown_capability_is_refused(self):
        payload = json.loads(json.dumps(self.good))
        payload["rule"]["pipeline"]["v"][0]["capability"]["v"] = "probably_fine"
        self._refuses(payload)

    def test_a_payload_that_decodes_to_something_other_than_a_rule_is_refused(self):
        self._refuses(
            {"schema": SCHEMA_VERSION, "rule": {"@": "int", "v": 3}}
        )

    def test_a_rule_whose_pipeline_has_no_emit_is_refused(self):
        # The IR's own construction refusal has to survive the codec, or the
        # codec becomes a way to build rules the IR forbids.
        payload = json.loads(json.dumps(self.good))
        stages = payload["rule"]["pipeline"]["v"]
        payload["rule"]["pipeline"]["v"] = [
            s for s in stages if s.get("@") != "Emit"
        ]
        self._refuses(payload)

    def test_a_dangling_binding_reference_is_refused(self):
        payload = json.loads(json.dumps(self.good))
        for stage in payload["rule"]["pipeline"]["v"]:
            if stage.get("@") == "Join":
                stage["right"] = {"@": "str", "v": "NoSuchBinding"}
        self._refuses(payload)

    def test_a_deeply_nested_payload_is_refused_not_a_recursion_error(self):
        node: dict = {"@": "Literal", "value": {"@": "int", "v": 1}}
        for _ in range(MAX_DEPTH + 50):
            node = {"@": "Not", "operand": node}
        with self.assertRaises(Refusal) as caught:
            rule_from_dict({"schema": SCHEMA_VERSION, "rule": node})
        self.assertEqual(caught.exception.code, "CODEC_TOO_DEEP")

    def test_text_that_is_not_json_is_refused_with_a_position(self):
        with self.assertRaises(Refusal) as caught:
            rule_from_json("{not json")
        self.assertEqual(caught.exception.code, "CODEC_NOT_JSON")
        self.assertIn("line", caught.exception.message)

    def test_json_text_that_is_not_text_is_refused(self):
        with self.assertRaises(Refusal):
            rule_from_json(b"{}")  # type: ignore[arg-type]


class EncodingRefusals(unittest.TestCase):
    def test_encoding_something_that_is_not_a_rule_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            rule_to_dict("not a rule")  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, "CODEC_NOT_A_RULE")

    def test_a_dataclass_outside_the_allowlist_is_refused(self):
        # Scoper holds a live row of event data. A codec that encoded any
        # dataclass it met would write somebody's logs into the history file.
        rule = filter_rule(
            Comparison("==", FieldRef("a"), Literal(ir.Scoper(row=None)))
        )
        with self.assertRaises(Refusal) as caught:
            rule_to_dict(rule)
        self.assertEqual(caught.exception.code, "CODEC_TYPE_NOT_CARRIED")

    def test_an_unencodable_value_is_refused_by_type_name(self):
        rule = filter_rule(Comparison("==", FieldRef("a"), Literal(object())))
        with self.assertRaises(Refusal) as caught:
            rule_to_dict(rule)
        self.assertEqual(caught.exception.code, "CODEC_VALUE_NOT_ENCODABLE")
        self.assertIn("object", caught.exception.message)


class CoverageIsProvable(unittest.TestCase):
    """The test that matters in a year.

    Everything above checks the codec as it is. This one fails when an IR node
    is added and the codec is not, which is the failure that would otherwise
    reach a user as a rule with a stage quietly missing. An ordered-sequence
    node is already planned, so this will fire.
    """

    def test_every_expression_type_is_carried(self):
        missing = [t.__name__ for t in ir.EXPR_TYPES if t not in KNOWN_TYPES]
        self.assertEqual(
            missing, [],
            f"these expression types have no codec support: {missing}. A rule "
            f"using one would encode as a refusal, or worse, silently lose it.",
        )

    def test_every_stage_type_is_carried(self):
        missing = [t.__name__ for t in ir.NODE_TYPES if t not in KNOWN_TYPES]
        self.assertEqual(missing, [], f"these stage types have no codec: {missing}")

    def test_span_is_carried_despite_being_appended_late(self):
        # ir.py defines Span AFTER EXPR_TYPES and re-binds the tuple at the
        # bottom of the module. A codec that captured EXPR_TYPES at the wrong
        # moment would miss exactly one node -- the temporal correlation one.
        self.assertIn(Span, ir.EXPR_TYPES)
        self.assertIn(Span, KNOWN_TYPES)

    def test_the_assembly_types_are_carried(self):
        for required in (Window, Measure, Binding, Annotations, Rule,
                         Duration, Seq):
            with self.subTest(type=required.__name__):
                self.assertIn(required, KNOWN_TYPES)

    def test_every_carried_type_is_a_dataclass_with_fields(self):
        # The encoder walks dataclasses.fields(). A non-dataclass in the
        # allowlist would encode as an empty object and decode as a default.
        for carried in KNOWN_TYPES:
            with self.subTest(type=carried.__name__):
                self.assertTrue(dataclasses.is_dataclass(carried))

    def test_no_two_carried_types_share_a_name(self):
        # The tag is the class name, so a collision would decode as the wrong
        # type without any error at all.
        names = [t.__name__ for t in KNOWN_TYPES]
        self.assertEqual(len(names), len(set(names)))


if __name__ == "__main__":
    unittest.main()
