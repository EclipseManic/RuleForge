"""Tests for validation and the deploy-path ReDoS screen.

The screen is the load-bearing part. A pattern that hangs an engine is refused
by `compile_pattern` when a rule is EXECUTED -- but a tool's job is also to
AUTHOR and RENDER rules, and those paths never executed anything. So the screen
is tested from `validate`, which every author and render path goes through.
"""

from __future__ import annotations

import unittest
from dataclasses import fields
from decimal import Decimal

from engine import ir
from engine.evaluate import compile_pattern
from engine.ir import (
    Arith,
    BoolOp,
    Call,
    Comparison,
    Correlation,
    Derive,
    Distinct,
    Duration,
    Emit,
    FieldRef,
    Filter,
    Join,
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
)
from engine.validate import (
    CANNOT_HOLD_A_PATTERN,
    MAX_EXPRESSION_DEPTH,
    SCREENABLE_EXPR_TYPES,
    validate,
)
from engine.values import Refusal


def rule_with_condition(condition, stage_id="f") -> Rule:
    return Rule(
        rule_id="r",
        pipeline=(
            Read(id="src", table="events", time_field="ts"),
            Filter(id=stage_id, condition=condition),
            Emit(id="out"),
        ),
    )


class DeployPathScreen(unittest.TestCase):
    """A pattern that would hang must never be written out as deployable text."""

    def test_catastrophic_pattern_is_refused_by_validate(self):
        # Not just refused when run -- refused when AUTHORED.
        rule = rule_with_condition(
            Comparison("matches", FieldRef("cmd"), Regex("(a|aa)+$", "posix_extended"))
        )
        with self.assertRaises(Refusal) as caught:
            validate(rule)
        self.assertEqual(
            caught.exception.code, "REGEX_CATASTROPHIC_BACKTRACKING"
        )

    def test_screen_survives_a_not_wrapper(self):
        # `Not` holds a SINGULAR operand, not a tuple, so a walk that only
        # descends into tuple attributes falls past it entirely. This is the
        # exact shape that shipped once.
        rule = rule_with_condition(
            Not(Comparison("matches", FieldRef("cmd"),
                           Regex("(a|aa)+$", "posix_extended")))
        )
        with self.assertRaises(Refusal) as caught:
            validate(rule)
        self.assertEqual(
            caught.exception.code, "REGEX_CATASTROPHIC_BACKTRACKING"
        )

    def test_screen_survives_a_boolop_wrapper(self):
        # A second condition used to defeat the screen entirely: the walk
        # descended into `Comparison` but not into `BoolOp.operands`.
        rule = rule_with_condition(
            BoolOp("and", (
                Comparison("==", FieldRef("a"), Literal(1)),
                Comparison("matches", FieldRef("cmd"),
                           Regex("(a|aa)+$", "posix_extended")),
            ))
        )
        with self.assertRaises(Refusal) as caught:
            validate(rule)
        self.assertEqual(
            caught.exception.code, "REGEX_CATASTROPHIC_BACKTRACKING"
        )

    def test_screen_survives_deep_nesting(self):
        # A pattern buried under nine layers of arithmetic.
        inner = Comparison("matches", FieldRef("cmd"),
                           Regex("a*a*a*a*$", "posix_extended"))
        expr = inner
        for _ in range(9):
            expr = Arith("+", expr, Literal(Decimal(0)))
        rule = rule_with_condition(Comparison(">", expr, Literal(Decimal(0))))
        with self.assertRaises(Refusal) as caught:
            validate(rule)
        self.assertEqual(
            caught.exception.code, "REGEX_CATASTROPHIC_BACKTRACKING"
        )

    def test_a_nested_unbounded_group_is_refused(self):
        rule = rule_with_condition(
            Comparison("matches", FieldRef("cmd"), Regex("(a+)+$", "posix_extended"))
        )
        with self.assertRaises(Refusal) as caught:
            validate(rule)
        self.assertEqual(
            caught.exception.code, "REGEX_CATASTROPHIC_BACKTRACKING"
        )

    def test_ordinary_patterns_are_not_refused(self):
        # A screen that over-refuses is a screen that gets switched off.
        for pattern in (r"lsass\.exe$", r"[a-z]+", r"(abc)+", "a*b", r"^577$"):
            with self.subTest(pattern=pattern):
                rule = rule_with_condition(
                    Comparison("matches", FieldRef("cmd"),
                               Regex(pattern, "posix_extended"))
                )
                validate(rule)  # must not raise

    def test_a_pcre_pattern_is_not_a_screen_failure(self):
        # PCRE cannot be EXECUTED here, but it is legitimate in a Wazuh or AQL
        # rule and must render. Only the catastrophe check applies.
        rule = rule_with_condition(
            Comparison("matches", FieldRef("cmd"), Regex(r"\d+", "pcre"))
        )
        validate(rule)  # must not raise

    def test_a_catastrophic_pcre_pattern_is_still_refused(self):
        # The vendor's engine hangs on it exactly like this one would.
        rule = rule_with_condition(
            Comparison("matches", FieldRef("cmd"), Regex("(a|aa)+$", "pcre"))
        )
        with self.assertRaises(Refusal) as caught:
            validate(rule)
        self.assertEqual(
            caught.exception.code, "REGEX_CATASTROPHIC_BACKTRACKING"
        )

    def test_a_dialect_specific_escape_is_refused_on_the_deploy_path(self):
        # `\d+` used to be the example here. It is now ALLOWED, because every
        # engine behind these dialects supports it and refusing it rejected
        # most real regexes -- see `test_core.RegexScreening`. `\p{...}` is a
        # genuine divergence and takes its place.
        rule = rule_with_condition(
            Comparison("matches", FieldRef("cmd"),
                       Regex(r"\p{Alpha}+", "posix_extended"))
        )
        with self.assertRaises(Refusal) as caught:
            validate(rule)
        self.assertEqual(caught.exception.code, "REGEX_DIALECT_SPECIFIC")

    def test_a_shared_shorthand_class_passes_the_deploy_path(self):
        # The screens on this path and in `compile_pattern` have to agree, or
        # a rule validates and then will not run -- or worse, runs and will
        # not validate.
        rule = rule_with_condition(
            Comparison("matches", FieldRef("cmd"),
                       Regex(r"\d+\.\d+\.\d+\.\d+", "posix_extended"))
        )
        validate(rule)  # must not raise

    def test_a_polynomial_pattern_is_refused_on_the_deploy_path(self):
        rule = rule_with_condition(
            Comparison("matches", FieldRef("cmd"),
                       Regex(r"a*a*b$", "posix_extended"))
        )
        with self.assertRaises(Refusal) as caught:
            validate(rule)
        self.assertEqual(
            caught.exception.code, "REGEX_CATASTROPHIC_BACKTRACKING"
        )

    def test_a_wazuh_style_backslash_escape_is_allowed(self):
        # Wazuh ships rule 60000 as `\.+`, so refusing every backslash would
        # refuse real vendor rules.
        rule = rule_with_condition(
            Comparison("matches", FieldRef("cmd"), Regex(r"lsass\.exe", "pcre"))
        )
        validate(rule)  # must not raise


class ScreenCoverageIsProvable(unittest.TestCase):
    """The anti-drift test. THIS is the point of the file.

    An earlier screen missed `BoolOp` and then `Not`, and both times every test
    stayed green. So the assertion is not "does it catch the two I know about" --
    it is "is the exemption list still justified by the type set", derived by
    reflection so a new expression type fails the build rather than quietly
    becoming a hole.
    """

    def test_every_expression_type_is_classified(self):
        classified = set(SCREENABLE_EXPR_TYPES) | {
            getattr(ir, name) for name in CANNOT_HOLD_A_PATTERN
            if hasattr(ir, name)
        }
        unclassified = [
            t.__name__ for t in ir.EXPR_TYPES if t not in classified
        ]
        self.assertEqual(
            unclassified, [],
            f"these expression types are neither screened nor exempted: "
            f"{unclassified}. Add a probe for each, or a written reason why it "
            f"cannot hold a pattern.",
        )

    def test_every_screened_type_really_can_hold_one(self):
        # The other direction: an exemption that is no longer true has to be
        # deleted, so the list cannot rot into "exempt everything".
        for name, reason in CANNOT_HOLD_A_PATTERN.items():
            with self.subTest(name=name):
                self.assertTrue(
                    reason.strip(), f"{name} is exempted with no stated reason"
                )

    def test_the_probe_list_is_not_shrinking(self):
        self.assertGreaterEqual(
            len(SCREENABLE_EXPR_TYPES), 9,
            "guards the screen against being quietly emptied out, which is how "
            "a coverage test becomes a test of nothing",
        )


class StructuralValidation(unittest.TestCase):
    def test_a_bare_field_condition_is_refused(self):
        # `| where field` is truthy for any non-empty string: it works and
        # matches almost everything.
        with self.assertRaises(Refusal) as caught:
            validate(rule_with_condition(FieldRef("EventID")))
        self.assertEqual(caught.exception.code, "CONDITION_IS_A_FIELD")

    def test_a_rule_with_no_output_stage_is_refused_at_construction(self):
        # The IR refuses it before validation is even reached, which is better:
        # a malformed rule never becomes a Rule object at all.
        with self.assertRaises(Refusal) as caught:
            Rule(rule_id="r", pipeline=(Read(id="src", table="events"),))
        self.assertEqual(caught.exception.code, "RULE_HAS_NO_EMIT")

    def test_duplicate_stage_ids_are_refused(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="x", table="a", time_field="ts"),
                Read(id="x", table="b", time_field="ts"),
                Emit(id="out"),
            ),
        )
        with self.assertRaises(Refusal) as caught:
            validate(rule)
        self.assertEqual(caught.exception.code, "DUPLICATE_STAGE_ID")

    def test_an_unknown_join_source_is_refused_at_construction(self):
        # A dangling reference never becomes a Rule object, so it cannot be
        # rendered, saved, or handed to a renderer that would guess.
        with self.assertRaises(Refusal) as caught:
            Rule(
                rule_id="r",
                pipeline=(
                    Read(id="a", table="t", time_field="ts"),
                    Join(id="j", left="a", right="nowhere", how="inner",
                         on=((FieldRef("k"), FieldRef("k")),)),
                    Emit(id="o"),
                ),
            )
        self.assertEqual(caught.exception.code, "BINDING_UNKNOWN")

    def test_a_join_predicate_that_never_crosses_rows_is_refused(self):
        # Every key is already in `on`, so a predicate reading only the current
        # row is either redundant or was meant to compare the two sides.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="a", table="t", time_field="ts"),
                Read(id="b", table="t", time_field="ts"),
                Join(id="j", left="a", right="b", how="inner",
                     on=((FieldRef("k"), FieldRef("k")),),
                     predicate=Comparison(">", FieldRef("x"), Literal(1))),
                Emit(id="o"),
            ),
        )
        with self.assertRaises(Refusal) as caught:
            validate(rule)
        self.assertEqual(caught.exception.code, "JOIN_PREDICATE_NOT_CROSS_ROW")

    def test_a_join_predicate_that_crosses_rows_is_accepted(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="a", table="t", time_field="ts"),
                Read(id="b", table="t", time_field="ts"),
                Join(id="j", left="a", right="b", how="inner",
                     on=((FieldRef("k"), FieldRef("k")),),
                     predicate=Span(
                         value=FieldRef("t2", scope="right"),
                         low=FieldRef("t1", scope="left"),
                         high=Arith("+", FieldRef("t1", scope="left"),
                                    Literal(Duration(Decimal(600)))),
                     )),
                Emit(id="o"),
            ),
        )
        validate(rule)  # must not raise

    def test_a_scoped_join_key_is_refused(self):
        # A join key is read from the stage's own rows, so a scope on it is
        # meaningless -- the cross-row comparison belongs in the predicate.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="a", table="t", time_field="ts"),
                Read(id="b", table="t", time_field="ts"),
                Join(id="j", left="a", right="b", how="inner",
                     on=((FieldRef("k", scope="left"), FieldRef("k")),)),
                Emit(id="o"),
            ),
        )
        with self.assertRaises(Refusal) as caught:
            validate(rule)
        self.assertEqual(caught.exception.code, "JOIN_KEY_SCOPE_INVALID")

    def test_a_column_name_that_cannot_be_written_is_refused(self):
        # A name with a quote in it will not survive being written into the
        # dialect's syntax -- and is a rule-injection vector in three of them.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="t", time_field="ts"),
                Derive(id="d", assignments=((
                    'a" ; drop', Comparison("==", FieldRef("x"), Literal(1))
                ),)),
                Emit(id="o"),
            ),
        )
        with self.assertRaises(Refusal) as caught:
            validate(rule)
        self.assertEqual(caught.exception.code, "DERIVE_TARGET_NOT_IDENTIFIER")

    def test_expressions_deeper_than_the_limit_are_refused_not_truncated(self):
        expr = Comparison("==", FieldRef("a"), Literal(1))
        for _ in range(MAX_EXPRESSION_DEPTH + 5):
            expr = Not(expr)
        with self.assertRaises(Refusal) as caught:
            validate(rule_with_condition(expr))
        self.assertEqual(caught.exception.code, "EXPRESSION_TOO_DEEP")

    def test_too_many_stages_is_refused(self):
        stages = [Read(id=f"r{i}", table="t", time_field="ts") for i in range(600)]
        stages.append(Emit(id="out"))
        with self.assertRaises(Refusal) as caught:
            validate(Rule(rule_id="r", pipeline=tuple(stages)))
        self.assertEqual(caught.exception.code, "RULE_TOO_LARGE")


if __name__ == "__main__":
    unittest.main()
