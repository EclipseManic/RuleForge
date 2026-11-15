"""Tests for the value model and the scoped evaluator.

These are the load-bearing semantics. Everything else in the tool is
expendable; if `absent == ""` ever becomes True, or a `left.` reference ever
falls back to the current row, the tool is worse than useless -- it will
confidently report a match count that no deployment reproduces.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from engine.evaluate import Context, Row, Scope, compile_pattern, eval_expr
from engine.ir import (
    Arith,
    Call,
    Comparison,
    Duration,
    FieldRef,
    ListExpr,
    Literal,
    Not,
    Regex,
    Span,
)
from engine.values import (
    ABSENT,
    UNDECIDED,
    Capability,
    Refusal,
    Seq,
    and_,
    compare,
    coalesce,
    duration_seconds,
    has_value,
    not_,
    or_,
    type_name,
)


def row(**values) -> Row:
    return Row(dict(values))


def scope(current=None, left=None, right=None) -> Scope:
    return Scope(current=current, left=left, right=right)


class AbsentIsNotNullIsNotEmpty(unittest.TestCase):
    """The three states, kept three."""

    def test_absent_is_not_equal_to_empty(self):
        # THE test. A missing field compared against "" must not be True. If this
        # ever passes, a rule matches every event that lacks the field.
        self.assertIs(compare(ABSENT, "==", "").value, UNDECIDED)

    def test_absent_is_not_equal_to_none(self):
        self.assertIs(compare(ABSENT, "==", None).value, UNDECIDED)

    def test_absent_is_not_equal_to_zero(self):
        self.assertIs(compare(ABSENT, "==", 0).value, UNDECIDED)

    def test_empty_string_equals_empty_string(self):
        self.assertIs(compare("", "==", "").value, True)

    def test_null_equals_null(self):
        self.assertIs(compare(None, "==", None).value, True)

    def test_null_against_a_value_is_undecided(self):
        self.assertIs(compare(None, "==", "x").value, UNDECIDED)

    def test_zero_is_a_value(self):
        self.assertIs(compare(0, "==", 0).value, True)
        self.assertTrue(has_value(0))

    def test_false_is_a_value(self):
        self.assertIs(compare(False, "==", False).value, True)
        self.assertTrue(has_value(False))

    def test_empty_string_is_a_value(self):
        self.assertTrue(has_value(""))

    def test_absent_null_undecided_are_not_values(self):
        for value in (ABSENT, None, UNDECIDED):
            self.assertFalse(has_value(value))

    def test_type_names_are_for_humans(self):
        self.assertEqual(type_name(ABSENT), "absent")
        self.assertEqual(type_name(None), "null")
        self.assertEqual(type_name(""), "string")
        self.assertEqual(type_name(Decimal(1)), "number")


class KleeneLogic(unittest.TestCase):
    def test_not_undecided_is_undecided(self):
        # The whole reason this tool exists.
        self.assertIs(not_(UNDECIDED), UNDECIDED)

    def test_not_true_is_false(self):
        self.assertIs(not_(True), False)

    def test_false_dominates_and(self):
        self.assertIs(and_(UNDECIDED, False), False)

    def test_true_dominates_or(self):
        self.assertIs(or_(UNDECIDED, True), True)

    def test_undecided_propagates_through_and(self):
        self.assertIs(and_(UNDECIDED, True), UNDECIDED)

    def test_undecided_propagates_through_or(self):
        self.assertIs(or_(UNDECIDED, False), UNDECIDED)

    def test_all_decided_is_decided(self):
        self.assertIs(and_(True, True), True)
        self.assertIs(or_(False, False), False)


class Coalesce(unittest.TestCase):
    def test_skips_absent_and_null(self):
        self.assertEqual(coalesce(ABSENT, None, "x"), "x")

    def test_never_invents_a_default(self):
        # Returning None here would make a rule quietly match something.
        self.assertIs(coalesce(ABSENT, None), ABSENT)

    def test_empty_string_is_a_real_value(self):
        self.assertEqual(coalesce(ABSENT, ""), "")


class Numbers(unittest.TestCase):
    def test_float_noise_does_not_break_equality(self):
        # 0.1 + 0.2 != 0.3 in binary floating point, so a naive engine reports a
        # rule as non-matching when the analyst's arithmetic says it matches.
        total = Decimal(str(0.1)) + Decimal(str(0.2))
        self.assertEqual(total, Decimal("0.3"))

    def test_numeric_strings_are_coerced(self):
        # SIEM payloads carry "4624" as often as 4624.
        self.assertIs(compare("4624", "==", 4624).value, True)

    def test_bool_is_not_a_number(self):
        # bool subclasses int, so without this True satisfies a numeric threshold.
        self.assertIs(compare(True, "==", 1).value, UNDECIDED)

    def test_mixed_kinds_cannot_be_ordered(self):
        self.assertIs(compare("abc", ">", 5).value, UNDECIDED)


class Durations(unittest.TestCase):
    def test_parses_vendor_spellings(self):
        self.assertEqual(duration_seconds("10m").seconds, Decimal(600))
        self.assertEqual(duration_seconds("30 seconds").seconds, Decimal(30))
        self.assertEqual(duration_seconds("2h").seconds, Decimal(7200))
        self.assertEqual(duration_seconds("500ms").seconds, Decimal("0.5"))

    def test_refuses_what_it_cannot_parse(self):
        self.assertIsNone(duration_seconds("soon"))
        self.assertIsNone(duration_seconds("1h30m"))


class ScopedReferences(unittest.TestCase):
    """Cross-row comparison -- what makes correlation expressible."""

    def setUp(self):
        self.left = row(Computer="WS1", Account="svc", LSASSTime=Decimal(1000))
        self.right = row(Computer="WS1", Account="svc", LoginTime=Decimal(1300))
        self.far = row(Computer="WS1", Account="svc", LoginTime=Decimal(99999))

    def _span(self):
        return Span(
            value=FieldRef("LoginTime", scope="right"),
            low=FieldRef("LSASSTime", scope="left"),
            high=Arith("+", FieldRef("LSASSTime", scope="left"),
                       Literal(Duration(Decimal(600)))),
        )

    def test_span_across_two_rows_with_arithmetic_bound(self):
        # The KQL `where LoginTime between (LSASSTime .. LSASSTime + 10m)` shape.
        ctx = Context()
        self.assertIs(
            eval_expr(self._span(), scope(self.left, self.left, self.right), ctx),
            True,
        )

    def test_span_rejects_a_row_outside_the_window(self):
        ctx = Context()
        self.assertIs(
            eval_expr(self._span(), scope(self.left, self.left, self.far), ctx),
            False,
        )

    def test_scoped_reference_outside_a_join_is_refused(self):
        # NOT silently read from the current row. Falling back would make a
        # correlation rule compare a field with itself, which is always false
        # for a positive window and always true for a negative one.
        with self.assertRaises(Refusal) as caught:
            eval_expr(
                Comparison(">", FieldRef("a", scope="left"), Literal(1)),
                scope(row(a=5)),
                Context(),
            )
        self.assertEqual(caught.exception.code, "SCOPE_NOT_AVAILABLE")

    def test_both_sides_read_different_rows(self):
        ctx = Context()
        result = eval_expr(
            Comparison("==", FieldRef("Account", scope="left"),
                       FieldRef("Account", scope="right")),
            scope(self.left, self.left, self.right),
            ctx,
        )
        self.assertIs(result, True)

    def test_field_path_parsing_with_scope_prefix(self):
        ref = FieldRef.parse("right.win.eventdata.Image")
        self.assertEqual(ref.scope, "right")
        self.assertEqual(ref.name, "win")
        self.assertEqual(ref.full, "win.eventdata.Image")

    def test_scoped_display_keeps_the_prefix(self):
        self.assertEqual(FieldRef("t", scope="left").scoped, "left.t")
        self.assertEqual(FieldRef("t").scoped, "t")


class ApplianceFunctions(unittest.TestCase):
    """DECLARED_ONLY, never a guessed answer."""

    def test_qidname_is_not_evaluated_locally(self):
        ctx = Context()
        result = eval_expr(
            Call("qidname", (FieldRef("qid"),)), scope(row(qid=1)), ctx
        )
        self.assertIs(result, UNDECIDED)
        self.assertEqual(ctx.caveats[-1].code, "DECLARED_ONLY")
        self.assertIs(ctx.caveats[-1].capability, Capability.DECLARED_ONLY)

    def test_local_function_is_evaluated(self):
        ctx = Context()
        result = eval_expr(
            Call("cidr_contains", (Literal("10.0.0.5"), Literal("10.0.0.0/8"))),
            scope(),
            ctx,
        )
        self.assertIs(result, True)
        self.assertEqual(ctx.caveats, [])

    def test_cidr_is_containment_not_prefix(self):
        ctx = Context()
        # The property `in` on strings gets wrong: "192.168" does not start with
        # "10." so a prefix test happens to agree here, but "10.0.0.5" IS a prefix
        # of "10.0.0.55" and containment must not be.
        self.assertIs(
            eval_expr(Call("cidr_contains",
                           (Literal("10.0.0.55"), Literal("10.0.0.0/8"))),
                      scope(), ctx),
            True,
        )
        self.assertIs(
            eval_expr(Call("cidr_contains",
                           (Literal("192.168.1.1"), Literal("10.0.0.0/8"))),
                      scope(), ctx),
            False,
        )

    def test_cidr_across_families_is_undecided(self):
        ctx = Context()
        result = eval_expr(
            Call("cidr_contains", (Literal("10.0.0.1"), Literal("fe80::/10"))),
            scope(), ctx,
        )
        self.assertIs(result, UNDECIDED)

    def test_unknown_function_is_refused_by_name(self):
        with self.assertRaises(Refusal) as caught:
            eval_expr(Call("frobnicate", (Literal(1),)), scope(), Context())
        self.assertEqual(caught.exception.code, "FUNCTION_UNKNOWN")


class PatternOperators(unittest.TestCase):
    def test_like_is_anchored(self):
        # `lsass%` must NOT match `not-lsass-helper.exe`. An unanchored
        # implementation is right about `%lsass%` and wrong about this, which is
        # how a rule ends up matching a helper binary.
        ctx = Context()
        result = eval_expr(
            Comparison("like", FieldRef("p"), Regex("lsass%", "posix_extended")),
            scope(row(p="not-lsass-helper.exe")), ctx,
        )
        self.assertIs(result, False)

    def test_like_leading_wildcard_matches(self):
        ctx = Context()
        result = eval_expr(
            Comparison("like", FieldRef("p"), Regex("%lsass%", "posix_extended")),
            scope(row(p=r"c:\windows\lsass.exe")), ctx,
        )
        self.assertIs(result, True)

    def test_like_is_case_sensitive(self):
        ctx = Context()
        result = eval_expr(
            Comparison("like", FieldRef("p"), Regex("lsass", "posix_extended")),
            scope(row(p="LSASS.EXE")), ctx,
        )
        self.assertIs(result, False)

    def test_ilike_is_case_insensitive(self):
        ctx = Context()
        result = eval_expr(
            Comparison("ilike", FieldRef("p"), Regex("%lsass%", "posix_extended")),
            scope(row(p="LSASS.EXE")), ctx,
        )
        self.assertIs(result, True)

    def test_pcre_is_refused_rather_than_run_with_re(self):
        ctx = Context()
        result = eval_expr(
            Comparison("matches", FieldRef("p"), Regex(r"\d+", "pcre")),
            scope(row(p="123")), ctx,
        )
        self.assertIs(result, UNDECIDED)
        self.assertEqual(ctx.caveats[-1].code, "REGEX_NOT_EXECUTABLE")

    def test_posix_extended_runs(self):
        ctx = Context()
        result = eval_expr(
            Comparison("matches", FieldRef("p"), Regex(r"lsass\.exe$", "posix_extended")),
            scope(row(p="/usr/bin/lsass.exe")), ctx,
        )
        self.assertIs(result, True)

    # -- LIKE against a plain Literal, which is the shape the dialects
    #    actually produce. Every test above hands LIKE a `Regex` node, and
    #    that is why this gap survived: a LIKE pattern is a GLOB, not a
    #    regex, so `qradar.py`, `splunk.py` and `kql.py` all lower
    #    `username LIKE '%adm%'` with a `Literal` on the right. Only the
    #    Regex branch handled the operator, so a literal pattern fell through
    #    to generic equality and asked whether the subject equalled the seven
    #    characters `%adm%` -- False for every row. The rule reported a
    #    confident no_match and never fired, in three dialects at once.

    def test_like_against_a_literal_pattern_matches(self):
        ctx = Context()
        result = eval_expr(
            Comparison("like", FieldRef("u"), Literal("%adm%")),
            scope(row(u="badmin")), ctx,
        )
        self.assertIs(
            result, True,
            "a LIKE whose pattern is a Literal silently evaluated as string "
            "equality, so the rule never fired.",
        )

    def test_like_against_a_literal_is_still_anchored(self):
        ctx = Context()
        result = eval_expr(
            Comparison("like", FieldRef("u"), Literal("adm%")),
            scope(row(u="badmin")), ctx,
        )
        self.assertIs(result, False)

    def test_ilike_against_a_literal_folds_case(self):
        # Downgraded to a case-sensitive test this stops matching the events
        # the rule was written for.
        ctx = Context()
        result = eval_expr(
            Comparison("ilike", FieldRef("u"), Literal("%ADM%")),
            scope(row(u="badmin")), ctx,
        )
        self.assertIs(result, True)

    def test_a_negated_like_is_inverted(self):
        # `negate` is data on the node. Ignoring it inverts the detection.
        ctx = Context()
        result = eval_expr(
            Comparison("like", FieldRef("u"), Literal("%adm%"), negate=True),
            scope(row(u="badmin")), ctx,
        )
        self.assertIs(result, False)

    def test_like_underscore_matches_one_character(self):
        ctx = Context()
        self.assertIs(
            eval_expr(
                Comparison("like", FieldRef("u"), Literal("a_c")),
                scope(row(u="abc")), ctx,
            ),
            True,
        )
        self.assertIs(
            eval_expr(
                Comparison("like", FieldRef("u"), Literal("a_c")),
                scope(row(u="abbc")), ctx,
            ),
            False,
        )

    def test_like_over_an_absent_field_is_undecided_not_false(self):
        # An absent field has no answer to "does it look like this", and
        # deciding it False would make the rule match a different set of
        # events than the one written.
        ctx = Context()
        result = eval_expr(
            Comparison("like", FieldRef("missing"), Literal("%adm%")),
            scope(row(u="badmin")), ctx,
        )
        self.assertIs(result, UNDECIDED)
        self.assertEqual(ctx.caveats[-1].code, "COMPARISON_UNDECIDABLE")

    # -- An escaped wildcard is a LITERAL. `qradar.py` and `crowdstrike.py`
    #    both escape a `%` or `_` that came from data, because neither
    #    character is special in AQL or FQL and an unescaped one would widen
    #    the test here. The escape was then passed through as a backslash
    #    FOLLOWED by a live wildcard, so `100\%` meant "100, a backslash, then
    #    anything" -- matching neither `100%` nor anything else a rule sees.
    #    Every escaped pattern from those two dialects silently matched
    #    nothing.

    def test_an_escaped_percent_is_a_literal_percent(self):
        ctx = Context()
        self.assertIs(
            eval_expr(
                Comparison("like", FieldRef("a"), Literal(r"100\%")),
                scope(row(a="100%")), ctx,
            ),
            True,
        )

    def test_an_escaped_percent_is_not_a_wildcard(self):
        ctx = Context()
        self.assertIs(
            eval_expr(
                Comparison("like", FieldRef("a"), Literal(r"100\%")),
                scope(row(a="100 and more")), ctx,
            ),
            False,
        )

    def test_an_escaped_underscore_is_a_literal_underscore(self):
        ctx = Context()
        self.assertIs(
            eval_expr(
                Comparison("like", FieldRef("a"), Literal(r"a\_c")),
                scope(row(a="a_c")), ctx,
            ),
            True,
        )
        self.assertIs(
            eval_expr(
                Comparison("like", FieldRef("a"), Literal(r"a\_c")),
                scope(row(a="abc")), ctx,
            ),
            False,
        )

    def test_an_escaped_backslash_is_a_literal_backslash(self):
        # Windows paths are the common case, so this is not an edge case.
        ctx = Context()
        self.assertIs(
            eval_expr(
                Comparison("like", FieldRef("p"), Literal(r"%\\lsass.exe")),
                scope(row(p=r"c:\windows\lsass.exe")), ctx,
            ),
            True,
        )


class RegexScreening(unittest.TestCase):
    def test_pcre_refused_at_compile(self):
        with self.assertRaises(Refusal) as caught:
            compile_pattern("pcre", "abc")
        self.assertEqual(caught.exception.code, "REGEX_NOT_EXECUTABLE")

    def test_posix_basic_refused_at_compile(self):
        # In BRE, + ? { | ( ) are LITERALS, so a partial translation returns
        # confidently wrong booleans.
        with self.assertRaises(Refusal) as caught:
            compile_pattern("posix_basic", "abc+")
        self.assertEqual(caught.exception.code, "REGEX_NOT_EXECUTABLE")

    def test_catastrophic_alternation_refused(self):
        with self.assertRaises(Refusal) as caught:
            compile_pattern("posix_extended", "(a|aa)+$")
        self.assertEqual(caught.exception.code, "REGEX_CATASTROPHIC_BACKTRACKING")

    def test_nested_unbounded_group_refused(self):
        # (a+)+ is the canonical exponential shape.
        with self.assertRaises(Refusal) as caught:
            compile_pattern("posix_extended", "(a+)+$")
        self.assertEqual(caught.exception.code, "REGEX_CATASTROPHIC_BACKTRACKING")

    def test_many_unbounded_quantifiers_refused_without_parentheses(self):
        # Twelve characters, no grouping. A detector that only looks INSIDE
        # groups misses this entirely.
        with self.assertRaises(Refusal) as caught:
            compile_pattern("posix_extended", "a*a*a*a*$")
        self.assertEqual(caught.exception.code, "REGEX_CATASTROPHIC_BACKTRACKING")

    def test_polynomial_patterns_are_refused_too(self):
        # This test previously asserted the OPPOSITE: that `a*a*b$` is allowed
        # because it is polynomial rather than exponential, and that refusing
        # it would be "the over-refusal that gets a ReDoS screen disabled".
        #
        # The argument against over-refusal is right; the conclusion was not.
        # O(n^2) is survivable on a short string and is not survivable on the
        # inputs this domain actually carries: a Windows command line may be
        # 32,000 characters, and `a*a*b$` against one is a billion steps in an
        # indexer. The refusal message has always claimed to catch exactly
        # this shape.
        #
        # The over-refusal worry is answered by measurement rather than by
        # loosening the rule -- `test_ordinary_patterns_are_not_refused` below
        # now covers fourteen realistic patterns, including the IPv4,
        # base64-tail and email shapes the old thresholds rejected.
        for pattern in (r"a*a*b$", r"a+a+b$", r"[a-z]*[a-z]*$",
                        r".*.*x$", r"a*.*b$", r"[a-z]*[a-m]*$"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(Refusal) as caught:
                    compile_pattern("posix_extended", pattern)
                self.assertEqual(
                    caught.exception.code, "REGEX_CATASTROPHIC_BACKTRACKING"
                )

    def test_the_old_detector_could_not_see_that_shape(self):
        # Why it was missed rather than allowed on purpose.
        # `_adjacent_quantifiers` counted quantifiers with no ATOM between
        # them, and in `a*a*` the second `a` resets the run -- so every
        # polynomial pattern scored 1, and so did every safe one. The
        # threshold was `> 2`, which nothing of this shape could reach.
        from engine.evaluate import _adjacent_quantifiers, _overlapping_run

        self.assertEqual(_adjacent_quantifiers(r"a*a*b$"), 1)
        self.assertIsNotNone(_overlapping_run(r"a*a*b$"))

    def test_alternation_does_not_count_as_adjacency(self):
        # `a*|b*` is two alternatives, not two quantifiers in sequence.
        # Treating it as the latter refuses an ordinary pattern.
        self.assertIsNotNone(compile_pattern("posix_extended", r"a*|b*"))

    def test_ordinary_patterns_are_not_refused(self):
        # A ReDoS screen that over-refuses is a screen nobody turns off. This
        # list is the evidence for the stricter rule above: every one of these
        # is a shape that appears in real rulesets, and the last four were
        # REFUSED by the previous thresholds.
        for pattern in (
            r"lsass\.exe$", r"[a-z]+", r"(abc)+", "a*b", r"^577$",
            r"a.*b.*c$", r"(foo|bar)baz", r"cmd\.exe.*whoami",
            r"^[a-z]+@[a-z]+\.[a-z]+$", r"^[A-Za-z_][A-Za-z0-9_]*$",
            r"\d+\.\d+\.\d+\.\d+",          # IPv4: four unbounded, all anchored
            r"[0-9]{1,3}\.[0-9]{1,3}$",     # a bounded repeat
            r"[A-Za-z0-9+/]+={0,2}$",       # a base64 tail
            r"powershell.*-enc",
        ):
            with self.subTest(pattern=pattern):
                self.assertIsNotNone(
                    compile_pattern("posix_extended", pattern)
                )

    def test_the_shared_shorthand_classes_are_allowed(self):
        # This test previously asserted that `\d+` is REFUSED, on the reasoning
        # that a backslash escape is dialect-specific. For these particular
        # escapes it is not: `\d`, `\w`, `\s`, their negations and `\b` are
        # supported by PCRE, PCRE2, RE2, Java and .NET -- every engine behind
        # the eight dialects here. Refusing them rejected
        # `\d+\.\d+\.\d+\.\d+` and most of the regexes in any real ruleset,
        # which is how a screen stops being a screen.
        for pattern in (r"\d+", r"\w+", r"\s+", r"\D+", r"\W+", r"\S+",
                        r"\bword\b"):
            with self.subTest(pattern=pattern):
                self.assertIsNotNone(
                    compile_pattern("posix_extended", pattern)
                )

    def test_a_shorthand_class_is_pinned_to_ascii(self):
        # The one genuine divergence. Python's `\d` matches Unicode digits;
        # Java's and RE2's match `[0-9]`. Without `re.ASCII` the local answer
        # would differ from production for an Arabic-Indic digit, which is
        # exactly the silent disagreement this module refuses patterns to
        # avoid.
        compiled = compile_pattern("posix_extended", r"^\d+$")
        self.assertIsNotNone(compiled.search("123"))
        self.assertIsNone(
            compiled.search("\u0661\u0662"),  # Arabic-Indic one, two
            "a Unicode digit matched `\\d`, so this engine disagrees with the "
            "vendor's",
        )

    def test_a_truly_dialect_specific_escape_is_still_refused(self):
        # The screen is narrowed, not removed. `\p{...}`, `\A`, `\Z`, `\G`
        # and backreferences genuinely differ between these engines.
        for pattern in (r"\p{Alpha}+", r"\Ax", r"\Gx", r"(a)\1"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(Refusal) as caught:
                    compile_pattern("posix_extended", pattern)
                self.assertEqual(
                    caught.exception.code, "REGEX_DIALECT_SPECIFIC"
                )

    def test_a_bounded_repeat_is_allowed_and_an_odd_brace_is_not(self):
        self.assertIsNotNone(compile_pattern("posix_extended", r"a{2,4}"))
        self.assertIsNotNone(compile_pattern("posix_extended", r"a{3}"))
        self.assertIsNotNone(compile_pattern("posix_extended", r"a{2,}"))
        with self.assertRaises(Refusal):
            compile_pattern("posix_extended", r"a{,}")

    def test_escaped_literal_is_allowed(self):
        # Wazuh ships rule 60000 as `\.+`, so refusing every backslash would
        # refuse real vendor rules.
        self.assertIsNotNone(compile_pattern("posix_extended", r"lsass\.exe"))

    def test_extended_group_is_refused_not_crashed(self):
        # Regression: the refusal looked up a key that was not in the table, so
        # a non-capturing group raised KeyError instead of Refusal. `(?:` is one
        # of the most common constructs in real vendor rules, so the screen
        # crashed on ordinary input rather than answering.
        with self.assertRaises(Refusal) as caught:
            compile_pattern("posix_extended", "(?:lsass|svchost)")
        self.assertEqual(caught.exception.code, "REGEX_DIALECT_SPECIFIC")
        self.assertIn("extended group", caught.exception.message)

    def test_posix_named_class_is_refused(self):
        # Regression: `[` is a portable literal, so this walked through the
        # screen and reached Python's re, which reads `[[:alpha:]]` as the class
        # {[, :, a, l, p, h}. It compiled, it matched, and it meant something
        # other than what the author wrote -- the exact failure this screen is
        # for. A refusal message existed for it but nothing ever raised it.
        with self.assertRaises(Refusal) as caught:
            compile_pattern("posix_extended", "[[:alpha:]]+")
        self.assertEqual(caught.exception.code, "REGEX_DIALECT_SPECIFIC")
        self.assertIn("named character class", caught.exception.message)

    def test_an_ordinary_bracket_class_is_still_allowed(self):
        # The named-class refusal must not take plain character classes with it.
        self.assertIsNotNone(compile_pattern("posix_extended", "[abc]+"))
        self.assertIsNotNone(compile_pattern("posix_extended", "[a-z0-9_]"))


class NegationIsNotOptional(unittest.TestCase):
    """`negate` is DATA on a Comparison, so EVERY path has to apply it.

    The evaluator had four return paths and only two of them did. For the eight
    text operators -- `contains startswith endswith matches =~ !~ like ilike` --
    `negate` was read off the node and silently discarded, so
    `NOT (cmd contains "lsass")` evaluated as `cmd contains "lsass"` and matched
    exactly the events the author wrote the rule to exclude.

    An inverted detection is the worst defect this tool can ship: it does not
    fail, it does not warn, and the rule reads correctly in review.
    ir.Comparison.describe() carries a comment warning about this same failure
    mode on the RENDERING side; this class is the evaluator's half.
    """

    def ev(self, expr, **values):
        ctx = Context()
        return eval_expr(expr, scope(row(**values)), ctx), ctx

    def test_negated_contains_is_false_when_the_value_contains_it(self):
        result, _ = self.ev(
            Comparison("contains", FieldRef("cmd"), Literal("lsass"), negate=True),
            cmd=r"c:\windows\lsass.exe",
        )
        self.assertIs(result, False)

    def test_negated_contains_is_true_when_the_value_does_not(self):
        result, _ = self.ev(
            Comparison("contains", FieldRef("cmd"), Literal("lsass"), negate=True),
            cmd=r"c:\windows\svchost.exe",
        )
        self.assertIs(result, True)

    def test_negation_is_applied_to_every_text_operator(self):
        # Table-driven on purpose: the bug was per-operator, so a single-operator
        # test would have passed while three others stayed inverted.
        matching = {
            "contains": Literal("lsass"),
            "startswith": Literal("c:"),
            "endswith": Literal(".exe"),
            "matches": Regex("lsass", "posix_extended"),
            "=~": Regex("lsass", "posix_extended"),
        }
        for op, right in matching.items():
            with self.subTest(op=op):
                plain, _ = self.ev(
                    Comparison(op, FieldRef("cmd"), right), cmd=r"c:\lsass.exe"
                )
                self.assertIs(plain, True, f"{op} should match the value")
                negated, _ = self.ev(
                    Comparison(op, FieldRef("cmd"), right, negate=True),
                    cmd=r"c:\lsass.exe",
                )
                self.assertIs(
                    negated, False,
                    f"NOT ({op}) matched the same value as ({op}), so the rule "
                    f"means the opposite of what it says",
                )

    def test_the_two_negations_on_a_not_match_operator_compose(self):
        # `!~` negates by its own definition and `negate` negates again. Applying
        # only one of the two is an inverted rule in both directions.
        pattern = Regex("lsass", "posix_extended")
        self.assertIs(
            self.ev(Comparison("!~", FieldRef("cmd"), pattern),
                    cmd=r"c:\lsass.exe")[0],
            False,
        )
        self.assertIs(
            self.ev(Comparison("!~", FieldRef("cmd"), pattern, negate=True),
                    cmd=r"c:\lsass.exe")[0],
            True,
        )
        self.assertIs(
            self.ev(Comparison("!~", FieldRef("cmd"), pattern),
                    cmd=r"c:\svchost.exe")[0],
            True,
        )

    def test_negation_does_not_turn_undecided_into_a_decision(self):
        # Three-valued logic: NOT UNDECIDED is still UNDECIDED. A negation that
        # resolved it would answer a question the engine has no evidence for.
        result, _ = self.ev(
            Comparison("contains", FieldRef("missing"), Literal("x"), negate=True),
            other=1,
        )
        self.assertIs(result, UNDECIDED)


class TextPredicatesNameWhatTheyCouldNotDecide(unittest.TestCase):
    """An undecidable comparison must say WHICH operand and WHY.

    `contains`, `startswith` and `endswith` returned UNDECIDED before reaching
    the guard that emits COMPARISON_UNDECIDABLE, so they produced a bare
    UNDECIDED with no caveat at all. The analyst saw only the filter's summary
    -- "could not decide 1 of 1 rows" -- with no field named, which is exactly
    the question this engine exists to answer. Those three operators cover the
    common case in real vendor rules, not an exotic one.
    """

    def ev(self, expr, **values):
        ctx = Context()
        return eval_expr(expr, scope(row(**values)), ctx), ctx

    def test_an_absent_field_is_named(self):
        for op in ("contains", "startswith", "endswith"):
            with self.subTest(op=op):
                result, ctx = self.ev(
                    Comparison(op, FieldRef("win", ("eventdata", "Image")),
                               Literal("lsass.exe")),
                    other=1,
                )
                self.assertIs(result, UNDECIDED)
                self.assertTrue(
                    any(c.code == "COMPARISON_UNDECIDABLE" for c in ctx.caveats),
                    f"{op} over an absent field reported nothing at all",
                )
                message = " ".join(c.message for c in ctx.caveats)
                self.assertIn("win.eventdata.Image", message)
                # The analyst must never be shown the engine's own sentinel.
                self.assertNotIn("ABSENT", message)

    def test_the_reason_distinguishes_absent_from_null(self):
        _, absent = self.ev(
            Comparison("contains", FieldRef("f"), Literal("x")), other=1
        )
        _, nulled = self.ev(
            Comparison("contains", FieldRef("f"), Literal("x")), f=None
        )
        self.assertIn("absent", " ".join(c.message for c in absent.caveats))
        self.assertIn("null", " ".join(c.message for c in nulled.caveats))

    def test_a_non_text_operand_is_named_with_its_type(self):
        # `contains` over a number is a rule asking a question the engine cannot
        # answer. Coercing it would be guessing at what the vendor does.
        result, ctx = self.ev(
            Comparison("contains", FieldRef("Port"), Literal("443")),
            Port=Decimal(443),
        )
        self.assertIs(result, UNDECIDED)
        message = " ".join(c.message for c in ctx.caveats)
        self.assertIn("Port", message)
        self.assertIn("number", message.lower())

    def test_a_decidable_text_predicate_reports_nothing(self):
        # A caveat on every comparison is noise, and noise is how a caveat list
        # stops being read.
        result, ctx = self.ev(
            Comparison("endswith", FieldRef("p"), Literal(".exe")),
            p=r"c:\lsass.exe",
        )
        self.assertIs(result, True)
        self.assertEqual(ctx.caveats, [])

    def test_the_caveat_survives_to_the_filters_report(self):
        # The end-to-end path: what the analyst actually sees after running a
        # rule that could not be decided.
        from engine.ir import Emit, Filter, Read, Rule
        from engine.pipeline import evaluate

        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="T"),
                Filter(id="f", condition=Comparison(
                    "endswith", FieldRef("TargetImage"), Literal("lsass.exe"))),
                Emit(id="out"),
            ),
        )
        result = evaluate(rule, [{"EventID": 4624}])
        self.assertEqual(result.verdict, "not_evaluated")
        message = " ".join(c.message for c in result.caveats)
        self.assertIn(
            "TargetImage", message,
            "the analyst was told rows could not be decided but not which "
            "field was missing, which is the whole question",
        )


class UndecidedPropagation(unittest.TestCase):
    def test_absent_field_makes_the_filter_undecided_not_false(self):
        ctx = Context()
        result = eval_expr(
            Comparison("==", FieldRef("missing"), Literal("x")),
            scope(row(other=1)), ctx,
        )
        self.assertIs(result, UNDECIDED)
        self.assertTrue(any(c.code == "COMPARISON_UNDECIDABLE" for c in ctx.caveats))

    def test_caveat_names_the_rule_field_not_the_sentinel(self):
        ctx = Context()
        eval_expr(
            Comparison("==", FieldRef("win.eventdata.Image"), Literal("x")),
            scope(row(other=1)), ctx,
        )
        message = " ".join(c.message for c in ctx.caveats)
        self.assertIn("win.eventdata.Image", message)
        self.assertNotIn("ABSENT", message)

    def test_not_of_undecided_is_undecided(self):
        ctx = Context()
        result = eval_expr(
            Not(Comparison("==", FieldRef("missing"), Literal("x"))),
            scope(row(other=1)), ctx,
        )
        self.assertIs(result, UNDECIDED)

    def test_and_of_false_with_undecided_is_false(self):
        ctx = Context()
        result = eval_expr(
            Comparison("==", FieldRef("missing"), Literal("x")),
            scope(row(other=1)), ctx,
        )
        self.assertIs(and_(result, False), False)

    def test_arithmetic_on_absent_is_undecided_not_zero(self):
        # Treating it as zero would quietly widen a correlation window.
        ctx = Context()
        result = eval_expr(
            Arith("+", FieldRef("missing"), Literal(Decimal(600))),
            scope(row(other=1)), ctx,
        )
        self.assertIs(result, UNDECIDED)
        self.assertTrue(any(c.code == "ARITH_UNDECIDABLE" for c in ctx.caveats))

    def test_a_bare_field_evaluates_to_its_value_not_a_boolean(self):
        # A non-empty string is truthy, so `| where field` matches almost
        # everything and looks like it works.
        ctx = Context()
        result = eval_expr(FieldRef("name"), scope(row(name="bob")), ctx)
        self.assertIs(result, "bob")
        # The refusal happens where it belongs: at the stage that demands a
        # predicate, not here. See test_validate.StructuralValidation.


class Lists(unittest.TestCase):
    def test_in_over_a_list(self):
        ctx = Context()
        result = eval_expr(
            Comparison("in", FieldRef("EventID"),
                       ListExpr((Literal(4624), Literal(4688)))),
            scope(row(EventID=4624)), ctx,
        )
        self.assertIs(result, True)

    def test_in_rejects_a_non_member(self):
        ctx = Context()
        result = eval_expr(
            Comparison("in", FieldRef("EventID"),
                       ListExpr((Literal(4624), Literal(4688)))),
            scope(row(EventID=9999)), ctx,
        )
        self.assertIs(result, False)

    def test_in_over_absent_is_undecided(self):
        # NOT False: a rule must not decide "not in the set" about a field it
        # never saw.
        ctx = Context()
        result = eval_expr(
            Comparison("in", FieldRef("EventID"),
                       ListExpr((Literal(4624),))),
            scope(row(other=1)), ctx,
        )
        self.assertIs(result, UNDECIDED)

    def test_negated_in_over_absent_is_also_undecided(self):
        # NOT (undecided) is undecided, so this cannot become a match.
        ctx = Context()
        result = eval_expr(
            Comparison("in", FieldRef("EventID"),
                       ListExpr((Literal(4624),)), negate=True),
            scope(row(other=1)), ctx,
        )
        self.assertIs(result, UNDECIDED)

    def test_contains_all_requires_every_member(self):
        ctx = Context()
        result = eval_expr(
            Comparison("contains_all", FieldRef("cmd"),
                       ListExpr((Literal("lsass"), Literal("dump")))),
            scope(row(cmd="lsass_dump.exe")), ctx,
        )
        self.assertIs(result, True)

    def test_contains_all_fails_on_a_partial_match(self):
        ctx = Context()
        result = eval_expr(
            Comparison("contains_all", FieldRef("cmd"),
                       ListExpr((Literal("lsass"), Literal("dump")))),
            scope(row(cmd="lsass.exe")), ctx,
        )
        self.assertIs(result, False)


class AbsenceIsAskedTwoDifferentWays(unittest.TestCase):
    """Two predicates, because two vendors mean two different things.

    Sigma's `field: null` asks whether a field is PRESENT and null, and
    `test_sigma.NullIsNotAbsent` pins that: collapsing absence into it would
    report a confident answer with no evidence. KQL has no such distinction --
    its schema is fixed, so every row carries every column and a missing value
    IS null there.

    One predicate could not serve both. Mapping KQL's `isnull()` onto the
    strict one left every row that actually lacked the field UNDECIDED, so the
    rule reported `not_evaluated` on exactly the events it was written for,
    and "this field is missing" was unexpressible anywhere in the system.
    """

    def ask(self, function: str, values: dict):
        return eval_expr(
            Call(function, (FieldRef("A"),)),
            scope(row(**values)),
            Context(),
        )

    def test_the_strict_predicate_stays_undecided_on_an_absent_field(self):
        self.assertIs(self.ask("is_null", {"B": 1}), UNDECIDED)

    def test_the_strict_predicate_still_answers_a_present_null(self):
        self.assertIs(self.ask("is_null", {"A": None}), True)
        self.assertIs(self.ask("is_null", {"A": "x"}), False)

    def test_the_vendor_predicate_decides_an_absent_field(self):
        self.assertIs(self.ask("is_null_or_absent", {"B": 1}), True)

    def test_the_vendor_predicate_also_answers_a_present_null(self):
        self.assertIs(self.ask("is_null_or_absent", {"A": None}), True)
        self.assertIs(self.ask("is_null_or_absent", {"A": "x"}), False)

    def test_presence_is_the_exact_negation(self):
        for values in ({"B": 1}, {"A": None}, {"A": "x"}, {"A": ""}):
            with self.subTest(row=values):
                self.assertIs(
                    self.ask("is_present", values),
                    not self.ask("is_null_or_absent", values),
                )

    def test_emptiness_covers_absent_null_and_blank(self):
        for values in ({"B": 1}, {"A": None}, {"A": ""}):
            with self.subTest(row=values):
                self.assertIs(self.ask("is_empty", values), True)
        self.assertIs(self.ask("is_empty", {"A": "x"}), False)

    def test_non_emptiness_is_the_exact_negation(self):
        for values in ({"B": 1}, {"A": None}, {"A": ""}, {"A": "x"}):
            with self.subTest(row=values):
                self.assertIs(
                    self.ask("not_empty", values),
                    not self.ask("is_empty", values),
                )

    def test_both_predicates_are_declared_local(self):
        # A function missing from LOCAL_FUNCTIONS is treated as appliance-only
        # and returns UNDECIDED with a caveat, which is the failure this whole
        # class is about.
        from engine.ir import LOCAL_FUNCTIONS

        for name in ("is_null_or_absent", "is_present"):
            with self.subTest(function=name):
                self.assertIn(name, LOCAL_FUNCTIONS)

    def test_deciding_absence_costs_no_caveat(self):
        # An answer the engine is certain of must not be reported as a doubt.
        context = Context()
        eval_expr(
            Call("is_null_or_absent", (FieldRef("A"),)),
            scope(row(B=1)),
            context,
        )
        self.assertEqual(context.caveats, [])


class EveryDeclaredLocalFunctionIsComputable(unittest.TestCase):
    """The drift guard for `ir.LOCAL_FUNCTIONS`.

    That set is the engine's CLAIM about what it can run locally. A name in it
    with no handler reaches `Refusal("FUNCTION_UNKNOWN")` at evaluation time:
    the engine says it can run the rule, then refuses. `min`, `max` and
    `strftime` sat in that gap, and `strftime` is reachable from AQL's
    `DATEFORMAT`, so an ordinary QRadar rule refused on every row.

    Written as reflection over the declaration rather than a list, so the
    check cannot go stale when a function is added.
    """

    def test_every_declared_name_has_a_handler(self):
        from engine import evaluate as engine
        from engine.ir import LOCAL_FUNCTIONS

        handled = (
            set(engine._FUNCTIONS)
            | set(engine._ABSENCE_TESTS)
            | {"coalesce"}  # handled ahead of the ABSENT guard, by design
        )
        missing = sorted(set(LOCAL_FUNCTIONS) - handled)
        self.assertEqual(
            missing, [],
            f"these are declared locally evaluable and have no "
            f"implementation, so a rule using one refuses at run time: "
            f"{missing}",
        )

    def test_every_handler_is_declared(self):
        # The other direction. An implemented function missing from the
        # declaration is reachable but undocumented, so the set stops being
        # the source of truth about what this engine can do.
        from engine import evaluate as engine
        from engine.ir import APPLIANCE_FUNCTIONS, LOCAL_FUNCTIONS

        undeclared = sorted(
            set(engine._FUNCTIONS) - set(LOCAL_FUNCTIONS)
            - set(APPLIANCE_FUNCTIONS)
        )
        self.assertEqual(undeclared, [])

    def test_no_function_is_both_local_and_appliance_only(self):
        # One would shadow the other and which wins would depend on lookup
        # order, so the same rule could be evaluable or not depending on a
        # dict.
        from engine.ir import APPLIANCE_FUNCTIONS, LOCAL_FUNCTIONS

        self.assertEqual(
            sorted(set(LOCAL_FUNCTIONS) & set(APPLIANCE_FUNCTIONS)), []
        )

    def test_every_declared_name_actually_runs(self):
        # Reflection proves a handler exists; this proves calling it does not
        # raise. A handler that throws on its own documented arguments is the
        # same failure wearing a different hat.
        from engine.ir import LOCAL_FUNCTIONS

        sample = row(s="LSASS.exe", n=Decimal(5), ip="10.1.2.3")
        arity = {
            "cidr_contains": (FieldRef("ip"), Literal("10.0.0.0/8")),
            "strftime": (Literal(Decimal(0)), Literal("%Y")),
            "ago": (Literal(Decimal(60)),),
            "bin": (FieldRef("n"), Literal(Decimal(2))),
            "now": (),
            "coalesce": (FieldRef("zz"), Literal("x")),
            "iff": (Literal(True), Literal("yes"), Literal("no")),
        }
        for name in sorted(LOCAL_FUNCTIONS):
            args = arity.get(name)
            if args is None:
                # Default shape: a text subject and a text needle covers the
                # predicates, the unary converters and the list tests.
                args = (FieldRef("s"), Literal("LSA"))
            with self.subTest(function=name):
                try:
                    eval_expr(Call(name, args), scope(sample), Context())
                except Refusal as exc:
                    self.fail(
                        f"{name} is declared local but refused: {exc.code}"
                    )


class TheClockFunctions(unittest.TestCase):
    """`ago(x)` is a timestamp, not an offset."""

    def test_ago_is_now_minus_the_span(self):
        # It returned the NEGATIVE offset, so `TimeGenerated > ago(1h)`
        # compared a real timestamp against -3600 -- true for every row. The
        # window check passed everything and the rule silently matched outside
        # its own time bound.
        context = Context()
        now = eval_expr(Call("now", ()), scope(row()), context)
        ago = eval_expr(
            Call("ago", (Literal(Decimal(3600)),)), scope(row()), context
        )
        self.assertAlmostEqual(float(now - ago), 3600.0, delta=2.0)

    def test_ago_accepts_a_duration_as_well_as_a_number(self):
        from engine.values import Duration

        context = Context()
        now = eval_expr(Call("now", ()), scope(row()), context)
        ago = eval_expr(
            Call("ago", (Literal(Duration(Decimal(60))),)),
            scope(row()), context,
        )
        self.assertAlmostEqual(float(now - ago), 60.0, delta=2.0)

    def test_ago_is_undecided_for_a_non_span(self):
        self.assertIs(
            eval_expr(Call("ago", (Literal("soon"),)), scope(row()), Context()),
            UNDECIDED,
        )

    def test_a_row_inside_the_window_matches_and_one_outside_does_not(self):
        # The property the sign error destroyed, stated end to end.
        import time

        now = int(time.time())
        inside = Comparison(
            ">", FieldRef("t"), Call("ago", (Literal(Decimal(3600)),))
        )
        self.assertIs(
            eval_expr(inside, scope(row(t=Decimal(now - 60))), Context()), True
        )
        self.assertIs(
            eval_expr(inside, scope(row(t=Decimal(now - 7200))), Context()),
            False,
        )


class StrftimeIsUtc(unittest.TestCase):
    def test_the_epoch_formats_as_the_epoch(self):
        # Local time would make the same rule produce different output on two
        # machines, which is not a rule.
        self.assertEqual(
            eval_expr(
                Call("strftime", (Literal(Decimal(0)), Literal("%Y-%m-%d"))),
                scope(row()), Context(),
            ),
            "1970-01-01",
        )

    def test_a_non_numeric_time_is_undecided(self):
        self.assertIs(
            eval_expr(
                Call("strftime", (Literal("noon"), Literal("%Y"))),
                scope(row()), Context(),
            ),
            UNDECIDED,
        )

    def test_a_non_string_format_is_undecided(self):
        self.assertIs(
            eval_expr(
                Call("strftime", (Literal(Decimal(0)), Literal(Decimal(1)))),
                scope(row()), Context(),
            ),
            UNDECIDED,
        )

    def test_an_unformattable_value_is_reported_not_raised(self):
        # A formatting problem is not grounds to abandon the rule, but it must
        # not look like a successful format either.
        context = Context()
        result = eval_expr(
            Call("strftime", (Literal(Decimal(10 ** 30)), Literal("%Y"))),
            scope(row()), context,
        )
        self.assertIs(result, UNDECIDED)
        self.assertEqual(
            [c.code for c in context.caveats], ["STRFTIME_UNFORMATTABLE"]
        )


class MatchesRegexTakesAStringPattern(unittest.TestCase):
    """YARA-L's `re.regex` and EQL's `match` pass the pattern as a string.

    Only the `Regex`-node branch existed, so those calls returned UNDECIDED --
    a regex test that silently never ran, in two dialects.
    """

    def ask(self, pattern):
        return eval_expr(
            Call("matches_regex", (FieldRef("s"), pattern)),
            scope(row(s="LSASS.exe")), Context(),
        )

    def test_a_string_pattern_matches(self):
        self.assertIs(self.ask(Literal("LSASS")), True)

    def test_a_string_pattern_can_also_not_match(self):
        self.assertIs(self.ask(Literal("notpresent")), False)

    def test_a_regex_node_still_works(self):
        self.assertIs(self.ask(Regex("LSASS", "posix_extended")), True)

    def test_a_string_pattern_is_still_screened(self):
        # It must go through `compile_pattern`, not `re.compile`: bypassing it
        # would let an untrusted pattern reach the engine without the ReDoS
        # screen or the portable-syntax screen.
        context = Context()
        result = eval_expr(
            Call("matches_regex", (FieldRef("s"), Literal("(a+)+$"))),
            scope(row(s="LSASS.exe")), context,
        )
        self.assertIs(result, UNDECIDED)

    def test_a_non_text_subject_is_undecided(self):
        self.assertIs(
            eval_expr(
                Call("matches_regex", (FieldRef("missing"), Literal("x"))),
                scope(row(s="a")), Context(),
            ),
            UNDECIDED,
        )


if __name__ == "__main__":
    unittest.main()
