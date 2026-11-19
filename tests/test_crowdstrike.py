"""CrowdStrike Falcon FQL.

`CommaIsOrNotAnd` is the class this module exists for. Every other list syntax
a reader has met uses the comma as a separator inside a conjunction, so
`a:'1',b:'2'` reads like "a is 1 AND b is 2" and means "a is 1 OR b is 2". A
rule misread that way matches the union instead of the intersection, which is
not a near miss: an alert meant for one process on one host fires on every
host and reports success.

`FqlHasNoPipeline` is second. FQL is a filter and nothing else, so a rule that
counts or correlates has no FQL form. Emitting the filter half alone is the
failure that turns "five failed logons from one host" into "any failed logon".
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from engine import dialects
from engine.evaluate import _glob_match
from engine.dialects.crowdstrike import (
    BOOLEAN_OPERATORS,
    DEFAULT_TABLE,
    DIALECT,
    UNSUPPORTED_STAGES,
    lower_crowdstrike,
    parse_crowdstrike,
    render_crowdstrike,
)
from engine.ir import (
    Aggregate,
    Annotations,
    BoolOp,
    Call,
    Comparison,
    Correlation,
    Distinct,
    Emit,
    FieldRef,
    Filter,
    Join,
    Limit,
    ListExpr,
    Literal,
    Measure,
    Not,
    Read,
    Rule,
    Sort,
    render_expr,
)
from engine.pipeline import evaluate
from engine.values import Duration, Refusal

LSASS = "event_simpleName:'ProcessRollup2'+FileName:['lsass.exe','procdump.exe']"


def lower(text: str) -> Rule:
    rule, _ = lower_crowdstrike(text)
    return rule


def condition(text: str):
    return lower(text).pipeline[1].condition


def plain(condition_expr) -> str:
    """The expression's STRUCTURE, with the case-fold flag left out.

    FQL's `:` is case-insensitive by default, so every equality lowered from it
    now carries `nocase=True`. These tests are about boolean grouping and
    operator mapping, not about case, so the flag is stripped here rather than
    repeated in thirty expected strings.
    """
    return render_expr(condition_expr).replace(" nocase", "")


class CommaIsOrNotAnd(unittest.TestCase):
    """The defect this module exists to prevent."""

    def test_the_mapping_is_data(self):
        # Written down so it cannot drift into an inlined assumption.
        self.assertEqual(BOOLEAN_OPERATORS["+"], "and")
        self.assertEqual(BOOLEAN_OPERATORS[","], "or")

    def test_a_comma_lowers_to_or(self):
        self.assertEqual(plain(condition("a:'1',b:'2'")), '(a == "1" OR b == "2")')

    def test_a_plus_lowers_to_and(self):
        self.assertEqual(plain(condition("a:'1'+b:'2'")), '(a == "1" AND b == "2")')

    def test_plus_binds_tighter_than_comma(self):
        # `a+b,c` is `(a AND b) OR c`. Read the other way it becomes
        # `a AND (b OR c)`, which matches records where `a` holds and `c` does
        # -- records the author excluded.
        self.assertEqual(
            plain(condition("a:'1'+b:'2',c:'3'")),
            '((a == "1" AND b == "2") OR c == "3")',
        )

    def test_the_or_reading_is_proven_by_running_it(self):
        # One row satisfying only the second clause. Under AND this is no
        # match; under OR it is a match, and OR is what FQL means.
        self.assertTrue(evaluate(lower("a:'1',b:'2'"), [{"b": "2"}]).matched)
        self.assertFalse(evaluate(lower("a:'1'+b:'2'"), [{"b": "2"}]).matched)

    def test_a_comma_is_reported_so_a_misreading_is_visible(self):
        _, diagnostics = lower_crowdstrike("a:'1',b:'2'")
        self.assertIn("FQL_COMMA_IS_OR", [d.code for d in diagnostics])

    def test_an_and_only_filter_says_nothing(self):
        # A caveat that fires on the clean path gets ignored on the dirty one.
        _, diagnostics = lower_crowdstrike("a:'1'+b:'2'")
        self.assertEqual(diagnostics, [])

    def test_an_or_inside_an_and_keeps_its_brackets_on_the_way_out(self):
        # `a+(b,c)` without brackets becomes `a+b,c`, which is `(a AND b) OR c`
        # -- a wider filter than the one being written out.
        rule = lower("a:'1'+(b:'2',c:'3')")
        self.assertEqual(render_crowdstrike(rule), "a:'1'+(b:'2',c:'3')")

    def test_that_bracketing_survives_a_round_trip(self):
        rule = lower("a:'1'+(b:'2',c:'3')")
        again = lower(render_crowdstrike(rule))
        self.assertEqual(plain(again.pipeline[1].condition),
                         plain(rule.pipeline[1].condition))


class MatchersAreNotAllEquality(unittest.TestCase):
    """`:` introduces a matcher whose prefix is part of the operator."""

    def test_plain_colon_is_equality(self):
        self.assertEqual(plain(condition("a:'1'")), 'a == "1"')

    def test_bang_is_inequality(self):
        self.assertEqual(plain(condition("a:!'1'")), 'NOT (a == "1")')

    def test_orderings_are_parsed_not_swallowed_into_the_value(self):
        # Read as equality these compare against the literal text `>=443`,
        # which matches nothing and errors nowhere.
        self.assertEqual(plain(condition("Port:>=443")), "Port >= 443")
        self.assertEqual(plain(condition("Port:<1024")), "Port < 1024")

    def test_a_list_is_a_membership_test(self):
        self.assertEqual(
            plain(condition("a:['x','y']")), 'a in ["x", "y"]'
        )

    def test_a_negated_list_is_still_a_membership_test(self):
        parsed = condition("a:!['x','y']")
        self.assertEqual(parsed.op, "in")
        self.assertTrue(parsed.negate)

    def test_null_is_absence_not_equality_with_null(self):
        # `field == null` and `field is absent` are different questions, and
        # the engine keeps them apart.
        self.assertEqual(plain(condition("UserName:null")), "is_null(UserName)")

    def test_a_negated_null_is_presence(self):
        self.assertIsInstance(condition("UserName:!null"), Not)

    def test_a_dotted_field_keeps_its_path(self):
        reference = condition("a.b.c:'1'").left
        self.assertEqual(reference.name, "a")
        self.assertEqual(reference.path, ("b", "c"))

    def test_a_bare_word_value_is_accepted(self):
        # `platform_name:Windows` is idiomatic FQL; refusing it would reject
        # working rules.
        self.assertEqual(plain(condition("platform_name:Windows")),
                         'platform_name == "Windows"')

    def test_a_bare_number_stays_a_number(self):
        self.assertEqual(condition("Port:443").right.value, Decimal(443))


class TheWildcardIsAGlobNotARegex(unittest.TestCase):
    def test_star_becomes_a_like_pattern(self):
        self.assertEqual(plain(condition("FileName:*'*lsass*'")),
                         'FileName like "%lsass%"')

    def test_a_dot_stays_literal(self):
        # As a regex, `.` matches any character, so `*'1.2.3.4'` would match
        # `1x2y3z4`. As a glob it does not.
        rule = lower("ip:*'1.2.3.4'")
        self.assertFalse(evaluate(rule, [{"ip": "1x2y3z4"}]).matched)
        self.assertTrue(evaluate(rule, [{"ip": "1.2.3.4"}]).matched)

    def test_a_question_mark_matches_one_character(self):
        rule = lower("a:*'a?c'")
        self.assertTrue(evaluate(rule, [{"a": "abc"}]).matched)
        self.assertFalse(evaluate(rule, [{"a": "abbc"}]).matched)

    def test_a_literal_percent_is_escaped_rather_than_becoming_a_wildcard(self):
        # `%` has no meaning in FQL but is a wildcard in the engine's LIKE.
        # Passed through it would widen the test.
        rule = lower("a:*'100%'")
        self.assertTrue(evaluate(rule, [{"a": "100%"}]).matched)
        self.assertFalse(evaluate(rule, [{"a": "100 and more"}]).matched)

    def test_it_evaluates(self):
        rule = lower("FileName:*'*lsass*'")
        self.assertTrue(
            evaluate(rule, [{"FileName": r"c:\windows\lsass.exe"}]).matched
        )
        self.assertFalse(evaluate(rule, [{"FileName": "notepad.exe"}]).matched)

    def test_a_negated_wildcard_round_trips(self):
        rule = lower("FileName:!*'*lsass*'")
        self.assertEqual(render_crowdstrike(rule), "FileName:!*'*lsass*'")


class FqlHasNoPipeline(unittest.TestCase):
    """A stage FQL cannot express is refused, never dropped."""

    def pipeline_with(self, stage):
        return Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table=DEFAULT_TABLE),
                Filter(id="f", condition=Comparison(
                    "==", FieldRef(name="a"), Literal(1)
                )),
                stage,
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )

    def test_every_unsupported_stage_has_a_stated_reason(self):
        for kind, reason in UNSUPPORTED_STAGES.items():
            with self.subTest(stage=kind):
                self.assertTrue(reason.strip())

    def test_an_aggregate_is_refused_rather_than_losing_its_threshold(self):
        rule = self.pipeline_with(Aggregate(
            id="g",
            measures=(Measure(function="count", name="c"),),
            keys=(FieldRef(name="a"),),
        ))
        with self.assertRaises(Refusal) as caught:
            render_crowdstrike(rule)
        self.assertEqual(caught.exception.code, "FQL_RENDER_NO_AGGREGATE")

    def test_a_correlation_is_refused(self):
        # `parent` names the stage being counted, and `ir.Rule` checks that it
        # resolves, so it points at the filter rather than at a made-up id.
        rule = self.pipeline_with(Correlation(
            id="c", parent="f", frequency=5,
            timeframe=Duration(Decimal(60)),
            group_by=(FieldRef(name="a"),),
        ))
        with self.assertRaises(Refusal) as caught:
            render_crowdstrike(rule)
        self.assertEqual(caught.exception.code, "FQL_RENDER_NO_CORRELATION")

    def test_a_sort_and_a_limit_are_refused(self):
        for stage, code in (
            (Sort(id="s2", keys=((FieldRef(name="a"), True),)),
             "FQL_RENDER_NO_SORT"),
            (Limit(id="l", count=10), "FQL_RENDER_NO_LIMIT"),
            (Distinct(id="d", keys=(FieldRef(name="a"),)),
             "FQL_RENDER_NO_DISTINCT"),
        ):
            with self.subTest(stage=type(stage).__name__):
                with self.assertRaises(Refusal) as caught:
                    render_crowdstrike(self.pipeline_with(stage))
                self.assertEqual(caught.exception.code, code)

    def test_a_rule_with_bindings_is_refused(self):
        from engine.ir import Binding
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table=DEFAULT_TABLE),
                Filter(id="f", condition=Comparison(
                    "==", FieldRef(name="a"), Literal(1)
                )),
                Emit(id="o"),
            ),
            bindings=(Binding(name="b", pipeline=(
                Read(id="bs", table="x"), Emit(id="be"),
            )),),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_crowdstrike(rule)
        self.assertEqual(caught.exception.code, "FQL_RENDER_BINDINGS")

    def test_a_rule_with_no_filter_is_refused(self):
        # An empty filter returns every record, which is the opposite of a
        # detection.
        rule = Rule(
            rule_id="r",
            pipeline=(Read(id="s", table=DEFAULT_TABLE), Emit(id="o")),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_crowdstrike(rule)
        self.assertEqual(caught.exception.code, "FQL_RENDER_NO_CONDITION")

    def test_several_filters_are_anded_not_dropped(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table=DEFAULT_TABLE),
                Filter(id="f1", condition=Comparison(
                    "==", FieldRef(name="a"), Literal("1")
                )),
                Filter(id="f2", condition=Comparison(
                    "==", FieldRef(name="b"), Literal("2")
                )),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        self.assertEqual(render_crowdstrike(rule), "a:'1'+b:'2'")


class Parsing(unittest.TestCase):
    def test_an_empty_filter_is_refused(self):
        # An empty filter is not a filter that matches nothing: the API would
        # return every record.
        with self.assertRaises(Refusal) as caught:
            parse_crowdstrike("   ")
        self.assertEqual(caught.exception.code, "FQL_EMPTY")

    def test_a_bare_field_is_refused(self):
        # FQL has no bare-word search. Reading one as a search would pass
        # every record where the field merely exists.
        with self.assertRaises(Refusal) as caught:
            parse_crowdstrike("event_simpleName")
        self.assertEqual(caught.exception.code, "FQL_NO_MATCHER")

    def test_a_dangling_operator_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_crowdstrike("a:'1'+")
        self.assertEqual(caught.exception.code, "FQL_NO_FIELD")

    def test_an_unterminated_string_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_crowdstrike("a:'oops")
        self.assertEqual(caught.exception.code, "FQL_STRING_UNTERMINATED")

    def test_an_unbalanced_bracket_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_crowdstrike("(a:'1'")
        self.assertEqual(caught.exception.code, "FQL_UNBALANCED")

    def test_trailing_text_is_refused_rather_than_ignored(self):
        # Text after the filter means the filter was only partly read, and a
        # partly-read filter matches a different set of records.
        with self.assertRaises(Refusal) as caught:
            parse_crowdstrike("a:'1')")
        self.assertEqual(caught.exception.code, "FQL_TRAILING")

    def test_an_escaped_quote_survives(self):
        self.assertEqual(condition(r"a:'it\'s'").right.value, "it's")

    def test_the_operators_are_reported_in_order(self):
        parsed = parse_crowdstrike("a:'1'+b:'2',c:'3'")
        self.assertEqual(parsed.operators, ("and", "or"))


class Rendering(unittest.TestCase):
    def setUp(self):
        self.rule = lower(LSASS)
        self.text = render_crowdstrike(self.rule)

    def test_the_filter_comes_back(self):
        self.assertEqual(self.text, LSASS)

    def test_rendering_is_stable_across_two_round_trips(self):
        again = lower(self.text)
        self.assertEqual(render_crowdstrike(again), self.text)

    def test_a_case_insensitive_test_is_refused_rather_than_downgraded(self):
        # FQL's wildcard is case-SENSITIVE. Writing an ILIKE as `:*` would
        # silently narrow the rule.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table=DEFAULT_TABLE),
                Filter(id="f", condition=Comparison(
                    "ilike", FieldRef(name="a"), Literal("%x%")
                )),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_crowdstrike(rule)
        self.assertEqual(
            caught.exception.code, "FQL_RENDER_CASE_INSENSITIVE"
        )

    def test_a_contains_becomes_a_wildcard_with_the_value_escaped(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table=DEFAULT_TABLE),
                Filter(id="f", condition=Comparison(
                    "contains", FieldRef(name="a"), Literal("a*b")
                )),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        # TWO backslashes, not one. The glob layer needs `\*` to keep the star
        # literal, and the FQL string literal consumes one layer on the way
        # back in -- so a single `\*` arrived at the matcher as a bare `*`,
        # which is a WILDCARD. `a:*'*a\*b*'` matched `axb`; the pattern now
        # matches `a*b` and not `axb`, which is what `contains "a*b"` says.
        self.assertEqual(render_crowdstrike(rule), r"a:*'*a\\*b*'")
        back, _ = dialects.lower("crowdstrike", render_crowdstrike(rule))
        condition = next(
            n.condition for n in back.pipeline if type(n).__name__ == "Filter"
        )
        self.assertTrue(_glob_match("a*b", condition.right.value, False))
        self.assertFalse(_glob_match("axb", condition.right.value, False))

    def test_a_value_ending_in_a_backslash_keeps_its_wildcard(self):
        # The reported false positive: `User|startswith: 'NT AUTHORITY\'`
        # became `NT AUTHORITY\*`, where `\*` is an ESCAPED star. The filter
        # matched nothing, so its negation alerted on every SYSTEM event.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table=DEFAULT_TABLE),
                Filter(id="f", condition=Comparison(
                    "startswith", FieldRef(name="User"),
                    Literal("NT AUTHORITY\\"), nocase=True,
                )),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        back, _ = dialects.lower("crowdstrike", render_crowdstrike(rule))
        condition = next(
            n.condition for n in back.pipeline if type(n).__name__ == "Filter"
        )
        self.assertTrue(
            _glob_match("NT AUTHORITY\\SYSTEM", condition.right.value, True)
        )
        self.assertFalse(
            _glob_match("NT AUTHORITYX", condition.right.value, True)
        )

    def test_a_negated_ordering_is_refused_because_fql_cannot_spell_it(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table=DEFAULT_TABLE),
                Filter(id="f", condition=Comparison(
                    ">", FieldRef(name="a"), Literal(1), negate=True
                )),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_crowdstrike(rule)
        self.assertEqual(
            caught.exception.code, "FQL_RENDER_NEGATED_ORDERING"
        )

    def test_comparing_two_fields_is_refused(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table=DEFAULT_TABLE),
                Filter(id="f", condition=Comparison(
                    "==", FieldRef(name="a"), FieldRef(name="b")
                )),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_crowdstrike(rule)
        self.assertEqual(
            caught.exception.code, "FQL_RENDER_RIGHT_NOT_LITERAL"
        )


class RegistryIntegration(unittest.TestCase):
    def test_it_is_registered_and_ready(self):
        entry = dialects.get("crowdstrike")
        self.assertTrue(entry.can_parse)
        self.assertTrue(entry.can_render)

    def test_it_round_trips_through_the_registry(self):
        rule, _ = dialects.lower("crowdstrike", LSASS)
        text, notes = dialects.render("crowdstrike", rule)
        self.assertEqual(notes, [])
        self.assertEqual(text, LSASS)

    def test_a_filter_only_rule_crosses_into_another_dialect(self):
        # FQL carries no selector, so nothing is lost on the way out and the
        # audit must stay quiet.
        rule, _ = dialects.lower("crowdstrike", LSASS)
        text, notes = dialects.render("sentinel", rule)
        self.assertEqual(
            [n.code for n in notes if n.code == "SELECTOR_NOT_TRANSFERABLE"],
            [],
        )
        self.assertIn("where", text)


class ABareValueDoesNotSwallowTheNextClause(unittest.TestCase):
    """`A:1+B:2+C:3` parsed as ONE comparison against `"1+B:2+C:3"`.

    The unquoted-value scanner treated `+`, `,` and `:` as value characters,
    so three conditions collapsed into a single garbage comparison that
    matches nothing -- and it did so with NO error. The filter looked like it
    loaded. That is worse than a refusal, and worse than the `FQL_TRAILING`
    the quoted form produced, because nothing drew attention to it.
    """

    def test_three_bare_terms_stay_three_terms(self):
        self.assertEqual(
            plain(condition("A:1+B:2+C:3")),
            "(A == 1 AND B == 2 AND C == 3)",
        )

    def test_two_bare_terms_stay_two(self):
        self.assertEqual(
            plain(condition("A:1+B:2")), "(A == 1 AND B == 2)"
        )

    def test_bare_terms_with_orderings_parse(self):
        # `Port:>=443+Bytes:<1000` was refused as trailing junk, because the
        # value scanner had eaten `443+Bytes:`.
        self.assertEqual(
            plain(condition("Port:>=443+Bytes:<1000")),
            "(Port >= 443 AND Bytes < 1000)",
        )

    def test_a_comma_still_separates_bare_terms(self):
        self.assertEqual(
            plain(condition("A:1,B:2")), "(A == 1 OR B == 2)"
        )

    def test_the_value_types_still_work(self):
        for text, expected in (
            ("A:1.5", Decimal("1.5")),
            ("A:-3", Decimal(-3)),
            ("A:true", True),
            ("platform_name:Windows", "Windows"),
        ):
            with self.subTest(filter=text):
                self.assertEqual(condition(text).right.value, expected)

    def test_a_value_needing_a_structural_character_must_be_quoted(self):
        # An ISO timestamp contains `:`. Quoted it is one value; unquoted it
        # would be a field, a matcher and a value again.
        self.assertEqual(
            condition("A:'2026-01-01T10:00:00Z'").right.value,
            "2026-01-01T10:00:00Z",
        )

    def test_every_compound_form_round_trips(self):
        for text in (
            "A:1+B:2+C:3",
            "Port:>=443+Bytes:<1000",
            "A:1,B:2",
            "A:'1'+(B:'2',C:'3')",
            "event_simpleName:'ProcessRollup2'+FileName:['a.exe','b.exe']",
        ):
            with self.subTest(filter=text):
                rule = lower(text)
                once = render_crowdstrike(rule)
                self.assertEqual(render_crowdstrike(lower(once)), once)


class ForeignBooleansAreNamed(unittest.TestCase):
    """`AND` is not FQL, and saying so is more useful than where it stopped.

    FQL joins with `+` and `,`. Someone arriving from SPL or KQL writes `AND`,
    and the scanner refused with `FQL_TRAILING` -- "needed the end of the
    filter" -- which says where it gave up and not what to write instead.
    """

    def test_and_is_refused_by_name(self):
        with self.assertRaises(Refusal) as caught:
            lower("A:'1' AND B:'2'")
        self.assertEqual(caught.exception.code, "FQL_FOREIGN_BOOLEAN")

    def test_the_message_gives_the_fql_spelling(self):
        with self.assertRaises(Refusal) as caught:
            lower("A:'1' AND B:'2'")
        self.assertIn("`+`", caught.exception.message)

    def test_or_names_the_comma(self):
        with self.assertRaises(Refusal) as caught:
            lower("A:'1' OR B:'2'")
        self.assertIn("`,`", caught.exception.message)

    def test_not_names_the_bang(self):
        with self.assertRaises(Refusal) as caught:
            lower("NOT A:'1'")
        self.assertEqual(caught.exception.code, "FQL_FOREIGN_BOOLEAN")
        self.assertIn("field:!'value'", caught.exception.message)

    def test_a_field_merely_containing_the_word_is_not_refused(self):
        # `android_version` starts with no boolean, but `andthing` does start
        # with `and`. Only a whole word followed by a space or a bracket
        # counts, or the guard would reject ordinary field names.
        self.assertEqual(
            plain(condition("andromeda:'1'")), 'andromeda == "1"'
        )
        self.assertEqual(
            plain(condition("notable:'1'")), 'notable == "1"'
        )

    def test_the_native_spellings_still_work(self):
        self.assertEqual(
            plain(condition("A:'1'+B:'2'")), '(A == "1" AND B == "2")'
        )
        self.assertEqual(
            plain(condition("A:'1',B:'2'")), '(A == "1" OR B == "2")'
        )


if __name__ == "__main__":
    unittest.main()
