"""IBM QRadar AQL.

`ClauseOrderIsNotExecutionOrder` is the class this module exists for. AQL is
SQL: the clauses are written in an order that is not the order they run, and
`ir.Rule.pipeline` is an ordered stream where stage N sees what stage N-1
produced. Lowering the clauses in written order puts the `SELECT` projection
first, which drops every column the later predicates read -- and a filter
reading an absent column goes UNDECIDED and reports a clean `no_match` on the
events the rule was written to catch.

`QuotingFollowsSql` is second in importance, and it is the one a reader coming
from the other dialects will get wrong. In AQL `'x'` is a string and `"x"` is a
COLUMN. Reading them the other way round turns `WHERE username = 'admin'` into
a comparison between two columns.
"""

from __future__ import annotations

import unittest

from engine import dialects
from engine.evaluate import _glob_match
from engine.dialects.qradar import (
    AGGREGATES,
    CLAUSE_EXECUTION_ORDER,
    DIALECT,
    REGEX_DIALECT,
    SPEC,
    lower_qradar,
    parse_qradar,
    render_qradar,
)
from engine.ir import (
    Aggregate,
    Annotations,
    Comparison,
    Distinct,
    Emit,
    Expand,
    FieldRef,
    Filter,
    Limit,
    Literal,
    Project,
    Read,
    Regex,
    Rule,
    Sort,
    render_expr,
)
from engine.pipeline import evaluate
from engine.values import Refusal

BRUTE_FORCE = """
SELECT sourceip, "Event Name", COUNT(*) AS hits
FROM events
WHERE qid = 28250080 AND username ILIKE '%admin%'
GROUP BY sourceip
HAVING COUNT(*) > 5
ORDER BY hits DESC
LIMIT 10
LAST 24 HOURS
"""


def lower(text: str) -> Rule:
    rule, _ = lower_qradar(text)
    return rule


def stages(rule: Rule) -> list[str]:
    return [type(node).__name__ for node in rule.pipeline]


def first(rule: Rule, kind: type):
    return next(n for n in rule.pipeline if isinstance(n, kind))


def all_of(rule: Rule, kind: type) -> list:
    return [n for n in rule.pipeline if isinstance(n, kind)]


class ClauseOrderIsNotExecutionOrder(unittest.TestCase):
    """The defect this module exists to prevent.

    SELECT is written first and runs last. Emitting stages in written order
    puts a projection ahead of the predicates that read the columns it does
    not keep, and the rule then reports no_match on the events it was written
    to catch.
    """

    def test_the_execution_order_is_stated_as_data(self):
        # Written down so it can be asserted about rather than inferred from
        # the shape of a function.
        self.assertEqual(CLAUSE_EXECUTION_ORDER[0], "from")
        self.assertEqual(CLAUSE_EXECUTION_ORDER[-1], "select")

    def test_select_is_lowered_last_not_first(self):
        rule = lower(BRUTE_FORCE)
        self.assertEqual(
            stages(rule),
            ["Read", "Filter", "Aggregate", "Filter", "Sort", "Limit", "Emit"],
        )

    def test_the_projection_never_precedes_a_filter(self):
        # The concrete failure: `SELECT sourceip` keeps one column, and the
        # WHERE reads `username`. A projection placed first removes `username`
        # before the filter can read it.
        rule = lower("SELECT sourceip FROM events WHERE username = 'admin'")
        order = stages(rule)
        self.assertLess(order.index("Filter"), order.index("Project"))

    def test_the_filter_still_sees_the_column_the_projection_drops(self):
        # The same property, proven by running it rather than by reading the
        # stage list. If the projection ran first this returns nothing.
        rule = lower("SELECT sourceip FROM events WHERE username = 'admin'")
        result = evaluate(rule, [
            {"sourceip": "10.0.0.5", "username": "admin"},
            {"sourceip": "10.0.0.9", "username": "bob"},
        ])
        self.assertTrue(result.matched)
        self.assertEqual(
            [row.values for row in result.rows],
            [{"sourceip": "10.0.0.5"}],
        )

    def test_having_is_lowered_after_the_aggregate_and_where_before_it(self):
        rule = lower(BRUTE_FORCE)
        order = stages(rule)
        self.assertLess(order.index("Filter"), order.index("Aggregate"))
        self.assertGreater(
            len(all_of(rule, Filter)), 1,
            "WHERE and HAVING are two different filters and must not be merged",
        )
        self.assertEqual(all_of(rule, Filter)[1].id, "having")

    def test_limit_runs_after_sort(self):
        # `LIMIT 10` with the sort after it keeps an arbitrary ten rows and
        # then orders those, which is a different ten than the query asked for.
        rule = lower(BRUTE_FORCE)
        order = stages(rule)
        self.assertLess(order.index("Sort"), order.index("Limit"))

    def test_the_written_order_is_recorded_for_the_analyst(self):
        rule = lower(BRUTE_FORCE)
        self.assertIn("qradar.clause_order", rule.metadata)
        self.assertTrue(
            rule.metadata["qradar.clause_order"].startswith("select,from")
        )


class QuotingFollowsSql(unittest.TestCase):
    """`'x'` is a string and `"x"` is a column, as in SQL.

    This is the opposite of the convention in most of the other dialects here,
    and getting it backwards makes `WHERE username = 'admin'` a comparison
    between the `username` column and a column called `admin`.
    """

    def condition(self, text: str) -> Comparison:
        return lower(text).pipeline[1].condition

    def test_single_quotes_are_a_string(self):
        right = self.condition(
            "SELECT * FROM events WHERE username = 'admin'"
        ).right
        self.assertIsInstance(right, Literal)
        self.assertEqual(right.value, "admin")

    def test_double_quotes_are_a_column(self):
        right = self.condition(
            'SELECT * FROM events WHERE username = "admin"'
        ).right
        self.assertIsInstance(
            right, FieldRef,
            "a double-quoted word is a COLUMN in SQL. Reading it as a string "
            "silently changes what the rule compares.",
        )
        self.assertEqual(right.name, "admin")

    def test_a_property_name_with_spaces_survives(self):
        # QRadar property names routinely contain spaces, which is the reason
        # quoted identifiers are the normal case rather than an exotic one.
        left = self.condition(
            """SELECT * FROM events WHERE "Event Name" = 'Logon'"""
        ).left
        self.assertEqual(left.name, "Event Name")

    def test_it_is_written_back_the_same_way(self):
        rule = lower("""SELECT * FROM events WHERE "Event Name" = 'Logon'""")
        text = render_qradar(rule)
        self.assertIn("\"Event Name\" = 'Logon'", text)

    def test_a_clause_word_in_quotes_is_a_column_not_a_clause(self):
        # A property called "Last" must not start a `LAST n HOURS` time range.
        rule = lower("""SELECT * FROM events WHERE "Last" = 'x'""")
        self.assertEqual(first(rule, Read).selector, "")
        self.assertEqual(first(rule, Filter).condition.left.name, "Last")


class TheTimeRangeIsIndexTime(unittest.TestCase):
    """`LAST 24 HOURS` is resolved against the index, not against a row."""

    def test_it_lands_on_the_source_stage_verbatim(self):
        rule = lower(BRUTE_FORCE)
        self.assertEqual(first(rule, Read).selector, "LAST 24 HOURS")

    def test_it_is_not_a_row_predicate(self):
        # Modelled as a filter it would be evaluated locally, and a local run
        # would claim a match the appliance's index had already excluded.
        rule = lower("SELECT * FROM events WHERE qid = 1 LAST 7 DAYS")
        for node in all_of(rule, Filter):
            self.assertNotIn("LAST", render_expr(node.condition))

    def test_it_is_reported_rather_than_applied_silently(self):
        _, diagnostics = lower_qradar(BRUTE_FORCE)
        self.assertIn("INDEX_TIME_FILTER", [d.code for d in diagnostics])

    def test_an_absolute_window_is_kept_too(self):
        rule = lower(
            "SELECT * FROM events WHERE qid = 1 "
            "START '2024-01-01 00:00' STOP '2024-01-02 00:00'"
        )
        self.assertIn("START", first(rule, Read).selector)
        self.assertIn("STOP", first(rule, Read).selector)


class HavingIsNotWhere(unittest.TestCase):
    """`WHERE` filters rows before grouping; `HAVING` filters groups after."""

    def test_an_aggregate_in_having_becomes_the_measures_column(self):
        # After grouping the count IS a column. Re-expressing the aggregate as
        # a row predicate asks each row whether its own count exceeds the
        # threshold, which is never true.
        rule = lower(BRUTE_FORCE)
        having = all_of(rule, Filter)[1]
        self.assertEqual(having.condition.left.name, "hits")
        self.assertEqual(having.condition.right.value, 5)

    def test_an_aggregate_only_named_in_having_is_added_to_the_grouping(self):
        rule, diagnostics = lower_qradar(
            "SELECT sourceip FROM events GROUP BY sourceip "
            "HAVING COUNT(*) > 3"
        )
        aggregate = first(rule, Aggregate)
        self.assertEqual(len(aggregate.measures), 1)
        self.assertIn("AQL_AGGREGATE_ADDED", [d.code for d in diagnostics])

    def test_an_aggregate_in_where_is_refused_rather_than_moved(self):
        # Moving it to HAVING would change which rows reach the grouping.
        with self.assertRaises(Refusal) as caught:
            lower(
                "SELECT sourceip FROM events WHERE COUNT(*) > 3 "
                "GROUP BY sourceip"
            )
        self.assertEqual(caught.exception.code, "AQL_AGGREGATE_IN_WHERE")

    def test_having_without_any_aggregate_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower("SELECT sourceip FROM events HAVING sourceip = '1'")
        self.assertEqual(
            caught.exception.code, "AQL_HAVING_WITHOUT_AGGREGATE"
        )

    def test_the_two_filters_are_not_collapsed_into_one(self):
        rule = lower(BRUTE_FORCE)
        ids = [node.id for node in all_of(rule, Filter)]
        self.assertEqual(ids, ["where", "having"])


class Aggregates(unittest.TestCase):
    def test_count_star_counts_rows_and_count_field_skips_nulls(self):
        # SQL's `COUNT(field)` does not count rows where the field is NULL.
        # Lowering it as `COUNT(*)` counts a population the rule excluded.
        star = first(lower(
            "SELECT COUNT(*) AS c FROM events GROUP BY sourceip"
        ), Aggregate).measures[0]
        self.assertIsNone(star.field)

        named = first(lower(
            "SELECT COUNT(username) AS c FROM events GROUP BY sourceip"
        ), Aggregate).measures[0]
        self.assertEqual(named.field.name, "username")

    def test_uniquecount_is_a_distinct_count_not_a_count(self):
        # Mapped to `count` this reports attempts where the rule asked for
        # actors, which fires a password-spray rule on one account retrying.
        measure = first(lower(
            "SELECT UNIQUECOUNT(username) AS u FROM events GROUP BY sourceip"
        ), Aggregate).measures[0]
        self.assertEqual(measure.function, "dcount")

    def test_count_distinct_is_also_a_distinct_count(self):
        measure = first(lower(
            "SELECT COUNT(DISTINCT username) AS u FROM events "
            "GROUP BY sourceip"
        ), Aggregate).measures[0]
        self.assertEqual(measure.function, "dcount")
        self.assertTrue(measure.distinct)

    def test_a_distinct_count_actually_counts_distinctly(self):
        rule = lower(
            "SELECT sourceip, UNIQUECOUNT(username) AS users FROM events "
            "GROUP BY sourceip HAVING UNIQUECOUNT(username) > 2"
        )
        # One host, one user, five attempts: a spray rule must NOT fire.
        same_user = [{"sourceip": "10.0.0.5", "username": "bob"}] * 5
        self.assertFalse(evaluate(rule, same_user).matched)
        # One host, three users: it must.
        many = [
            {"sourceip": "10.0.0.5", "username": name}
            for name in ("a", "b", "c")
        ]
        self.assertTrue(evaluate(rule, many).matched)

    def test_group_by_without_an_aggregate_is_a_distinct(self):
        # Dropping the grouping instead would widen the result set.
        rule = lower("SELECT sourceip FROM events GROUP BY sourceip")
        self.assertIsInstance(first(rule, Distinct), Distinct)

    def test_an_aggregate_over_no_column_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower("SELECT SUM(*) AS s FROM events GROUP BY sourceip")
        self.assertEqual(caught.exception.code, "AQL_AGGREGATE_NEEDS_FIELD")

    def test_the_aggregate_output_survives_the_projection(self):
        # `SELECT sourceip, COUNT(*) AS hits` returned `sourceip` alone: the
        # projection kept only the non-aggregate items, so a threshold rule
        # reported WHICH host fired but not how many times -- the number the
        # threshold was set on was missing from the output.
        rule = lower(
            "SELECT sourceip, COUNT(*) AS hits FROM events "
            "GROUP BY sourceip HAVING COUNT(*) > 2"
        )
        result = evaluate(
            rule, [{"sourceip": "10.0.0.5"}] * 3
        )
        self.assertTrue(result.matched)
        self.assertEqual(
            set(result.rows[0].values), {"sourceip", "hits"}
        )

    def test_every_aggregate_in_the_table_lowers(self):
        for name, (_function, needs_argument) in AGGREGATES.items():
            argument = "username" if needs_argument else "*"
            with self.subTest(aggregate=name):
                rule = lower(
                    f"SELECT {name.upper()}({argument}) AS v FROM events "
                    f"GROUP BY sourceip"
                )
                self.assertEqual(len(first(rule, Aggregate).measures), 1)

    def test_last_as_an_aggregate_is_not_the_last_time_range(self):
        # `LAST` is both an Ariel clause keyword and an aggregate function.
        # Read as the clause, `SELECT LAST(username) ...` swallowed the SELECT
        # list into a time range and produced a rule with no measures at all.
        rule = lower(
            "SELECT LAST(username) AS seen FROM events GROUP BY sourceip"
        )
        self.assertEqual(first(rule, Read).selector, "")
        self.assertEqual(first(rule, Aggregate).measures[0].function, "latest")

    def test_the_time_range_still_parses_when_an_aggregate_shares_its_name(self):
        rule = lower(
            "SELECT LAST(username) AS seen FROM events GROUP BY sourceip "
            "LAST 2 HOURS"
        )
        self.assertEqual(first(rule, Read).selector, "LAST 2 HOURS")
        self.assertEqual(first(rule, Aggregate).measures[0].function, "latest")


class Functions(unittest.TestCase):
    def test_incidr_takes_the_network_first_and_is_swapped(self):
        # AQL puts the network first; the engine's `cidr_contains` puts the
        # address first, like every other dialect here. Passing them straight
        # through makes the network the subject, which never matches and never
        # errors.
        condition = lower(
            "SELECT * FROM events WHERE INCIDR('10.0.0.0/8', sourceip)"
        ).pipeline[1].condition
        self.assertEqual(
            render_expr(condition), 'cidr_contains(sourceip, "10.0.0.0/8")'
        )

    def test_it_is_swapped_back_on_the_way_out(self):
        rule = lower(
            "SELECT * FROM events WHERE INCIDR('10.0.0.0/8', sourceip)"
        )
        self.assertIn("INCIDR('10.0.0.0/8', sourceip)", render_qradar(rule))

    def test_incidr_actually_evaluates(self):
        rule = lower(
            "SELECT * FROM events WHERE INCIDR('10.0.0.0/8', sourceip)"
        )
        self.assertTrue(evaluate(rule, [{"sourceip": "10.1.2.3"}]).matched)
        self.assertFalse(evaluate(rule, [{"sourceip": "192.168.1.1"}]).matched)

    def test_strlen_and_lower_round_trip(self):
        rule = lower("SELECT * FROM events WHERE LOWER(username) = 'admin'")
        self.assertIn("LOWER(username) = 'admin'", render_qradar(rule))


class RegexIsJavaAndIsNotExecutable(unittest.TestCase):
    def test_matches_is_tagged_as_java_regex(self):
        condition = lower(
            "SELECT * FROM events WHERE payload MATCHES 'a.*b'"
        ).pipeline[1].condition
        self.assertIsInstance(condition.right, Regex)
        self.assertEqual(condition.right.dialect, REGEX_DIALECT)

    def test_the_spec_declares_it(self):
        self.assertEqual(SPEC.default_regex_dialect, REGEX_DIALECT)

    def test_running_it_refuses_rather_than_guessing(self):
        # Running a Java pattern with Python's `re` and reporting the result as
        # Java would be a false claim about a security control.
        rule = lower("SELECT * FROM events WHERE payload MATCHES 'a.*b'")
        result = evaluate(rule, [{"payload": "aXXb"}])
        self.assertFalse(result.matched)

    def test_like_is_not_a_regex_and_does_evaluate(self):
        # LIKE is a SQL wildcard test, so most AQL rules stay testable.
        rule = lower("SELECT * FROM events WHERE username LIKE '%adm%'")
        self.assertTrue(evaluate(rule, [{"username": "badmin"}]).matched)
        self.assertFalse(evaluate(rule, [{"username": "root"}]).matched)

    def test_ilike_keeps_its_case_insensitivity(self):
        # Downgraded to LIKE this becomes case-SENSITIVE and stops matching
        # the events it was written for.
        rule = lower("SELECT * FROM events WHERE username ILIKE '%ADM%'")
        self.assertTrue(evaluate(rule, [{"username": "badmin"}]).matched)
        self.assertIn("ILIKE", render_qradar(rule))

    def test_not_like_is_read_back_as_a_negated_match(self):
        rule = lower(
            "SELECT * FROM events WHERE username NOT LIKE '%guest%'"
        )
        condition = rule.pipeline[1].condition
        self.assertTrue(condition.negate)
        rendered = render_qradar(rule)
        self.assertIn("NOT (username LIKE", rendered)
        self.assertEqual(render_qradar(lower(rendered)), rendered)


class Parsing(unittest.TestCase):
    def test_the_clauses_are_split(self):
        parsed = parse_qradar(BRUTE_FORCE)
        self.assertEqual(parsed.source, "events")
        self.assertEqual(parsed.group_by, "sourceip")
        self.assertEqual(parsed.limit, "10")
        self.assertEqual(parsed.time_range, "24 HOURS")

    def test_a_subselect_does_not_split_the_predicate(self):
        # `IN (SELECT ...)` contains the word SELECT. Splitting on it would cut
        # the predicate in half and leave the remainder unread.
        parsed = parse_qradar(
            "SELECT * FROM events WHERE sourceip IN "
            "(SELECT sourceip FROM events) AND qid = 1"
        )
        self.assertIn("qid = 1", parsed.where)

    def test_a_comment_is_ignored(self):
        parsed = parse_qradar(
            "SELECT * FROM events -- the comment\nWHERE qid = 1"
        )
        self.assertEqual(parsed.where, "qid = 1")

    def test_a_repeated_clause_is_refused_rather_than_picked(self):
        with self.assertRaises(Refusal) as caught:
            parse_qradar("SELECT * FROM events WHERE a=1 WHERE b=2")
        self.assertEqual(caught.exception.code, "AQL_CLAUSE_REPEATED")

    def test_several_statements_are_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_qradar("SELECT * FROM events; SELECT * FROM flows")
        self.assertEqual(caught.exception.code, "AQL_MULTIPLE_STATEMENTS")

    def test_empty_text_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_qradar("   \n  ")
        self.assertEqual(caught.exception.code, "AQL_EMPTY")

    def test_text_that_is_not_aql_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_qradar("index=main | stats count")
        self.assertEqual(caught.exception.code, "AQL_NO_CLAUSES")


class Refusals(unittest.TestCase):
    def test_a_query_with_no_from_is_refused(self):
        # AQL defaults to `events` interactively. Defaulting here would make a
        # rule whose source depends on where it was run.
        with self.assertRaises(Refusal) as caught:
            lower("SELECT * WHERE qid = 1")
        self.assertEqual(caught.exception.code, "AQL_NO_FROM")

    def test_several_sources_are_refused_rather_than_joined(self):
        with self.assertRaises(Refusal) as caught:
            lower("SELECT * FROM events, flows WHERE qid = 1")
        self.assertEqual(caught.exception.code, "AQL_FROM_MULTIPLE")

    def test_a_computed_select_expression_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower("SELECT sourceport + 1 AS p FROM events")
        self.assertEqual(caught.exception.code, "AQL_SELECT_EXPRESSION")

    def test_an_empty_where_is_refused_rather_than_passing_everything(self):
        # The dangerous shape: the analyst wrote a restriction and left it
        # blank. Treated as absent it becomes a rule with no filter, which
        # passes every row and reports success.
        with self.assertRaises(Refusal) as caught:
            lower("SELECT * FROM events WHERE   ")
        self.assertEqual(caught.exception.code, "AQL_CLAUSE_EMPTY")

    def test_a_predicate_that_is_only_partly_read_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower("SELECT * FROM events WHERE qid = 1 frobnicate 2")
        self.assertEqual(caught.exception.code, "AQL_EXPRESSION_TRAILING")

    def test_a_limit_that_keeps_nothing_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower("SELECT * FROM events WHERE qid=1 LIMIT 0")
        self.assertEqual(caught.exception.code, "AQL_LIMIT_NOT_POSITIVE")

    def test_a_limit_that_is_not_a_number_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower("SELECT * FROM events WHERE qid=1 LIMIT lots")
        self.assertEqual(caught.exception.code, "AQL_LIMIT_NOT_A_NUMBER")

    def test_grouping_by_an_expression_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower("SELECT COUNT(*) AS c FROM events GROUP BY LOWER(username)")
        self.assertEqual(caught.exception.code, "AQL_NOT_A_FIELD")


class Rendering(unittest.TestCase):
    def setUp(self):
        self.rule = lower(BRUTE_FORCE)
        self.text = render_qradar(self.rule)

    def test_the_clauses_come_back_in_written_order(self):
        # Lowering reordered them into execution order; rendering has to put
        # them back, because AQL is not valid in execution order.
        lines = [l.split()[0] for l in self.text.splitlines() if l.strip()]
        self.assertEqual(
            lines[:6],
            ["SELECT", "FROM", "WHERE", "GROUP", "HAVING", "ORDER"],
        )

    def test_the_time_range_is_written_back(self):
        self.assertIn("LAST 24 HOURS", self.text)

    def test_rendering_is_stable_across_two_round_trips(self):
        # An unstable renderer makes every save look like a change in history.
        again, _ = lower_qradar(self.text)
        self.assertEqual(render_qradar(again), self.text)

    def test_a_group_key_is_selected_as_well_as_grouped(self):
        # Ariel returns only what is selected, so grouping by a column without
        # selecting it produces counts with nothing to attribute them to.
        rule = lower(
            "SELECT COUNT(*) AS c FROM events GROUP BY sourceip"
        )
        text = render_qradar(rule)
        self.assertIn("sourceip", text.splitlines()[0])

    def test_a_contains_becomes_a_like_with_escaped_wildcards(self):
        # A literal `%` in the value would otherwise become a wildcard and
        # widen the test.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table="events"),
                Filter(id="f", condition=Comparison(
                    "contains", FieldRef(name="msg"), Literal("100%")
                )),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        # TWO backslashes: one layer for the LIKE escape, one for the AQL
        # string literal that the tokenizer unescapes on the way back in.
        self.assertIn("LIKE '%100\\\\%%'", render_qradar(rule))
        # And prove it is the form that survives a round trip.
        back, _ = dialects.lower("qradar", render_qradar(rule))
        condition = next(
            n.condition for n in back.pipeline if type(n).__name__ == "Filter"
        )
        self.assertTrue(_glob_match("100%", condition.right.value, False))
        self.assertFalse(_glob_match("100x", condition.right.value, False))

    def test_an_unrenderable_stage_is_refused_rather_than_dropped(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table="events"),
                Expand(id="e", field=FieldRef(name="a"), into="b"),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_qradar(rule)
        self.assertEqual(caught.exception.code, "AQL_RENDER_STAGE")

    def test_a_rule_with_no_source_is_refused(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Filter(id="f", condition=Comparison(
                    "==", FieldRef(name="a"), Literal(1)
                )),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_qradar(rule)
        self.assertEqual(caught.exception.code, "AQL_RENDER_NO_SOURCE")

    def test_a_nested_field_is_refused_because_ariel_is_flat(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table="events"),
                Filter(id="f", condition=Comparison(
                    "==", FieldRef(name="a", path=("b",)), Literal(1)
                )),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_qradar(rule)
        self.assertEqual(caught.exception.code, "AQL_RENDER_NESTED_FIELD")

    def test_a_keyword_column_is_quoted_on_the_way_out(self):
        # An unquoted `order` would start an ORDER BY clause when the query is
        # read back.
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table="events"),
                Filter(id="f", condition=Comparison(
                    "==", FieldRef(name="order"), Literal(1)
                )),
                Emit(id="o"),
            ),
            annotations=Annotations(title=""),
            metadata={"dialect": DIALECT},
        )
        self.assertIn('"order" = 1', render_qradar(rule))


class RegistryIntegration(unittest.TestCase):
    def test_it_is_registered_and_ready(self):
        entry = dialects.get("qradar")
        self.assertTrue(entry.can_parse)
        self.assertTrue(entry.can_render)

    def test_it_round_trips_through_the_registry(self):
        rule, _ = dialects.lower("qradar", BRUTE_FORCE)
        text, notes = dialects.render("qradar", rule)
        self.assertEqual(notes, [], "a same-dialect render loses nothing")
        again, _ = dialects.lower("qradar", text)
        self.assertEqual(stages(again), stages(rule))

    def test_its_time_range_is_reported_when_rendered_elsewhere(self):
        # `LAST 24 HOURS` is AQL text. Rendered into KQL it is dropped, and a
        # rule that reads a wider window than it was written for must say so.
        rule, _ = dialects.lower("qradar", BRUTE_FORCE)
        _, notes = dialects.render("sentinel", rule)
        self.assertIn("SELECTOR_NOT_TRANSFERABLE", [n.code for n in notes])


if __name__ == "__main__":
    unittest.main()
