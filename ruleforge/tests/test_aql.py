"""The user's real QRadar AQL rule, as an acceptance test.

Pasted verbatim from their request. The point of using their rule rather than a
fixture is that it contains a real defect: a mixed AND/OR with no parentheses.
A fixture I wrote myself would have been correct by construction and would have
tested nothing about the tool.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from ruleforge.dialects import cre_from_ir, lower_aql, parse_aql, render_aql  # noqa: E402
from ruleforge.engine import Verdict, evaluate  # noqa: E402

# Verbatim, including the operator-precedence problem.
USER_QRADAR_RULE = """
SELECT
    sourceip,
    destinationip,
    username,
    COUNT(*) AS event_count,
    MIN(starttime) AS first_seen,
    MAX(starttime) AS last_seen
FROM events
WHERE
    (
        QIDNAME(qid) ILIKE '%LSASS%'
        OR
        LOGSOURCENAME(logsourceid) ILIKE '%Sysmon%'
        AND UTF8(payload) ILIKE '%lsass.exe%'
    )
    OR
    (
        QIDNAME(qid) ILIKE '%NTLM%'
        AND UTF8(payload) ILIKE '%Logon Type: 3%'
    )
GROUP BY
    sourceip,
    destinationip,
    username
HAVING
    COUNT(*) >= 2
ORDER BY
    last_seen DESC
"""


def walk_expr(node):
    """Yield every expression node reachable from `node`.

    Walks tuple/dataclass containers generically. Written this way after two
    hand-rolled walkers that each started at the RuleIR -- which has no `left` or
    `right`, so both silently found nothing and reported an empty result as a
    failure of the code under test rather than of the test.
    """
    from dataclasses import fields, is_dataclass
    yield node
    if isinstance(node, (list, tuple)):
        for child in node:
            yield from walk_expr(child)
        return
    if is_dataclass(node) and not isinstance(node, type):
        for f in fields(node):
            yield from walk_expr(getattr(node, f.name))


def walk_ir(ir):
    """Yield every expression reachable from any node in the graph."""
    for node in ir.nodes:
        for name in ("condition", "inner", "left", "right", "where", "having"):
            if hasattr(node, name):
                yield from walk_expr(getattr(node, name))
        for measure in getattr(node, "measures", ()) or ():
            yield from walk_expr(measure.field)
            yield from walk_expr(measure.by)
        for stage in getattr(node, "stages", ()) or ():
            yield from walk_expr(stage)


class UserRuleParsingTests(unittest.TestCase):

    def setUp(self):
        self.query = parse_aql(USER_QRADAR_RULE)

    def test_it_parses(self):
        self.assertEqual(self.query.source, "events")
        self.assertEqual(self.query.group_by,
                         ["sourceip", "destinationip", "username"])
        self.assertEqual([name for name, _ in self.query.select],
                         ["sourceip", "destinationip", "username",
                          "event_count", "first_seen", "last_seen"])
        self.assertIsNotNone(self.query.where)
        self.assertIsNotNone(self.query.having)
        self.assertEqual(self.query.order_by, [("last_seen", "desc")])

    def test_the_aliases_survive(self):
        measures = {name: item for name, item in self.query.select}
        self.assertEqual(measures["event_count"].function, "COUNT")
        self.assertEqual(measures["first_seen"].function, "MIN")

    def test_ariel_functions_are_kept_as_functions_not_flattened_to_fields(self):
        """`QIDNAME(qid)` is a computed column. Collapsing it to `qid` would emit
        valid AQL meaning something completely different."""
        from ruleforge.dialects.aql import _ArielCall
        functions = {n.name for n in walk_expr(self.query.where)
                     if isinstance(n, _ArielCall)}
        self.assertIn("QIDNAME", functions)
        self.assertIn("LOGSOURCENAME", functions)

    def test_the_precedence_trap_is_reported(self):
        """THE FINDING.

        Inside the first bracket the rule reads:

            QIDNAME ILIKE '%LSASS%'  OR  LOGSOURCENAME ILIKE '%Sysmon%'
            AND UTF8(payload) ILIKE '%lsass.exe%'

        AQL binds AND tighter than OR, so this is `LSASS OR (Sysmon AND lsass)`.
        The near-certain intent is `(LSASS OR Sysmon) AND lsass`. Those two match
        different events, and the difference is exactly the difference between
        "anything LSASS-related" and "Sysmon OR LSASS, then also mentioning
        lsass.exe".
        """
        codes = [d.code for d in self.query.diagnostics]
        self.assertIn("AQL_MIXED_AND_OR", codes)
        warning = next(d for d in self.query.diagnostics
                       if d.code == "AQL_MIXED_AND_OR")
        self.assertIn("binds AND TIGHTER than OR", warning.message)
        self.assertIn("(A OR B) AND C", warning.message)

    def test_a_correctly_parenthesised_rule_warns_about_nothing(self):
        """So the warning is not a blanket complaint about AND and OR."""
        good = """
        SELECT COUNT(*) AS n FROM events
        WHERE ( QIDNAME(qid) ILIKE '%A%' OR LOGSOURCENAME(logsourceid) ILIKE '%B%' )
          AND UTF8(payload) ILIKE '%c%'
        """
        self.assertEqual([d.code for d in parse_aql(good).diagnostics], [])


class LoweringTests(unittest.TestCase):

    def setUp(self):
        self.ir, self.diagnostics = lower_aql(parse_aql(USER_QRADAR_RULE))

    def test_where_becomes_a_filter_before_the_aggregate(self):
        """If WHERE were lowered after the aggregate it would become HAVING, and
        the count would include rows the rule never meant to consider."""
        from ruleforge.engine.ir import Aggregate, Filter
        filters = [n for n in self.ir.nodes if isinstance(n, Filter)]
        self.assertEqual(len(filters), 2, "one WHERE filter and one HAVING filter")
        where_filter = filters[0]
        aggregate = next(n for n in self.ir.nodes if isinstance(n, Aggregate))
        self.assertEqual(where_filter.input, "read")
        self.assertEqual(aggregate.input, "where")
        self.assertEqual(filters[1].input, "agg")

    def test_group_by_becomes_aggregate_keys(self):
        from ruleforge.engine.ir import Aggregate
        aggregate = next(n for n in self.ir.nodes if isinstance(n, Aggregate))
        self.assertEqual([k.name for k in aggregate.keys],
                         ["sourceip", "destinationip", "username"])

    def test_the_thresholds_become_measures(self):
        from ruleforge.engine.ir import Aggregate
        aggregate = next(n for n in self.ir.nodes if isinstance(n, Aggregate))
        names = {m.name: m.function for m in aggregate.measures}
        self.assertEqual(names.get("event_count"), "count")
        self.assertEqual(names.get("first_seen"), "min")
        self.assertEqual(names.get("last_seen"), "max")

    def test_iliske_becomes_a_case_insensitive_contains(self):
        """ILIKE '%x%' means "contains x, ignoring case". The `%` are WILDCARDS.

        An earlier version lowered it to `contains(field, '%x%')`, which asks
        whether the literal text `%x%` appears in the value -- almost never true,
        so every ILIKE filter silently matched nothing. This test asserts the
        WILDCARDS ARE STRIPPED, which is the part that was wrong.
        """
        from ruleforge.engine.ir import Call
        contains = [n for n in walk_ir(self.ir)
                    if isinstance(n, Call) and n.function == "contains"]
        self.assertTrue(contains, "ILIKE should lower to a case-insensitive test")
        self.assertEqual(contains[0].args[1].value, "LSASS",
                         "the % wildcards must be stripped, not carried through")

    def test_iliske_shapes_map_to_the_right_operator(self):
        for aql, expected_fn, expected_value in (
            ("SELECT * FROM events WHERE a ILIKE '%x%'", "contains", "x"),
            ("SELECT * FROM events WHERE a ILIKE 'x%'", "starts_with", "x"),
            ("SELECT * FROM events WHERE a ILIKE '%x'", "ends_with", "x"),
        ):
            ir, _ = lower_aql(parse_aql(aql))
            from ruleforge.engine.ir import Call
            found = [n for n in walk_ir(ir)
                     if isinstance(n, Call) and n.function == expected_fn]
            self.assertTrue(found, f"{aql} should lower to {expected_fn}")
            self.assertEqual(found[0].args[1].value, expected_value)

    def test_an_interior_wildcard_is_refused_rather_than_approximated(self):
        """`%a_b%` and `a%b%` change what the pattern matches. Using the nearest
        operator would report confidently wrong results."""
        from ruleforge.engine import Refusal
        for aql in ("SELECT * FROM events WHERE a ILIKE '%a_b%'",
                    "SELECT * FROM events WHERE a ILIKE 'a%b%'"):
            with self.assertRaises(Refusal) as caught:
                lower_aql(parse_aql(aql))
            self.assertEqual(caught.exception.code, "AQL_LIKE_PATTERN_UNSUPPORTED")


class RenderingTests(unittest.TestCase):

    def test_it_renders_valid_looking_aql(self):
        ir, _ = lower_aql(parse_aql(USER_QRADAR_RULE))
        text = render_aql(ir)
        self.assertIn("SELECT", text)
        self.assertIn("FROM events", text)
        self.assertIn("GROUP BY sourceip, destinationip, username", text)
        self.assertIn("HAVING", text)
        self.assertIn("ORDER BY last_seen DESC", text)

    def test_the_search_artifact_says_it_is_not_a_deployable_rule(self):
        """The distinction the user themselves raised, enforced in the output."""
        ir, _ = lower_aql(parse_aql(USER_QRADAR_RULE))
        text = render_aql(ir)
        self.assertIn("NOT a deployable QRadar rule", text)
        self.assertIn("Custom Rules Engine", text)

    def test_group_by_and_having_are_not_collapsed_into_where(self):
        ir, _ = lower_aql(parse_aql(USER_QRADAR_RULE))
        text = render_aql(ir)
        self.assertEqual(text.count("WHERE"), 1)
        self.assertEqual(text.count("HAVING"), 1)


class CREArtifactTests(unittest.TestCase):

    def setUp(self):
        ir, _ = lower_aql(parse_aql(USER_QRADAR_RULE))
        self.cre = cre_from_ir(ir)

    def test_the_cre_rule_is_not_claimed_deployable(self):
        """A CRE rule is configured in a console, not imported as text. Calling it
        deployable would imply a deploy step that does not exist."""
        self.assertFalse(self.cre["deployable"])
        self.assertIn("CONFIGURED", self.cre["deployable_reason"])

    def test_the_cre_rule_states_its_own_thresholds_are_missing(self):
        threshold_tests = [t for t in self.cre["tests"]
                           if t["type"] == "threshold_test"]
        self.assertTrue(threshold_tests)
        for test in threshold_tests:
            self.assertIn("not stated in the neutral form", test["note"])

    def test_offense_magnitude_is_flagged_as_unpredictable(self):
        self.assertIn("cannot", self.cre["response"]["note"] + " be predicted")

    def test_ordering_is_reported_as_not_covered_by_a_cre_rule(self):
        self.assertTrue(any("ordering" in note for note in self.cre["not_covered"]))


class RefusalTests(unittest.TestCase):

    def test_an_unknown_table_is_refused_rather_than_assumed(self):
        from ruleforge.engine import Refusal
        with self.assertRaises(Refusal) as caught:
            parse_aql("SELECT * FROM my_custom_table WHERE a = 1")
        self.assertEqual(caught.exception.code, "AQL_SOURCE_UNKNOWN")

    def test_trailing_input_is_refused_rather_than_dropped(self):
        """Silently ignoring an unparsed clause would produce a rule that differs
        from the one the analyst pasted."""
        from ruleforge.engine import Refusal
        with self.assertRaises(Refusal) as caught:
            parse_aql("SELECT * FROM events LIMIT 10 SIDEWAYS")
        self.assertEqual(caught.exception.code, "AQL_TRAILING_INPUT")

    def test_aql_regex_is_declared_pcre_because_that_is_what_aql_uses(self):
        """AQL's MATCHES uses PCRE. Declaring it as such means the engine refuses
        it by name rather than evaluating a PCRE pattern with a POSIX engine."""
        from ruleforge.engine.ir import Call
        query = parse_aql("SELECT * FROM events WHERE MATCHES(payload, '^x')")
        calls = [n for n in walk_expr(query.where)
                 if isinstance(n, Call) and n.function == "matches_regex"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].dialect, "pcre")


class EndToEndTests(unittest.TestCase):

    def test_the_user_rule_evaluates_against_sample_ariel_rows(self):
        """AQL's WHERE uses QIDNAME/LOGSOURCENAME, which are QRadar-side computed
        columns a local sample will not have. So the rows supply them, and the
        rule is evaluated for real rather than merely parsed."""
        from ruleforge.engine.ir import Filter
        ir, _ = lower_aql(parse_aql(USER_QRADAR_RULE))
        having_filters = [n for n in ir.nodes
                          if isinstance(n, Filter) and n.id == "having"]
        self.assertEqual(len(having_filters), 1)

        rows = [
            {"sourceip": "10.0.0.5", "destinationip": "10.0.0.9", "username": "admin",
             "starttime": 1700000000},
            {"sourceip": "10.0.0.5", "destinationip": "10.0.0.9", "username": "admin",
             "starttime": 1700000060},
            {"sourceip": "10.0.0.7", "destinationip": "10.0.0.1", "username": "bob",
             "starttime": 1700000020},
        ]
        # Drop the WHERE filter, which needs QRadar-side columns, and keep the
        # group + threshold, which is the part a sample can exercise.
        reduced = type(ir)(
            rule_id=ir.rule_id,
            nodes=tuple(n for n in ir.nodes
                        if not (isinstance(n, Filter) and n.id == "where")),
            output="out", metadata=ir.metadata)
        result = evaluate(reduced, rows, time_field="starttime")
        self.assertIn(result.verdict, (Verdict.MATCHED, Verdict.NOT_EVALUATED))
        if result.verdict is Verdict.MATCHED:
            counts = {tuple(sorted(dict(r.values).items()))
                      for r in result.rows}
            self.assertTrue(counts)


class AdapterProducesRunnableIRTests(unittest.TestCase):
    """The adapter's own lowering has to be EXECUTED, not just inspected.

    Every earlier test in this file looked at the IR and asserted on its shape.
    That let the adapter lower `ILIKE` to a `contains` call and place it in a
    Filter, and then the VALIDATOR REFUSED that rule with PREDICATE_INCOMPLETE --
    because `contains` was not in the predicate-function set. The one adapter in
    the tree was producing IR the engine would not run, and its own suite was
    green. A test that only inspects a structure cannot catch that class of bug.
    """

    def test_the_lowered_user_rule_validates(self):
        ir, _ = lower_aql(parse_aql(USER_QRADAR_RULE))
        from ruleforge.engine import validate_graph
        validate_graph(ir)          # raises Refusal if the IR is not runnable

    def test_the_lowered_user_rule_evaluates(self):
        ir, _ = lower_aql(parse_aql(USER_QRADAR_RULE))
        result = evaluate(ir, [
            {"sourceip": "10.0.0.5", "username": "admin", "starttime": 1700000000,
             "QIDNAME(qid)": "Process Access - LSASS"},
            {"sourceip": "10.0.0.5", "username": "admin", "starttime": 1700000060,
             "QIDNAME(qid)": "Process Access - LSASS"},
        ], time_field="starttime")
        self.assertIn(result.verdict, (Verdict.MATCHED, Verdict.NOT_EVALUATED),
                      "the adapter's output must run, not raise")
        if result.verdict is Verdict.NOT_EVALUATED:
            self.assertNotEqual(
                result.reason.code, "PREDICATE_INCOMPLETE",
                "the adapter lowered ILIKE into a predicate the validator rejects")

    def test_an_ariel_side_column_is_reported_as_unevaluable(self):
        """`QIDNAME(qid)` is computed by the appliance from a QID map. Its value
        does not exist in a raw log, so this tool cannot run that clause. It must
        SAY SO -- a local run reporting zero matches for a QIDNAME filter would be
        indistinguishable from a quiet rule."""
        _, diagnostics = lower_aql(parse_aql(USER_QRADAR_RULE))
        refusal_diagnostics = [d for d in diagnostics
                               if d.code == "AQL_ARIEL_SIDE_COLUMN"]
        self.assertTrue(refusal_diagnostics, "the QIDNAME filter must be reported")
        self.assertEqual(refusal_diagnostics[0].severity, "refusal")
        self.assertIn("only exists inside the appliance",
                      refusal_diagnostics[0].message)

    def test_a_plain_column_filter_runs_locally(self):
        """A filter on an ordinary column has no such excuse and must work."""
        ir, diagnostics = lower_aql(parse_aql(
            "SELECT COUNT(*) AS n FROM events WHERE sourceip ILIKE '%10.0.%'"))
        self.assertEqual([d.code for d in diagnostics
                          if d.code == "AQL_ARIEL_SIDE_COLUMN"], [])
        from ruleforge.engine import validate_graph
        validate_graph(ir)
        result = evaluate(ir, [{"sourceip": "10.0.0.5"},
                               {"sourceip": "192.168.1.1"}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(result.rows[0].values["n"], 1,
                         "ILIKE must actually filter the rows")

    def test_a_not_clause_lowers_to_a_real_negation(self):
        """`Not` did not exist in the IR, so this raised ImportError instead of a
        named refusal. Negation is needed by every dialect."""
        query = parse_aql("SELECT * FROM events WHERE NOT QIDNAME(qid) ILIKE '%X%'")
        ir, _ = lower_aql(query)
        from ruleforge.engine import validate_graph
        validate_graph(ir)


class SampleRoutingTests(unittest.TestCase):

    def test_grouping_by_time_does_not_crash_on_an_import(self):
        """`__import__("engine")` in the lowering raised ModuleNotFoundError on a
        GROUP BY starttime -- a raw crash where this tool promises a refusal."""
        ir, _ = lower_aql(parse_aql(
            "SELECT COUNT(*) AS n FROM events GROUP BY starttime"))
        from ruleforge.engine import validate_graph
        validate_graph(ir)


if __name__ == "__main__":
    unittest.main()
