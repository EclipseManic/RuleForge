"""Splunk SPL tests.

IMPORTANT ABOUT THE FIXTURE

The user's own SPL rule is NOT reproduced here. It is not present anywhere in the
repository, and inventing one and calling it "the user's rule" would repeat the
exact mistake the Wazuh work made twice: a fixture I wrote is correct by
construction, so it proves nothing about the parser.

So the search below is the reference SPL from this project's own
`docs/advanced-rule-corpus.md`, which the old tool owned and which no longer
exists; the search below is inlined here for that reason and is labelled as such.
It is still a real
search -- it uses Splunk's documented syntax -- and the tstats cases come
verbatim from Splunk's official SearchReference, which is where the constraints
that actually shape this lowering are written down.
"""
from __future__ import annotations

import unittest

from dialects.spl import (
    SplParseError,
    parse_search_terms,
    parse_spl,
    parse_stats,
    walk_terms,
)
from dialects.spl_ir import lower
from dialects.spl_render import render as render_spl
from engine import Verdict, evaluate
from engine.ir import Aggregate, Filter

#: From docs/advanced-rule-corpus.md. Real syntax, not invented.
CORPUS_SPL = (
    'index=windows sourcetype=WinEventLog:Security EventCode=4688 '
    '| search process_name IN ("powershell.exe", "cmd.exe") '
    "| stats count AS process_count dc(dest_ip) AS destination_count "
    "values(command_line) AS commands by host user "
    "| where process_count >= 3 AND destination_count >= 2"
)

#: From Splunk SearchReference: tstats.
DOC_TSTATS = (
    "| tstats count AS n distinct_count(dest_ip) AS d "
    "FROM datamodel=Authentication.Authentication "
    "WHERE index=main sourcetype=WinEventLog:Security "
    "BY host span=1h"
)


class ParseTests(unittest.TestCase):
    def test_the_leading_search_terms_are_read(self):
        search = parse_spl(CORPUS_SPL)
        self.assertEqual(search.indexes, ("windows",))
        self.assertEqual(search.sourcetypes, ("WinEventLog:Security",))

    def test_the_pipeline_is_split_on_pipes(self):
        search = parse_spl(CORPUS_SPL)
        self.assertEqual([c.name for c in search.pipeline],
                         ["search", "stats", "where"])

    def test_all_three_measures_survive(self):
        """`count` HAS NO PARENTHESES. An earlier parser required `name(` and
        dropped it, so the most common aggregate in SPL vanished from the rule
        while the rest still parsed and the output still looked well formed."""
        search = parse_spl(CORPUS_SPL)
        stats = parse_stats(search.pipeline[1].args, "stats")
        self.assertEqual([(m.function, m.field, m.alias) for m in stats.measures],
                         [("count", None, "process_count"),
                          ("dc", "dest_ip", "destination_count"),
                          ("values", "command_line", "commands")])

    def test_by_fields_split_on_whitespace_as_well_as_commas(self):
        """`by host user` is two keys. Splitting on commas alone produced the
        single key "host user", a field that does not exist."""
        search = parse_spl(CORPUS_SPL)
        stats = parse_stats(search.pipeline[1].args, "stats")
        self.assertEqual(stats.keys, ("host", "user"))

    def test_in_a_value_list_is_parsed(self):
        terms = walk_terms((parse_search_terms('process_name IN ("a.exe", "b.exe")'),))
        term = terms[0]
        self.assertEqual(term.field, "process_name")
        self.assertEqual(term.values, ("a.exe", "b.exe"))
        self.assertFalse(term.negate)

    def test_not_in_is_negated(self):
        terms = walk_terms((parse_search_terms('user NOT IN ("admin")'),))
        self.assertTrue(terms[0].negate)

    def test_multi_character_operators_stay_whole(self):
        """Splitting `<=` into `<` and `=` would compare a field to nothing."""
        terms = walk_terms((parse_search_terms("bytes >= 1024"),))
        self.assertEqual(terms[0].op, ">=")

    def test_a_value_containing_an_equals_sign_survives(self):
        terms = walk_terms((parse_search_terms('query="a=b"'),))
        self.assertEqual(terms[0].value, "a=b")

    def test_or_becomes_a_nested_tree_not_a_flattened_list(self):
        terms = walk_terms((parse_search_terms("a=1 OR b=2"),))
        self.assertEqual({t.field for t in terms}, {"a", "b"})

    def test_a_bare_word_is_a_field_existence_test_not_a_dropped_term(self):
        """In Splunk search a bare term asserts the field exists.

        An earlier version of this test demanded a refusal, on the theory that a
        bare word means "the raw event contains this string". That is only true
        when the word is NOT a field in the index -- and which fields exist is
        something only the deployment knows, not the rule text. So the honest
        lowering is field-existence PLUS a diagnostic saying the other reading is
        possible. Refusing outright would reject `index=main EventCode` in a rule
        a Splunk user would consider ordinary.
        """
        terms = walk_terms((parse_search_terms("index=main EventCode"),))
        self.assertEqual(len(terms), 2)
        bare = next(t for t in terms if t.field == "EventCode")
        self.assertIsNone(bare.op, "a bare term has no comparison operator")

    def test_the_bare_word_ambiguity_is_reported_when_lowering(self):
        ir, diagnostics = lower("index=main EventCode")
        self.assertIn("SPL_BARE_TERM_MAY_BE_A_RAW_SEARCH",
                      [d["code"] for d in diagnostics])


class TstatsTests(unittest.TestCase):
    """The facts from Splunk's SearchReference that shape this lowering."""

    def test_dc_is_not_a_tstats_function(self):
        """tstats spells distinct count `distinct_count`. `dc` is the stats
        alias. Accepting it would claim the agent runs a function tstats lacks."""
        with self.assertRaises(SplParseError) as caught:
            parse_stats("dc(user) AS u BY host", "tstats")
        self.assertEqual(caught.exception.code,
                         "SPL_TSTATS_FUNCTION_NOT_SUPPORTED")

    def test_distinct_count_is_accepted_under_tstats(self):
        stats = parse_stats("distinct_count(user) AS u BY host", "tstats")
        self.assertEqual(stats.measures[0].function, "distinct_count")

    def test_tstats_is_refused_for_local_evaluation_by_name(self):
        """tstats reads INDEX-TIME fields from tsidx. No event sample can
        reproduce that, so it is named rather than approximated as `stats`."""
        with self.assertRaises(SplParseError) as caught:
            lower(DOC_TSTATS)
        self.assertEqual(caught.exception.code, "TSTATS_NOT_EXECUTABLE_LOCALLY")
        self.assertIn("datamodel=Authentication.Authentication",
                      caught.exception.message)

    def test_the_refusal_says_what_to_do_instead(self):
        with self.assertRaises(SplParseError) as caught:
            lower(DOC_TSTATS)
        self.assertIn("run it in Splunk", caught.exception.message)

    def test_the_from_clause_does_not_swallow_the_where_clause(self):
        stats = parse_stats(DOC_TSTATS, "tstats")
        self.assertEqual(stats.from_clause,
                         "datamodel=Authentication.Authentication")
        self.assertEqual({t.field for t in walk_terms(stats.where)},
                         {"index", "sourcetype"})

    def test_span_is_carried(self):
        self.assertEqual(parse_stats(DOC_TSTATS, "tstats").span, "1h")


class SpanTests(unittest.TestCase):
    def test_grouping_by_time_without_a_span_is_refused(self):
        """Splunk requires span= with BY _time. Without it every event lands in
        one bucket, which is a different report from the one asked for."""
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | stats count BY _time")
        self.assertEqual(caught.exception.code, "SPL_TIME_BUCKET_WITHOUT_SPAN")

    def test_grouping_by_time_with_a_span_lowers(self):
        ir, diagnostics = lower("index=main | stats count BY _time span=1h")
        aggregate = next(n for n in ir.nodes if isinstance(n, Aggregate))
        self.assertEqual(aggregate.frame.kind, "tumbling")
        self.assertEqual(aggregate.frame.size.seconds, 3600)
        self.assertIn("SPL_TIME_BUCKET_SYNTHESISED",
                      [d["code"] for d in diagnostics])


class OpaqueCommandTests(unittest.TestCase):
    def test_lookup_is_refused_by_name(self):
        """A lookup reads an external CSV. Treating it as a filter changes what
        the rule detects."""
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | lookup privileged.csv user OUTPUT is_priv")
        self.assertEqual(caught.exception.code, "SPL_COMMAND_NOT_LOWERABLE")

    def test_transaction_is_refused_by_name(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | transaction user | stats count BY user")
        self.assertEqual(caught.exception.code, "SPL_COMMAND_NOT_LOWERABLE")

    def test_streamstats_is_refused_by_name(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | streamstats count BY user")
        self.assertEqual(caught.exception.code, "SPL_COMMAND_NOT_LOWERABLE")


class LoweringTests(unittest.TestCase):
    def test_the_aggregate_carries_three_measures_and_two_keys(self):
        ir, _ = lower(CORPUS_SPL)
        aggregate = next(n for n in ir.nodes if isinstance(n, Aggregate))
        self.assertEqual({m.name: m.function for m in aggregate.measures},
                         {"process_count": "count",
                          "destination_count": "distinct_count",
                          "commands": "set"})
        self.assertEqual({k.full for k in aggregate.keys}, {"host", "user"})

    def test_values_is_a_set_not_a_count(self):
        ir, _ = lower(CORPUS_SPL)
        aggregate = next(n for n in ir.nodes if isinstance(n, Aggregate))
        measure = next(m for m in aggregate.measures if m.name == "commands")
        self.assertEqual(measure.function, "set")

    def test_the_where_after_the_aggregate_becomes_a_filter(self):
        ir, _ = lower(CORPUS_SPL)
        condition = next(n.condition for n in ir.nodes
                         if isinstance(n, Filter) and n.id == "where_2")
        self.assertIsNotNone(condition)

    def test_index_and_sourcetype_become_one_filter_not_two_reads(self):
        """They are ANDed in SPL. Two Reads would union them, which is a
        different and much larger result set."""
        ir, _ = lower(CORPUS_SPL)
        selectors = next(n for n in ir.nodes
                         if isinstance(n, Filter) and n.id == "selectors")
        self.assertEqual(selectors.input, "read")
        reads = [n for n in ir.nodes if type(n).__name__ == "Read"]
        self.assertEqual(len(reads), 1)


class ExecutionTests(unittest.TestCase):
    """`stats` over raw events IS reproducible from a sample, so it runs."""

    def _ir(self):
        ir, _ = lower(CORPUS_SPL)
        return ir

    def _row(self, host, user, dest_ip, command, source="powershell.exe"):
        return {
            "index": "windows",
            "sourcetype": "WinEventLog:Security",
            "EventCode": 4688,
            "process_name": source,
            "host": host,
            "user": user,
            "dest_ip": dest_ip,
            "command_line": command,
        }

    def test_three_processes_to_two_hosts_fires(self):
        rows = [
            self._row("h1", "u1", "10.0.0.1", "cmd1"),
            self._row("h1", "u1", "10.0.0.2", "cmd2"),
            self._row("h1", "u1", "10.0.0.1", "cmd3"),
        ]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.MATCHED)

    def test_three_processes_to_one_host_does_not_fire(self):
        """The `destination_count >= 2` half of the rule."""
        rows = [self._row("h1", "u1", "10.0.0.1", f"cmd{n}") for n in range(3)]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_two_processes_to_two_hosts_does_not_fire(self):
        """The `process_count >= 3` half of the rule."""
        rows = [self._row("h1", "u1", "10.0.0.1", "cmd1"),
                self._row("h1", "u1", "10.0.0.2", "cmd2")]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_a_different_process_name_is_excluded(self):
        rows = [self._row("h1", "u1", f"10.0.0.{n}", f"cmd{n}",
                          source="notepad.exe") for n in range(1, 4)]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_grouping_is_per_host_and_user(self):
        """Three events each on three different hosts is three groups of one."""
        rows = [self._row(f"h{n}", "u1", "10.0.0.1", "cmd") for n in range(3)]
        result = evaluate(self._ir(), rows)
        self.assertIs(result.verdict, Verdict.NO_MATCH)


class PipelineCommandLoweringTests(unittest.TestCase):
    """`fields`, `rename`, `sort` and `head` LOWER instead of being refused.

    All eight of these used to hit ONE blanket `raise` in `spl_ir.py`, on the
    reasoning that each "changes which rows the search returns". True of
    `dedup`, `fillnull` and `regex`. Not true of these four: they change the
    OUTPUT SHAPE or the ORDER, which the IR models exactly, and the renderers
    already knew how to emit. So a plain `| fields a, b` -- one of the most
    ordinary lines in Splunk -- was refused.

    Each test asserts the ROUND TRIP, not just that lowering succeeded. A lowerer
    that produces a graph the renderer cannot faithfully write back has not fixed
    anything; it has moved the failure.
    """

    def _round_trip(self, source):
        ir, _ = lower(source)
        return " ".join(render_spl(ir).split())

    def test_fields_restricts_the_output_columns(self):
        self.assertEqual(
            self._round_trip("index=main EventCode=4624 | fields a, b"),
            'index=main | search EventCode="4624" | fields a, b')

    def test_rename_rewrites_the_field_name(self):
        self.assertEqual(
            self._round_trip("index=main EventCode=4624 | rename user as account"),
            'index=main | search EventCode="4624" | rename user as account')

    def test_sort_descending_uses_the_minus_sign(self):
        """From Splunk's `sort` documentation: minus is descending, plus is
        ascending, ascending is the default. CITED rather than remembered -- the
        previous version of this file asserted an SPL convention from memory."""
        self.assertEqual(self._round_trip("index=main | sort -count"),
                         "index=main | sort count desc")

    def test_head_becomes_sort_then_head(self):
        self.assertEqual(self._round_trip("index=main | head 5 -_time"),
                         "index=main | sort -_time | head 5")

    def test_head_after_stats_keeps_the_aggregate(self):
        """The ordering case that motivated the renderer fix, end to end."""
        self.assertEqual(
            self._round_trip("index=main | stats count by host | head 3 host"),
            "index=main | stats count AS count by host | sort +host | head 3")

    def test_a_rename_is_followed_by_a_term_reading_the_new_name(self):
        """The chain has to actually thread, or the rename is decorative."""
        rendered = self._round_trip(
            'index=main EventCode=4624 | rename user as account '
            '| where account="admin"')
        self.assertIn("rename user as account", rendered)
        self.assertIn('account="admin"', rendered)

    def test_projection_is_not_rendered_as_eval(self):
        """`fields a, b` rendered as `| eval a=a, b=b`, which is a NO-OP -- it
        assigns each field its own value -- so a projection that restricted the
        output instead kept every column. Asserted explicitly because the
        round-trip tests above would not catch it: both spellings parse."""
        ir, _ = lower("index=main | fields a, b")
        rendered = render_spl(ir)
        self.assertIn("| fields a, b", rendered)
        self.assertNotIn("eval", rendered)

    def test_rename_is_not_rendered_as_eval(self):
        """`rename` rendered as `eval account=user` ADDS a column and leaves the
        original, so a later term reading `user` still worked and one reading
        `account` found a different field."""
        ir, _ = lower("index=main | rename user as account")
        rendered = render_spl(ir)
        self.assertIn("| rename user as account", rendered)
        self.assertNotIn("eval", rendered)

    def test_a_dotted_field_survives_both_directions(self):
        rendered = self._round_trip("index=main | sort -win.eventdata.targetImage")
        self.assertIn("win.eventdata.targetImage", rendered)

    def test_a_malformed_field_list_is_refused_not_partly_honoured(self):
        """A `fields` list that silently dropped the one column it could not
        read would narrow the output, and a half-applied `rename` leaves later
        terms reading a field the analyst renamed away. Both are refused whole."""
        for source, code in (
            ("index=main | fields a, b,", "SPL_FIELD_LIST_MALFORMED"),
            ("index=main | fields a, 1bad", "SPL_FIELD_LIST_MALFORMED"),
            ("index=main | rename user as", "SPL_RENAME_MALFORMED"),
            ("index=main | rename user as account as x", "SPL_RENAME_MALFORMED"),
        ):
            with self.subTest(source=source):
                with self.assertRaises(Exception) as caught:
                    lower(source)
                self.assertEqual(getattr(caught.exception, "code", ""), code)

    def test_a_head_with_no_count_is_refused(self):
        """`head` with a non-numeric limit is a different rule, so it is named
        rather than guessed."""
        for source in ("index=main | head x", "index=main | head 0",
                       "index=main | head -3"):
            with self.subTest(source=source):
                with self.assertRaises(Exception) as caught:
                    lower(source)
                self.assertIn("SPL_HEAD_LIMIT",
                              getattr(caught.exception, "code", ""))

    def test_a_sort_on_something_that_is_not_a_field_is_refused(self):
        with self.assertRaises(Exception) as caught:
            lower("index=main | sort 5 = 3")
        self.assertIn("SPL_SORT_FIELD_NOT_A_NAME",
                      getattr(caught.exception, "code", ""))

    def test_the_two_remaining_commands_are_still_refused(self):
        """`dedup` and `fillnull` are NOT in this commit. `dedup` collapses rows
        and `fillnull` fills empties so a LATER term matches rows it otherwise
        would not -- both change which rows match in ways the IR does not model.
        They stay refused, and refused HONESTLY by name rather than hiding inside
        the blanket message this replaced. Asserted, so they cannot quietly
        change into something that silently drops the command.

        `eval` and `regex` WERE refused when this test was written and now lower,
        so the list shrank -- which is the point of asserting it.
        """
        for source in ("index=main | dedup host",
                       "index=main | fillnull value=0"):
            with self.subTest(source=source):
                with self.assertRaises(Exception) as caught:
                    lower(source)
                self.assertEqual(getattr(caught.exception, "code", ""),
                                 "SPL_COMMAND_NOT_LOWERABLE")

    def test_eval_and_regex_now_lower(self):
        """The other half of the above: they are no longer in the refused set."""
        self.assertEqual(self._round_trip("index=main | eval x=1"),
                         "index=main | eval x=1")
        self.assertEqual(
            self._round_trip('index=main | regex CommandLine="mimikatz"'),
            'index=main | search CommandLine="mimikatz"')

    def test_a_regex_filter_survives_into_a_later_stats(self):
        """The exact case the blanket refusal's comment described as having once
        deleted the whole detection: `| regex ... | stats count by host` must
        keep the filter."""
        rendered = self._round_trip(
            'index=main | regex CommandLine="mimikatz" | stats count by host')
        self.assertIn('CommandLine="mimikatz"', rendered)
        self.assertIn("stats count", rendered)
        self.assertLess(rendered.index("CommandLine"),
                        rendered.index("stats"),
                        "the filter must come before the aggregate or the "
                        "aggregate is counting unfiltered events")

    def test_eval_field_copy_stays_an_eval_and_not_a_rename(self):
        """`rename` REMOVES the original column and `eval` KEEPS it, so a later
        term reading the original works under one and finds nothing under the
        other. The previous version rendered this as `rename` and broke it."""
        rendered = self._round_trip('index=main | eval copy=user | where user="a"')
        self.assertIn("| eval copy=user", rendered)
        self.assertNotIn("rename", rendered)
        self.assertIn('user="a"', rendered)

    def test_a_comma_inside_a_quoted_eval_value_is_not_an_assignment_separator(self):
        """`eval list=\"a,b\"` is ONE assignment. Splitting on every comma makes
        it two broken ones, and the second one is a syntax error the analyst
        never wrote."""
        self.assertEqual(self._round_trip('index=main | eval list="a,b"'),
                         'index=main | eval list="a,b"')

    def test_an_eval_expression_ruleforge_cannot_compute_is_refused(self):
        """`if()` is a real Splunk function, and refusing it is the honest answer
        -- approximating a conditional would make every later term read a value
        the analyst never computed."""
        with self.assertRaises(Exception) as caught:
            lower("index=main | eval n=if(a>1,2,3)")
        self.assertEqual(getattr(caught.exception, "code", ""),
                         "SPL_EVAL_EXPRESSION_NOT_LOWERABLE")

    def test_a_duplicate_eval_target_is_refused(self):
        """The second assignment would silently overwrite the first."""
        with self.assertRaises(Exception) as caught:
            lower("index=main | eval x=1, x=2")
        self.assertEqual(getattr(caught.exception, "code", ""),
                         "SPL_EVAL_DUPLICATE_FIELD")

    def test_a_regex_without_a_field_is_refused(self):
        """`regex` filters on a NAMED field, and guessing which one is a
        different rule."""
        with self.assertRaises(Exception) as caught:
            lower('index=main | regex "mimikatz"')
        self.assertEqual(getattr(caught.exception, "code", ""),
                         "SPL_REGEX_NOT_A_FIELD_TEST")


if __name__ == "__main__":
    unittest.main()
