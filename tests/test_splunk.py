"""Splunk SPL.

Most of these tests are about the three things SPL does differently from every
other pipeline language, each of which is silent when it goes wrong:

`PrecedenceIsNotCLike` is the one to read first. Splunk evaluates OR BEFORE AND,
so `a=1 OR b=2 c=3` means `(a=1 OR b=2) AND c=3` -- the opposite of what the
shared default would give. Nothing warns, and the rule reads identically either
way; only the matched events differ.

`ImplicitAnd` exists because SPL writes nothing between ANDed terms. The shared
parser stops at the first term it cannot continue, so without normalisation the
rest of the search is silently unread and the rule matches far more than it says.

`CaseMattersInASearch` is the third: `AND` is an operator, `and` is a word to
search for.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from engine.dialects.splunk import (
    AGGREGATES,
    DIALECT,
    LANGUAGE,
    UNSUPPORTED_COMMANDS,
    lower_splunk,
    normalise_search,
    parse_splunk,
    render_splunk,
)
from engine.ir import (
    Aggregate,
    BoolOp,
    Call,
    Comparison,
    Derive,
    Distinct,
    Emit,
    Expand,
    FieldRef,
    Filter,
    Join,
    Limit,
    Project,
    Read,
    Regex,
    Sort,
    render_expr,
)
from engine.values import Capability, Refusal

BRUTE_FORCE = """index=main sourcetype=WinEventLog:Security EventCode=4625
| where user != "guest"
| stats count as Attempts, dc(user) as Users by host
| where Attempts >= 10
| eval risk = if(Users > 3, "high", "low")
| sort - Attempts
| head 20"""


def lower(text=BRUTE_FORCE):
    rule, _ = lower_splunk(text)
    return rule


def first(rule, kind):
    for node in rule.pipeline:
        if isinstance(node, kind):
            return node
    raise AssertionError(f"no {kind.__name__} stage in the rule")


def condition_text(rule):
    return render_expr(first(rule, Filter).condition)


class Parsing(unittest.TestCase):
    def test_the_pipeline_splits_on_the_bar(self):
        parsed = parse_splunk(BRUTE_FORCE)
        self.assertEqual(
            [s.operator for s in parsed.stages],
            ["where", "stats", "where", "eval", "sort", "head"],
        )

    def test_the_leading_search_has_no_command_word(self):
        parsed = parse_splunk(BRUTE_FORCE)
        self.assertTrue(parsed.search.startswith("index=main"))

    def test_an_explicit_leading_search_command_is_accepted(self):
        self.assertEqual(
            parse_splunk("search index=main a=1").search, "index=main a=1"
        )

    def test_a_bar_inside_a_quoted_value_is_not_a_separator(self):
        # Splitting here would hand the parser two fragments, neither valid.
        parsed = parse_splunk('index=main cmd="a | b" | head 1')
        self.assertEqual(len(parsed.stages), 1)

    def test_a_bar_inside_a_subsearch_is_not_a_separator(self):
        parsed = parse_splunk(
            "index=main | join host [ search index=b | head 1 ] | head 2"
        )
        self.assertEqual([s.operator for s in parsed.stages], ["join", "head"])

    def test_an_empty_search_is_refused(self):
        # An empty search reads every event in every index.
        with self.assertRaises(Refusal) as caught:
            parse_splunk("   ")
        self.assertEqual(caught.exception.code, "SPL_EMPTY")

    def test_a_macro_is_refused_because_its_body_is_elsewhere(self):
        with self.assertRaises(Refusal) as caught:
            parse_splunk("index=main | `detect_brute_force`")
        self.assertEqual(caught.exception.code, "SPL_MACRO")

    def test_an_unterminated_quote_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower_splunk('index=main cmd="unclosed')
        self.assertEqual(caught.exception.code, "SPL_UNTERMINATED_STRING")


class ImplicitAnd(unittest.TestCase):
    """SPL writes nothing between ANDed terms. Unread terms are invisible."""

    def test_adjacent_terms_get_an_explicit_and(self):
        self.assertEqual(
            normalise_search("index=main EventCode=4624 user=svc"),
            "index=main and EventCode=4624 and user=svc",
        )

    def test_an_explicit_boolean_is_not_doubled(self):
        self.assertEqual(normalise_search("a=1 OR b=2"), "a=1 or b=2")

    def test_not_is_left_as_a_prefix(self):
        self.assertEqual(normalise_search("NOT a=1 b=2"), "not a=1 and b=2")

    def test_a_parenthesised_group_is_normalised_too(self):
        # Without recursing, the terms inside the group stay unseparated and
        # the parser reads only the first one.
        self.assertEqual(
            normalise_search("(a=1 b=2) OR c=3"), "(a=1 and b=2) or c=3"
        )

    def test_every_term_survives_into_the_tree(self):
        # The actual failure this prevents: terms silently unread.
        rule = lower("index=main a=1 b=2 c=3")
        condition = first(rule, Filter).condition
        self.assertIsInstance(condition, BoolOp)
        self.assertEqual(len(condition.operands), 3)

    def test_a_quoted_value_with_spaces_stays_one_term(self):
        rule = lower('index=main cmd="net user /add"')
        self.assertIn("net user /add", condition_text(rule))


class PrecedenceIsNotCLike(unittest.TestCase):
    """Splunk evaluates OR before AND. Every other language does the reverse.

    This is the single most dangerous thing about SPL for a converter. Reading
    a search with the ordinary precedence regroups it without a warning, and
    the rule reads identically while matching a different set of events.
    """

    def test_or_binds_tighter_than_and_in_a_search(self):
        rule = lower("index=main a=1 OR b=2 c=3")
        condition = first(rule, Filter).condition
        # (a=1 OR b=2) AND c=3  -- NOT  a=1 OR (b=2 AND c=3)
        self.assertEqual(condition.op, "and")
        self.assertEqual(condition.operands[0].op, "or")

    def test_and_binds_tighter_than_or_in_a_where(self):
        # `| where` is eval syntax, which uses the ordinary precedence. One
        # table for both grammars would therefore be wrong for one of them.
        rule = lower("index=main | where a==1 OR b==2 AND c==3")
        condition = [
            n for n in rule.pipeline if isinstance(n, Filter)
        ][-1].condition
        self.assertEqual(condition.op, "or")
        self.assertEqual(condition.operands[1].op, "and")

    def test_parentheses_still_win(self):
        rule = lower("index=main (a=1 OR b=2) c=3")
        condition = first(rule, Filter).condition
        self.assertEqual(condition.op, "and")


class CaseMattersInASearch(unittest.TestCase):
    def test_uppercase_or_is_an_operator(self):
        rule = lower("index=main a=1 OR b=2")
        self.assertEqual(first(rule, Filter).condition.op, "or")

    def test_lowercase_or_is_refused_with_an_explanation(self):
        # Splunk reads it as the literal word. Silently treating it as the
        # operator would change what the rule matches.
        with self.assertRaises(Refusal) as caught:
            lower("index=main a=1 or b=2")
        self.assertEqual(caught.exception.code, "SPL_BOOLEAN_NOT_UPPERCASE")
        self.assertIn("OR", caught.exception.message)

    def test_a_bare_word_is_refused_rather_than_invented(self):
        with self.assertRaises(Refusal) as caught:
            lower("index=main failed_login")
        self.assertEqual(caught.exception.code, "SPL_BARE_SEARCH_TERM")


class GeneratingCommandsAreNamedForWhatTheyAre(unittest.TestCase):
    """`| tstats` was refused as "a bare search term".

    A search beginning with `|` starts with a generating command, so its name
    landed where an index search was expected and came back as
    `SPL_BARE_SEARCH_TERM` -- telling the analyst that `tstats` is "a
    full-text match across every field of the event". It is not; it is a
    command. The message sent them looking for a quoting problem that was
    never there, and `tstats` appears in a large share of real Splunk
    detections, so it was the first thing many rules hit.
    """

    def test_tstats_is_refused_as_a_generating_command(self):
        from engine.dialects.splunk import lower_splunk

        with self.assertRaises(Refusal) as caught:
            lower_splunk("| tstats count where index=main by src_ip")
        self.assertEqual(caught.exception.code, "SPL_GENERATING_TSTATS")

    def test_it_is_not_called_a_search_term(self):
        from engine.dialects.splunk import lower_splunk

        with self.assertRaises(Refusal) as caught:
            lower_splunk("| tstats count where index=main by src_ip")
        self.assertNotIn("bare search term", caught.exception.message)

    def test_the_reason_says_what_the_command_actually_reads(self):
        # "Unsupported" sends the analyst nowhere. Saying it reads an
        # accelerated summary explains why no sample of events can test it.
        from engine.dialects.splunk import lower_splunk

        with self.assertRaises(Refusal) as caught:
            lower_splunk("| tstats count where index=main by src_ip")
        self.assertIn("SUMMARY", caught.exception.message)
        self.assertIn("rewrite it as a `search`", caught.exception.message)

    def test_every_generating_command_is_refused_by_its_own_name(self):
        from engine.dialects.splunk import (
            GENERATING_COMMANDS,
            lower_splunk,
        )

        for name in GENERATING_COMMANDS:
            with self.subTest(command=name):
                with self.assertRaises(Refusal) as caught:
                    lower_splunk(f"| {name} something by x")
                self.assertEqual(
                    caught.exception.code, f"SPL_GENERATING_{name.upper()}"
                )

    def test_every_generating_command_states_a_reason(self):
        from engine.dialects.splunk import GENERATING_COMMANDS

        for name, reason in GENERATING_COMMANDS.items():
            with self.subTest(command=name):
                self.assertGreater(
                    len(reason.strip()), 40,
                    "a one-word reason is not a reason",
                )

    def test_an_ordinary_search_is_unaffected(self):
        # The guard must not swallow the normal path.
        from engine.dialects.splunk import lower_splunk

        rule, _ = lower_splunk("index=main EventCode=4625")
        self.assertEqual(
            [type(n).__name__ for n in rule.pipeline],
            ["Read", "Filter", "Emit"],
        )

    def test_a_field_that_shares_a_command_name_is_not_refused(self):
        # The guard must be POSITIONAL. A field called `tstats` is unusual but
        # legal, and refusing it would make the fix worse than the bug.
        from engine.dialects.splunk import lower_splunk

        rule, _ = lower_splunk('index=main tstats="x"')
        self.assertEqual(
            [type(n).__name__ for n in rule.pipeline],
            ["Read", "Filter", "Emit"],
        )

    def test_every_generating_name_is_usable_as_a_field(self):
        # `from` is the one exception, and it is not this guard's doing: the
        # SHARED parser reserves it, which predates the generating-command
        # table and is defensible because `from` is an SPL command keyword.
        from engine.dialects.splunk import (
            GENERATING_COMMANDS,
            lower_splunk,
        )

        for name in GENERATING_COMMANDS:
            if name == "from":
                continue
            with self.subTest(field=name):
                rule, _ = lower_splunk(f'index=main {name}="x"')
                self.assertIn(
                    "Filter", [type(n).__name__ for n in rule.pipeline]
                )


class TheParserReadsWhatTheRendererWrites(unittest.TestCase):
    """Two shapes `render_splunk` emitted and `parse_splunk` refused."""

    def test_its_own_source_comment_can_be_read_back(self):
        # Rendering a foreign rule writes a ``` ``` ``` note saying the source
        # selector could not be mapped. The SHARED `strip_comments` knows
        # `//`, `--` and `/* */` but not SPL's triple backtick, so the comment
        # came back as a bare search term and was refused.
        from engine import dialects

        rule, _ = dialects.lower(
            "sigma",
            "title: t\nlogsource:\n    category: process_access\n"
            "detection:\n    selection:\n        Image: 'a.exe'\n"
            "    condition: selection\n",
        )
        out, _ = dialects.render("splunk", rule)
        self.assertIn("```", out)
        dialects.lower("splunk", out)  # must not raise

    def test_a_comment_is_stripped_rather_than_searched_for(self):
        from engine.dialects.splunk import lower_splunk

        rule, _ = lower_splunk("``` a note ```\nindex=main EventCode=4625")
        self.assertEqual(
            [type(n).__name__ for n in rule.pipeline],
            ["Read", "Filter", "Emit"],
        )

    def test_a_backtick_inside_a_string_is_not_a_comment(self):
        from engine.dialects.splunk import lower_splunk

        rule, _ = lower_splunk('index=main | where f == "a ``` b"')
        condition = next(
            n.condition for n in rule.pipeline if isinstance(n, Filter)
        )
        self.assertEqual(condition.right.value, "a ``` b")

    def test_a_macro_is_still_refused(self):
        # Comment stripping must not swallow a macro, which starts with the
        # same character and genuinely cannot be resolved here.
        from engine.dialects.splunk import lower_splunk

        with self.assertRaises(Refusal) as caught:
            lower_splunk("index=main | `my_macro`")
        self.assertEqual(caught.exception.code, "SPL_MACRO")

    def test_the_like_function_form_parses(self):
        # `render_splunk` writes a substring test as `like(field, "%x%")`,
        # which is correct SPL -- `like` in eval is a FUNCTION, not an infix
        # operator -- and the parser only knew the infix form. The failed
        # `like(` left the rest of the condition unread, so the refusal came
        # back as "`AND` is a reserved word".
        from engine.dialects.splunk import lower_splunk

        rule, _ = lower_splunk('index=a | where like(f, "%x")')
        condition = next(
            n.condition for n in rule.pipeline if isinstance(n, Filter)
        )
        self.assertEqual(condition.op, "like")

    def test_both_like_spellings_mean_the_same_thing(self):
        from engine.dialects.splunk import lower_splunk
        from engine.ir import render_expr

        function_form, _ = lower_splunk('index=a | where like(f, "%x")')
        infix_form, _ = lower_splunk('index=a | where f like "%x"')
        self.assertEqual(
            render_expr(function_form.pipeline[1].condition),
            render_expr(infix_form.pipeline[1].condition),
        )

    def test_a_like_inside_a_conjunction_parses(self):
        from engine.dialects.splunk import lower_splunk

        rule, _ = lower_splunk(
            'index=a | where like(f, "%x") AND g == "y"'
        )
        condition = next(
            n.condition for n in rule.pipeline if isinstance(n, Filter)
        )
        self.assertEqual(condition.op, "and")

    def test_a_substring_rule_survives_a_full_round_trip(self):
        # Rendered from a foreign rule, re-imported, and rendered again: the
        # second pass must be stable. `endswith` was written as
        # `like(f, "%x")` while a `like` comparison was written as
        # `f LIKE "%x"`, so the same rule produced two different texts and
        # every save looked like an edit.
        from engine import dialects

        rule, _ = dialects.lower(
            "sigma",
            "title: t\nlogsource:\n    category: process_access\n"
            "detection:\n    selection:\n"
            "        Image|endswith: '/lsass.exe'\n"
            "    condition: selection\n",
        )
        once, _ = dialects.render("splunk", rule)
        back, _ = dialects.lower("splunk", once)
        twice, _ = dialects.render("splunk", back)
        # The source comment is present on the first pass only, because the
        # re-imported rule IS native SPL and its selector is reused directly.
        # What must agree is the predicate.
        # Sigma's `|endswith` is case-INSENSITIVE by specification, so the
        # predicate now carries the fold as SPL's own idiom: `lower(field)
        # LIKE "...lowercased..."`. It used to render as exact-case
        # `Image LIKE "%/lsass.exe"`, which silently narrowed the detection --
        # `/LSASS.EXE` would not have matched.
        self.assertIn('lower(Image) LIKE "%/lsass.exe"', once)
        # Still stable on the second pass, which is what this test is for.
        self.assertIn('LIKE "%/lsass.exe"', twice)

    def test_a_native_rule_renders_identically_twice(self):
        from engine import dialects

        rule, _ = dialects.lower(
            "splunk", 'index=main | where Image LIKE "%/lsass.exe"'
        )
        once, _ = dialects.render("splunk", rule)
        back, _ = dialects.lower("splunk", once)
        twice, _ = dialects.render("splunk", back)
        self.assertEqual(once, twice)


class IndexTimeTerms(unittest.TestCase):
    """What the indexer resolves never reaches a local row."""

    def test_index_and_sourcetype_are_kept_verbatim(self):
        read = first(lower(BRUTE_FORCE), Read)
        self.assertEqual(
            read.selector, "index=main sourcetype=WinEventLog:Security"
        )

    def test_the_index_becomes_the_table(self):
        self.assertEqual(first(lower(BRUTE_FORCE), Read).table, "main")

    def test_an_index_term_is_not_also_a_row_predicate(self):
        # Testing a column called `index` would never resolve, because no event
        # carries one.
        self.assertNotIn("index", condition_text(lower(BRUTE_FORCE)))

    def test_an_index_term_is_hoisted_out_of_a_disjunction_of_others(self):
        # Because OR binds tighter, `index=main a=1 OR b=2` really is
        # `index=main AND (a=1 OR b=2)`, so the index term IS top level.
        rule = lower("index=main a=1 OR b=2")
        self.assertEqual(first(rule, Read).selector, "index=main")
        self.assertEqual(first(rule, Filter).condition.op, "or")

    def test_an_index_term_inside_an_or_is_reported_not_silently_kept(self):
        # Lifting either half would change which events the search reads, so it
        # stays -- and the analyst is told it will not resolve.
        _, diagnostics = lower_splunk("index=main OR index=other a=1")
        self.assertIn(
            "SPL_INDEX_TERM_IN_DISJUNCTION", [d.code for d in diagnostics]
        )

    def test_hoisting_does_not_swallow_a_following_not(self):
        # NOT is a PREFIX operator. Trimming it as a dangling joiner turned
        # `index=main NOT a=1` into `a=1`, which matches exactly the events the
        # author excluded.
        rule = lower("index=main NOT a=1")
        self.assertEqual(first(rule, Read).selector, "index=main")
        self.assertEqual(condition_text(rule), "NOT (a == 1)")

    def test_host_stays_a_row_predicate(self):
        # It is an indexed field, but it is genuinely on every event, so a
        # pasted sample can carry it and a local run can honestly decide it.
        rule = lower("index=main host=DC01")
        self.assertNotIn("host", first(rule, Read).selector)
        self.assertIn("host", condition_text(rule))

    def test_an_index_does_not_block_a_confident_non_match(self):
        # This used to assert `not_evaluated`, justified only as "it surprises
        # people". An `index=` term can only REMOVE events from what the
        # engine saw, and for a rule with no anti-join removing events cannot
        # create a match -- so "no match against the sample you gave me" is
        # the honest answer, and the caveat still records that the index was
        # not applied.
        from engine.pipeline import evaluate

        rule = lower("index=main EventCode=4625")
        result = evaluate(rule, [{"EventCode": 4624}])
        self.assertFalse(result.matched)
        self.assertEqual(result.verdict, "no_match")
        self.assertIn("INDEX_TIME_FILTER", [c.code for c in result.caveats])

    def test_an_anti_join_keeps_the_strict_verdict(self):
        # The exception that makes the relaxation conditional. An anti-join
        # asks for rows with NO counterpart, so taking rows away from the
        # right-hand side makes left rows unmatched: a rule that found nothing
        # locally can fire once the index has narrowed the input. Those rules
        # must not claim a confident negative.
        from decimal import Decimal

        from engine.ir import (
            Annotations, Binding, Comparison, Emit, FieldRef, Join, Literal,
            Read, Rule,
        )
        from engine.pipeline import evaluate

        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="main", selector="index=main",
                     time_field="ts"),
                Join(id="j", left="src", right="other", how="anti",
                     on=((FieldRef("host"),
                          FieldRef("host", scope="right")),)),
                Emit(id="out"),
            ),
            bindings=(Binding(name="other", pipeline=(
                Read(id="o", table="u", time_field="ts"),
                Emit(id="oe"),
            )),),
            annotations=Annotations(title=""),
        )
        result = evaluate(rule, [{"ts": 1, "host": "A"}])
        self.assertNotEqual(result.verdict, "no_match")


class Aggregates(unittest.TestCase):
    def test_stats_becomes_an_aggregate_with_measures_and_keys(self):
        aggregate = first(lower(BRUTE_FORCE), Aggregate)
        self.assertEqual(
            [(m.function, m.name) for m in aggregate.measures],
            [("count", "Attempts"), ("dcount", "Users")],
        )
        self.assertEqual([k.full for k in aggregate.keys], ["host"])

    def test_dc_is_a_distinct_count(self):
        # `dc` meaning the row count rather than the distinct count fires a
        # password-spray rule on one user retrying.
        aggregate = first(lower(BRUTE_FORCE), Aggregate)
        users = next(m for m in aggregate.measures if m.name == "Users")
        self.assertEqual(users.function, "dcount")
        self.assertTrue(users.distinct)

    def test_every_mapped_aggregate_lowers(self):
        for name in sorted(AGGREGATES):
            with self.subTest(aggregate=name):
                argument = "" if name in ("count", "c") else "bytes"
                rule = lower(f"index=main | stats {name}({argument}) by host")
                self.assertTrue(first(rule, Aggregate).measures)

    def test_an_unmapped_aggregate_is_refused_rather_than_passed_through(self):
        # An aggregate this engine cannot compute would silently produce no
        # value, and the stage would look like it ran.
        with self.assertRaises(Refusal) as caught:
            lower("index=main | stats mode(user) by host")
        self.assertEqual(caught.exception.code, "SPL_AGGREGATE_UNKNOWN")

    def test_percentile_carries_its_parameter(self):
        measure = first(lower("index=main | stats p95(dur) by host"),
                        Aggregate).measures[0]
        self.assertEqual(measure.function, "percentile")
        self.assertEqual(measure.param, Decimal(95))

    def test_median_is_the_fiftieth_percentile(self):
        measure = first(lower("index=main | stats median(dur) by host"),
                        Aggregate).measures[0]
        self.assertEqual(measure.param, Decimal(50))

    def test_span_becomes_a_window_not_a_grouping_key(self):
        # Grouping on `_time` would put every distinct second in its own group.
        aggregate = first(
            lower("index=main | stats count by _time span=5m, host"), Aggregate
        )
        self.assertIsNotNone(aggregate.window)
        self.assertEqual(aggregate.window.size.seconds, Decimal(300))
        self.assertEqual([k.full for k in aggregate.keys], ["host"])

    def test_grouping_with_nothing_measured_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower("index=main | stats by host")
        self.assertEqual(caught.exception.code, "SPL_STATS_NO_MEASURE")

    def test_tstats_is_modelled_but_marked_appliance_only(self):
        # It reads index-time acceleration that no event sample carries.
        rule, diagnostics = lower_splunk(
            "index=main | tstats count by host"
        )
        aggregate = first(rule, Aggregate)
        self.assertIs(aggregate.capability, Capability.DECLARED_ONLY)
        self.assertIn("SPL_TSTATS_APPLIANCE_ONLY", [d.code for d in diagnostics])


class Stages(unittest.TestCase):
    def test_eval_becomes_a_derive(self):
        derive = first(lower(BRUTE_FORCE), Derive)
        self.assertEqual([name for name, _ in derive.assignments], ["risk"])

    def test_fields_keeps_and_fields_minus_drops(self):
        self.assertTrue(first(lower("index=main | fields a, b"), Project).keeps)
        self.assertTrue(first(lower("index=main | fields - a"), Project).drops)

    def test_table_keeps(self):
        self.assertTrue(first(lower("index=main | table a, b"), Project).keeps)

    def test_rename_becomes_a_projection_rename(self):
        project = first(lower("index=main | rename src AS source"), Project)
        self.assertEqual(project.renames[0][1], "source")

    def test_a_wildcard_rename_is_refused(self):
        # Which columns come out depends on the data, not on the rule.
        with self.assertRaises(Refusal) as caught:
            lower("index=main | rename src* AS *_source")
        self.assertEqual(caught.exception.code, "SPL_RENAME_WILDCARD")

    def test_sort_reads_the_minus_prefix_as_descending(self):
        sort = first(lower("index=main | sort - count"), Sort)
        self.assertTrue(sort.keys[0][1])

    def test_sort_reads_a_leading_count_as_a_limit(self):
        self.assertEqual(first(lower("index=main | sort 10 -count"), Sort).limit, 10)

    def test_head_and_tail_differ(self):
        self.assertFalse(first(lower("index=main | head 5"), Limit).keep_last)
        self.assertTrue(first(lower("index=main | tail 5"), Limit).keep_last)

    def test_a_limit_with_no_number_is_refused(self):
        # Silently keeping Splunk's default is not what the rule says.
        with self.assertRaises(Refusal) as caught:
            lower("index=main | head")
        self.assertEqual(caught.exception.code, "SPL_LIMIT_NOT_A_NUMBER")

    def test_dedup_becomes_distinct(self):
        self.assertEqual(
            [k.full for k in first(lower("index=main | dedup host, user"),
                                   Distinct).keys],
            ["host", "user"],
        )

    def test_mvexpand_becomes_expand(self):
        self.assertEqual(
            first(lower("index=main | mvexpand users"), Expand).field.full,
            "users",
        )

    def test_regex_becomes_a_pattern_filter(self):
        rule = lower('index=main | regex cmd="lsass"')
        condition = [n for n in rule.pipeline if isinstance(n, Filter)][-1].condition
        self.assertIsInstance(condition.right, Regex)
        self.assertEqual(condition.right.dialect, "pcre")

    def test_top_becomes_count_then_sort_then_limit(self):
        # One command, three stages. Lowering it as a bare Aggregate would drop
        # the ordering and the cut-off, which are the whole point of `top`.
        rule = lower("index=main | top 5 user by host")
        kinds = [type(n).__name__ for n in rule.pipeline]
        self.assertEqual(kinds[-4:], ["Aggregate", "Sort", "Limit", "Emit"])
        self.assertEqual(first(rule, Limit).count, 5)
        self.assertTrue(first(rule, Sort).keys[0][1])

    def test_rare_sorts_the_other_way(self):
        self.assertFalse(first(lower("index=main | rare 5 user"), Sort).keys[0][1])

    def test_bin_becomes_a_derived_column(self):
        derive = first(lower("index=main | bin _time span=5m"), Derive)
        self.assertIsInstance(derive.assignments[0][1], Call)

    def test_bin_without_a_span_is_refused(self):
        # Splunk would choose one from the data, making the buckets depend on
        # the events rather than on the rule.
        with self.assertRaises(Refusal) as caught:
            lower("index=main | bin _time")
        self.assertEqual(caught.exception.code, "SPL_BIN_NO_SPAN")


class WhereIsNotSearch(unittest.TestCase):
    def test_a_single_equals_in_where_is_reported(self):
        # Splunk's `where` is eval syntax and rejects it outright. Reading it
        # silently would hand back a rule Splunk will not run.
        _, diagnostics = lower_splunk("index=main | where status=200")
        self.assertIn("SPL_WHERE_SINGLE_EQUALS", [d.code for d in diagnostics])

    def test_a_double_equals_in_where_is_clean(self):
        _, diagnostics = lower_splunk("index=main | where status==200")
        self.assertEqual(
            [d.code for d in diagnostics if d.code == "SPL_WHERE_SINGLE_EQUALS"],
            [],
        )


class CidrArgumentOrder(unittest.TestCase):
    """Splunk writes the network first; this engine takes the address first."""

    def test_the_arguments_are_swapped_on_the_way_in(self):
        # Passed through in written order it asks whether the network is inside
        # the address, which is false for every real input -- so the rule looks
        # like one that simply never fires.
        rule = lower('index=fw | eval internal = cidrmatch("10.0.0.0/8", src_ip)')
        call = first(rule, Derive).assignments[0][1]
        self.assertIsInstance(call, Call)
        self.assertEqual(call.function, "cidr_contains")
        self.assertEqual(call.args[0].full, "src_ip")
        self.assertEqual(call.args[1].value, "10.0.0.0/8")

    def test_they_are_swapped_back_on_the_way_out(self):
        rule = lower('index=fw | eval internal = cidrmatch("10.0.0.0/8", src_ip)')
        self.assertIn('cidrmatch("10.0.0.0/8", src_ip)', render_splunk(rule))

    def test_it_actually_evaluates(self):
        from engine.pipeline import evaluate

        rule = lower(
            'index=fw | eval internal = cidrmatch("10.0.0.0/8", src_ip) '
            "| where internal == true()"
        )
        self.assertTrue(evaluate(rule, [{"src_ip": "10.1.2.3"}]).matched)
        self.assertFalse(evaluate(rule, [{"src_ip": "192.168.1.1"}]).matched)


class Joins(unittest.TestCase):
    JOINED = (
        "index=main EventCode=10\n"
        "| join type=inner Computer "
        "[ search index=main EventCode=4624 | fields Computer, user ]\n"
        "| stats count by Computer"
    )

    def test_the_subsearch_becomes_a_binding(self):
        # A subsearch is a separate stream with its own stages. Flattening it
        # into the main pipeline would change which rows the join sees.
        rule = lower(self.JOINED)
        self.assertEqual(len(rule.bindings), 1)
        self.assertEqual(
            [type(n).__name__ for n in rule.bindings[0].pipeline],
            ["Read", "Filter", "Project"],
        )

    def test_the_right_key_is_scoped(self):
        # Left unscoped, both keys read the current row and every row matches
        # itself.
        join = first(lower(self.JOINED), Join)
        self.assertEqual(join.on[0][0].scope, "current")
        self.assertEqual(join.on[0][1].scope, "right")

    def test_the_join_type_is_carried(self):
        self.assertEqual(first(lower(self.JOINED), Join).how, "inner")
        self.assertEqual(
            first(lower(self.JOINED.replace("type=inner", "type=outer")),
                  Join).how,
            "left",
        )

    def test_a_join_with_no_subsearch_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower("index=main | join Computer")
        self.assertEqual(caught.exception.code, "SPL_JOIN_NO_SUBSEARCH")

    def test_a_join_with_no_key_is_refused(self):
        # Every row on the left would match every row on the right.
        with self.assertRaises(Refusal) as caught:
            lower("index=main | join [ search index=b ]")
        self.assertEqual(caught.exception.code, "SPL_JOIN_NO_KEY")

    def test_the_subsearch_renders_on_one_line(self):
        # Brackets delimit a subsearch, not newlines; Splunk rejects a
        # multi-line one, so a pretty-printed nested stream will not run.
        text = render_splunk(lower(self.JOINED))
        join_line = next(l for l in text.splitlines() if l.startswith("| join"))
        self.assertTrue(join_line.rstrip().endswith("]"))
        self.assertIn("[ search", join_line)


class RexIsApplianceOnly(unittest.TestCase):
    def test_each_named_group_becomes_a_declared_only_column(self):
        rule, diagnostics = lower_splunk(
            r'index=main | rex field=cmd "(?<target_user>\w+)"'
        )
        derive = first(rule, Derive)
        self.assertEqual([n for n, _ in derive.assignments], ["target_user"])
        self.assertIs(derive.capability, Capability.DECLARED_ONLY)
        self.assertIn("SPL_REX_APPLIANCE_ONLY", [d.code for d in diagnostics])

    def test_a_rex_with_no_capture_group_is_refused(self):
        # It would create no field, so the rule's later references resolve to
        # nothing.
        with self.assertRaises(Refusal) as caught:
            lower(r'index=main | rex field=cmd "\w+"')
        self.assertEqual(caught.exception.code, "SPL_REX_NO_CAPTURE")


class RefusedCommands(unittest.TestCase):
    def test_every_listed_command_is_refused_with_its_reason(self):
        for command in sorted(UNSUPPORTED_COMMANDS):
            with self.subTest(command=command):
                with self.assertRaises(Refusal) as caught:
                    lower(f"index=main | {command} something")
                self.assertEqual(
                    caught.exception.code, "SPL_COMMAND_UNSUPPORTED"
                )
                self.assertIn(command, caught.exception.message)

    def test_eventstats_explains_why_it_is_not_an_aggregate(self):
        # It ADDS columns instead of collapsing rows, so lowering it as an
        # Aggregate would delete the rows the rest of the rule reads.
        with self.assertRaises(Refusal) as caught:
            lower("index=main | eventstats count by host")
        self.assertIn("collapsing", caught.exception.message)

    def test_fillnull_explains_the_absent_distinction(self):
        with self.assertRaises(Refusal) as caught:
            lower("index=main | fillnull value=0")
        self.assertIn("absent", caught.exception.message)

    def test_an_unknown_command_is_refused_rather_than_skipped(self):
        # A dropped stage produces a search that reads correctly and matches a
        # different set of events.
        with self.assertRaises(Refusal) as caught:
            lower("index=main | frobnicate x")
        self.assertEqual(caught.exception.code, "SPL_COMMAND_UNKNOWN")


class Rendering(unittest.TestCase):
    def setUp(self):
        self.rule = lower(BRUTE_FORCE)
        self.text = render_splunk(self.rule)

    def test_the_selector_comes_back_verbatim(self):
        self.assertTrue(
            self.text.startswith("index=main sourcetype=WinEventLog:Security")
        )

    def test_every_stage_is_written(self):
        for fragment in ("| where", "| stats", "| eval", "| sort", "| head"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.text)

    def test_a_string_constant_is_always_quoted(self):
        # In eval syntax a bare word is a FIELD NAME, so `user != guest`
        # compares two columns rather than a column and a string. The search
        # runs, returns rows, and tests something else entirely.
        self.assertIn('user != "guest"', self.text)
        self.assertIn('"high"', self.text)

    def test_a_number_is_not_quoted(self):
        self.assertIn("Attempts >= 10", self.text)

    def test_the_aggregate_keeps_its_output_names(self):
        self.assertIn("count as Attempts", self.text)
        self.assertIn("dc(user) as Users", self.text)

    def test_the_rendered_search_lowers_again_to_the_same_stages(self):
        again = lower(self.text)
        self.assertEqual(
            [type(n).__name__ for n in again.pipeline],
            [type(n).__name__ for n in self.rule.pipeline],
        )

    def test_rendering_is_stable_across_two_round_trips(self):
        # An unstable renderer makes every save look like a change in history.
        self.assertEqual(render_splunk(lower(self.text)), self.text)

    def test_an_unrenderable_stage_is_refused_rather_than_dropped(self):
        from engine.ir import Correlation, Duration, Rule

        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="src", table="main"),
                Correlation(id="c", parent="src", frequency=5,
                            timeframe=Duration(Decimal(300)),
                            group_by=(FieldRef("host"),)),
                Emit(id="out"),
            ),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_splunk(rule)
        self.assertEqual(caught.exception.code, "SPL_RENDER_STAGE")


class TheArtifact(unittest.TestCase):
    def test_it_is_recorded_as_a_search_not_a_rule(self):
        # An SPL search is not a saved alert. Calling one the other sends an
        # analyst looking for scheduling and throttling the artifact lacks.
        self.assertEqual(lower(BRUTE_FORCE).metadata["artifact"], "search")

    def test_the_dialect_and_language_are_recorded(self):
        rule = lower(BRUTE_FORCE)
        self.assertEqual(rule.metadata["dialect"], DIALECT)
        self.assertEqual(rule.metadata["language"], LANGUAGE)


class ItEvaluates(unittest.TestCase):
    def test_a_lowered_search_runs_against_a_sample(self):
        from engine.pipeline import evaluate

        rule = lower(
            "index=main EventCode=4625\n"
            "| stats count as Attempts by host\n"
            "| where Attempts >= 3"
        )
        events = [{"EventCode": 4625, "host": "DC01"} for _ in range(4)]
        self.assertTrue(evaluate(rule, events).matched)

    def test_the_threshold_actually_bites(self):
        from engine.pipeline import evaluate

        rule = lower(
            "index=main EventCode=4625\n"
            "| stats count as Attempts by host\n"
            "| where Attempts >= 3"
        )
        events = [{"EventCode": 4625, "host": "DC01"} for _ in range(2)]
        self.assertFalse(evaluate(rule, events).matched)

    def test_a_distinct_count_threshold_needs_distinct_values(self):
        from engine.pipeline import evaluate

        rule = lower(
            "index=main EventCode=4625\n"
            "| stats dc(user) as Users by host\n"
            "| where Users >= 3"
        )
        one = [{"EventCode": 4625, "host": "DC01", "user": "bob"}
               for _ in range(9)]
        self.assertFalse(evaluate(rule, one).matched)
        many = [{"EventCode": 4625, "host": "DC01", "user": name}
                for name in ("bob", "amy", "cat")]
        self.assertTrue(evaluate(rule, many).matched)

    def test_a_pcre_pattern_refuses_to_run_rather_than_pretending(self):
        # There is no PCRE engine here. Running the pattern with Python's `re`
        # and calling the answer Splunk would be a false claim about a control.
        from engine.pipeline import evaluate

        rule = lower(r'index=main | regex cmd="(?<name>\w+)"')
        result = evaluate(rule, [{"cmd": "whoami"}])
        self.assertFalse(result.matched)
        codes = [c.code for c in result.caveats]
        self.assertTrue(
            any("REGEX" in code for code in codes),
            f"expected a regex refusal among {codes}",
        )


if __name__ == "__main__":
    unittest.main()
