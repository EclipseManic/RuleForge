"""KQL, against the reference enterprise rule.

The rule under test is the LSASS-credential-access-then-NTLM-lateral-movement
correlation, in the form an analyst actually writes it. It is here because it
contains every construct that makes KQL hard, and because each one has a
specific way of silently producing a rule that matches the wrong events:

  - a `let` binding is a pipeline used AFTER both are defined
  - the join operand is a NAME, not a subquery
  - the correlated predicate reads one field from each side of the join
  - a `where` after a `summarize` is a different operator from one before it
  - `make_set` is list-valued and must not be collapsed

If these hold, the architecture handles enterprise rules. If they do not,
nothing else in the dialect matters.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from engine.dialects.kql import Diagnostic, lower_kql, parse_kql, render_kql
from engine.ir import (
    Aggregate,
    Comparison,
    Derive,
    Emit,
    FieldRef,
    Filter,
    Join,
    Literal,
    Measure,
    Project,
    Read,
    Rule,
    Sort,
    Span,
    render_expr,
)
from engine.pipeline import Verdict, evaluate
from engine.validate import validate
from engine.values import Refusal, Seq

#: The reference rule, verbatim in shape.
#: Raw, because the KQL verbatim string `@"\lsass.exe"` is exactly the case the
#: tokenizer has to get right and a Python escape warning would drown it out.
USER_RULE = r"""
let LSASSAccess =
SecurityEvent
| where EventID == 10
| where TargetImage endswith @"\lsass.exe"
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


def stages_of(rule: Rule, binding: str) -> list:
    for b in rule.bindings:
        if b.name == binding:
            return list(b.pipeline)
    raise AssertionError(f"no binding named {binding}")


class Parsing(unittest.TestCase):
    def test_two_bindings_and_a_main_pipeline(self):
        parsed = parse_kql(USER_RULE)
        self.assertEqual([let.name for let in parsed.lets],
                         ["LSASSAccess", "LateralMovement"])
        self.assertEqual(parsed.source, "LSASSAccess")
        self.assertEqual(
            [s.operator for s in parsed.stages],
            ["join", "where", "summarize", "where", "extend"],
        )

    def test_a_semicolon_inside_a_string_is_not_a_separator(self):
        parsed = parse_kql("let a = T | where x == 'a;b';\nT | take 1")
        self.assertEqual(len(parsed.lets), 1)

    def test_a_statement_that_is_not_a_let_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_kql("SecurityEvent | take 1; SecurityEvent | take 2")
        self.assertEqual(caught.exception.code, "KQL_STATEMENT_UNKNOWN")

    def test_a_let_with_no_name_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_kql("let = SecurityEvent | take 1;\nSecurityEvent | take 1")
        self.assertEqual(caught.exception.code, "KQL_LET_NAME_MISSING")

    def test_a_stage_after_an_unreadable_one_is_also_refused(self):
        # The message has to say that nothing after it was checked, or the
        # analyst fixes one operator and believes the rule now works.
        with self.assertRaises(Refusal) as caught:
            lower_kql("SecurityEvent | frobnicate x | where y == 1")
        self.assertEqual(caught.exception.code, "KQL_OPERATOR_UNKNOWN")
        self.assertIn("not been checked", caught.exception.message)


class Bindings(unittest.TestCase):
    def setUp(self):
        self.rule, self.diagnostics = lower_kql(USER_RULE)

    def test_both_bindings_exist(self):
        self.assertEqual(
            [b.name for b in self.rule.bindings],
            ["LSASSAccess", "LateralMovement"],
        )

    def test_a_binding_is_a_pipeline_not_a_table(self):
        nodes = stages_of(self.rule, "LSASSAccess")
        self.assertIsInstance(nodes[0], Read)
        self.assertIsInstance(nodes[1], Filter)
        self.assertIsInstance(nodes[3], Project)

    def test_both_where_stages_are_present(self):
        # `EventID == 10` AND `TargetImage endswith ...` -- two separate filters,
        # and dropping either one widens the rule to every process access.
        filters = [n for n in stages_of(self.rule, "LSASSAccess")
                   if isinstance(n, Filter)]
        self.assertEqual(len(filters), 2)

    def test_project_renames_and_keeps(self):
        project = next(n for n in stages_of(self.rule, "LSASSAccess")
                       if isinstance(n, Project))
        self.assertIsInstance(project, Project)
        renamed = {target for _, target in project.renames}
        self.assertIn("LSASSTime", renamed)
        self.assertIn("Computer", {r.full for r in project.keeps})

    def test_a_rename_does_not_silently_keep_the_source(self):
        # The two halves of a rename are separate facts. A renderer or an
        # evaluator that treats "rename" as "copy" leaves `TimeGenerated` in the
        # output, and one that treats it as "move" loses a column the author
        # meant to keep.
        project = next(n for n in stages_of(self.rule, "LSASSAccess")
                       if isinstance(n, Project))
        self.assertIsInstance(project, Project)
        self.assertIn("LSASSTime", project.output_names)
        self.assertNotIn("TimeGenerated", project.output_names)


class TheJoin(unittest.TestCase):
    def setUp(self):
        self.rule, self.diagnostics = lower_kql(USER_RULE)
        self.join = next(n for n in self.rule.pipeline if isinstance(n, Join))

    def test_the_operand_is_the_binding_name(self):
        # `join ... (LateralMovement)` names a let-bound pipeline. Reading it as
        # a TABLE called LateralMovement is a rule that matches nothing, and
        # looks perfectly reasonable in the rendered output.
        self.assertEqual(self.join.right, "LateralMovement")

    def test_the_left_is_the_previous_stage(self):
        self.assertTrue(self.join.left)

    def test_both_keys_are_carried(self):
        self.assertEqual(len(self.join.on), 2)
        keys = {(left.full, right.full) for left, right in self.join.on}
        self.assertEqual(keys, {("Computer", "Computer"), ("Account", "Account")})

    def test_the_right_key_is_scoped(self):
        # A key read from the other side of the join is a SCOPED reference. Left
        # unscoped, it reads the current row and every row matches itself.
        for _, right in self.join.on:
            self.assertEqual(right.scope, "right")

    def test_it_is_a_temporal_join(self):
        self.assertIsInstance(self.join.predicate, Span)

    def test_the_predicate_reads_both_sides(self):
        # THE capability. `LoginTime between (LSASSTime .. LSASSTime + 10m)`
        # reads the right row's LoginTime against the left row's LSASSTime.
        span = self.join.predicate
        self.assertIsInstance(span, Span)
        self.assertEqual(span.value.scope, "right")
        self.assertEqual(span.low.scope, "left")

    def test_the_upper_bound_is_arithmetic(self):
        from engine.ir import Arith
        span = self.join.predicate
        self.assertIsInstance(span.high, Arith)
        self.assertEqual(span.high.op, "+")
        self.assertEqual(span.high.right.value.seconds, Decimal(600))


class Summarize(unittest.TestCase):
    def setUp(self):
        self.rule, _ = lower_kql(USER_RULE)
        self.agg = next(n for n in self.rule.pipeline if isinstance(n, Aggregate))

    def test_three_measures(self):
        self.assertEqual(len(self.agg.measures), 3)

    def test_count_is_named(self):
        names = {m.name for m in self.agg.measures}
        self.assertIn("Hits", names)

    def test_make_set_is_kept_as_a_list_aggregate(self):
        # Collapsing `make_set(SourceIp)` to one IP loses exactly the evidence a
        # correlation rule exists to collect.
        measure = next(m for m in self.agg.measures if m.function == "make_set")
        self.assertTrue(measure.distinct)
        self.assertEqual(measure.field.full, "SourceIp")

    def test_grouped_by_both_columns(self):
        self.assertEqual(
            {r.full for r in self.agg.keys}, {"Computer", "Account"}
        )

    def test_a_where_after_summarize_is_a_separate_filter(self):
        # `| where Hits >= 1` is a POST-AGGREGATE filter, a different operator
        # from the `where` before it. Collapsing the two produces a rule that
        # filters raw events on a column that only exists after aggregation.
        filters = [n for n in self.rule.pipeline if isinstance(n, Filter)]
        self.assertEqual(len(filters), 1)
        self.assertIsInstance(filters[0].condition, Comparison)

    def test_extend_after_summarize_is_a_derive(self):
        derives = [n for n in self.rule.pipeline if isinstance(n, Derive)]
        self.assertEqual(len(derives), 1)
        self.assertEqual(derives[0].assignments[0][0], "DetectionName")


class CountRefusals(unittest.TestCase):
    def test_count_of_a_column_is_refused_not_substituted(self):
        # `count(x)` counts non-null values; `count()` counts rows. On any
        # column with absent values those are different numbers, and swapping
        # them silently changes an alert threshold.
        with self.assertRaises(Refusal) as caught:
            lower_kql("T | summarize n=count(User) by Computer")
        self.assertEqual(
            caught.exception.code, "KQL_COUNT_OF_COLUMN_UNSUPPORTED"
        )
        self.assertIn("dcount", caught.exception.message)

    def test_an_unknown_aggregate_is_refused_by_name(self):
        with self.assertRaises(Refusal) as caught:
            lower_kql("T | summarize n=percentiles(User, 50) by Computer")
        self.assertEqual(caught.exception.code, "KQL_AGGREGATE_UNKNOWN")

    def test_an_unrenderable_aggregate_is_refused_before_writing_bad_kql(self):
        from engine.dialects.qradar import lower_qradar

        rule, _ = lower_qradar(
            "SELECT sourceip, FIRST(username) AS first_user "
            "FROM events GROUP BY sourceip"
        )
        with self.assertRaises(Refusal) as caught:
            render_kql(rule)
        self.assertEqual(caught.exception.code, "KQL_RENDER_AGGREGATE")

    def test_a_join_kind_is_refused_with_the_supported_set(self):
        with self.assertRaises(Refusal) as caught:
            lower_kql("T | join kind=permutation (U) on A")
        self.assertEqual(caught.exception.code, "KQL_JOIN_KIND_UNSUPPORTED")
        self.assertIn("leftouter", caught.exception.message)

    def test_a_join_with_no_on_clause_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower_kql("T | join kind=inner (U)")
        self.assertEqual(caught.exception.code, "KQL_JOIN_NO_ON")

    def test_an_unknown_operator_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower_kql("T | frobnicate x")
        self.assertEqual(caught.exception.code, "KQL_OPERATOR_UNKNOWN")

    def test_extend_without_an_equals_is_refused(self):
        # `extend` only adds or replaces. A bare column name there is a typo
        # for `project-away`, and treating it as one would delete a column.
        with self.assertRaises(Refusal) as caught:
            lower_kql("T | extend JustAField")
        self.assertEqual(caught.exception.code, "KQL_EXTEND_MALFORMED")


class RoundTrip(unittest.TestCase):
    def setUp(self):
        self.rule, _ = lower_kql(USER_RULE)
        self.rendered = render_kql(self.rule)

    def test_both_bindings_are_written_back(self):
        self.assertIn("let LSASSAccess =", self.rendered)
        self.assertIn("let LateralMovement =", self.rendered)

    def test_the_join_keeps_its_kind(self):
        # An earlier renderer emitted the join KEYS where the right-hand TABLE
        # belongs, producing `join kind=inner (Computer, Account) on ... = Table`
        # -- not valid KQL, and not caught by a test that only asserted the word
        # "join" appeared.
        self.assertIn("join kind=inner (LateralMovement) on", self.rendered)

    def test_the_temporal_predicate_survives(self):
        self.assertIn("between", self.rendered)
        self.assertIn("10m", self.rendered)

    def test_every_stage_is_written(self):
        for fragment in ("where", "project", "summarize", "extend"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.rendered)

    def test_the_rerendered_rule_lowers_again(self):
        again, _ = lower_kql(self.rendered)
        self.assertEqual(
            [type(n).__name__ for n in again.pipeline],
            [type(n).__name__ for n in self.rule.pipeline],
        )

    def test_an_unrenderable_stage_is_refused_not_skipped(self):
        from engine.dialects.kql import _render_node
        from engine.ir import Expand
        with self.assertRaises(Refusal) as caught:
            _render_node(Expand(id="x", field=FieldRef("a"), into="b"))
        self.assertEqual(caught.exception.code, "KQL_NODE_NOT_RENDERABLE")
        self.assertIn("missing this stage", caught.exception.message)


class EndToEnd(unittest.TestCase):
    """The rule, run against events. This is the whole point."""

    def setUp(self):
        self.rule, _ = lower_kql(USER_RULE)

    def _lsass(self, at, computer="WS1", account="svc"):
        return {
            "TimeGenerated": at, "EventID": 10, "Computer": computer,
            "Account": account, "TargetImage": r"c:\windows\lsass.exe",
            "SourceImage": r"c:\windows\system32\procdump.exe",
            "SourceIp": "10.0.0.5",
        }

    def _logon(self, at, computer="WS1", account="svc"):
        return {
            "TimeGenerated": at, "EventID": 4624, "Computer": computer,
            "Account": account, "LogonType": 3,
            "AuthenticationPackageName": "NTLM", "IpAddress": "10.0.0.9",
        }

    def test_the_correlation_fires(self):
        result = evaluate(self.rule, [self._lsass(1000), self._logon(1300)])
        self.assertEqual(result.verdict, Verdict.MATCHED, result.caveats)

    def test_a_logon_outside_the_window_does_not_fire(self):
        result = evaluate(self.rule, [self._lsass(1000), self._logon(100_000)])
        self.assertEqual(result.verdict, Verdict.NO_MATCH)

    def test_a_different_account_does_not_fire(self):
        result = evaluate(self.rule, [
            self._lsass(1000), self._logon(1100, account="other"),
        ])
        self.assertEqual(result.verdict, Verdict.NO_MATCH)

    def test_the_lsass_event_alone_does_not_fire(self):
        # A correlation must not fire on half its evidence.
        result = evaluate(self.rule, [self._lsass(1000)])
        self.assertEqual(result.verdict, Verdict.NO_MATCH)

    def test_a_non_lsass_process_does_not_fire(self):
        events = [self._lsass(1000), self._logon(1100)]
        events[0]["TargetImage"] = r"c:\windows\notepad.exe"
        result = evaluate(self.rule, events)
        self.assertEqual(result.verdict, Verdict.NO_MATCH)

    def test_a_non_ntlm_logon_does_not_fire(self):
        events = [self._lsass(1000), self._logon(1100)]
        events[1]["AuthenticationPackageName"] = "Kerberos"
        result = evaluate(self.rule, events)
        self.assertEqual(result.verdict, Verdict.NO_MATCH)

    def test_source_ips_come_back_as_a_collection(self):
        result = evaluate(self.rule, [self._lsass(1000), self._logon(1300)])
        self.assertEqual(result.verdict, Verdict.MATCHED)
        row = result.rows[0]
        self.assertIsInstance(row.get("SourceIPs"), Seq)
        self.assertEqual(list(row.get("SourceIPs")), ["10.0.0.5"])

    def test_the_two_directions_never_fire_together(self):
        # A logon with no LSASS access, and an LSASS access with no logon, in
        # either order, must both be no-match.
        for events in (
            [self._logon(1000)],
            [self._lsass(1000)],
            [self._logon(1000), self._lsass(1100)],
        ):
            with self.subTest(events=len(events)):
                result = evaluate(self.rule, events)
                self.assertNotEqual(result.verdict, Verdict.MATCHED)


class TheRendererWritesQueryTextNotDisplayText(unittest.TestCase):
    """`render_expr` is display text by its own docstring.

    This dialect used it to produce EXECUTABLE KQL, which is how a `where`
    clause came to contain things Sentinel cannot parse. Three consequences,
    each tested below: an unescaped backslash changed what the rule matched,
    an unescaped quote truncated the condition, and the case-insensitive
    operators were indistinguishable from the case-sensitive ones.
    """

    def roundtrip(self, text: str) -> tuple[str, str]:
        rule, _ = lower_kql(text)
        once = render_kql(rule)
        again, _ = lower_kql(once)
        return once, render_kql(again)

    def test_a_backslash_survives_the_round_trip(self):
        # `endswith "\\lsass.exe"` re-read as `endswith "lsass.exe"`, which
        # drops the path separator: `maliciouslsass.exe` then matches a rule
        # written for `\\lsass.exe`.
        #
        # The separator now lives inside the case-folding regex the operator
        # becomes, so what is asserted is the behaviour rather than the
        # spelling: the path form matches and the bare form does not.
        rule, _ = lower_kql(r'T | where Image endswith @"\lsass.exe"')
        self.assertTrue(evaluate(rule, [
            {"Image": r"C:\Windows\System32\lsass.exe", "TimeGenerated": 1},
        ]).matched)
        self.assertFalse(evaluate(rule, [
            {"Image": "maliciouslsass.exe", "TimeGenerated": 1},
        ]).matched)

    def test_the_backslash_is_still_there_after_a_re_import(self):
        once, twice = self.roundtrip(r'T | where Image endswith @"\lsass.exe"')
        self.assertEqual(once, twice)
        again, _ = lower_kql(once)
        self.assertFalse(evaluate(again, [
            {"Image": "maliciouslsass.exe", "TimeGenerated": 1},
        ]).matched, "the separator was lost on the way back in")

    def test_the_backslash_is_escaped_in_the_output(self):
        once, _ = self.roundtrip(r'T | where Image endswith @"\lsass.exe"')
        self.assertIn(r"\\lsass", once)

    def test_a_quote_in_a_value_does_not_truncate_the_condition(self):
        # `Cmd == "say "hi""` re-read as `Cmd == "say "` and the rest of the
        # condition was silently gone.
        once, twice = self.roundtrip(r'T | where Cmd == "say \"hi\""')
        self.assertEqual(once, twice)
        self.assertIn(r"\"hi\"", once)

    def test_a_case_insensitive_operator_stays_case_insensitive(self):
        # KQL's bare `endswith` ignores case and the engine's does not. Mapped
        # onto the same operator, a round trip turned this into the
        # case-SENSITIVE form and the rule stopped matching `LSASS.EXE`.
        rule, _ = lower_kql('T | where Image endswith "lsass.exe"')
        result = evaluate(
            rule, [{"Image": r"C:\Windows\LSASS.EXE", "TimeGenerated": 1}]
        )
        self.assertTrue(result.matched)

    def test_the_case_sensitive_operator_stays_case_sensitive(self):
        rule, _ = lower_kql('T | where Image endswith_cs "lsass.exe"')
        result = evaluate(
            rule, [{"Image": r"C:\Windows\LSASS.EXE", "TimeGenerated": 1}]
        )
        self.assertFalse(result.matched)

    def test_the_two_spellings_come_back_as_themselves(self):
        once, _ = self.roundtrip('T | where Image endswith "x"')
        self.assertIn('endswith "x"', once)
        self.assertNotIn("endswith_cs", once)
        cs, _ = self.roundtrip('T | where Image endswith_cs "x"')
        self.assertIn("endswith_cs", cs)

    def test_a_dot_in_a_folded_value_stays_literal(self):
        # The fold goes through a regex, so an unescaped `.` would become
        # "any character" and `lsassXexe` would match.
        rule, _ = lower_kql('T | where Image endswith "lsass.exe"')
        self.assertFalse(
            evaluate(rule, [{"Image": "lsassXexe", "TimeGenerated": 1}]).matched
        )

    def test_a_real_regex_is_not_rewritten_as_a_substring_test(self):
        once, twice = self.roundtrip(r'T | where Cmd matches regex "lsa.+ss"')
        self.assertEqual(once, twice)
        self.assertIn("matches regex", once)


class TheSortKeywordIsNotAColumn(unittest.TestCase):
    """`sort by A desc` named a column called `by A`.

    `FieldRef.parse` accepted it as a field name with a space in it, so the
    ordering was silently meaningless and the `take` that followed returned an
    arbitrary N rather than the top N. It also grew another `by` on every
    render/re-import cycle.
    """

    def test_the_keyword_is_consumed(self):
        rule, _ = lower_kql("T | where A == 1 | sort by A desc")
        keys = next(
            n.keys for n in rule.pipeline if isinstance(n, Sort)
        )
        self.assertEqual([k.full for k, _d in keys], ["A"])

    def test_the_direction_survives(self):
        rule, _ = lower_kql("T | where A == 1 | sort by A desc")
        keys = next(n.keys for n in rule.pipeline if isinstance(n, Sort))
        self.assertTrue(keys[0][1])

    def test_it_does_not_accumulate_on_re_render(self):
        rule, _ = lower_kql("T | where A == 1 | sort by A desc | take 5")
        once = render_kql(rule)
        again, _ = lower_kql(once)
        self.assertEqual(render_kql(again), once)
        self.assertNotIn("by by", once)

    def test_several_keys_are_all_read(self):
        rule, _ = lower_kql("T | where A == 1 | sort by A, B desc")
        keys = next(n.keys for n in rule.pipeline if isinstance(n, Sort))
        self.assertEqual([k.full for k, _d in keys], ["A", "B"])

    def test_a_sort_with_no_key_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower_kql("T | where A == 1 | sort by")
        self.assertEqual(caught.exception.code, "KQL_SORT_NO_KEYS")


class TheJoinPredicateIsItsOwnWhere(unittest.TestCase):
    """KQL's `on` clause holds equality keys and nothing else.

    The cross-row predicate was appended to it with ` and `, producing text
    that is not valid KQL and that this dialect's own parser swallowed into
    the key list. The temporal predicate vanished, so the rule became "any
    LSASS access on a host that ever had an NTLM logon" instead of "within ten
    minutes" -- and `validate` then refused the re-imported rule, which is the
    only reason this was visible at all.
    """

    def setUp(self):
        self.rule, _ = lower_kql(USER_RULE)
        self.rendered = render_kql(self.rule)

    def test_the_on_clause_holds_only_keys(self):
        line = next(
            l for l in self.rendered.splitlines() if "join kind=" in l
        )
        self.assertNotIn("between", line)
        self.assertNotIn(" and ", line)

    def test_the_predicate_is_a_following_where(self):
        lines = [l.strip() for l in self.rendered.splitlines()]
        join_at = next(i for i, l in enumerate(lines) if "join kind=" in l)
        self.assertTrue(lines[join_at + 1].startswith("| where"))
        self.assertIn("between", lines[join_at + 1])

    def test_the_key_uses_kql_shorthand(self):
        # `on Computer = Computer` is not KQL. The shorthand is `on Computer`.
        self.assertIn("on Computer, Account", self.rendered)

    def test_the_predicate_survives_a_re_import(self):
        again, _ = lower_kql(self.rendered)
        before = next(n for n in self.rule.pipeline if isinstance(n, Join))
        after = next(n for n in again.pipeline if isinstance(n, Join))
        self.assertIsNotNone(after.predicate)
        self.assertEqual(
            render_expr(after.predicate), render_expr(before.predicate)
        )

    def test_the_re_imported_rule_still_validates(self):
        again, _ = lower_kql(self.rendered)
        self.assertEqual(render_kql(again), self.rendered)


class TheFunctionMapUsesKqlSpellings(unittest.TestCase):
    """The map's keys were the ENGINE's underscored names.

    KQL has no `to_lower`; it has `tolower`. So `tolower(Account)` matched
    nothing in the map, passed through lowering as a function called
    `tolower`, and the evaluator could not resolve it -- every row went
    UNDECIDED and the rule reported `not_evaluated` rather than a verdict.
    """

    def test_tolower_evaluates(self):
        rule, _ = lower_kql('T | where tolower(Account) == "bob"')
        result = evaluate(
            rule, [{"Account": "BOB", "TimeGenerated": 1}]
        )
        self.assertTrue(result.matched)

    def test_tostring_evaluates(self):
        rule, _ = lower_kql('T | where tostring(Port) == "443"')
        self.assertTrue(
            evaluate(rule, [{"Port": 443, "TimeGenerated": 1}]).matched
        )

    def test_isnull_decides_a_missing_field(self):
        # KQL's schema is fixed: every row carries every column, so a missing
        # value IS null. Mapped to the strict `is_null` -- which Sigma needs --
        # this reported `not_evaluated` on exactly the rows it was written for.
        rule, _ = lower_kql("T | where isnull(Account)")
        self.assertTrue(
            evaluate(rule, [{"Other": 1, "TimeGenerated": 1}]).matched
        )

    def test_isnotnull_decides_a_missing_field(self):
        rule, _ = lower_kql("T | where isnotnull(Account)")
        self.assertFalse(
            evaluate(rule, [{"Other": 1, "TimeGenerated": 1}]).matched
        )
        self.assertTrue(
            evaluate(rule, [{"Account": "x", "TimeGenerated": 1}]).matched
        )

    def test_the_underscored_aliases_still_parse(self):
        # Anything that parsed before must keep parsing.
        rule, _ = lower_kql('T | where to_lower(Account) == "bob"')
        self.assertTrue(
            evaluate(rule, [{"Account": "BOB", "TimeGenerated": 1}]).matched
        )

    def test_every_parseable_function_can_be_rendered_back(self):
        # The drift guard. A function the parser accepts and the renderer does
        # not produces a rule that imports cleanly and then refuses on the way
        # out, which is what happened to `isnull` and `tostring`.
        from engine.dialects.kql import SPEC, _RENDER_FUNCTIONS

        missing = sorted(
            engine for engine in SPEC.functions.values()
            if engine not in _RENDER_FUNCTIONS
        )
        self.assertEqual(
            missing, [],
            f"these functions parse but cannot be written back: {missing}",
        )

    def test_the_absence_tests_name_the_field_they_could_not_decide(self):
        # A pattern test over an absent value returned a bare UNDECIDED, so
        # the analyst saw "could not decide 1 of 1 rows" with no way to find
        # out which field was missing.
        rule, _ = lower_kql('T | where Image endswith "lsass.exe"')
        result = evaluate(rule, [{"Other": 1, "TimeGenerated": 1}])
        messages = " ".join(c.message for c in result.caveats)
        self.assertIn("Image", messages)


if __name__ == "__main__":
    unittest.main()
