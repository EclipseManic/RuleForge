"""The user's real Sentinel KQL, as an acceptance test.

Verbatim from their request. It is the hardest of the five for this engine in one
specific way: it correlates TWO separately-defined event sets over a window, which
means `let` bindings, a join, and a temporal range expressed as a same-row
comparison of two joined columns.
"""

from __future__ import annotations

import unittest

from ruleforge.dialects import lower_kql, parse_kql  
from typing import Any  

from ruleforge.engine import (  
    Aggregate,
    Join,
    Refusal,
    RuleIR,
    Verdict,
    evaluate,
    validate_graph,
)
from ruleforge.engine.ir import BoolOp  

USER_SENTINEL_RULE = """
let timeframe = 30m;

let LSASSAccess =
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 10
| where TargetImage endswith @"\\lsass.exe"
| where GrantedAccess in ("0x1fffff", "0x1010", "0x1410", "0x143a")
| project
    LSASSTime=TimeGenerated,
    Computer,
    Account,
    SourceImage,
    SourceIp,
    TargetImage;

let LateralMovement =
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| project
    LoginTime=TimeGenerated,
    Computer,
    Account,
    IpAddress;

LSASSAccess
| join kind=inner LateralMovement
    on Computer, Account
| where LoginTime between (LSASSTime .. LSASSTime + 10m)
| summarize
    LSASSAccessCount=count(),
    FirstSeen=min(LSASSTime),
    LastSeen=max(LoginTime),
    SourceIPs=make_set(SourceIp),
    SourceImages=make_set(SourceImage)
    by Computer, Account
| where LSASSAccessCount >= 1
| extend
    DetectionName="Credential Access Followed By NTLM Lateral Movement",
    MITRE="T1003.001,T1021.002"
"""


class ParsingTests(unittest.TestCase):

    def setUp(self):
        self.parsed = parse_kql(USER_SENTINEL_RULE)

    def test_both_let_bindings_are_found(self):
        self.assertEqual(set(self.parsed.lets),
                         {"timeframe", "LSASSAccess", "LateralMovement"})

    def test_the_final_expression_is_the_join_pipeline(self):
        self.assertIn("join", self.parsed.body)
        self.assertIn("summarize", self.parsed.body)

    def test_a_duplicate_let_is_refused_rather_than_resolved_by_position(self):
        script = """
        let a = SecurityEvent | where EventID == 1;
        let a = SecurityEvent | where EventID == 2;
        a
        """
        with self.assertRaises(Refusal) as caught:
            parse_kql(script)
        self.assertEqual(caught.exception.code, "KQL_LET_DUPLICATE")


class LoweringTests(unittest.TestCase):

    def setUp(self):
        self.ir, self.diagnostics = lower_kql(parse_kql(USER_SENTINEL_RULE))

    def test_it_produces_a_runnable_graph(self):
        validate_graph(self.ir)

    def test_the_where_before_the_join_filters_the_left_side(self):
        """Order is semantics, not style. A `where` lifted above a join that names
        a column only the join produces would reference a field no row has yet.

        The branch's filters are UPSTREAM of the node the join consumes, so this
        walks back from the join rather than looking for a filter whose input is
        the join's left id.
        """
        join = next(n for n in self.ir.nodes if isinstance(n, Join))
        by_id = {n.id: n for n in self.ir.nodes}
        upstream: list[Any] = []
        cursor = join.left
        while cursor in by_id:
            node = by_id[cursor]
            upstream.append(node)
            cursor = getattr(node, "input", None)
        filter_count = sum(1 for n in upstream
                           if type(n).__name__ == "Filter")
        self.assertGreaterEqual(filter_count, 3,
                                "each let branch filters before it is joined")

        after = [n for n in self.ir.nodes
                 if type(n).__name__ == "Filter" and n.input == join.id]
        self.assertTrue(after,
                        "the range filter runs on MERGED columns, so it must sit "
                        "after the join")

    def test_the_join_is_on_the_two_named_columns(self):
        join = next(n for n in self.ir.nodes if isinstance(n, Join))
        self.assertEqual(join.how, "inner")
        self.assertEqual({left.name for left, _ in join.on},
                         {"Computer", "Account"})

    def test_between_expands_to_two_conjoined_comparisons(self):
        """`a between (x .. y)` is exactly `a >= x and a <= y`. Expanding it means
        the rendered rule shows the two tests the engine actually applied instead
        of hiding them behind an operator the analyst cannot verify."""
        join = next(n for n in self.ir.nodes if isinstance(n, Join))
        after = [n for n in self.ir.nodes
                 if type(n).__name__ == "Filter" and n.input == join.id]
        condition = after[0].condition
        self.assertIsInstance(condition, BoolOp)
        self.assertEqual(condition.op, "and")
        self.assertEqual(len(condition.operands), 2)
        self.assertEqual({o.op for o in condition.operands}, {">=", "<="})

    def test_the_join_carries_NO_temporal_predicate(self):
        """Applying the engine's temporal predicate as well would filter TWICE,
        and the second filter would be invisible in the rendered rule -- which
        would show one `where` while the join quietly did extra work."""
        join = next(n for n in self.ir.nodes if isinstance(n, Join))
        self.assertEqual(join.temporal, (),
                         "the rule's own `where between` is the window constraint")

    def test_the_aggregate_carries_the_four_measures_and_two_keys(self):
        join = next(n for n in self.ir.nodes if isinstance(n, Join))
        aggregate = next(n for n in self.ir.nodes if isinstance(n, Aggregate))
        measures = {m.name: m.function for m in aggregate.measures}
        self.assertEqual(measures.get("LSASSAccessCount"), "count")
        self.assertEqual(measures.get("FirstSeen"), "min")
        self.assertEqual(measures.get("LastSeen"), "max")
        self.assertEqual(measures.get("SourceIPs"), "set",
                         "make_set collects values, it does not count them")

        # THE GROUPING KEYS ARE THE JOIN PREFIXED, NOT BARE. The `summarize`
        # runs downstream of the join, and the engine's Join stores merged
        # columns prefixed so one side cannot silently overwrite the other. The
        # merged row therefore HAS NO BARE `Computer` -- keying on it would be
        # unresolvable. An earlier version of this test asserted the bare names,
        # which was written before post-join resolution existed and described a
        # row shape the engine does not produce.
        self.assertEqual({k.name for k in aggregate.keys},
                         {"l_Computer", "l_Account"})

        # TIE THE EXPECTATION TO THE JOIN RATHER THAN HARD-CODING THE PREFIX, so
        # changing `left_prefix` cannot silently invalidate this test.
        for key in aggregate.keys:
            self.assertTrue(
                key.name.startswith((join.left_prefix, join.right_prefix)),
                f"{key.name} is neither side's column")

        # THE JOIN KEYS THEMSELVES STAY BARE, because they are compared BEFORE
        # the merge. This is the asymmetry that makes the round-trip recoverable:
        # a KQL renderer must strip the prefix on post-join references and leave
        # the join condition untouched. It must NOT strip by string match --
        # `l_Process` is a legal KQL field name -- so it has to invert the
        # join's actual column map, which the IR does not yet carry.
        self.assertEqual({left.name for left, _ in join.on},
                         {"Computer", "Account"})

    def test_make_set_is_not_the_same_as_a_distinct_count(self):
        """`make_set` returns a collection; `dcount` returns a number. Mapping one
        to the other changes the column's type and every use of it."""
        rows = [{"SourceIp": "10.0.0.1"}, {"SourceIp": "10.0.0.2"},
                {"SourceIp": "10.0.0.1"}]
        from ruleforge.engine import FieldRef, Frame, Measure
        node = Aggregate(id="a", input="r",
                         measures=(Measure("ips", "set", field=FieldRef("SourceIp")),),
                         frame=Frame(kind="per_event"))
        ir = RuleIR(rule_id="t", nodes=(
            __import__("ruleforge.engine", fromlist=["Read"]).Read(
                id="r", selector=__import__(
                    "ruleforge.engine", fromlist=["SourceSelector"]
                ).SourceSelector(name="events")),
            node,
            __import__("ruleforge.engine", fromlist=["Emit"]).Emit(
                id="o", input="a")), output="o")
        result = evaluate(ir, rows)
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(result.rows[0].values["ips"], ("10.0.0.1", "10.0.0.2"))

    def test_the_ingestion_delay_is_disclosed(self):
        codes = [d.code for d in self.diagnostics]
        self.assertIn("SENTINEL_INGESTION_DELAY", codes)
        delay = next(d for d in self.diagnostics
                     if d.code == "SENTINEL_INGESTION_DELAY")
        self.assertIn("5 minutes", delay.message)


class RefusalTests(unittest.TestCase):

    def test_a_conditional_aggregate_is_refused_not_approximated(self):
        """`countif(...)` counts matching rows, not all rows. Mapping it to
        `count` would count the wrong rows and look entirely plausible."""
        script = "SecurityEvent | summarize n=countif(EventID == 10)"
        with self.assertRaises(Refusal) as caught:
            lower_kql(parse_kql(script))
        self.assertEqual(caught.exception.code,
                         "KQL_AGGREGATE_CONDITIONAL_UNSUPPORTED")

    def test_count_of_a_column_is_refused_because_it_is_not_count_star(self):
        script = "SecurityEvent | summarize n=count(Account)"
        with self.assertRaises(Refusal) as caught:
            lower_kql(parse_kql(script))
        self.assertEqual(caught.exception.code, "KQL_COUNT_OF_COLUMN_UNSUPPORTED")

    def test_an_unimplemented_join_kind_is_refused(self):
        """`leftouter` changes which rows survive, so a wrong row set here changes
        the correlation the rule exists to detect."""
        script = ("let a = SecurityEvent | where EventID == 1;\n"
                  "let b = SecurityEvent | where EventID == 2;\n"
                  "a | join kind=leftouter (b) on Computer")
        with self.assertRaises(Refusal) as caught:
            lower_kql(parse_kql(script))
        self.assertIn(caught.exception.code,
                      ("KQL_JOIN_KIND_UNSUPPORTED", "KQL_JOIN_KIND_UNKNOWN"))

    def test_an_unimplemented_operator_is_refused_rather_than_dropped(self):
        script = "SecurityEvent | mv-expand foo"
        with self.assertRaises(Refusal) as caught:
            lower_kql(parse_kql(script))
        self.assertEqual(caught.exception.code, "KQL_OPERATOR_UNSUPPORTED")

    def test_a_cross_product_join_is_refused(self):
        script = ("let a = SecurityEvent | where EventID == 1;\n"
                  "let b = SecurityEvent | where EventID == 2;\n"
                  "a | join kind=inner (b)")
        with self.assertRaises(Refusal) as caught:
            lower_kql(parse_kql(script))
        self.assertEqual(caught.exception.code, "KQL_JOIN_NO_ON")


class ExecutionTests(unittest.TestCase):
    """The correlation, run against sample SecurityEvent rows."""

    def _ir(self):
        # Everything up to and including the range filter. The `summarize` and
        # everything downstream of it are cut, because a windowed aggregate would
        # need a time field on every row. Cutting only the Aggregate and keeping
        # its consumer left a filter reading a node that was no longer in the
        # graph, which validation correctly refused.
        parsed = parse_kql(USER_SENTINEL_RULE)
        ir, _ = lower_kql(parsed)
        join = next(n for n in ir.nodes if isinstance(n, Join))
        cut = next(n for n in ir.nodes
                   if type(n).__name__ == "Filter" and n.input == join.id).id
        by_id = {n.id: n for n in ir.nodes}
        keep: list[Any] = []

        def walk_back(node_id: str | None) -> None:
            """Walk a chain backwards, following BOTH sides of a join.

            A join's right input is a separate chain, so a single-parent walk
            dropped the whole `LateralMovement` branch and left the join reading
            a node that was never in the graph.
            """
            while node_id and node_id in by_id and node_id not in seen:
                seen.add(node_id)
                node = by_id[node_id]
                keep.append(node)
                if isinstance(node, (Aggregate,)):
                    return
                if isinstance(node, Join):
                    walk_back(node.right)
                    node_id = node.left
                else:
                    node_id = getattr(node, "input", None)

        seen: set[str] = set()
        walk_back(cut)
        keep.reverse()
        from ruleforge.engine import Emit
        return RuleIR(rule_id="t", nodes=tuple(keep) + (Emit(id="o", input=cut),),
                      output="o")

    #: The access happens at 5000s. The rule filters `TimeGenerated > ago(30m)`,
    #: which lowers to `> 1800`, so sample timestamps must be ABOVE the lookback or
    #: every row is filtered out before the join and the correlation is never
    #: exercised. A sample below its own lookback window is a plausible-looking
    #: test that proves nothing.
    ACCESS_TIME = 5000

    def _rows(self, login_delta):
        # The left branch filters on EventID, TargetImage AND GrantedAccess, so a
        # sample missing any of them is UNDECIDABLE rather than matching -- which
        # looked like a broken correlation when it was an incomplete fixture.
        return {
            "LSASSAccess_read": [
                {"TimeGenerated": self.ACCESS_TIME, "EventID": 10,
                 "TargetImage": r"C:\Windows\System32\lsass.exe",
                 "GrantedAccess": "0x1fffff",
                 "Computer": "C1", "Account": "admin", "SourceIp": "10.0.0.1",
                 "SourceImage": r"C:\Windows\System32\procdump.exe"},
            ],
            "LateralMovement_read": [
                {"TimeGenerated": self.ACCESS_TIME + login_delta, "EventID": 4624,
                 "Computer": "C1", "Account": "admin", "LogonType": 3,
                 "AuthenticationPackageName": "NTLM", "IpAddress": "10.0.0.9"},
            ],
        }

    def test_a_logon_inside_the_window_correlates(self):
        result = evaluate(self._ir(), self._rows(300))
        self.assertIs(result.verdict, Verdict.MATCHED,
                      "a logon 5 minutes after the access is inside 10 minutes")

    def test_a_logon_beyond_the_window_does_not_correlate(self):
        result = evaluate(self._ir(), self._rows(3600))
        self.assertIsNot(result.verdict, Verdict.MATCHED,
                         "a logon an hour later is not within 10 minutes")

    def test_a_logon_before_the_access_does_not_correlate(self):
        """The range is `LSASSTime .. LSASSTime + 10m`, so it starts AT the
        access. A logon before it is outside, which is the asymmetry the rule
        states and a symmetric 'within 10 minutes' reading would lose."""
        result = evaluate(self._ir(), self._rows(-300))
        self.assertIsNot(result.verdict, Verdict.MATCHED,
                         "a logon before the access is outside the range")


if __name__ == "__main__":
    unittest.main()
