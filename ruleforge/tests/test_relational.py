"""Tests for the relational tier and the remaining invariant leaks.

The review found `Join` and `SetOp` had evaluator functions sitting unused while
being absent from the dispatch table: any rule containing a join validated
cleanly and then refused to run. The Sentinel shape -- a temporal join over two
event sets -- could not run at all. These tests exist so that cannot recur
silently.
"""

from __future__ import annotations

import unittest

from ruleforge.engine import (  
    ABSENT,
    Aggregate,
    Comparison,
    Derive,
    Duration,
    Emit,
    FieldExpr,
    FieldRef,
    Filter,
    Frame,
    Join,
    Literal,
    Measure,
    Read,
    Refusal,
    RuleIR,
    SetOp,
    SourceSelector,
    Verdict,
    evaluate,
)
from ruleforge.engine.ir import Call  
from ruleforge.engine.run import EVALUATORS  
from ruleforge.engine.ir import NODE_TYPES  

SRC = SourceSelector(name="events")


def read(node_id="r"):
    return Read(id=node_id, selector=SRC)


def emit(source, node_id="o"):
    return Emit(id=node_id, input=source)


def f(name, *path):
    return FieldExpr(FieldRef(name, tuple(path)))


def eq(name, value, *path):
    return Comparison("=", f(name, *path), Literal(value))


class DispatchTableTests(unittest.TestCase):
    """Every registered node must be executable.

    A node type that is registered but has no evaluator is the defect that made
    joins unrunnable. `evaluate` refused with NODE_NOT_EXECUTABLE, which is
    correct behaviour but arrived far too late -- the rule had already passed
    validation and looked fine.
    """

    def test_every_node_type_has_an_evaluator(self):
        missing = sorted(NODE_TYPES - set(EVALUATORS))
        self.assertEqual(missing, [],
                         f"{missing} are registered as node types but cannot be "
                         f"executed, so a rule using one validates and then refuses "
                         f"to run")

    def test_the_evaluator_table_has_no_extras(self):
        self.assertEqual(set(EVALUATORS) - set(NODE_TYPES), set())


class JoinTests(unittest.TestCase):

    def _graph(self, node, rows):
        return evaluate(RuleIR(rule_id="t", nodes=(read(), node, emit("j")),
                               output="o"), rows)

    def test_an_inner_join_keeps_matching_pairs(self):
        node = Join(id="j", left="r", right="r",
                    on=((FieldRef("u"), FieldRef("u")),))
        result = self._graph(node, [{"u": "a", "n": 1}, {"u": "b", "n": 2}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 2)

    def test_a_left_join_keeps_unmatched_left_rows(self):
        node = Join(id="j", left="r", right="r",
                    on=((FieldRef("u"), FieldRef("u")),), how="left")
        result = self._graph(node, [{"u": "a"}, {"u": "z"}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 2,
                         "a left join exists to keep the unmatched row")

    def test_a_temporal_join_bounds_the_difference(self):
        """The Sentinel shape: a logon from 0 to 10 minutes AFTER the access.

        Asymmetric on purpose. Collapsing it to "within 10 minutes either way"
        would match a logon BEFORE the access, which the rule never said. Two
        Reads are used so each side is a distinct set of events.
        """
        left = Read(id="l", selector=SRC)
        right = Read(id="r", selector=SRC)
        node = Join(id="j", left="l", right="r",
                    on=((FieldRef("acct"), FieldRef("acct")),),
                    temporal=((FieldRef("t1"), FieldRef("t2"),
                               Duration(0), Duration(600), True, False),))
        ir = RuleIR(rule_id="t", nodes=(left, right, node, emit("j")), output="o")
        result = evaluate(ir, {
            "l": [{"acct": "a", "t1": 0}],      # the access
            "r": [{"acct": "a", "t2": 300}],     # login 5m later: inside
        })
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 1)

    def test_a_temporal_join_excludes_a_negative_delta(self):
        """A logon BEFORE the access is outside [0, 600) and must not match."""
        left = Read(id="l", selector=SRC)
        right = Read(id="r", selector=SRC)
        node = Join(id="j", left="l", right="r",
                    on=((FieldRef("acct"), FieldRef("acct")),),
                    temporal=((FieldRef("t1"), FieldRef("t2"),
                               Duration(0), Duration(600), True, False),))
        ir = RuleIR(rule_id="t", nodes=(left, right, node, emit("j")), output="o")
        result = evaluate(ir, {
            "l": [{"acct": "a", "t1": 9000}],
            "r": [{"acct": "a", "t2": 0}],      # login 2.5h BEFORE
        })
        self.assertNotEqual(result.verdict, Verdict.MATCHED)

    def test_a_temporal_join_excludes_a_delta_beyond_the_window(self):
        left = Read(id="l", selector=SRC)
        right = Read(id="r", selector=SRC)
        node = Join(id="j", left="l", right="r",
                    on=((FieldRef("acct"), FieldRef("acct")),),
                    temporal=((FieldRef("t1"), FieldRef("t2"),
                               Duration(0), Duration(600), True, False),))
        ir = RuleIR(rule_id="t", nodes=(left, right, node, emit("j")), output="o")
        result = evaluate(ir, {
            "l": [{"acct": "a", "t1": 0}],
            "r": [{"acct": "a", "t2": 9000}],    # 2.5h later
        })
        self.assertNotEqual(result.verdict, Verdict.MATCHED)

    def test_an_outer_join_is_refused_rather_than_becoming_inner(self):
        """`how="outer"` used to validate and then behave as an inner join,
        dropping exactly the rows an outer join exists to keep."""
        with self.assertRaises(Refusal) as caught:
            Join(id="j", left="a", right="b", how="outer",
                 on=((FieldRef("u"), FieldRef("u")),))
        self.assertEqual(caught.exception.code, "JOIN_HOW_UNKNOWN")

    def test_a_conditionless_join_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            Join(id="j", left="a", right="b")
        self.assertEqual(caught.exception.code, "JOIN_NO_CONDITION")

    def test_an_inverted_temporal_window_is_refused(self):
        """A window starting after it ends matches nothing, ever. That is a rule
        that cannot fire, not a filter."""
        with self.assertRaises(Refusal) as caught:
            Join(id="j", left="a", right="b",
                 on=((FieldRef("u"), FieldRef("u")),),
                 temporal=((FieldRef("t1"), FieldRef("t2"),
                            Duration(600), Duration(60), True, True),))
        self.assertEqual(caught.exception.code, "JOIN_TEMPORAL_INVERTED")

    def test_joined_fields_are_prefixed_so_neither_wins(self):
        node = Join(id="j", left="r", right="r",
                    on=((FieldRef("u"), FieldRef("u")),))
        result = self._graph(node, [{"u": "a", "ip": "10.0.0.1"}])
        names = set(result.rows[0].values)
        self.assertTrue(any(n.endswith("ip") and n.startswith("l_") for n in names))
        self.assertTrue(any(n.endswith("ip") and n.startswith("r_") for n in names))


class SetOpTests(unittest.TestCase):

    def _graph(self, op, rows):
        node = SetOp(id="s", op=op, left="r", right="r",
                     keys=(FieldRef("u"),))
        return evaluate(RuleIR(rule_id="t", nodes=(read(), node, emit("s")),
                               output="o"), rows)

    def test_intersect_keeps_only_shared_keys(self):
        result = self._graph("intersect", [{"u": "a"}, {"u": "b"}])
        self.assertEqual(len(result.rows), 2)

    def test_except_removes_right_hand_keys(self):
        """A self-join would make left and right identical, so except would remove
        everything. Two DISTINCT inputs are needed for difference to mean
        anything, which is why this test builds its own graph."""
        left = Read(id="l", selector=SRC)
        right = Read(id="r", selector=SRC)
        node = SetOp(id="s", op="except", left="l", right="r",
                     keys=(FieldRef("u"),))
        ir = RuleIR(rule_id="t", nodes=(left, right, node, emit("s")), output="o")
        result = evaluate(ir, {"l": [{"u": "a"}, {"u": "b"}],
                              "r": [{"u": "b"}]})
        kept = {dict(row.values).get("u") for row in result.rows}
        self.assertEqual(kept, {"a"}, "except removes keys present on the right")

    def test_one_row_list_for_two_reads_is_refused_rather_than_assumed(self):
        """Feeding both Reads the same list makes every equality key match, so the
        join output is the square of the input and looks entirely plausible."""
        left = Read(id="l", selector=SRC)
        right = Read(id="r", selector=SRC)
        node = Join(id="j", left="l", right="r",
                    on=((FieldRef("u"), FieldRef("u")),))
        ir = RuleIR(rule_id="t", nodes=(left, right, node, emit("j")), output="o")
        result = evaluate(ir, [{"u": "a"}])
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertEqual(result.reason.code, "SAMPLE_AMBIGUOUS_FOR_MULTIPLE_READS")

    def test_an_unknown_op_is_refused_at_construction(self):
        with self.assertRaises(Refusal) as caught:
            SetOp(id="s", op="minus", left="a", right="b", keys=(FieldRef("u"),))
        self.assertEqual(caught.exception.code, "SETOP_OP_UNKNOWN")

    def test_a_keyless_setop_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            SetOp(id="s", op="union", left="a", right="b")
        self.assertEqual(caught.exception.code, "SETOP_NO_KEYS")


class NestedFieldTests(unittest.TestCase):
    """FieldRef.path was honoured by the expression layer and IGNORED by every
    node. So `event.v` resolved to `event.v` in a Filter and to the whole `event`
    dict in an Aggregate, a Join key, a sort column and a time reference. The two
    layers disagreed about what a field was."""

    def _agg(self, field_ref):
        return Aggregate(id="a", input="r",
                         measures=(Measure("m", "max", field=field_ref),),
                         frame=Frame(kind="per_event"))

    def test_a_nested_measure_reads_the_nested_value(self):
        rows = [{"event": {"v": 1}}, {"event": {"v": 7}}]
        result = evaluate(RuleIR(rule_id="t", nodes=(
            read(), self._agg(FieldRef("event", ("v",))), emit("a")),
            output="o"), rows)
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(result.rows[0].values["m"], 7,
                         "the whole event dict is not a max of v")

    def test_a_nested_group_key_groups_on_the_nested_value(self):
        rows = [{"e": {"g": "x"}, "n": 1}, {"e": {"g": "x"}, "n": 2},
                {"e": {"g": "y"}, "n": 3}]
        node = Aggregate(id="a", input="r",
                         measures=(Measure("n", "count"),),
                         keys=(FieldRef("e", ("g",),),),
                         frame=Frame(kind="per_event"))
        result = evaluate(RuleIR(rule_id="t", nodes=(read(), node, emit("a")),
                                 output="o"), rows)
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 2, "x and y are two groups")

    def test_the_resolver_reads_a_nested_path_and_reports_a_missing_one(self):
        """`TimeRef` names a plain field, so a nested timestamp cannot be declared
        there. The resolver itself is what the rest of the engine depends on, so it
        is verified directly rather than through a node that cannot carry a path.
        """
        from ruleforge.engine.nodes import resolve_field
        from ruleforge.engine.evaluate import Row
        row = Row({"t": {"v": 42}})
        self.assertEqual(resolve_field(row, FieldRef("t", ("v",))), 42)
        self.assertIs(resolve_field(row, FieldRef("t", ("missing",))), ABSENT)
        self.assertIs(resolve_field(row, FieldRef("absent", ("v",))), ABSENT)


class NoFabricatedNullTests(unittest.TestCase):
    """Derive and Aggregate both wrote None for an ABSENT value, turning "this
    field is not in the row" into "this field is present and null"."""

    def test_derive_does_not_invent_a_null_column(self):
        node = Derive(id="d", input="r", assignments=(("x", eq("a", 1)),))
        node2 = Emit(id="o", input="d", columns=("x",))
        result = evaluate(RuleIR(rule_id="t", nodes=(read(), node, node2),
                                 output="o"), [{}])
        self.assertIsNot(result.verdict, Verdict.MATCHED)
        self.assertEqual(result.reason.code, "EMIT_COLUMN_MISSING")

    def test_an_aggregate_key_that_is_absent_is_not_written_as_null(self):
        node = Aggregate(id="a", input="r",
                         measures=(Measure("n", "count"),),
                         keys=(FieldRef("user"),),
                         frame=Frame(kind="per_event"))
        result = evaluate(RuleIR(rule_id="t", nodes=(read(), node, emit("a")),
                                 output="o"), [{}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertNotIn("user", result.rows[0].values,
                         "an absent key must stay absent, not become null")
        self.assertEqual(result.rows[0].uncertain.get("user"), "absent")


class DistinctCountTests(unittest.TestCase):
    """`distinct_count` returned len(group_rows) because the model refuses a
    field on a nullary aggregate, so the field branch was never taken. The two
    aggregates were transpositions of each other."""

    def test_distinct_count_needs_a_field(self):
        with self.assertRaises(Refusal) as caught:
            Measure("d", "distinct_count")
        self.assertEqual(caught.exception.code, "MEASURE_FIELD_REQUIRED")

    def test_distinct_count_is_not_the_same_as_count(self):
        rows = [{"u": "a"}, {"u": "a"}, {"u": "b"}, {}]
        node = Aggregate(id="a", input="r", measures=(
            Measure("total", "count"),
            Measure("distinct", "distinct_count", field=FieldRef("u")),
        ), frame=Frame(kind="per_event"))
        result = evaluate(RuleIR(rule_id="t", nodes=(read(), node, emit("a")),
                                 output="o"), rows)
        values = result.rows[0].values
        self.assertEqual(values["total"], 4)
        self.assertEqual(values["distinct"], 2,
                         "count and distinct_count must not be the same number")


class CoalesceTests(unittest.TestCase):
    """coalesce returned UNDECIDED whenever any argument was ABSENT -- which is
    the only case coalesce exists for. It could never do its one job."""

    def test_coalesce_takes_the_first_present_argument(self):
        node = Filter(id="fl", input="r", condition=Comparison(
            "=", Call("coalesce", (f("user"), f("owner"))), Literal("admin")))
        result = evaluate(RuleIR(rule_id="t", nodes=(read(), node, emit("fl")),
                                 output="o"),
                          [{"owner": "admin"}, {"user": "admin"}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 2)

    def test_coalesce_with_nothing_present_is_undecided(self):
        node = Filter(id="fl", input="r", condition=Comparison(
            "=", Call("coalesce", (f("user"), f("owner"))), Literal("admin")))
        result = evaluate(RuleIR(rule_id="t", nodes=(read(), node, emit("fl")),
                                 output="o"), [{"nothing": 1}])
        self.assertIsNot(result.verdict, Verdict.MATCHED)


class FrameGapTests(unittest.TestCase):
    """Frame.gap was accepted and ignored on every kind except session."""

    def test_a_gap_on_a_tumbling_frame_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            Frame(kind="tumbling", size=Duration(300), gap=Duration(60),
                  time_ref=__import__("ruleforge.engine", fromlist=["TimeRef"]
                                      ).TimeRef("t"))
        self.assertEqual(caught.exception.code, "FRAME_GAP_NOT_APPLICABLE")

    def test_a_gap_on_a_session_frame_is_accepted(self):
        frame = Frame(kind="session", gap=Duration(300))
        self.assertEqual(frame.gap.seconds, 300)


if __name__ == "__main__":
    unittest.main()
