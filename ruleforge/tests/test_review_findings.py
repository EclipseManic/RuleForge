"""Tests written from an independent review's findings.

Every test here corresponds to a defect the review found in code that had 66
passing tests. That is the uncomfortable part: the suite was green and the engine
was still wrong seven ways. A green suite is not evidence of correctness unless
the tests can actually distinguish the broken behaviour from the right one, which
is why each test below is paired with a mutation in `mutation_check.py`.

The review's own verdict on the earlier mutation set: it mutated the 5% of the
code that was already densely tested and left the 40% that was not. This file
closes the largest part of that gap.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from ruleforge.engine import (  # noqa: E402
    Duration,
    Emit,
    FieldExpr,
    FieldRef,
    Filter,
    Literal,
    Pattern,
    Join,
    Read,
    Refusal,
    RuleIR,
    SourceSelector,
    Verdict,
    evaluate,
)
from ruleforge.engine.ir import BoolOp, Comparison as Cmp, Not  # noqa: E402

SRC = SourceSelector(name="events")


def read(node_id="r"):
    return Read(id=node_id, selector=SRC)


def emit(source, node_id="o"):
    return Emit(id=node_id, input=source)


def f(name):
    return FieldExpr(FieldRef(name))


def is_eq(name, value):
    return Cmp("=", f(name), Literal(value))


class StageZeroTests(unittest.TestCase):
    """CRITICAL 1: Pattern stage 0 was validated and then discarded.

    `consumed = [start_row]` for EVERY row in the group, with only stages[1:]
    walked. So "a=1 THEN b=2" matched on rows where a was never 1 -- a
    correlation rule firing on arbitrary events.
    """

    def _pattern(self):
        return Pattern(id="p", input="r",
                       stages=((is_eq("a", 1),), (is_eq("b", 2),)),
                       within=Duration(600), time_field="ts")

    def test_stage_zero_must_actually_match(self):
        ir = RuleIR(rule_id="t", nodes=(read(), self._pattern(), emit("p")),
                    output="o")
        result = evaluate(ir, [{"a": 99, "b": 2, "ts": 10},
                               {"a": 99, "b": 2, "ts": 20}])
        self.assertIsNot(result.verdict, Verdict.MATCHED,
                         "no row has a=1, so the sequence cannot have occurred")

    def test_a_real_sequence_still_matches(self):
        ir = RuleIR(rule_id="t", nodes=(read(), self._pattern(), emit("p")),
                    output="o")
        result = evaluate(ir, [{"a": 1, "b": 0, "ts": 10},
                               {"a": 1, "b": 2, "ts": 20}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 1)


class WithinWindowTests(unittest.TestCase):
    """CRITICAL 2: `Pattern.within` was referenced nowhere in the engine.

    The window is the whole point of "credential access, then a privileged logon
    WITHIN 10 MINUTES". Ignoring it matched across any gap whatsoever.
    """

    def _pattern(self):
        return Pattern(id="p", input="r",
                       stages=((is_eq("a", 1),), (is_eq("b", 2),)),
                       within=Duration(60), time_field="ts")

    def test_a_second_event_beyond_the_window_does_not_match(self):
        ir = RuleIR(rule_id="t", nodes=(read(), self._pattern(), emit("p")),
                    output="o")
        result = evaluate(ir, [{"a": 1, "b": 0, "ts": 0},
                               {"a": 1, "b": 2, "ts": 10800}])   # 3 hours later
        self.assertIsNot(result.verdict, Verdict.MATCHED,
                         "3 hours is not within 60 seconds")

    def test_a_second_event_inside_the_window_does_match(self):
        ir = RuleIR(rule_id="t", nodes=(read(), self._pattern(), emit("p")),
                    output="o")
        result = evaluate(ir, [{"a": 1, "b": 0, "ts": 0},
                               {"a": 1, "b": 2, "ts": 30}])
        self.assertIs(result.verdict, Verdict.MATCHED)


class UntilVetoTests(unittest.TestCase):
    """CRITICAL 3: `until` vetoed the LAST matched row, not the window.

    "Access, then NO logout for 10 minutes" is the negative twin the node exists
    to express. Deciding it from whichever event happened to end the sequence
    meant a logout in the middle of the window passed straight through.
    """

    def test_a_veto_anywhere_in_the_window_discards_the_match(self):
        pattern = Pattern(id="p", input="r",
                          stages=((is_eq("a", 1),), (is_eq("b", 2),),
                                  (is_eq("c", 3),)),
                          within=Duration(600), time_field="ts",
                          until=is_eq("d", 9))
        ir = RuleIR(rule_id="t", nodes=(read(), pattern, emit("p")), output="o")
        result = evaluate(ir, [
            {"a": 1, "b": 2, "c": 3, "d": 0, "ts": 1},
            {"d": 9, "ts": 2},        # the veto, in the MIDDLE of the window
            {"b": 2, "ts": 3},
            {"c": 3, "ts": 4},
        ])
        self.assertIsNot(result.verdict, Verdict.MATCHED,
                         "a logout inside the window must veto the sequence")

    def test_no_veto_in_the_window_allows_the_match(self):
        pattern = Pattern(id="p", input="r",
                          stages=((is_eq("a", 1),), (is_eq("b", 2),)),
                          within=Duration(600), time_field="ts",
                          until=is_eq("d", 9))
        ir = RuleIR(rule_id="t", nodes=(read(), pattern, emit("p")), output="o")
        result = evaluate(ir, [{"a": 1, "b": 0, "d": 0, "ts": 1},
                               {"a": 1, "b": 2, "d": 0, "ts": 2}])
        self.assertIs(result.verdict, Verdict.MATCHED)


class BoolOpLeakTests(unittest.TestCase):
    """CRITICAL 6: `and_` treated anything that was not False/Undecided as True.

    So `a = 999 AND <absent field>` reported MATCHED. The primary invariant, the
    one the whole engine exists for, violated in the most direct way available.
    """

    def test_a_non_boolean_operand_never_becomes_a_match(self):
        ir = RuleIR(rule_id="t", nodes=(
            read(),
            Filter(id="fl", input="r", condition=BoolOp(
                "and", (is_eq("a", 999), f("nope")))),
            emit("fl"),
        ), output="o")
        result = evaluate(ir, [{"a": 999}])
        self.assertIsNot(result.verdict, Verdict.MATCHED)

    def test_a_bare_literal_operand_never_becomes_a_match(self):
        ir = RuleIR(rule_id="t", nodes=(
            read(),
            Filter(id="fl", input="r", condition=BoolOp(
                "and", (is_eq("a", 999), Literal(1)))),
            emit("fl"),
        ), output="o")
        self.assertIsNot(evaluate(ir, [{"a": 999}]).verdict, Verdict.MATCHED)


class PresenceTests(unittest.TestCase):
    """HIGH 8: every `exists` / `is_not_null` returned UNDECIDED, always.

    The code evaluated `left` first and then asked whether the RESULT was a
    FieldExpr. It never is. So the presence vocabulary was entirely unrunnable,
    and the caveat then claimed a field was absent on rows where it was present
    -- a false statement about the analyst's data.
    """

    def _filter(self, op):
        return RuleIR(rule_id="t", nodes=(
            read(),
            Filter(id="fl", input="r",
                   condition=Cmp(op, f("a"), Literal(True))),
            emit("fl"),
        ), output="o")

    def test_exists_matches_rows_that_have_the_field(self):
        result = evaluate(self._filter("exists"), [{"a": 1}, {"a": 2}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 2)

    def test_exists_excludes_rows_that_do_not(self):
        result = evaluate(self._filter("exists"), [{"a": 1}, {"b": 2}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 1)

    def test_is_not_null_excludes_a_null_value(self):
        result = evaluate(self._filter("is_not_null"), [{"a": 1}, {"a": None}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 1)

    def test_presence_never_claims_a_present_field_is_absent(self):
        result = evaluate(self._filter("exists"), [{"a": 1}, {"a": 2}])
        for caveat in result.caveats:
            self.assertNotIn("ROW_UNDECIDABLE", [caveat.code],
                             "a present field must never be reported undecidable")


class DedupeTests(unittest.TestCase):
    """CRITICAL 7: `Emit(dedupe_by=...)` collapsed rows lacking the key.

    `_group_key` maps ABSENT to one shared identity, so 50 events with no `user`
    became ONE alert, silently, with no caveat.
    """

    def test_rows_missing_the_dedupe_key_are_not_collapsed(self):
        ir = RuleIR(rule_id="t", nodes=(
            read(),
            Emit(id="o", input="r", dedupe_by=(FieldRef("user"),)),
        ), output="o")
        rows = [{"a": i} for i in range(50)]
        result = evaluate(ir, rows)
        self.assertEqual(len(result.rows), 50,
                         "50 events must not silently become 1 alert")
        self.assertIn("EMIT_DEDUPE_KEY_ABSENT", [c.code for c in result.caveats])

    def test_dedupe_still_works_when_the_key_is_present(self):
        ir = RuleIR(rule_id="t", nodes=(
            read(),
            Emit(id="o", input="r", dedupe_by=(FieldRef("user"),)),
        ), output="o")
        rows = [{"user": "a", "n": 1}, {"user": "a", "n": 2}, {"user": "b", "n": 3}]
        self.assertEqual(len(evaluate(ir, rows).rows), 2)


class RegexHonestyTests(unittest.TestCase):
    """CRITICALs 4 and 5: the regex layer returned WRONG BOOLEANS, not refusals.

    In POSIX BRE the characters + ? { | ( ) are LITERALS, not operators. The
    translation passed them through, so a literal `a+b` was evaluated as "one or
    more a, then b" -- wrong in both directions. A missed detection.
    """

    def test_posix_basic_is_not_executable(self):
        from ruleforge.engine.regex import compile_pattern
        with self.assertRaises(Refusal) as caught:
            compile_pattern("posix_basic", "abc")
        self.assertEqual(caught.exception.code, "REGEX_NOT_EXECUTABLE")

    def test_pcre_is_not_executable(self):
        from ruleforge.engine.regex import compile_pattern
        with self.assertRaises(Refusal) as caught:
            compile_pattern("pcre", "^abc$")
        self.assertEqual(caught.exception.code, "REGEX_NOT_EXECUTABLE")

    def test_a_bre_literal_metacharacter_is_never_evaluated(self):
        """`a+b` in BRE is four literal characters. Evaluating it as a quantifier
        reports a match where BRE says no-match, and vice versa."""
        from ruleforge.engine.regex import EXECUTABLE_DIALECTS
        self.assertNotIn("posix_basic", EXECUTABLE_DIALECTS)

    def test_a_lookaround_is_refused_rather_than_evaluated(self):
        from ruleforge.engine.regex import compile_pattern
        for pattern in ("(?<=a)b", "(?=a)b", "(?!a)b", "(?P<n>a)", "(?m)a.b"):
            with self.assertRaises(Refusal, msg=f"{pattern} was not refused"):
                compile_pattern("posix_extended", pattern)

    def test_a_backslash_escape_is_refused_rather_than_evaluated(self):
        from ruleforge.engine.regex import compile_pattern
        for pattern in (r"^\d+$", r"\bword\b", r"a{2,4}"):
            with self.assertRaises(Refusal, msg=f"{pattern} was not refused"):
                compile_pattern("posix_extended", pattern)

    def test_a_posix_named_class_is_refused(self):
        from ruleforge.engine.regex import compile_pattern
        with self.assertRaises(Refusal):
            compile_pattern("posix_extended", "[[:digit:]]+")

    def test_a_plain_anchor_pattern_still_runs(self):
        from ruleforge.engine.regex import compile_pattern
        matcher = compile_pattern("posix_extended", "^x")
        self.assertTrue(matcher("xyz"))
        self.assertFalse(matcher("abc"))

    def test_describe_dialect_makes_no_false_claim(self):
        """An earlier version told the analyst portable PCRE patterns "are
        accepted" while every PCRE pattern was refused before being read."""
        from ruleforge.engine.regex import EXECUTABLE_DIALECTS, describe_dialect
        for dialect in ("pcre", "posix_extended", "posix_basic"):
            text = describe_dialect(dialect)
            if dialect not in EXECUTABLE_DIALECTS:
                self.assertIn("NOT executable", text)
                self.assertNotIn("are accepted", text)


class CrashPathTests(unittest.TestCase):
    """HIGH 11: four unhandled-exception paths escaped as raw tracebacks."""

    def test_an_unhashable_group_key_is_a_refusal_not_a_crash(self):
        from ruleforge.engine import Aggregate, Frame, Measure
        ir = RuleIR(rule_id="t", nodes=(
            read(),
            Aggregate(id="a", input="r", keys=(FieldRef("user"),),
                      measures=(Measure("n", "count"),),
                      frame=Frame(kind="per_event")),
            emit("a"),
        ), output="o")
        result = evaluate(ir, [{"user": ["a", "b"]}, {"user": "c"}])
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)
        self.assertIsNotNone(result.reason)

    def test_a_mixed_type_sort_column_is_a_refusal_not_a_crash(self):
        from ruleforge.engine import Arrange
        ir = RuleIR(rule_id="t", nodes=(
            read(),
            Arrange(id="s", input="r", order_by=((FieldRef("v"), "asc"),)),
            emit("s"),
        ), output="o")
        result = evaluate(ir, [{"v": 1}, {"v": "x"}, {"v": 2}])
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED)

    def test_the_whole_walk_cannot_leak_a_traceback(self):
        """Whatever goes wrong, an analyst gets a named refusal, never a 500."""
        for rows in ([{"user": ["a"]}], [{"v": {"deep": 1}}], [{"v": 1e308}]):
            ir = RuleIR(rule_id="t", nodes=(
                read(),
                Emit(id="o", input="r"),
            ), output="o")
            result = evaluate(ir, rows)
            self.assertIsInstance(result.reason, (Refusal, type(None)))


class UndecidabilityBlocksCleanNoMatchTests(unittest.TestCase):
    """HIGH 14: only two caveat codes blocked NO_MATCH; the rest were ignored.

    An earlier version allowlisted them, so undecidability reported by Pattern,
    Join, Aggregate or Emit still produced a confident `no_match`.
    """

    def test_a_pattern_without_a_decidable_time_does_not_claim_no_match(self):
        pattern = Pattern(id="p", input="r",
                          stages=((is_eq("a", 1),), (is_eq("b", 2),)),
                          within=Duration(600), time_field="missing_field")
        ir = RuleIR(rule_id="t", nodes=(read(), pattern, emit("p")), output="o")
        result = evaluate(ir, [{"a": 1, "b": 0}, {"a": 1, "b": 2}])
        self.assertIs(result.verdict, Verdict.NOT_EVALUATED,
                      "an undecidable evaluation must not be reported as no_match")


class StringOperatorTests(unittest.TestCase):
    """`contains` had its operands reversed: `value in pattern` instead of
    `pattern in value`. Every case-insensitive filter in the tool therefore
    matched nothing and reported a clean no_match -- and the AQL ILIKE path runs
    through it. No test covered a contains that actually matched."""

    def _filter(self, call):
        return RuleIR(rule_id="t", nodes=(read(), Filter(id="fl", input="r",
                                                          condition=call),
                                          emit("fl")), output="o")

    def test_contains_matches_a_substring(self):
        from ruleforge.engine.ir import Call
        result = evaluate(self._filter(Call("contains", (f("a"),
                                                         Literal("10.0.")))),
                          [{"a": "10.0.0.5"}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 1)

    def test_contains_does_not_match_a_different_value(self):
        from ruleforge.engine.ir import Call
        result = evaluate(self._filter(Call("contains", (f("a"),
                                                         Literal("10.0.")))),
                          [{"a": "192.168.1.1"}])
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_contains_is_case_insensitive(self):
        from ruleforge.engine.ir import Call
        result = evaluate(self._filter(Call("contains", (f("a"),
                                                         Literal("lsass")))),
                          [{"a": "LSASS.EXE"}])
        self.assertIs(result.verdict, Verdict.MATCHED)

    def test_starts_with_is_case_sensitive(self):
        """The two contracts genuinely differ, which is why the case behaviour is
        declared per function rather than assumed."""
        from ruleforge.engine.ir import Call
        result = evaluate(self._filter(Call("starts_with", (f("a"),
                                                              Literal("LSASS")))),
                          [{"a": "lsass.exe"}])
        self.assertIs(result.verdict, Verdict.NO_MATCH)

    def test_ends_with_matches(self):
        from ruleforge.engine.ir import Call
        result = evaluate(self._filter(Call("ends_with", (f("a"),
                                                            Literal(".exe")))),
                          [{"a": "lsass.exe"}])
        self.assertIs(result.verdict, Verdict.MATCHED)


class NotTests(unittest.TestCase):
    """`Not` did not exist in the IR at all, so `aql_ir` imported it and the
    import failed with ImportError instead of a named refusal."""

    def test_not_inverts_a_decided_comparison(self):
        from ruleforge.engine.ir import Not
        result = evaluate(RuleIR(rule_id="t", nodes=(
            read(), Filter(id="fl", input="r", condition=Not(is_eq("a", 1))),
            emit("fl")), output="o"), [{"a": 2}, {"a": 1}])
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 1)

    def test_not_of_undecided_is_undecided_not_true(self):
        """The invariant, reached through negation."""
        from ruleforge.engine.ir import Not
        result = evaluate(RuleIR(rule_id="t", nodes=(
            read(), Filter(id="fl", input="r", condition=Not(is_eq("nope", 1))),
            emit("fl")), output="o"), [{"a": 1}])
        self.assertIsNot(result.verdict, Verdict.MATCHED,
                         "NOT of an undecidable comparison must not become a match")

    def test_not_accepts_a_predicate_function(self):
        from ruleforge.engine.ir import Call
        result = evaluate(RuleIR(rule_id="t", nodes=(
            read(), Filter(id="fl", input="r", condition=Not(Call(
                "matches_regex", (f("a"), Literal("^x")), dialect="pcre"))),
            emit("fl")), output="o"), [{"a": "xyz"}])
        self.assertIsNot(result.verdict, Verdict.MATCHED)


class MultiReadTests(unittest.TestCase):

    def test_two_reads_take_separate_rows(self):
        node = Join(id="j", left="l", right="r",
                    on=((FieldRef("u"), FieldRef("u")),))
        ir = RuleIR(rule_id="t", nodes=(
            read("l"), read("r"), node, emit("j")), output="o")
        result = evaluate(ir, {"l": [{"u": "a"}], "r": [{"u": "a"}, {"u": "b"}]})
        self.assertIs(result.verdict, Verdict.MATCHED)
        self.assertEqual(len(result.rows), 1, "only 'a' matches across the join")


if __name__ == "__main__":
    unittest.main()
