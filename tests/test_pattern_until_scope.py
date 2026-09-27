"""`Pattern.until` means two different things to the two dialects that use it.

Elastic EQL, from its own documentation: "If this expiration event occurs BETWEEN
matching events in a sequence, the sequence expires and is not considered a
match. If the expiration event occurs AFTER matching events in a sequence, the
sequence is still considered a match."

YARA-L wants the opposite for the rule it is actually written for -- "a
credential access followed by no logout within 10 minutes" is violated by a
logout at ANY point in those ten minutes, including one after the logon.

One evaluator cannot be right for both without saying which it is doing, so
`until_scope` is data. This file pins both, and pins that they DIFFER, because
the earlier state was one behaviour with a comment claiming it was the only one.

The discriminating dataset is Elastic's own worked example, which is why it is
used here rather than an invented one: with `C` as the expiry condition, `A, B`
and `A, B, C` must both match under EQL, and `A, C, B` must not.
"""

import unittest
from engine import (
    Comparison as Cmp,
    Duration,
    Emit,
    FieldExpr,
    FieldRef,
    Literal,
    Pattern,
    Read,
    RuleIR,
    SourceSelector,
    Verdict,
    evaluate,
)
from engine.values import Refusal

SRC = SourceSelector(name="e")



def _eq(field: str, value: object) -> Cmp:
    return Cmp("=", FieldExpr(FieldRef(field)), Literal(value))


#: A is "credential access", B is "privileged logon", C is the expiry event.
#: STAGES are tuples of conditions. `until` is a SINGLE condition, not a tuple --
#: `_stage_matches((condition,), row, ctx)` wraps it itself, so a one-tuple here
#: never matches anything and the whole graph comes back NOT_EVALUATED.
A = (_eq("kind", "A"),)
B = (_eq("kind", "B"),)
C = _eq("kind", "C")


def _graph(scope: str) -> RuleIR:
    return RuleIR(
        rule_id="t",
        nodes=(Read(id="r", selector=SourceSelector(name="e")),
               Pattern(id="p", input="r", stages=(A, B),
                       within=Duration(600), time_field="ts",
                       until=C, until_scope=scope),
               Emit(id="o", input="p")),
        output="o", metadata={"dialect": "test"})


def _rows(*kinds_and_times):
    return [{"kind": kind, "ts": t} for kind, t in kinds_and_times]


def _matched(scope: str, rows) -> bool:
    result = evaluate(_graph(scope), rows)
    return result.verdict is Verdict.MATCHED


class BetweenScopeIsEql(unittest.TestCase):
    """EQL: only an expiry BETWEEN the matched events expires the sequence."""

    def test_an_expiry_after_the_match_does_not_expire_it(self):
        """THE DISCRIMINATING CASE. `A, B, C` with C the expiry: the sequence
        completed at B, so C is irrelevant and `A, B` stands."""
        self.assertTrue(
            _matched("between", _rows(("A", 0), ("B", 10), ("C", 20))),
            "EQL: an expiry after the matching events leaves the match standing")

    def test_an_expiry_between_the_matches_expires_it(self):
        self.assertFalse(
            _matched("between", _rows(("A", 0), ("C", 5), ("B", 10))),
            "EQL: an expiry between the matching events expires the sequence")

    def test_elastic_worked_example_end_to_end(self):
        """From the EQL documentation: the dataset contains `A, B`, `A, B, C` and
        `A, C, B`, and the query must match the first two and reject the third."""
        self.assertTrue(_matched("between", _rows(("A", 0), ("B", 10))),
                        "A, B must match")
        self.assertTrue(_matched("between", _rows(("A", 0), ("B", 10), ("C", 20))),
                        "A, B, C must match -- C is after the sequence completed")
        self.assertFalse(_matched("between",
                                  _rows(("A", 0), ("C", 5), ("B", 10))),
                         "A, C, B must NOT match")


class WindowScopeIsYaralAndIsTheDefault(unittest.TestCase):
    """YARA-L: "no logout within 10 minutes" is violated by a logout at any point
    in the window. That is the historical behaviour here, so it is the default and
    nothing that works today may change."""

    def test_an_expiry_after_the_match_still_expires_it(self):
        """Where the two scopes DISAGREE. Under EQL this matches; here it must
        not, and that difference is the entire reason the field exists."""
        self.assertFalse(
            _matched("window", _rows(("A", 0), ("B", 10), ("C", 20))),
            "YARA-L: a logout anywhere in the ten minutes violates the rule, "
            "including one after the logon")

    def test_an_expiry_between_the_matches_expires_it(self):
        self.assertFalse(_matched("window", _rows(("A", 0), ("C", 5), ("B", 10))))

    def test_no_expiry_in_the_window_still_matches(self):
        self.assertTrue(_matched("window", _rows(("A", 0), ("B", 10))))

    def test_the_default_is_window(self):
        """So a new node cannot silently pick the EQL rule."""
        default = Pattern(id="p", input="r", stages=(A, B), within=Duration(600),
                          time_field="ts", until=C)
        self.assertEqual(default.until_scope, "window")
        self.assertFalse(
            _matched("window", _rows(("A", 0), ("B", 10), ("C", 20))),
            "the default and the explicit window scope must agree")

    def test_nothing_in_the_dialects_sets_until_at_all(self):
        """WHY the default is not a safety guarantee, stated as a fact that can
        stop being true.

        The field's comment used to claim the default "preserves every existing
        YARA-L rule" and that changing it "would silently re-break the YARA-L bug
        this node's until was written to fix". Both were vacuous: no lowerer sets
        `until`, so `until` is unreachable from analyst text and no rule depends
        on either scope. A comment that says "nothing depends on this" while
        implying "everything does" is worse than no comment, so the fact is
        asserted here instead -- and this test FAILS when a dialect starts
        lowering `until`, which is the moment the default actually starts
        mattering and someone has to think about it.
        """
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        offenders = []
        for path in sorted(root.glob("dialects/*.py")):
            if "until=" in path.read_text(encoding="utf-8"):
                offenders.append(path.name)
        self.assertEqual(offenders, [],
                         f"{offenders} now lower `until`. The default scope is "
                         f"no longer a free choice -- check whether 'window' is "
                         f"right for each of them, and update this test and the "
                         f"until_scope comment together.")


class TheTwoScopesReallyDiffer(unittest.TestCase):
    def test_the_same_input_gives_opposite_answers(self):
        """Without this, a test asserting each scope separately could both pass
        while the field did nothing."""
        rows = _rows(("A", 0), ("B", 10), ("C", 20))
        self.assertNotEqual(_matched("window", rows), _matched("between", rows))


class AnUnknownScopeIsRefused(unittest.TestCase):
    def test_a_misspelled_scope_is_refused_not_defaulted(self):
        """A typo'd scope that silently behaved like the default would
        reintroduce exactly the bug the field exists to make visible."""
        with self.assertRaises(Refusal) as caught:
            Pattern(id="p", input="r", stages=(A, B), within=Duration(600),
                    time_field="ts", until=C, until_scope="winodw")
        self.assertEqual(getattr(caught.exception, "code", ""),
                         "PATTERN_UNTIL_SCOPE_UNKNOWN")


class TheEndpointsAreNotBetweenThem(unittest.TestCase):
    """An event that IS one of the matching events is not "between" matching
    events, so the range must be open at both ends.

    This is the case the endpoint exclusion actually decides, and it is why the
    range is half-open rather than "everything up to the last match": if the
    FINAL stage also satisfies the expiry condition, including `last_matched`
    would veto with the sequence's own last row and reject a sequence that
    EQL says matches. The mutation "use start_index..last_matched inclusive"
    passes every other test in this file, which is why it has one of its own.
    """

    #: The last stage is B, and the expiry condition also matches B.
    ALSO_B = (_eq("kind", "B"),)

    def _graph_shared(self, scope: str) -> RuleIR:
        return RuleIR(
            rule_id="t",
            nodes=(Read(id="r", selector=SRC),
                   Pattern(id="p", input="r", stages=(A, self.ALSO_B),
                           within=Duration(600), time_field="ts",
                           until=self.ALSO_B[0], until_scope=scope),
                   Emit(id="o", input="p")),
            output="o", metadata={"dialect": "test"})

    def test_the_last_matching_event_does_not_veto_itself(self):
        rows = _rows(("A", 0), ("B", 10))
        result = evaluate(self._graph_shared("between"), rows)
        self.assertIs(result.verdict, Verdict.MATCHED,
                      "B is the last MATCHING event, so it cannot also be the "
                      "expiry sitting between the matches")

    def test_the_first_matching_event_does_not_veto_itself(self):
        """Same at the other end: if the first stage also satisfies the expiry
        condition, the range starts after it."""
        graph = RuleIR(
            rule_id="t",
            nodes=(Read(id="r", selector=SRC),
                   Pattern(id="p", input="r", stages=(A, B),
                           within=Duration(600), time_field="ts",
                           until=A[0], until_scope="between"),
                   Emit(id="o", input="p")),
            output="o", metadata={"dialect": "test"})
        result = evaluate(graph, _rows(("A", 0), ("B", 10)))
        self.assertIs(result.verdict, Verdict.MATCHED,
                      "A is the first MATCHING event, not one between them")


if __name__ == "__main__":
    unittest.main()
