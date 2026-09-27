"""`where` binds AND tighter than OR, and the lowerer used to bind it loosest.

This is a FALSE NEGATIVE, which is the worst direction a detection rule can be
wrong in, so the whole file is about that direction.

`_eval_condition` used to try `" AND "` first and return on the first split, so
AND became the OUTERMOST operator:

    a=1 OR b=2 AND c=3   ->   ((a=1 OR b=2) AND c=3)

SPL, like SQL, is NOT > AND > OR. The correct tree is `a=1 OR (b=2 AND c=3)`.
The built rule MISSES a row where `a=1` and nothing else holds -- a row the
analyst wrote the rule to catch.

The same one-line split was also blind to parentheses and to quotes, and refused
the two things a person actually writes:

    a=1 OR (b=2 AND c=3)   -> REFUSED, "'(b=2' is not a comparison"
    msg="x AND y"          -> REFUSED, "'y\"' is not a comparison"

The second is the worse of the two by inspection: it is a VALUE containing the
word, and refusing it blames the analyst for a comparison they wrote correctly.
"""

import unittest

from engine import Verdict, evaluate
from engine.ir import BoolOp, Call, Comparison, Not

from dialects.spl_ir import lower


def _ir(where: str):
    return lower(f"index=main | where {where}")[0]


def _tree(where: str):
    """The condition the `where` stage lowered to.

    The LAST filter, not the first: `index=main` is a selector and lowers to a
    Filter of its own, so taking the first one reads the selector back and every
    assertion here would compare the wrong tree.
    """
    from engine.ir import Filter
    filters = [n for n in _ir(where).nodes if isinstance(n, Filter)]
    return filters[-1].condition


def _shape(node) -> str:
    """A compact operator tree, so precedence is assertable as structure."""
    if isinstance(node, Not):
        return "not " + _shape(node.operand)
    if isinstance(node, BoolOp):
        return f"({node.op} {' '.join(_shape(o) for o in node.operands)})"
    if isinstance(node, Call):
        return f"call:{node.function}"
    if isinstance(node, Comparison):
        return f"cmp:{node.left.ref.name}{node.op}{node.right.value}"
    return type(node).__name__


class AndBindsTighterThanOr(unittest.TestCase):
    def test_or_with_and_is_or_outermost(self):
        """THE BUG. The old tree was (and (or a=1 b=2) c=3), which drops the
        row where a=1 alone should have fired."""
        self.assertEqual(_shape(_tree("a=1 OR b=2 AND c=3")),
                         "(or cmp:a=1 (and cmp:b=2 cmp:c=3))")

    def test_and_with_or_is_and_inner(self):
        self.assertEqual(_shape(_tree("a=1 AND b=2 OR c=3")),
                         "(or (and cmp:a=1 cmp:b=2) cmp:c=3)")

    def test_parentheses_are_honoured_not_refused(self):
        """`a=1 OR (b=2 AND c=3)` is correct SPL and used to be REFUSED with a
        message blaming a bare word."""
        self.assertEqual(_shape(_tree("a=1 OR (b=2 AND c=3)")),
                         "(or cmp:a=1 (and cmp:b=2 cmp:c=3))")

    def test_parentheses_can_invert_it(self):
        """`a=1 AND (b=2 OR c=3)` is NOT the same tree, and now differs."""
        self.assertEqual(_shape(_tree("a=1 AND (b=2 OR c=3)")),
                         "(and cmp:a=1 (or cmp:b=2 cmp:c=3))")

    def test_nested_parentheses_do_not_confuse_the_splitter(self):
        self.assertEqual(
            _shape(_tree("a=1 OR (b=2 AND (c=3 OR d=4))")),
            "(or cmp:a=1 (and cmp:b=2 (or cmp:c=3 cmp:d=4)))")

    def test_three_way_and_stays_flat(self):
        self.assertEqual(_shape(_tree("a=1 AND b=2 AND c=3")),
                         "(and cmp:a=1 cmp:b=2 cmp:c=3)")

    def test_not_binds_tighter_than_and(self):
        self.assertEqual(_shape(_tree("NOT a=1 AND b=2")),
                         "(and not cmp:a=1 cmp:b=2)")


class TheFalseNegativeIsGone(unittest.TestCase):
    """The same rule, executed, on the row the old tree missed."""

    ROWS = [{"index": "main", "a": 1, "b": 0, "c": 0}]

    def test_a_row_where_only_the_or_left_side_holds_now_matches(self):
        result = evaluate(_ir("a=1 OR b=2 AND c=3"), self.ROWS)
        self.assertIs(result.verdict, Verdict.MATCHED,
                      "a=1 alone satisfies `a=1 OR (b=2 AND c=3)`, so the rule "
                      "must fire; the old tree read this as "
                      "`((a=1 OR b=2) AND c=3)` and did not")

    def test_the_parenthesised_spelling_agrees_with_the_bare_one(self):
        bare = evaluate(_ir("a=1 OR b=2 AND c=3"), self.ROWS)
        parens = evaluate(_ir("a=1 OR (b=2 AND c=3)"), self.ROWS)
        self.assertEqual(bare.verdict, parens.verdict,
                         "adding the parentheses Splunk already implied must not "
                         "change the answer")

    def test_a_row_matching_neither_side_does_not_match(self):
        result = evaluate(_ir("a=1 OR b=2 AND c=3"),
                          [{"index": "main", "a": 0, "b": 0, "c": 0}])
        self.assertIsNot(result.verdict, Verdict.MATCHED)


class AQuotedSeparatorIsDataNotSyntax(unittest.TestCase):
    """`msg="x AND y"` is ONE comparison whose value contains the word."""

    def test_it_lowers_as_one_comparison(self):
        """`msg="x AND y"` used to REFUSE, with a message blaming a bare word.
        The point of the fix is that it is a perfectly good comparison, so this
        asserts structure: ONE comparison, not an `and` node."""
        self.assertTrue(_shape(_tree('msg="x AND y"')).startswith("cmp:msg="))
        self.assertNotIn("(and ", _shape(_tree('msg="x AND y"')))



    def test_a_single_quoted_value_containing_or_survives(self):
        """Asserted as STRUCTURE, not as an exact string: the point is that this
        is ONE comparison rather than an `or` node. The parsed value keeps its
        surrounding quotes, which is the literal's business and not this test's."""
        self.assertTrue(_shape(_tree("msg='x OR y'")).startswith("cmp:msg="))
        self.assertNotIn("(or ", _shape(_tree("msg='x OR y'")),
                         "a quoted OR must not become a boolean node")


    def test_an_operator_after_a_quoted_value_still_splits(self):
        """The string must not swallow the rest of the expression."""
        self.assertEqual(_shape(_tree('msg="x AND y" OR b=2')),
                         "(or cmp:msg=x AND y cmp:b=2)")

    def test_a_word_merely_containing_or_is_not_split(self):
        """`ORANGE` contains `OR`. Splitting there would turn a message about
        oranges into a rule about a variable named ORANGE."""
        self.assertEqual(_shape(_tree("ORANGE=1 AND b=2")),
                         "(and cmp:ORANGE=1 cmp:b=2)")


if __name__ == "__main__":
    unittest.main()
