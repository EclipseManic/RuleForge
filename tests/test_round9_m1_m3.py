"""Two guards that stopped guarding, both found by round 9.

Six other instances of this shape are already in HANDOFF.md. Both of these are
the same disease: the walk stopped early and said nothing, so a guard that read
as total was partial. The eighth and ninth.

M1 -- `_expression_depth` HAD NO `Not` ARM

`Not` fell through to `return 0`, so its depth was zero whatever the nesting, and
`MAX_EXPRESSION_DEPTH` never applied to it at all:

    BoolOp chain x101   ->  REFUSED: EXPRESSION_TOO_DEEP
    Not x5000           ->  _expression_depth = 0

The recursion this function exists to stop then happened anyway.
`validate_graph(Not x2000)` was ACCEPTED, and the RecursionError escaped from
`jobs.py`, where `web.py` turned it into INPUT_TOO_DEEP / "the pasted events are
nested too deeply to read" -- with no events pasted. AQL builds genuinely nested
`NOT` chains, so it was reachable from a real rule.

The function's own docstring promised "a RecursionError escaping as an opaque
crash tells the analyst nothing. Here it is a named refusal at a known depth."
For `Not` that was not true.

M3 -- THE `name` ARM REACHED A NODE AND ABANDONED THE REST OF IT

A `SourceSelector` has `name`, so it entered the arm; the three walks there found
nothing, because a selector has no `pattern`, `left` or `right`, and the bare
`return` ended the visit. `binding` and `kind` were never looked at. Not a live
hole today -- `binding` is a datamodel name by contract -- but a contract, not a
guarantee, and the round-8 comment says this walk "must reach EVERY node in the
tree" precisely so a new attribute cannot become a new hole.
"""

import unittest

from engine.ir import (
    Emit,
    BoolOp,
    Call,
    FieldRef,
    Literal,
    Not,
    Read,
    RuleIR,
    SourceSelector,
)
from engine.validate import MAX_EXPRESSION_DEPTH, _expression_depth, validate_graph
from engine.values import Refusal

LEAF = Call("matches_regex", (FieldRef("cmd"), Literal("x")), dialect="pcre")


def _nest_not(count: int):
    node = LEAF
    for _ in range(count):
        node = Not(node)
    return node


def _nest_boolop(count: int):
    node = LEAF
    for _ in range(count):
        node = BoolOp("and", (node, LEAF))
    return node


class NotIsCountedByTheDepthGuard(unittest.TestCase):
    """M1."""

    def test_a_deep_not_chain_is_refused_by_name(self):
        with self.assertRaises(Refusal) as caught:
            _expression_depth(_nest_not(MAX_EXPRESSION_DEPTH + 5))
        self.assertEqual(getattr(caught.exception, "code", ""),
                         "EXPRESSION_TOO_DEEP",
                         "the whole point: a named refusal, not a RecursionError")

    def test_not_depth_is_counted_not_zero(self):
        """It used to return 0 for any nesting."""
        self.assertGreater(_expression_depth(_nest_not(10)), 10)
        # Relative, because an absolute number counts the leaf too: LEAF is a
        # Call around a FieldRef, so the whole thing is 3 deep. Asserting the
        # RELATION is what pins the arm -- a missing arm returns 0 for any Not.
        self.assertEqual(_expression_depth(Not(LEAF)),
                         1 + _expression_depth(LEAF),
                         "a Not is one level above its operand, not zero")

    def test_a_reasonable_not_chain_still_lowers(self):
        """AQL builds real `NOT` chains; the guard must not refuse ordinary
        ones."""
        self.assertLessEqual(_expression_depth(_nest_not(20)),
                             MAX_EXPRESSION_DEPTH)

    def test_a_deep_not_chain_does_not_escape_as_a_recursion_error(self):
        """The failure this fixes: `Not x2000` was ACCEPTED and then blew the
        interpreter stack. It must be a refusal before the stack is at risk."""
        try:
            _expression_depth(_nest_not(2000))
        except Refusal as exc:
            self.assertEqual(getattr(exc, "code", ""), "EXPRESSION_TOO_DEEP")
        except RecursionError:  # pragma: no cover - this is the bug
            self.fail("Not nesting escaped as a RecursionError instead of a "
                      "named refusal")

    def test_not_is_guarded_like_every_other_container(self):
        """Belt and braces: a `BoolOp` chain and a `Not` chain of the same
        depth must both be refused, since the report found the asymmetry."""
        for label, node in (("BoolOp", _nest_boolop(MAX_EXPRESSION_DEPTH + 5)),
                            ("Not", _nest_not(MAX_EXPRESSION_DEPTH + 5))):
            with self.subTest(container=label):
                with self.assertRaises(Refusal):
                    _expression_depth(node)


    def _regex_filter(self):
        from engine.ir import Filter
        return Filter(id="f", input="read", condition=LEAF)

    def test_a_selector_binding_is_screened_now(self):
        """The real probe: a catastrophic pattern smuggled into `binding`, which
        the `name` arm used to walk straight past."""
        from engine.ir import Filter
        graph = RuleIR(
            rule_id="r",
            nodes=(Read(id="read",
                        selector=SourceSelector(name="events",
                                                binding="(a|aa)+$")),
                   Filter(id="f", input="read", condition=LEAF),
                   Emit(id="o", input="f")),
            output="o", metadata={"dialect": "test"})
        # The filter's own pattern is benign, so the only dangerous string in the
        # tree is the one in `binding`. If the name arm still abandons the node,
        # this is accepted.
        with self.assertRaises(Refusal) as caught:
            validate_graph(graph)
        self.assertEqual(getattr(caught.exception, "code", ""),
                         "REGEX_CATASTROPHIC_BACKTRACKING",
                         "a pattern in SourceSelector.binding must be screened, "
                         "not walked past by a bare return")

    def test_a_benign_binding_does_not_refuse(self):
        """The sweep must not start inventing refusals for ordinary values."""
        from engine.ir import Filter
        graph = RuleIR(
            rule_id="r",
            nodes=(Read(id="read",
                        selector=SourceSelector(name="events",
                                                binding="Authentication")),
                   Filter(id="f", input="read", condition=LEAF),
                   Emit(id="o", input="f")),
            output="o", metadata={"dialect": "test"})
        validate_graph(graph)  # must not raise


if __name__ == "__main__":
    unittest.main()
