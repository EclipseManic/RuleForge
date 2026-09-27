"""The ReDoS screen must reach EVERY node, and the failure is silent.

`engine/validate.py` screens a graph for catastrophic-backtracking patterns by
walking the tree looking for `regex` calls. Each time a container type was missed,
the guard silently stopped guarding:

  - a `BoolOp` holds `operands` (a tuple). The walk only descended inside the
    `Call` arm, so `Filter(eq)` was screened and `Filter(BoolOp("and", (eq, rx)))`
    was not. Reached by adding a second `<field>` to a Wazuh rule.
  - a `Not` holds `operand` -- SINGULAR, no tuple. Even after the `operands` fix,
    `walk` fell past every arm and dead-ended. Reached by writing one word:
        | where cmd matches regex "(a|aa)+$"     -> REFUSED
        | where not cmd matches regex "(a|aa)+$"  -> ok=True, deployable
    Measured 0.028s at n=24, 0.198s at n=28, 1.430s at n=32 -- about 7x per four
    characters, and unbounded, over `POST /api/author`.

The round-7 `BoolOp` fix was COMMENT-ONLY: reverting it left all 586 tests
green, so round 8 re-found the same defect from scratch. That is why this file
does not just assert the two known cases. `test_a_new_container_type_must_be_screened`
inspects the IR's own definitions and fails if any container type is not covered
by a probe here, so adding a node to `engine/ir.py` fails THIS test on the day it
is added instead of opening a hole a future reviewer has to rediscover.
"""

import dataclasses
import unittest
from typing import Any

import engine.ir as ir
from engine.ir import (
    BoolOp,
    Call,
    Comparison,
    Filter,
    Literal,
    Not,
    Read,
    RuleIR,
)
from engine.validate import validate_graph

#: Catastrophic on any realistic input, so one constant cannot be tuned into
#: passing this file.
BAD = "(a|aa)+$"

#: A realistic regex call: `matches_regex` takes TWO arguments, a field and the
#: pattern. Getting this wrong arity fails at construction with
#: FUNCTION_ARITY_VIOLATION, which is a good property to have.
RX = Call("matches_regex", (ir.FieldRef("cmd"), Literal(BAD)), dialect="pcre")
SAFE_RX = Call("matches_regex", (ir.FieldRef("cmd"), Literal("lsass\\.exe$")), dialect="pcre")
OK = Comparison("=", ir.FieldRef("a"), Literal("x"))

#: EVERY expression-shaped IR type, with the pattern buried one level down.
#: `NODE_CLASSES` is the IR's own registry, so this list cannot drift from the
#: dialect surface without the coverage test below noticing.
PROBES: dict[str, Any] = {
    "Call": RX,
    "Not": Not(RX),
    "BoolOp": BoolOp("and", (OK, RX)),
    "Comparison": Comparison("=", RX, Literal("x")),
    "Filter": Filter(id="f", input="read", condition=RX),
}

#: Graph-node types that hold an EXPRESSION and are covered by the explicit
#: `_nested_in_graph` probes in the anti-drift test rather than by an entry in
#: `PROBES` (they cannot appear inside `Filter(condition=...)`).
GRAPH_PROBES = frozenset({"Derive", "Join", "Pattern"})

#: Types that trip the `left`/`right`/`measures` field-name heuristic but are
#: STRUCTURALLY UNABLE to hold a pattern, so no probe can exist:
#:   `SetOp`    -- `left` and `right` are NODE IDS (strings), and `keys` is a
#:                 tuple of `FieldRef`. There is no expression slot.
#:   `Aggregate`-- `measures` is a tuple of `Measure(name, function, field, by)`
#:                 and `frame` is a `Frame`. No expression slot.
#: Listed with reasons rather than left implicit, so a future `SetOp` that grows
#: a `condition` field has to delete its exemption here and add a real probe.
CANNOT_HOLD_A_PATTERN = frozenset({"SetOp", "Aggregate"})


def _nested_in_graph(node: Any) -> str:
    """Put `node` between a Read and an Emit and screen the whole graph.

    Used for the node types that are GRAPH nodes rather than expressions. They are
    reached by the `for attribute in dir(node)` fallback at the end of `walk`
    rather than by a hand-written arm, and that is exactly the kind of thing that
    stops being true silently -- so it is asserted, not assumed.
    """
    graph = RuleIR(rule_id="r",
                   nodes=(Read(id="read",
                               selector=ir.SourceSelector(name="x")),
                          node,
                          ir.Emit(id="out", input=node.id)),
                   output="out",
                   metadata={"dialect": "test"})
    try:
        validate_graph(graph)
    except Exception as exc:
        text = str(exc)
        return text.split(":", 1)[0] if ":" in text else type(exc).__name__
    return ""


def _graph(condition: Any) -> RuleIR:
    """A minimal VALID graph, so a refusal means the screen fired and nothing
    else. Every field name here was read off the dataclasses rather than
    guessed: an earlier version passed `Read(source=...)`, which does not exist,
    so all 14 of these tests were measuring a `TypeError` about a missing
    keyword argument and reporting it as a ReDoS refusal."""
    return RuleIR(rule_id="r",
                  nodes=(Read(id="read",
                              selector=ir.SourceSelector(name="x")),
                         Filter(id="f", input="read", condition=condition),
                         ir.Emit(id="out", input="f")),
                  output="out",
                  metadata={"dialect": "test"})


def _refusal_code(condition: Any) -> str:
    """The refusal code, or "" when the graph was ACCEPTED.

    A refusal for any OTHER reason is returned as-is rather than being counted as
    a screen hit, so a broken probe fails loudly instead of passing by accident.
    """
    try:
        validate_graph(_graph(condition))
    except Exception as exc:
        text = str(exc)
        return text.split(":", 1)[0] if ":" in text else type(exc).__name__
    return ""


def _screened(condition: Any) -> bool:
    return _refusal_code(condition) == "REGEX_CATASTROPHIC_BACKTRACKING"


class TheScreenMustReachEveryContainer(unittest.TestCase):
    def test_a_bare_call_is_screened(self):
        """The control. If this stops being refused the probe is wrong and every
        other test in this file is vacuous."""
        self.assertTrue(_screened(RX), "the control probe must be refused")

    def test_a_negated_call_is_screened(self):
        """The live critical: `Not` holds `operand`, singular, so the walk used
        to dead-end. This is the one-word bypass."""
        self.assertTrue(_screened(Not(RX)),
                        "`not` must not disable the ReDoS screen")

    def test_a_negated_negation_is_screened(self):
        self.assertTrue(_screened(Not(Not(RX))))

    def test_a_boolop_is_screened(self):
        """The round-7 finding, which had no test at all."""
        for op in ("and", "or"):
            with self.subTest(op=op):
                self.assertTrue(_screened(BoolOp(op, (OK, RX))))

    def test_a_negated_boolop_is_screened(self):
        """Both bugs at once: a `BoolOp` fix defeated by a `not` on top."""
        self.assertTrue(_screened(Not(BoolOp("and", (OK, RX)))))

    def test_a_boolop_holding_a_negated_call_is_screened(self):
        """The reverse composition -- what a `not (...)` in a KQL `where` makes."""
        self.assertTrue(_screened(BoolOp("and", (OK, Not(RX)))))

    def test_a_new_container_type_must_be_screened(self):
        """THE ANTI-DRIFT TEST, and the reason this file exists.

        Enumerates the IR's own definitions for node types that can hold another
        node or a pattern, and requires every one of them to be covered by a
        probe above. A new container in `engine/ir.py` therefore fails HERE, on
        the day it is added.
        """
        # Required-field names that mean "this type can hold an EXPRESSION".
        # Deliberately excludes `measures` and `keys`: `Measure` is
        # (name, function, field, by) and `keys` is a tuple of `FieldRef`, so
        # neither can carry a pattern and demanding a probe for them would be
        # demanding a test for something structurally unreachable.
        child_fields = {"operand", "operands", "left", "right", "condition",
                        "args", "pattern", "assignments", "ref", "value",
                        "expression", "predicate", "order_by", "group_by",
                        "stages", "on"}
        containers = set()
        for cls in ir.NODE_CLASSES:
            if not dataclasses.is_dataclass(cls):
                continue
            required = {f.name for f in dataclasses.fields(cls)
                        if f.default is dataclasses.MISSING}
            if required & child_fields:
                containers.add(cls.__name__)

        # The GRAPH-node types that can actually hold an EXPRESSION. Note what is
        # NOT here: `Aggregate` and `SetOp`. `Aggregate` holds `Measure(name,
        # function, field, by)` and a `Frame` -- no expression anywhere -- and
        # `SetOp`'s `left`/`right` are NODE IDS, with `keys` a tuple of
        # `FieldRef`. Neither can carry a pattern, so neither needs a probe, and
        # a reflection check that demanded one would be demanding a test for
        # something unreachable.
        self.assertEqual(
            _nested_in_graph(ir.Derive(id="d", input="read",
                                       assignments=(("x", RX),))),
            "REGEX_CATASTROPHIC_BACKTRACKING", "Derive")
        self.assertEqual(
            _nested_in_graph(ir.Join(id="j", left="read", right="read",
                                     on=BoolOp("and", (OK, RX)))),
            "REGEX_CATASTROPHIC_BACKTRACKING", "Join")
        self.assertEqual(
            _nested_in_graph(
                ir.Pattern(id="p", input="read", within=None,
                           time_field=ir.FieldRef("@timestamp"),
                           stages=(BoolOp("and", (OK, RX)), OK))),
            "REGEX_CATASTROPHIC_BACKTRACKING", "Pattern")

        uncovered = sorted(containers - set(PROBES) - GRAPH_PROBES
                           - CANNOT_HOLD_A_PATTERN)
        self.assertEqual(
            uncovered, [],
            f"these IR node types can hold a child but have no ReDoS probe in "
            f"{__file__}: {uncovered}. Add one, and add a walk arm or refusal in "
            f"`_screen_regexes` if it turns out to be a new hole. A missing "
            f"probe here means the next reviewer has to rediscover it.")

    def test_the_probe_list_is_not_shrinking(self):
        """Guards the test against being quietly emptied out, which is how a
        coverage test becomes a test of nothing."""
        self.assertGreaterEqual(len(PROBES), 5,
                                f"only {sorted(PROBES)} are probed")


class TheScreenMustNotOverRefuse(unittest.TestCase):
    """A guard that refuses everything is a guard nobody can use, and this
    project has shipped over-refusal bugs before."""

    def test_linear_patterns_are_accepted(self):
        for pattern in ("lsass\\.exe$", r"^user\d+@corp\.example\.com$",
                        r"^\d{1,3}(\.\d{1,3}){3}$", "svc_", "^/var/log/"):
            with self.subTest(pattern=pattern):
                call = Call("matches_regex",
                            (ir.FieldRef("cmd"), Literal(pattern)),
                            dialect="pcre")
                self.assertEqual(_refusal_code(call), "",
                                 f"{pattern!r} is linear and must be accepted")
                self.assertEqual(_refusal_code(Not(call)), "",
                                 f"{pattern!r} must be accepted under `not` too")

    def test_a_bare_string_equal_to_a_bad_pattern_is_not_a_regex(self):
        """The pattern is only a ReDoS risk where it is used AS one. A literal
        string comparison containing those characters is fine, and refusing it
        would make the tool unusable on real rules."""
        self.assertEqual(
            _refusal_code(Comparison("=", ir.FieldRef("a"), Literal(BAD))),
            "")


if __name__ == "__main__":
    unittest.main()
