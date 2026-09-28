import unittest

from engine import evaluate
from engine.ir import (Comparison, Emit, FieldExpr, FieldRef, Filter, Literal,
                       Read, RuleIR, SourceSelector)
from engine.values import ABSENT


def _filter_ir(field: str, value: str) -> RuleIR:
    return RuleIR(rule_id="t", nodes=(
        Read(id="r", selector=SourceSelector(name="any")),
        Filter(id="f", input="r",
               condition=Comparison("=", FieldExpr(FieldRef(field)),
                                    Literal(value))),
        Emit(id="o", input="f")), output="o", title="t")


class CaveatNamesTheFieldTheRuleReferenced(unittest.TestCase):
    """The one message that exists to point at a missing field must name it.

    `eval_expr` returns the ABSENT sentinel for a field the row does not carry,
    and the caveat builder was handed that VALUE to describe. It fell through to
    `type(value).__name__.lower()`, which is the private class name, so the
    caveat read:

        `_absent` was a field was absent, so it cannot be ordered ...

    A reader cannot go and look for a field called `_absent`. The one message
    whose entire job is to name the missing column pointed at nothing, and it
    was a false statement about the analyst's data -- produced by the module
    whose purpose is to avoid exactly that.

    Two things had to change, and fixing only the first still names nothing:
    the sentinel is now described as `<an absent field>` instead of leaking its
    class name, AND the comparison path describes `expr.left` (the field the
    RULE referenced) rather than `left` (the value it evaluated to).
    """

    def test_the_caveat_names_the_field_not_the_sentinel(self):
        result = evaluate(_filter_ir("event.type", "creation"), [{"x": 1}])
        detail = result.caveats[0].detail
        self.assertIn("event.type", detail,
                      "the caveat must name the column the rule referenced")
        self.assertNotIn("_absent", detail,
                         "the internal sentinel name must never reach a user")
        self.assertNotIn("_Absent", detail)

    def test_the_sentinel_name_does_not_leak_through_any_operand_describer(self):
        from engine.evaluate import _describe_operand
        self.assertNotIn("_absent", _describe_operand(ABSENT))

    def test_a_present_field_produces_no_caveat_at_all(self):
        result = evaluate(_filter_ir("event.type", "creation"),
                          [{"event.type": "creation"}])
        self.assertEqual(len(result.caveats), 0,
                         "a field that is present and equal is decided, and a "
                         "decided comparison must not carry a caveat")

    def test_a_present_but_wrong_value_is_a_decided_non_match(self):
        result = evaluate(_filter_ir("event.type", "creation"),
                          [{"event.type": "termination"}])
        self.assertEqual(len(result.rows), 0)
        self.assertEqual(len(result.caveats), 0,
                         "'present and different' is DECIDED. It is not the "
                         "same as absent, and conflating them is the whole "
                         "point of the ABSENT sentinel")
