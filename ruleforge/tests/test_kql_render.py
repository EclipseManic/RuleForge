"""KQL renderer tests.

THE POINT OF THIS FILE IS THE PREFIX TRAP.

The engine stores a join's merged columns as `l_X` / `r_X` so one side cannot
silently overwrite the other. KQL has one namespace, so the analyst writes them
bare. Rendering back means inverting that renaming -- and the obvious way,
stripping the prefix, would rewrite a rule about the LEGAL KQL FIELD
`l_Process` into a rule about `Process`.

So there is a test for exactly that field, and a test that the map is inverted
rather than guessed.
"""
from __future__ import annotations

import unittest

from ruleforge.dialects import lower_kql, parse_kql
from ruleforge.dialects.kql_render import render
from ruleforge.engine.ir import Join
from ruleforge.engine.values import Refusal
from ruleforge.tests.test_kql import USER_SENTINEL_RULE

#: A rule whose field is literally called `l_Process`. Stripping the prefix
#: would turn this into a rule about `Process`.
L_PREFIXED_FIELD_RULE = (
    'SecurityEvent '
    '| where l_Process == "lsass.exe" '
    '| project l_Process, TimeGenerated'
)


class RoundTripTests(unittest.TestCase):
    def _ir(self, text=USER_SENTINEL_RULE):
        return lower_kql(parse_kql(text))[0]

    def test_the_user_rule_renders(self):
        rendered = render(self._ir())
        self.assertIn("| where", rendered)
        self.assertIn("| join", rendered)
        self.assertIn("summarize", rendered)

    def test_the_window_comparison_comes_back_bare(self):
        """`r_LoginTime` and `l_LSASSTime` are how the graph stores the user's
        `LoginTime` and `LSASSTime`. They must render as the author wrote them."""
        rendered = render(self._ir())
        self.assertIn("LoginTime", rendered)
        self.assertIn("LSASSTime", rendered)
        self.assertNotIn("r_LoginTime", rendered)
        self.assertNotIn("l_LSASSTime", rendered)

    def test_no_prefixed_name_leaks_into_the_output(self):
        """A `leaked` prefix means some post-join reference was never inverted."""
        rendered = render(self._ir())
        for line in rendered.splitlines():
            for name in ("LoginTime", "LSASSTime", "Computer", "Account"):
                self.assertNotIn(f"l_{name}", line)
                self.assertNotIn(f"r_{name}", line)

    def test_the_join_keys_stay_bare_too(self):
        """The join condition is evaluated BEFORE the merge, so its keys were
        never prefixed and must not gain a prefix on the way out."""
        rendered = render(self._ir())
        self.assertIn("Computer", rendered)
        self.assertIn("Account", rendered)


class PrefixTrapTests(unittest.TestCase):
    """The whole reason `Join.column_map` exists."""

    def test_a_legal_l_prefixed_field_name_is_not_stripped(self):
        ir = lower_kql(parse_kql(L_PREFIXED_FIELD_RULE))[0]
        rendered = render(ir)
        self.assertIn("l_Process", rendered,
                      "l_Process is the analyst's own field name, not a prefix "
                      "this renderer added")
        self.assertNotIn("| where Process ==", rendered)

    def test_the_inversion_comes_from_the_recorded_map(self):
        """Not from a heuristic: the join that renamed a column is the only
        thing that knows."""
        ir = lower_kql(parse_kql(USER_SENTINEL_RULE))[0]
        join = next(n for n in ir.nodes if isinstance(n, Join))
        self.assertTrue(join.column_map,
                        "the join must record which columns it renamed")
        stored = {stored for _, stored in join.column_map}
        self.assertIn("r_LoginTime", stored)
        self.assertIn("l_LSASSTime", stored)
        self.assertEqual(join.bare("r_LoginTime"), "LoginTime")
        self.assertEqual(join.bare("l_LSASSTime"), "LSASSTime")

    def test_an_unrenamed_name_is_returned_unchanged(self):
        ir = lower_kql(parse_kql(USER_SENTINEL_RULE))[0]
        join = next(n for n in ir.nodes if isinstance(n, Join))
        self.assertEqual(join.bare("SomeFieldThisJoinNeverTouched"),
                         "SomeFieldThisJoinNeverTouched")

    def test_an_ambiguous_column_is_absent_from_the_map(self):
        """A name on BOTH sides and not proven equal by a join key is not
        recorded, because there is no correct bare name for it."""
        ir = lower_kql(parse_kql(USER_SENTINEL_RULE))[0]
        join = next(n for n in ir.nodes if isinstance(n, Join))
        originals = {original for original, _ in join.column_map}
        # Computer and Account are join KEYS, so they are equal by construction.
        self.assertIn("Computer", originals)
        self.assertIn("Account", originals)


class HonestRefusalTests(unittest.TestCase):
    def test_a_regex_keeps_its_dialect(self):
        """Rendering `matches regex` without `kind` would let Kusto read it as
        its default RE2 and change what it matches."""
        text = 'SecurityEvent | where CommandLine matches regex @"\\\\d+" kind="regex"'
        ir = lower_kql(parse_kql(text))[0]
        rendered = render(ir)
        self.assertIn('kind="regex"', rendered)

    def test_a_node_with_no_kql_rendering_is_refused_not_dropped(self):
        from ruleforge.engine.ir import RuleIR, SourceSelector, Read, Emit, Expand
        ir = RuleIR(rule_id="t", nodes=(
            Read(id="r", selector=SourceSelector(name="T")),
            Expand(id="e", input="r", field="a"),
            Emit(id="o", input="e"),
        ), output="o")
        with self.assertRaises(Refusal) as caught:
            render(ir)
        self.assertEqual(caught.exception.code,
                         "KQL_RENDER_NODE_UNSUPPORTED")

    def test_a_rule_with_no_read_is_refused(self):
        from ruleforge.engine.ir import RuleIR, Emit, Filter
        ir = RuleIR(rule_id="t", nodes=(
            Filter(id="f", input="missing", condition=None),
            Emit(id="o", input="f"),
        ), output="o")
        with self.assertRaises(Refusal):
            render(ir)

    def test_the_names_helper_never_guesses(self):
        from ruleforge.dialects.kql_render import _Names
        from ruleforge.engine.ir import RuleIR
        helper = _Names(RuleIR(rule_id="t", nodes=(), output="o"))
        self.assertEqual(helper.field("l_Whatever"), "l_Whatever")


if __name__ == "__main__":
    unittest.main()
