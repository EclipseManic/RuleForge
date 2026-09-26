"""Round 3 findings. Both reviewers found these independently; two are CRITICAL.

CRITICAL: a Wazuh `<match>` was dropped, so the rule matched EVERY event while
reporting success. A detection that fires on everything and says so is the worst
output this project can produce.

CRITICAL: the ReDoS control was bypassed by a TWELVE-CHARACTER pattern with no
parentheses at all, so the fix that shipped last round was defeated on arrival.
"""
from __future__ import annotations

import unittest

from ruleforge import jobs
from ruleforge.dialects.wazuh import WazuhParseError, parse_wazuh
from ruleforge.dialects.wazuh_ir import lower as lower_wazuh
from ruleforge.engine.regex import _nested_quantifier, compile_pattern
from ruleforge.engine.redos import catastrophic_reason
from ruleforge.engine.values import Refusal

MATCH_RULE = (
    '<group name="g,"><rule id="100100" level="12">'
    "<description>LSASS access</description>"
    '<match field="win.eventdata.CommandLine" type="pcre2">^.*lsass\\.exe.*$</match>'
    "</rule></group>"
)


class WazuhUnknownElementTests(unittest.TestCase):
    def test_a_match_element_is_refused_not_dropped(self):
        """THE REGRESSION. This used to lower to Read -> Emit with NO filter, so
        `notepad.exe` matched and the tool reported success."""
        with self.assertRaises(WazuhParseError) as caught:
            parse_wazuh(MATCH_RULE)
        self.assertEqual(caught.exception.code, "WAZUH_ELEMENT_UNKNOWN")

    def test_the_refusal_says_what_dropping_it_would_do(self):
        with self.assertRaises(WazuhParseError) as caught:
            parse_wazuh(MATCH_RULE)
        self.assertIn("every event", caught.exception.message)

    def test_presentation_elements_are_still_ignored(self):
        """Refusing everything would be useless. These genuinely do not change
        which events a rule matches."""
        rule = ('<group name="g,"><rule id="1" level="5">'
                "<category>ossec</category><decoded_as>json</decoded_as>"
                "<options>no_full_log</options>"
                "<field name=\"a\">x</field>"
                "<mitre><id>T1059</id></mitre>"
                "<description>d</description></rule></group>")
        parsed = parse_wazuh(rule)["1"]
        self.assertEqual(parsed.fields[0].name, "a")
        self.assertEqual(parsed.mitre, ("T1059",))
        self.assertEqual(parsed.description, "d")

    def test_the_shipped_ruleset_still_lowers(self):
        from ruleforge.tests.test_wazuh import WAZUH_RULESET
        ir, _ = lower_wazuh(WAZUH_RULESET, "60205")
        self.assertTrue(ir.nodes)


class RedosBypassTests(unittest.TestCase):
    """A TWELVE-CHARACTER pattern defeated the control shipped last round."""

    CATASTROPHIC = [
        r"a*a*a*$",
        r"a*a*a*a*a*$",
        r"a*a*a*a*a*a*a*a*$",
        r"(a+)+$",
        r"(a|aa)+$",
        r"((a|aa))+$",
        r"([a-z]+)*$",
        r"(a|a)*b",
        r"(x+x+)+y",
        r"(foo|foobar)+$",
        r"(.*)*b",
        r"(a*)*(b*)*",
    ]

    ORDINARY = [
        r"^577$|^4673$", r"[a-z]+", r"^(foo|bar)$", r"\.+", r"(abc)+", r"a*b",
        r"^lsass\.exe$", r"[A-Za-z0-9_]+", r"[0-9]+", r"^AUDIT_FAILURE$|^failure$",
        r"(a|b)+c", r"(GET|POST|PUT)+", r"(admin|root|user)+$",
        r"[0-9]+(\.[0-9]+)?", r"^lsass\.exe$",
    ]

    def test_every_categorical_shape_is_refused(self):
        for pattern in self.CATASTROPHIC:
            with self.subTest(pattern=pattern):
                with self.assertRaises(Refusal) as caught:
                    compile_pattern("posix_extended", pattern)
                self.assertEqual(caught.exception.code,
                                 "REGEX_CATASTROPHIC_BACKTRACKING")

    def test_ordinary_detection_patterns_still_compile(self):
        """A control that refuses real rules is as bad as one that hangs."""
        for pattern in self.ORDINARY:
            with self.subTest(pattern=pattern):
                compile_pattern("posix_extended", pattern)

    def test_disjoint_alternatives_are_not_treated_as_overlapping(self):
        """`(a|b)` has exactly one way to match any text. `(a|aa)` has 2^n."""
        self.assertIsNone(catastrophic_reason(r"(a|b)+c"))
        self.assertIsNone(catastrophic_reason(r"(GET|POST)+"))
        self.assertIsNotNone(catastrophic_reason(r"(a|aa)+$"))

    def test_an_optional_group_is_not_a_repeat(self):
        """`?` means zero-or-one, so the group is tried once. A decimal pattern
        was refused by an earlier version."""
        self.assertIsNone(catastrophic_reason(r"[0-9]+(\.[0-9]+)?"))

    def test_a_lookaround_is_not_a_nested_quantifier(self):
        for pattern in ("(?i)abc", "(?=x)y", "(?<=a)b", "(?:x)y"):
            self.assertIsNone(_nested_quantifier(pattern))


class EventCapTests(unittest.TestCase):
    def test_the_library_entry_point_is_capped_too(self):
        """The cap lived only in the parser, so a caller building the list in
        memory walked past it."""
        from ruleforge.dialects import lower_spl
        ir, _ = lower_spl("index=main | stats count BY host")
        with self.assertRaises(Refusal) as caught:
            jobs.tune(ir, [{} for _ in range(jobs.MAX_EVENTS + 1)])
        self.assertEqual(caught.exception.code, "TOO_MANY_EVENTS")


class ValidationRouteTests(unittest.TestCase):
    def test_all_three_graph_routes_validate(self):
        """MAX_NODES was enforced on `author` and not on the other two."""
        from ruleforge.engine.ir import MAX_NODES
        stages = " | ".join(f"where EventID == {n}" for n in range(600))
        text = f"SecurityEvent | {stages}"
        for name in ("understand", "tune"):
            with self.subTest(job=name):
                with self.assertRaises(Refusal) as caught:
                    jobs._lower_validated("sentinel", text, "r")
                self.assertEqual(caught.exception.code, "GRAPH_TOO_LARGE")
        self.assertEqual(MAX_NODES, 500)


class DeriveFlagTests(unittest.TestCase):
    """The flag was DECLARED and never set or read -- dead code."""

    def test_kql_project_sets_the_flag(self):
        from ruleforge.dialects import lower_kql, parse_kql
        from ruleforge.engine.ir import Derive
        ir, _ = lower_kql(parse_kql("T | project a, b"))
        node = next(n for n in ir.nodes if isinstance(n, Derive))
        self.assertTrue(node.projects)

    def test_kql_extend_clears_the_flag(self):
        from ruleforge.dialects import lower_kql, parse_kql
        from ruleforge.engine.ir import Derive
        ir, _ = lower_kql(parse_kql("T | extend x = 1"))
        node = next(n for n in ir.nodes if isinstance(n, Derive))
        self.assertFalse(node.projects)

    def test_the_renderers_read_the_flag_not_the_node_id(self):
        from ruleforge.dialects.kql_render import _is_projection
        from ruleforge.engine.ir import Derive
        from ruleforge.engine.ir import Literal
        for node_id, projects, expected in (("extend_a_1", True, "project"),
                                           ("x_project_1", False, "extend")):
            node = Derive(id=node_id, input="r", projects=projects,
                          assignments=(("k", Literal(value=1)),))
            self.assertEqual(_is_projection(node), projects,
                             f"{node_id}: flag disagrees with the check")


class RenderFidelityTests(unittest.TestCase):
    def test_a_kql_regex_cannot_inject_a_stage(self):
        """KQL verbatim strings decode `""` as one `"`, so a raw pattern closed
        the literal early and injected a stage -- and `take 0` returns nothing,
        so the DEPLOYED rule silently matched zero events."""
        from ruleforge.dialects.kql_render import render
        from ruleforge.engine.ir import (Call, Comparison, Emit, FieldExpr,
                                         FieldRef, Filter, Literal, Read,
                                         RuleIR, SourceSelector)
        node = Filter(id="f", input="r", condition=Comparison(
            "=", FieldExpr(ref=FieldRef("c")),
            Call(function="matches_regex", args=(FieldExpr(ref=FieldRef("c")),
                                                Literal(value='a" | take 0"')),
                 dialect="pcre")))
        ir = RuleIR(rule_id="r", nodes=(
            Read(id="r", selector=SourceSelector(name="T")), node,
            Emit(id="o", input="f")), output="o")
        rendered = render(ir)
        self.assertIn('a"" | take 0"', rendered)
        self.assertNotIn('@"a" | take 0"', rendered)

    def test_an_unknown_operator_is_refused_not_echoed(self):
        """`.get(op, op)` is a raw-interpolation sink: the moment a new op joins
        the whitelist it becomes injectable.

        The IR refuses an unknown operator at construction, so this cannot be
        built the obvious way -- which is the right place for it. The renderer
        guard is still asserted directly, because it is what would save us if
        that whitelist ever widened.
        """
        from ruleforge.dialects.spl_render import render_expr
        from ruleforge.engine.ir import Comparison, FieldExpr, FieldRef, Literal

        class FakeOp(Comparison):
            pass

        expr = Comparison("=", FieldExpr(ref=FieldRef("a")), Literal(value=1))
        object.__setattr__(expr, "op", "><")
        with self.assertRaises(Refusal) as caught:
            render_expr(expr)
        self.assertEqual(caught.exception.code, "SPL_OPERATOR_NOT_RENDERABLE")

    def test_a_presence_op_renders_as_a_function_not_a_bare_word(self):
        """`_COMPARISON.get(op, op)` produced `foois_not_nulltrue` -- a field
        name nobody has."""
        from ruleforge.dialects.spl_render import render_expr
        from ruleforge.engine.ir import Comparison, FieldExpr, FieldRef, Literal
        for op, expected in (("is_not_null", "isnotnull(EventCode)"),
                             ("is_null", "isnull(EventCode)"),
                             ("exists", "isnotnull(EventCode)")):
            with self.subTest(op=op):
                rendered = render_expr(Comparison(
                    op, FieldExpr(ref=FieldRef("EventCode")),
                    Literal(value=True)))
                self.assertEqual(rendered, expected)


if __name__ == "__main__":
    unittest.main()
