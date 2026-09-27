"""SPL renderer tests.

THE POINT OF THIS FILE IS THE SELECTOR.

`index=windows sourcetype=WinEventLog:Security` at the head of an SPL search is
a SELECTOR: it chooses what is SEARCHED, so the planner can use the index. The
lowerer turns it into a `Filter` because the IR has no separate concept of source
selection. Rendering it as a leading `| where` would be a filter instead, which
returns the same rows at far higher cost -- a regression nobody notices until the
query times out.

So the renderer must put it back at the head, and only when the filter is
EXACTLY the selector shape.
"""
from __future__ import annotations

import unittest

from dialects.spl import parse_spl
from dialects.spl_ir import lower
from dialects.spl_render import render, _as_selector
from engine.ir import (Arrange, BoolOp, Comparison, Emit, FieldExpr, FieldRef,
                      Literal, RuleIR)
from tests.test_spl import CORPUS_SPL


class SelectorTests(unittest.TestCase):
    def _ir(self):
        return lower(CORPUS_SPL)[0]

    def test_the_selector_goes_back_at_the_head(self):
        """A selector is not a filter. It restricts what is SEARCHED, so it has
        to be the first thing in the search."""
        rendered = render(self._ir())
        self.assertTrue(rendered.startswith("index=windows sourcetype="),
                        f"the selector is not at the head: {rendered[:70]!r}")

    def test_the_selector_is_not_emitted_as_a_where(self):
        rendered = render(self._ir())
        self.assertNotIn("| search index=", rendered)
        self.assertNotIn("| where index", rendered)

    def test_a_selector_field_can_still_be_filtered_later(self):
        """The head placement is only for the LEADING selector. A later test on
        the same field is a genuine filter and belongs in a `search`."""
        ir, _ = lower("index=main | stats count BY index")
        rendered = render(ir)
        self.assertTrue(rendered.startswith("index=main"))

    def test_a_filter_with_a_non_selector_term_is_not_a_selector(self):
        """`index=main EventCode=4688` cannot be a head selector, because a
        selector cannot express the second term. Emitting both at the head would
        change what the search looks at."""
        from engine.ir import Filter, Read, RuleIR, SourceSelector, Emit
        from dialects.spl_render import render as render_ir
        condition = BoolOp("and", (
            Comparison("=", FieldExpr(ref=FieldRef("index")),
                       Literal(value="main")),
            Comparison("=", FieldExpr(ref=FieldRef("EventCode")),
                       Literal(value=4688)),
        ))
        ir = RuleIR(rule_id="t", nodes=(
            Read(id="r", selector=SourceSelector(name="events")),
            Filter(id="f", input="r", condition=condition),
            Emit(id="o", input="f"),
        ), output="o")
        rendered = render_ir(ir)
        self.assertIn("| search", rendered)
        self.assertNotIn("EventCode=4688 main", rendered)

    def test_as_selector_returns_none_for_a_non_selector(self):
        self.assertIsNone(_as_selector(
            Comparison(">", FieldExpr(ref=FieldRef("bytes")),
                       Literal(value=1024))))


class RoundTripTests(unittest.TestCase):
    def _ir(self):
        return lower(CORPUS_SPL)[0]

    def test_the_search_renders(self):
        rendered = render(self._ir())
        self.assertIn("| search", rendered)
        self.assertIn("| stats", rendered)

    def test_all_three_measures_survive(self):
        rendered = render(self._ir())
        self.assertIn("count AS process_count", rendered)
        self.assertIn("dc(dest_ip) AS destination_count", rendered)
        self.assertIn("values(command_line) AS commands", rendered)

    def test_values_comes_back_as_values_not_count(self):
        rendered = render(self._ir())
        self.assertIn("values(", rendered)

    def test_the_by_fields_survive(self):
        self.assertIn("by host, user", render(self._ir()))

    def test_the_in_list_survives(self):
        rendered = render(self._ir())
        self.assertIn('process_name IN ("powershell.exe", "cmd.exe")', rendered)

    def test_the_threshold_is_numeric_not_a_string(self):
        """`Decimal` is neither int nor float, so a count threshold rendered
        through a string branch becomes `>="1"` -- a number compared to a
        string. The corpus rule's thresholds are 3 and 2."""
        rendered = render(self._ir())
        self.assertIn("process_count>=3", rendered)
        self.assertNotIn('>= "3"', rendered)
        self.assertNotIn('>= "2"', rendered)

    def test_the_selector_and_the_first_pipe_are_space_separated(self):
        """Without the space the output is `WinEventLog:Security| search`, which
        is not a search Splunk will parse."""
        self.assertIn("Security | search", render(self._ir()))

    def test_the_rendered_search_re_parses(self):
        """THE REAL TEST."""
        again = parse_spl(render(self._ir()))
        self.assertEqual(again.indexes, ("windows",))
        self.assertEqual(again.sourcetypes, ("WinEventLog:Security",))
        from dialects.spl import parse_stats
        names = [c.name for c in again.pipeline]
        self.assertIn("stats", names)
        stats = parse_stats(
            next(c.args for c in again.pipeline if c.name == "stats"), "stats")
        self.assertEqual(
            {m.alias for m in stats.measures},
            {"process_count", "destination_count", "commands"})
        self.assertEqual(stats.keys, ("host", "user"))


class HonestRefusalTests(unittest.TestCase):
    def test_a_node_with_no_spl_rendering_is_refused_not_dropped(self):
        from dialects.spl_render import render as render_ir
        from engine.ir import (Emit, Expand, Read, RuleIR,
                                         SourceSelector)
        ir = RuleIR(rule_id="t", nodes=(
            Read(id="r", selector=SourceSelector(name="main")),
            Expand(id="e", input="r", field="a"),
            Emit(id="o", input="e"),
        ), output="o")
        with self.assertRaises(Exception) as caught:
            render_ir(ir)
        self.assertEqual(getattr(caught.exception, "code", ""),
                         "SPL_RENDER_NODE_UNSUPPORTED")

    def test_a_measure_with_no_spl_function_is_refused(self):
        """`stddev` is a real IR measure, so the IR accepts it -- and SPL has no
        direct spelling this renderer maps. Naming it beats rendering a different
        statistic under the same name. (`percentile` cannot be used here: the IR
        refuses it at construction, so the renderer guard would be untested.)"""
        from dialects.spl_render import _render_aggregate
        from engine.ir import Aggregate, Frame, Measure
        aggregate = Aggregate(id="a", input="r",
                              measures=(Measure(name="sd", function="stddev",
                                                field=FieldRef("bytes")),),
                              keys=(), frame=Frame(kind="per_event"))
        with self.assertRaises(Exception) as caught:
            _render_aggregate(aggregate)
        self.assertEqual(getattr(caught.exception, "code", ""),
                         "SPL_MEASURE_NOT_RENDERABLE")


class ArrangeDirectionTests(unittest.TestCase):
    """`head` encodes sort direction as a SIGN ON THE FIELD, and a bare field is
    not neutral.

    This whole path had NO test at all -- `test_spl_render.py` never built an
    `Arrange`, so `head` and `sort` were rendered by nothing and checked by
    nothing. Measured before the fix, on a real lowered corpus rule with an
    `Arrange` appended:

        head, field _time, direction desc  ->  head 5 _time
        head, field _time, direction asc   ->  head 5 _time     <- IDENTICAL
        head, fields host asc + _time desc ->  head 3 host      <- second GONE

    Splunk reads a bare field in `head` as reverse order, so the `asc` case was
    not merely unexpressed -- it was INVERTED, and the tool reported the
    analyst's rule back to them as their own. The second field vanishing is the
    same failure this project keeps finding: a complete-looking artifact with
    part of the request missing.
    """

    def _with_arrange(self, order_by, limit):
        base = lower(CORPUS_SPL)[0]
        last = base.nodes[-2]
        arrange = Arrange(id="arr", input=last.id, order_by=order_by,
                          limit=limit)
        return RuleIR(
            rule_id="r",
            nodes=(*base.nodes, arrange, Emit(id="o2", input="arr")),
            output="o2")

    def _tail(self, order_by, limit):
        rendered = render(self._with_arrange(order_by, limit))
        return rendered.split("|")[-1].strip()

    def test_head_descending_carries_a_minus(self):
        self.assertEqual(
            self._tail(((FieldRef(name="_time"), "desc"),), 5), "head 5 -_time")

    def test_head_ascending_carries_a_plus(self):
        """The inverted case. Without the `+`, Splunk reads this as reverse
        order and the analyst gets the opposite of what they asked for."""
        self.assertEqual(
            self._tail(((FieldRef(name="_time"), "asc"),), 5), "head 5 +_time")

    def test_ascending_and_descending_do_not_render_the_same(self):
        """Stated as its own test, because "both render as `head 5 _time`" was
        the bug and an assertion on each value separately would not have made
        that visible."""
        asc = self._tail(((FieldRef(name="_time"), "asc"),), 5)
        desc = self._tail(((FieldRef(name="_time"), "desc"),), 5)
        self.assertNotEqual(asc, desc)

    def test_every_ordering_field_survives(self):
        self.assertEqual(
            self._tail(((FieldRef(name="host"), "asc"),
                        (FieldRef(name="_time"), "desc")), 3),
            "head 3 +host -_time")

    def test_sort_keeps_its_explicit_keywords(self):
        """`sort` was always correct and must stay correct -- it spells the
        direction as a word, so it never needed a sign. Asserted so a future
        'make head and sort consistent' change has to notice this."""
        self.assertEqual(
            self._tail(((FieldRef(name="host"), "desc"),), None),
            "sort host desc")
        self.assertEqual(
            self._tail(((FieldRef(name="host"), "asc"),), None),
            "sort host asc")

    def test_a_dotted_field_keeps_its_path(self):
        """`-win.eventdata.targetImage`, not `-win` -- the sign attaches to the
        whole field name."""
        self.assertEqual(
            self._tail(((FieldRef(name="win.eventdata.targetImage"), "desc"),),
                       2),
            "head 2 -win.eventdata.targetImage")

    def test_head_with_no_ordering_field_is_still_refused(self):
        from engine.values import Refusal
        with self.assertRaises(Refusal) as caught:
            render(self._with_arrange((), 5))
        self.assertEqual(caught.exception.code,
                         "SPL_RENDER_HEAD_WITH_NO_ORDER")


if __name__ == "__main__":
    unittest.main()
