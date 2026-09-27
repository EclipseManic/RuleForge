"""Round 9, the low cluster: a contradicting message, a backwards rendering, and a
stale mutation.

None of these is reachable as a wrong artifact today, which is why they are
low. All three are the same disease one level down: text that says something
untrue about the code beside it.

`count(x)` IS NOT `count`

    index=main | stats COUNT(x) as c BY host
      -> REFUSED: MEASURE_FIELD_NOT_APPLICABLE, "'count' reads no field"

-- for an input that names field `x`. In Splunk bare `count` counts events and
`count(x)` counts NON-NULL values of `x`: different numbers on any column with
empties. The IR's `count` takes no field, and the generic map let `count(x)`
through to an engine-internal refusal whose message contradicted the rule. Now
SPL_COUNT_FIELD_NOT_LOWERABLE, naming the distinction, rather than a bare count
that would silently change the number.

The sub-search `rename` was backwards

The main loop renders `rename <old> as <new>`. `_render_subpipeline` rendered
`rename <new> AS <old>` -- the opposite direction. Currently a dead path
(`spl_ir.lower` has no `join` command), but the third copy of this renderer to
drift, in the function whose own comment says the duplication "already cost
twice". A dead path with the wrong direction in it becomes a live bug the day a
join lowering exists, so it is aligned now rather than later.

M8 targeted a string that no longer exists

`mutation_check.py` M8 replaced `if node.until is not None and
_window_satisfies(`, which the `until_scope` refactor removed. The harness
honestly counts a stale pattern as a failure, but nothing in pytest sees it and
it is a standalone script -- so the uncovered mutation (making the `until` veto
do nothing) sat unguarded. M8 now targets the current `if node.until is not
None:`, and all 15 mutations are caught.
"""

import unittest

import jobs
from dialects.spl_ir import SplParseError, lower


class CountWithAFieldIsNotBareCount(unittest.TestCase):
    def test_it_is_refused_by_name(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | stats COUNT(x) as c BY host")
        self.assertEqual(caught.exception.code, "SPL_COUNT_FIELD_NOT_LOWERABLE")

    def test_the_message_names_the_distinction(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | stats COUNT(x) as c BY host")
        self.assertIn("non-null", caught.exception.message,
                      "the analyst must be told these are different numbers, "
                      "not just that the function is unknown")

    def test_bare_count_still_works(self):
        self.assertEqual(
            jobs.author("splunk", "index=main | stats count BY host",
                        "r1").rendered,
            "index=main | stats count AS count by host")

    def test_no_artifact_is_produced(self):
        outcome = jobs.author(
            "splunk", "index=main | stats COUNT(x) as c BY host", "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"], "SPL_COUNT_FIELD_NOT_LOWERABLE")


class TheSubSearchRenameGoesTheRightWay(unittest.TestCase):
    def test_rename_renders_old_as_new(self):
        """Executed on a hand-built node, because `spl_ir.lower` has no `join`
        command and this path is unreachable from analyst text. The direction
        is pinned so a future join lowering inherits a correct renderer rather
        than a backwards one."""
        from dialects import spl_render
        from engine.ir import Derive, FieldExpr, FieldRef
        node = Derive(id="d", input="read", kind="rename",
                      assignments=(("account", FieldExpr(FieldRef("user"))),))
        out = spl_render._render_subpipeline([node], {})
        self.assertIn("rename user as account", out,
                      "rename <old> as <new>, matching the main loop -- not "
                      "the reverse")


if __name__ == "__main__":
    unittest.main()
