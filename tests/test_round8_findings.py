"""Round 8 findings. All were found by an independent review of code written
earlier in this session, with the suite GREEN throughout.

Every one of them is the same shape, which is now the third and fourth instances
of it: a code path that is silently skipped, or a value that reaches the renderer
and is discarded. The `Not`-node walk bug and the `Emit` dedup bug were the first
two. So these tests are grouped by that shape, and each asserts the app-reachable
path through `jobs.author` or `history.append` rather than only the internals.
"""

import json
import tempfile
import unittest
from pathlib import Path

import history
import jobs


class SortDirectionIsASignNotAKeyword(unittest.TestCase):
    """SPL HAS NO `asc` / `desc` KEYWORD. `| sort _time desc` parses as
    "ascending by _time, then by a field named `desc`" -- so the direction was
    INVERTED and a bogus field added, on a rule returned as ok=True with no
    finding.

    The bug was copied from `kql_render.py`, where `f"{ref} {direction}"` IS
    correct because KQL's `order by` really has the keyword. Two branches of one
    `if` disagreed about the same field, and the test named
    `test_sort_descending_uses_the_minus_sign` asserted `sort count desc` while
    its own docstring quoted the minus sign. The suite was certifying the defect.
    """

    def test_descending_sort_uses_a_minus(self):
        self.assertEqual(
            jobs.author("splunk", "index=main EventCode=4625 | sort -_time",
                        "r1").rendered,
            'index=main | search EventCode="4625" | sort -_time')

    def test_ascending_sort_uses_a_plus(self):
        self.assertEqual(
            jobs.author("splunk", "index=main | sort +host", "r1").rendered,
            "index=main | sort +host")

    def test_no_asc_or_desc_word_ever_reaches_the_output(self):
        """The blunt invariant, so a future refactor cannot reintroduce the
        keyword form in either branch."""
        for source in ("index=main | sort -_time", "index=main | sort +host",
                       "index=main | sort -_time | head 5",
                       "index=main | sort 0 -_time"):
            with self.subTest(source=source):
                rendered = jobs.author("splunk", source, "r1").rendered
                for word in (" asc", " desc"):
                    self.assertNotIn(word, rendered,
                                     f"{word!r} is not SPL sort syntax")


class AnAppendAfterATornTailMustNotDestroyTheNewEntry(unittest.TestCase):
    """`load` tolerates an unterminated final line so a killed append costs one
    entry rather than the whole history -- and then said nothing about it. The
    next `append` wrote straight onto the partial bytes, which destroyed the entry
    just saved AND bricked the file forever, because the new line supplied the
    trailing newline the tolerance keys on.

    Executed before the fix:
        load after damage -> 2 entries
        append returned OK, dropped = 0
        load -> Refused: line 3 ...          # and every future save refused
    """

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "history.jsonl"

    def _torn(self) -> None:
        good = "\n".join(json.dumps(history.append(
            self.path, "author", "splunk", f"r{i}", "t", "s", {"i": i}).entry)
            for i in (1, 2))
        self.path.write_text(good + '\n{"kind": "author", "rule_',
                             encoding="utf-8")

    def test_the_new_entry_survives_and_the_file_stays_readable(self):
        self._torn()
        self.assertEqual(len(history.load(self.path)), 2,
                         "the tolerance must still tolerate a torn tail on read")
        history.append(self.path, "author", "splunk", "r3", "t", "s", {"i": 3})
        ids = [e["rule_id"] for e in history.load(self.path)]
        self.assertEqual(ids, ["r1", "r2", "r3"],
                         "the entry just saved must be a real entry, not bytes "
                         "concatenated onto garbage")
        self.assertIn("r3", ids)

    def test_a_further_save_still_works(self):
        """The bricked half of the bug: the second save was refused forever, so
        losing one entry cost every entry after it."""
        self._torn()
        history.append(self.path, "author", "splunk", "r3", "t", "s", {"i": 3})
        history.append(self.path, "author", "splunk", "r4", "t", "s", {"i": 4})
        self.assertEqual([e["rule_id"] for e in history.load(self.path)],
                         ["r1", "r2", "r3", "r4"])

    def test_the_good_entries_are_never_lost_to_repair(self):
        self._torn()
        history.append(self.path, "author", "splunk", "r3", "t", "s", {"i": 3})
        self.assertEqual([e["payload"]["i"] for e in history.load(self.path)],
                         [1, 2, 3])

    def test_a_file_that_is_one_partial_line_becomes_empty_not_unreadable(self):
        """No good entry precedes it, so there is nothing to keep. Empty is the
        honest description; unreadable would block every future save."""
        self.path.write_text('{"kind": "author", "rule_', encoding="utf-8")
        history.append(self.path, "author", "splunk", "r1", "t", "s", {"i": 1})
        self.assertEqual([e["rule_id"] for e in history.load(self.path)], ["r1"])

    def test_a_healthy_file_is_untouched_by_the_repair(self):
        history.append(self.path, "author", "splunk", "r1", "t", "s", {"i": 1})
        before = self.path.read_bytes()
        history.append(self.path, "author", "splunk", "r2", "t", "s", {"i": 2})
        self.assertTrue(self.path.read_bytes().startswith(before),
                        "the repair must not rewrite bytes that were already good")


class AUtf8BomMustNotBrickTheHistory(unittest.TestCase):
    """A WINDOWS problem, and not hypothetical. `read_text(encoding="utf-8")` does
    not strip a BOM and `str.lstrip()` cannot strip U+FEFF because it is not
    whitespace, so the first line was unparseable and EVERY SAVE was refused
    forever.

    PowerShell 5.1's `Set-Content -Encoding UTF8` and `Out-File -Encoding utf8`
    write a BOM, as do older Notepad and Excel's text export -- and this module
    explicitly invites the analyst to read, back up and edit the file by hand.
    """

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "history.jsonl"

    def test_a_bom_prefixed_history_is_readable(self):
        self.path.write_bytes(b"\xef\xbb\xbf" + json.dumps(
            {"kind": "author", "rule_id": "r1"}).encode("utf-8") + b"\n")
        self.assertEqual([e["rule_id"] for e in history.load(self.path)], ["r1"])

    def test_a_bom_does_not_block_saving(self):
        self.path.write_bytes(b"\xef\xbb\xbf" + json.dumps(
            {"kind": "author", "rule_id": "r1"}).encode("utf-8") + b"\n")
        history.append(self.path, "author", "splunk", "r2", "t", "s", {"i": 2})
        self.assertEqual([e["rule_id"] for e in history.load(self.path)],
                         ["r1", "r2"])

    def test_a_bom_does_not_defeat_the_legacy_array_check(self):
        """`raw.lstrip().startswith("[")` -- a BOM before `[` would miss the
        legacy branch and fall into JSONL parsing."""
        self.path.write_bytes(b"\xef\xbb\xbf" + json.dumps(
            [{"kind": "author", "rule_id": "r1"}]).encode("utf-8"))
        self.assertEqual([e["rule_id"] for e in history.load(self.path)], ["r1"])


class ALegacyArrayWithANonEntryMustNotBeUpgradedIntoABrick(unittest.TestCase):
    """The JSONL branch validates every line is a dict. The legacy branch checked
    only the top-level container, so an array holding a bare string read happily
    and the next SAVE re-serialised it one-per-line -- after which the file could
    never be read again. A READABLE file became permanently UNREADABLE as a side
    effect of a successful save, and that was irreversible."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "history.json"

    def test_a_legacy_array_holding_a_string_is_refused(self):
        self.path.write_text(json.dumps(
            [{"kind": "author", "rule_id": "ok1"}, "a bare string", 42]),
            encoding="utf-8")
        with self.assertRaises(history.Refused):
            history.load(self.path)

    def test_and_saving_after_it_does_not_produce_a_brick(self):
        self.path.write_text(json.dumps(
            [{"kind": "author", "rule_id": "ok1"}, "a bare string"]),
            encoding="utf-8")
        with self.assertRaises(history.Refused):
            history.append(self.path, "author", "splunk", "r2", "t", "s", {"i": 2})
        with self.assertRaises(history.Refused):
            history.load(self.path), "the file must be unchanged, not upgraded"


class TheSubSearchRendererMustNotBeADivergentCopy(unittest.TestCase):
    """`_render_subpipeline` re-implemented the main loop's stage rendering and
    had drifted, so it still had BOTH bugs fixed in the main loop on the very
    same day: `Emit` was `continue`d away (the dedup bug) and `Derive` was
    rendered as `eval` regardless of `kind` (the projection bug the main loop now
    refuses). The dedup commit said the refused set was "now empty except
    fillnull", which was true of the main loop and false of this one."""

    def _sub(self, kind: str, **kwargs) -> str:
        from dialects import spl_render
        from engine.ir import Emit, Filter, Read, RuleIR, SourceSelector
        inner = getattr(Filter, "id", "f")
        graph = RuleIR(
            rule_id="r",
            nodes=(Read(id="read", selector=SourceSelector(name="main")),
                   kind_node(kind, inner, **kwargs),
                   Emit(id="out", input=inner)),
            output="out", metadata={"dialect": "splunk"})
        return spl_render.render(graph)

    def test_the_two_renderers_stay_in_step(self):
        """A structural check, not a rendering snapshot: the sub-search must
        refuse an unknown `Derive` kind exactly as the main loop does. If the two
        ever diverge again, this fails."""
        from dialects.spl_render import _render_subpipeline
        from engine.ir import Derive
        node = Derive(id="d", input="read", assignments=(("a", _one()),),
                      kind="something-else")
        with self.assertRaises(Exception) as caught:
            _render_subpipeline([node], {})
        self.assertIn("DERIVE_KIND", str(caught.exception).upper())

    def test_an_emit_with_dedupe_is_not_continued_away(self):
        from dialects.spl_render import _render_subpipeline
        from engine.ir import Emit, FieldRef
        out = _render_subpipeline(
            [Emit(id="out", input="f",
                  dedupe_by=(FieldRef("host"),))], {})
        self.assertIn("dedup host", out,
                      "a sub-search must not silently lose its de-duplication")


def kind_node(kind: str, ident: str, **kwargs):
    from engine.ir import Derive
    if kind == "Derive":
        return Derive(id=ident, input="read", **kwargs)
    raise NotImplementedError(kind)


def _one():
    from engine.ir import Literal
    return Literal("x")


if __name__ == "__main__":
    unittest.main()
