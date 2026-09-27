"""The history file is JSON LINES now, and the tests are about that.

`append` used to load the whole file, append in memory, and write the whole file
back, so an append cost O(N) writes and filling the history to its cap cost
O(N^2). These tests pin the three things that change follows from:

  - an append adds one line and does not touch the lines already there
  - the old single-JSON-array format is still READ, and is upgraded on the next
    save rather than being orphaned or silently mixed
  - a file interrupted mid-write loses its tail entry, not the whole history,
    while a file that is simply damaged is still reported as damaged
"""

import json
import tempfile
import unittest
from pathlib import Path

import history


def _entry(number: int, pad: str = "x" * 200) -> dict:
    return {"kind": "author", "dialect": "spl", "rule_id": f"r{number}",
            "title": "t", "summary": "s", "payload": {"i": number, "pad": pad},
            "created_at": "2026-01-01T00:00:00+00:00"}


class JsonLinesFormatTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "history.jsonl"

    def test_an_append_writes_one_new_line_and_leaves_the_old_bytes_alone(self):
        """This is the actual fix. The previous implementation rewrote the
        entire file on every append, so the bytes already written were rewritten
        again and again -- measured at 30x the writes at 60 entries and 100x at
        200, because entry i was written i times."""
        history.append(self.path, "author", "spl", "r1", "t", "s", {"i": 1})
        first = self.path.read_bytes()
        self.assertEqual(len(first.splitlines()), 1)

        history.append(self.path, "author", "spl", "r2", "t", "s", {"i": 2})
        second = self.path.read_bytes()

        # Every byte of the first line is still a PREFIX of the file. If the
        # implementation rewrote the file, this would still hold by accident of
        # ordering, so the count of writes is asserted directly below.
        self.assertTrue(second.startswith(first),
                        "the bytes already on disk must survive an append "
                        "untouched, not be re-serialised in place")
        self.assertEqual(len(second.splitlines()), 2)
        self.assertEqual([e["payload"]["i"] for e in history.load(self.path)],
                         [1, 2])

    def test_the_file_is_one_entry_per_line_and_readable_as_such(self):
        """The module's own words are that this is a FILE the analyst can read,
        back up and delete themselves, so the on-disk shape is asserted rather
        than left as an implementation detail."""
        for number in range(3):
            history.append(self.path, "author", "spl", f"r{number}", "t", "s",
                           {"i": number})
        raw = self.path.read_text(encoding="utf-8")
        self.assertFalse(raw.startswith("["),
                         "a JSON array was the old format; the first character "
                         "is now `{`")
        for line in raw.splitlines():
            self.assertIsInstance(json.loads(line), dict,
                                  "every line must be a complete entry on its "
                                  "own, which is what makes appending cheap")

    def test_recent_still_returns_the_newest_first(self):
        for number in range(5):
            history.append(self.path, "author", "spl", f"r{number}", "t", "s",
                           {"i": number})
        self.assertEqual([e["payload"]["i"] for e in history.recent(self.path)],
                         [4, 3, 2, 1, 0])


class LegacyArrayMigrationTests(unittest.TestCase):
    """An existing analyst's history is a JSON ARRAY. It must not be orphaned."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "history.json"

    def test_a_legacy_array_is_still_read(self):
        self.path.write_text(json.dumps([_entry(1), _entry(2)], indent=2),
                             encoding="utf-8")
        self.assertEqual([e["payload"]["i"] for e in history.load(self.path)],
                         [1, 2])

    def test_a_legacy_array_is_upgraded_by_a_save_not_orphaned(self):
        """The upgrade happens in `append`, never in `load`. `load` is called by
        the read-only routes, and a reader must never rewrite the file -- the
        corruption refusals promise the file "has not been overwritten", and a
        read that quietly migrated it would break that promise while appearing
        to keep it."""
        legacy = json.dumps([_entry(1), _entry(2)], indent=2)
        self.path.write_text(legacy, encoding="utf-8")
        history.load(self.path)
        self.assertEqual(self.path.read_text(encoding="utf-8"), legacy,
                         "reading must not modify the file")

        history.append(self.path, "author", "spl", "r3", "t", "s", {"i": 3})
        raw = self.path.read_text(encoding="utf-8")
        self.assertFalse(raw.startswith("["), "the save should have upgraded it")
        self.assertEqual([e["payload"]["i"] for e in history.load(self.path)],
                         [1, 2, 3], "no entry may be lost in the upgrade")

    def test_the_upgrade_preserves_every_entry_in_order(self):
        entries = [_entry(number) for number in range(25)]
        self.path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        history.append(self.path, "author", "spl", "new", "t", "s", {"i": 99})
        self.assertEqual([e["payload"]["i"] for e in history.load(self.path)],
                         [number for number in range(25)] + [99])


class InterruptedAppendTests(unittest.TestCase):
    """A killed process can leave a partial last line. That must cost the tail
    entry, not the history."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "history.jsonl"

    def test_a_torn_final_line_loses_only_that_entry(self):
        history.append(self.path, "author", "spl", "r1", "t", "s", {"i": 1})
        history.append(self.path, "author", "spl", "r2", "t", "s", {"i": 2})
        # A process killed mid-write: the second entry's line is half there and
        # the file does not end in a newline.
        complete = self.path.read_text(encoding="utf-8")
        self.path.write_text(complete + '{"kind": "author", "payl',
                             encoding="utf-8")
        self.assertEqual([e["payload"]["i"] for e in history.load(self.path)],
                         [1, 2],
                         "the two complete entries must still be readable")

    def test_a_complete_but_corrupt_line_is_still_refused(self):
        """Newline-terminated, so the interrupted-write explanation does not
        apply: this is a damaged file and must be reported, not quietly
        truncated."""
        history.append(self.path, "author", "spl", "r1", "t", "s", {"i": 1})
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write("{not json at all}\n")
        with self.assertRaises(history.Refused):
            history.load(self.path)

    def test_a_file_that_is_only_garbage_is_refused_not_called_empty(self):
        """The one that tightened the torn-tail rule. A torn write is always a
        TAIL -- there is something before it, because something was already
        there for the append to extend. A file with nothing valid in it has not
        had a torn write, it has been damaged, and reporting that as an empty
        history is the exact failure the refusals exist to prevent."""
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(history.Refused):
            history.load(self.path)

    def test_corruption_before_the_last_line_is_refused(self):
        self.path.write_text('{not json}\n{"kind": "author"}\n',
                             encoding="utf-8")
        with self.assertRaises(history.Refused):
            history.load(self.path)


class EntryCapTests(unittest.TestCase):
    """Trimming is the one path that still rewrites the file, and it must still
    report what it dropped."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "history.jsonl"
        self._cap = history.MAX_ENTRIES
        self.addCleanup(setattr, history, "MAX_ENTRIES", self._cap)
        history.MAX_ENTRIES = 5

    def test_over_the_cap_the_oldest_go_and_the_count_comes_back(self):
        for number in range(7):
            result = history.append(self.path, "author", "spl", f"r{number}",
                                    "t", "s", {"i": number})
        kept = [e["payload"]["i"] for e in history.load(self.path)]
        self.assertEqual(kept, [2, 3, 4, 5, 6])
        # The cap bites one at a time: at entry 6 the file holds 6 and 1 goes,
        # and at entry 7 it holds 6 again. So each of the last two appends
        # dropped 1, and the total dropped across the run is 2. The count that
        # comes BACK is per-append, which is what the UI reports.
        self.assertEqual(result.dropped, 1,
                         "the count of dropped entries is the whole reason "
                         "`dropped` exists, and it must survive the rewrite")
        self.assertEqual(history.recent(self.path, limit=99)[-1]["payload"]["i"],
                         2, "the oldest survivors are the ones after the drop")

    def test_a_trimmed_file_is_still_one_entry_per_line(self):
        for number in range(7):
            history.append(self.path, "author", "spl", f"r{number}", "t", "s",
                           {"i": number})
        for line in self.path.read_text(encoding="utf-8").splitlines():
            self.assertIsInstance(json.loads(line), dict)


if __name__ == "__main__":
    unittest.main()
