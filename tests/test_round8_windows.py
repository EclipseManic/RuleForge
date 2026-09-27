"""Round 8, continued: the two Windows findings, which are the analyst's own
workflow rather than an exotic input.

M4 -- the history file was created world-readable and narrowed afterwards.

    with path.open("a", ...) as stream:   # created HERE, at the umask (0644)
        ...
    os.chmod(path, 0o600)                 # narrowed HERE, after the close

So for the length of one write there was a window in which a file the
`.gitignore` comment describes as holding "pasted detection rules and EVENT
SAMPLES, which contain hostnames, usernames, source IPs and destination IPs" was
readable by anyone who could reach the directory. The chmod comment claimed the
append path was covered; it was covered eventually, which is not the same thing.

The rewrite path had this for free -- `mkstemp` creates 0600 -- so the two paths
were not equal, and the comment said they were. `os.open` takes the mode at
creation, so the append path now matches.

H6 -- a locked file escaped as a bare 500.

`web.py` caught `history.Refused` around the save, and nothing else. On Windows
`os.replace` over a file another process holds open fails with PermissionError,
because CPython does not open with FILE_SHARE_DELETE and Notepad-class handles
deny share-write too. The generic `except Exception` that would have caught it
lives in a different try block that ends at line 190, so a save that failed
because the analyst had the file open in an editor produced a server fault rather
than a sentence telling them to close it.
"""

import os
import tempfile
import unittest
from pathlib import Path

import history


class TheHistoryFileIsPrivateFromBirth(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "history.jsonl"

    @unittest.skipIf(os.name == "nt",
                     "POSIX permission bits; on Windows os.chmod has one bit and "
                     "grants nothing, which the module states explicitly")
    def test_an_appended_history_is_not_world_readable(self):
        history.append(self.path, "author", "splunk", "r1", "t", "s", {"i": 1})
        mode = os.stat(self.path).st_mode & 0o777
        self.assertEqual(mode & 0o077, 0,
                         f"the history file is {oct(mode)}; it holds pasted "
                         f"event samples with hostnames and IPs in it")

    def test_both_write_paths_end_up_the_same(self):
        """The append path and the rewrite path must agree, or the file's
        protection depends on which command happened to run last."""
        append_path = Path(self._dir.name) / "a.jsonl"
        rewrite_path = Path(self._dir.name) / "b.json"
        history.append(append_path, "author", "splunk", "r1", "t", "s", {"i": 1})
        history._write(rewrite_path, [history.append(
            append_path, "author", "splunk", "r2", "t", "s", {"i": 2}).entry])
        if os.name == "nt":
            self.skipTest("no POSIX bits on Windows")
        self.assertEqual(os.stat(append_path).st_mode & 0o777,
                         os.stat(rewrite_path).st_mode & 0o777,
                         "the two write paths produced different permissions")

    def test_appending_still_works_and_keeps_every_entry(self):
        for number in range(4):
            history.append(self.path, "author", "splunk", f"r{number}", "t", "s",
                           {"i": number})
        self.assertEqual([e["rule_id"] for e in history.load(self.path)],
                         ["r0", "r1", "r2", "r3"],
                         "switching to os.open must not change what is written")


class ALockedHistoryIsACautionNotAServerFault(unittest.TestCase):
    """The save route caught `history.Refused` and nothing else, so an OSError --
    which is what a locked file actually raises on Windows -- fell through to a
    bare 500."""

    def test_web_catches_an_oserror_around_a_save(self):
        """Structural: the save path must handle OSError, not just Refused.

        Asserted by reading the source because provoking a real file lock is
        platform-dependent and would make the test lie on one OS and pass on
        another. The alternative -- no assertion at all -- is what left this
        unfixed through a whole review round.
        """
        import inspect

        import web
        source = inspect.getsource(web)
        # The region from the save call to where the response is assembled --
        # splitting on "except" would stop at the FIRST one, which is the
        # `history.Refused` clause and so can never contain the OSError after it.
        save_block = source.split("history.append(")[1].split(
            "body = outcome.to_dict()")[0]
        self.assertIn("except history.Refused", save_block)
        self.assertIn("except OSError", save_block,
                      "the except clauses guarding a history save must catch "
                      "OSError, because a locked file raises that and not "
                      "history.Refused")
        self.assertIn("HISTORY_NOT_SAVED", save_block)

    def test_an_oserror_message_tells_the_analyst_what_to_do(self):
        import inspect

        import web
        save_block = inspect.getsource(web).split("except OSError")[1]
        self.assertIn("close it", save_block,
                      "the caution must say what to do, not just that it failed")


if __name__ == "__main__":
    unittest.main()
