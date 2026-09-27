"""A save that another PROCESS was told it had made must not be unlinked.

`history.append` used to hold a `threading.Lock` and, on the two paths that
rewrite the file, read the whole file, build a temp file from what it read, and
`os.replace` it over the original. `os.replace` is atomic BECAUSE it replaces,
and between the read and the rename a second process could append a line. That
line reached the file, the second process returned success, and the rename
unlinked the bytes underneath it. Executed evidence, before the fix:

    [other process] appended FROM_OTHER_PROCESS, returned success
    [process 1]    os.replace completed
    process 1 append returned OK, dropped = 1
    surviving entries: ['r2']
    FROM_OTHER_PROCESS survived? False

WHY EVERY TEST HERE SPAWNS A PROCESS. The broken code takes a
`threading.Lock` around the section that loses the entry, so no arrangement of
threads can interleave a rewrite with an append: a threaded test of this bug
passes against the code that has it. The harness runs
`tests/history_race_worker.py` under `sys.executable` instead, and the two
processes are given a SCHEDULE rather than a hope:

  - the process whose append FORCES A REWRITE pauses inside its window -- after
    its own read, before its own rename -- and will only rename once it has seen
    proof that the other process's entry is on the file
  - the other process is released only once that window is open

So on the broken code the destruction is not raced for, it is arranged, and the
test fails every time rather than sometimes. And the harness asserts the
arrangement as well as the result: the rewriter records whether it ever saw the
other entry land (`saw_landed`), which is `True` on the broken code and `False`
once the lock exists, because the other process cannot get into the window at
all. Two independent assertions, so a passing run cannot be a run where the
schedule simply failed to happen.

WHAT IS *NOT* CLAIMED HERE. The lock excludes another RuleForge in another
process. It does not exclude a hand edit in an editor, a second tool, or a
RuleForge too old to know the lock exists; `test_a_read_still_works_while_
another_process_holds_the_lock` pins the other half of that trade, and the
module states the rest.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import history

WORKER = Path(__file__).resolve().parent / "history_race_worker.py"
REPO_ROOT = Path(__file__).resolve().parent.parent

#: How long a paused writer waits for the OTHER process's entry to land before
#: it gives up and renames anyway. It is a real trade-off and the reason is
#: asymmetric: a run of the FIXED code always pays this, because the other
#: process provably cannot land its entry while the window is open, while a run
#: of the BROKEN code needs the other process to get from "released" to "line on
#: disk" inside it. Too small and the broken code would sometimes win the race
#: and the test would pass on broken code, which is worse than no test; too
#: large and the fixed run is slow. MEASURED, the other process needs 37-51 ms
#: to get from released to its entry on disk, so half a second is a margin of
#: about TEN times -- and in this harness that append is itself a full
#: 2000-entry REWRITE, not the O(1) line append an ordinary history does.
WAIT_S = 0.5

#: How long the parent waits for a child to say something before calling it a
#: hang. Generous: this is a failure message, not a race.
PATIENCE_S = 60.0


class _Child:
    """One spawned process, and the files that let the parent schedule it."""

    def __init__(self, process: subprocess.Popen, config: dict,
                 signals: Path) -> None:
        self.process = process
        self.gate = Path(config["gate"])
        self.result_path = Path(config["result"])
        self.signals = signals

    def release(self) -> None:
        self.gate.write_text("go", encoding="utf-8")

    def result(self) -> dict:
        code = self.process.wait(timeout=PATIENCE_S)
        if not self.result_path.exists():
            raise AssertionError(self._diagnose(
                f"the child wrote no result and exited {code}"))
        payload = json.loads(self.result_path.read_text(encoding="utf-8"))
        if code != (0 if payload.get("ok") else 1):
            raise AssertionError(self._diagnose(
                f"the child reported {payload!r}"))
        return payload

    def _diagnose(self, message: str) -> str:
        """A child's stderr is where its traceback is, and without it a failure
        here is just a number."""
        out, err = self.process.communicate()
        return (f"{message}\n--- stdout ---\n{out.decode('utf-8', 'replace')}"
                f"\n--- stderr ---\n{err.decode('utf-8', 'replace')}")


class ProcessHarness(unittest.TestCase):
    """Temporary history file, spawned children, and the schedule helpers."""

    def setUp(self) -> None:
        # `ignore_cleanup_errors=True`, AND HERE IS WHY IT IS NOT "HIDING A
        # FAILURE".
        #
        # This suite spawns real subprocesses, and several are killed on purpose
        # -- a holder that wedges the lock is supposed to die without cleaning
        # up. If an assertion fails BEFORE the kill, the child is still alive
        # with `history.json.lock` open, and `shutil.rmtree` (which walks the
        # tree) raises PermissionError on it during cleanup.
        #
        # That exception comes from the CLEANUP, so it REPLACES the real
        # failure. For a long time the only visible error was
        #
        #     PermissionError: [WinError 32] ... history.json.lock
        #
        # which is what the suite reported, and what I twice misattributed to a
        # regression in unrelated code. The actual failing assertion was never
        # printed at all.
        #
        # A leaked temp dir is recoverable and the OS clears it; losing the real
        # failure is not. So cleanup stops competing with the assertion. A
        # genuine cleanup problem stays visible by the file still being there.
        self._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        self.path = self.root / "history.json"
        self.signals = self.root / "signals"
        self.children: list[_Child] = []
        # Added AFTER the directory cleanup, so it runs BEFORE it: a child still
        # holding the history open makes `TemporaryDirectory` fail on Windows.
        self.addCleanup(self._reap)

    # -- children ---------------------------------------------------------
    def spawn(self, name: str, mode: str, **config) -> _Child:
        payload = {
            "mode": mode, "tag": name, "signals": str(self.signals),
            "gate": str(self.root / f"gate-{name}"),
            "result": str(self.root / f"result-{name}.json"),
            "history": str(self.path), "wait_s": WAIT_S, **config,
        }
        self.signals.mkdir(parents=True, exist_ok=True)
        config_path = self.root / f"config-{name}.json"
        config_path.write_text(json.dumps(payload), encoding="utf-8")
        # PYTHONPATH, NOT a `sys.path` insert in the child: two tests in
        # `tests/test_engine.py` fail any test file that touches `sys.path`,
        # and the exemption list they use is guarded against growing. The child
        # script says so too. Scoped to this one process either way.
        environment = dict(os.environ, PYTHONIOENCODING="utf-8",
                           PYTHONPATH=os.pathsep.join(
                               [str(REPO_ROOT),
                                *filter(None, [os.environ.get("PYTHONPATH")])]))
        process = subprocess.Popen(
            [sys.executable, str(WORKER), str(config_path)],
            cwd=str(REPO_ROOT), env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child = _Child(process, payload, self.signals)
        self.children.append(child)
        # WAIT FOR WARM, so the schedule never spends its window paying for an
        # interpreter start and an import.
        self.await_signal(f"warm-{name}")
        return child

    def await_signal(self, name: str) -> Path:
        marker = self.signals / name
        deadline = time.monotonic() + PATIENCE_S
        while not marker.exists():
            if time.monotonic() > deadline:
                self.fail(f"the child never wrote {marker.name}. "
                          f"signals present: "
                          f"{sorted(p.name for p in self.signals.glob('*'))}")
            time.sleep(0.001)
        return marker

    def _reap(self) -> None:
        for child in self.children:
            if child.process.poll() is None:
                child.process.kill()
                try:
                    child.process.wait(timeout=PATIENCE_S)
                except subprocess.TimeoutExpired:
                    pass

    # -- the history file -------------------------------------------------
    def seed(self, count: int, legacy: bool = False) -> list[str]:
        """Write `count` entries, as JSONL or as the old single-document array.

        `legacy=True` matters because the legacy upgrade is a SECOND rewrite
        path inside `append`, reached by a completely different condition, and
        a test that only arranges the cap-forced trim would leave it unchecked.
        """
        ids = [f"seed-{number}" for number in range(count)]
        entries = [self.entry(rule_id) for rule_id in ids]
        if legacy:
            self.path.write_text(json.dumps(entries, ensure_ascii=False),
                                 encoding="utf-8")
        else:
            self.path.write_text(
                "".join(json.dumps(one, ensure_ascii=False) + "\n"
                        for one in entries), encoding="utf-8")
        return ids

    @staticmethod
    def entry(rule_id: str) -> dict:
        return {"kind": "author", "dialect": "splunk", "rule_id": rule_id,
                "title": "t", "summary": "s", "payload": {"i": rule_id},
                "created_at": "2026-01-01T00:00:00+00:00"}

    def ids(self) -> list[str]:
        return [one["rule_id"] for one in history.load(self.path)]


class AConcurrentSaveIsNotUnlinked(ProcessHarness):
    """The reproducing test, on both rewrite paths."""

    def test_a_save_is_not_unlinked_by_a_cap_forced_rewrite(self):
        """The cap-forced trim, which is the path the reviewer reproduced."""
        self._one_race(legacy=False)

    def test_a_save_is_not_unlinked_by_a_legacy_upgrade(self):
        """The SAME loss through the OTHER rewrite path.

        Not a duplicate for tidiness: the legacy upgrade is reached by a
        different condition inside `append`, from a file whose shape the trim
        can never produce, and it is the path an analyst upgrading an old
        history actually takes. A test that only arranged the trim would leave
        it unchecked.
        """
        self._one_race(legacy=True)

    def _one_race(self, legacy: bool) -> None:
        cap = history.MAX_ENTRIES
        # `cap` for the trim and `cap - 1` for the legacy array, and the
        # DIFFERENCE IS THE WHOLE POINT OF HAVING TWO TESTS. Seeding the legacy
        # array with `cap` made the save exceed the cap, so `trim` was true and
        # the rewrite was forced by the CAP -- the two tests were the same test
        # twice and the legacy branch was never the deciding condition. Proof
        # that they were duplicates: changing `if not trim and
        # not _is_legacy_array(path):` to `if not trim:` left both passing. At
        # `cap - 1` the save lands exactly on the cap, so nothing trims and the
        # ONLY thing that can send this save down the rewrite path is the legacy
        # array -- the condition an analyst upgrading an old history actually
        # takes.
        seeded = cap - 1 if legacy else cap
        seeds = self.seed(seeded, legacy=legacy)
        # Both children are given the cap, so the cap cannot be the reason the
        # two of them disagree about how many entries the file has.
        common = {"max_entries": cap}
        rewriter = self.spawn("rewriter", "in-window", rule_id="REWRITER",
                              **common)
        appender = self.spawn("appender", "land-after-write",
                              rule_id="APPENDER", **common)

        rewriter.release()
        # The rewrite window is open: the rewriter has read the file and has not
        # renamed yet. Only now is the other process released, so its entry is
        # guaranteed to land AFTER the read the rewrite was built from -- which
        # is the only position from which the rename can destroy it.
        self.await_signal("in_window")
        appender.release()

        rewrote = rewriter.result()
        appended = appender.result()
        self.assertTrue(rewrote["ok"], f"the rewriter refused: {rewrote}")
        self.assertTrue(appended["ok"], f"the appender refused: {appended}")

        # 1. THE MECHANISM. `saw_landed` is the harness reporting that the other
        #    process's entry reached the file while the rename was pending. The
        #    lock exists to make that impossible, so this is the assertion that
        #    fails first on the unfixed module, and it fails for a reason that
        #    has nothing to do with what the file ends up containing.
        self.assertFalse(
            rewrote.get("saw_landed"),
            "the other process got its entry onto the file between the "
            "rewrite's read and its rename, which is the data loss")
        self.assertTrue(appended.get("landed"),
                        "the appender never reported landing; the schedule did "
                        "not happen, so this run proves nothing")

        # 2. THE INVARIANT. The appender was told the entry was saved. It is
        #    saved. Nothing is asserted about which entry the cap dropped --
        #    dropping the oldest is the cap's whole job -- only that the
        #    surviving file is exactly the newest `cap` of everything written.
        survivors = self.ids()
        self.assertIn(
            "APPENDER", survivors,
            "an entry that was reported as saved is not in the history")
        self.assertIn("REWRITER", survivors)
        # `cap` seeds means the rewriter's own save exceeds the cap and drops
        # one, then the appender's save exceeds it again and drops one more.
        # `cap - 1` seeds means the rewriter is exactly ON the cap and drops
        # nothing, so only the appender's save trims and drops one.
        expected = seeds[2:] if not legacy else seeds[1:]
        self.assertEqual(survivors, expected + ["REWRITER", "APPENDER"],
                         f"the history is not the newest {cap} of what was "
                         f"written")


class NothingIsLostWithoutAForcedWindow(ProcessHarness):
    """No schedule, no seams: just processes saving at once.

    THIS IS A GUARD AND NOT A REPRODUCER, and the distinction is the point of
    having it. It cannot fail reliably against the unfixed module, because
    nothing here arranges the interleaving; what it does catch is the class of
    damage that concurrency causes on its own -- two Windows processes each
    seek-to-end and write, and the bytes can end up interleaved into a line no
    reader can parse. A history that will not load is not a small problem.
    """

    def test_every_save_reported_under_the_cap_is_still_there_afterwards(self):
        workers, each = 4, 15
        self.spawn_group(workers, each, max_entries=10_000)
        written = [f"w{number}-{index}" for number in range(workers)
                   for index in range(each)]
        for child in self.children:
            self.assertTrue(child.result()["ok"], "a worker refused to save")
        survivors = self.ids()
        self.assertEqual(sorted(survivors), sorted(written),
                         "an entry reported as saved is not in the history")

    def test_the_cap_is_exact_and_the_file_still_parses_under_concurrent_rewrites(self):
        cap = 20
        seeds = self.seed(cap)
        self.spawn_group(4, 12, max_entries=cap)
        self.written = set(seeds) | {f"w{number}-{index}"
                                     for number in range(4)
                                     for index in range(12)}
        for child in self.children:
            self.assertTrue(child.result()["ok"], "a worker refused to save")
        survivors = self.ids()
        # The cap LEGITIMATELY drops here -- 48 appends into a cap of 20 -- so
        # survival is not the assertion. The assertions are that the cap was
        # enforced to the entry, that nothing that was written is present that
        # was not, and above all that the file still parses: concurrent
        # rewriting is where a torn line would show up.
        self.assertEqual(len(survivors), cap,
                         f"the cap is {cap} and the file holds {len(survivors)}")
        self.assertEqual(len(set(survivors)), cap, "the same entry twice")
        self.assertTrue(set(survivors) <= self.written, "the history holds an "
                        "entry that was never written")
        # AND NOTHING MORE ABOUT SURVIVAL, which took a wrong turn and is worth
        # recording. An earlier version of this test asserted that every
        # worker's LAST append survived, on the argument that at most three
        # appends could follow it. That is false: the workers are not
        # synchronised, so one worker's last append can be followed by all 36 of
        # the others' and be evicted by a cap of 20 quite legitimately. It
        # failed on the first run, and the file it produced said why:
        # `w0-11` gone while `w0-5` remained, and the cap full of w1/w2/w3.
        # Arrival order across processes is not knowable from here, so no
        # survival claim about WHICH entries should remain can be made by this
        # test, and the ones that can be made are in the two tests above: with
        # no cap pressure every one of the 60 reported saves is present, and
        # `tests/test_history_jsonl.py::EntryCapTests` pins which entries a
        # trim drops when there is one writer.
        self.assertTrue(set(self.written) - set(survivors),
                        "nothing was dropped, so this run never exercised the "
                        "cap")

    def spawn_group(self, workers: int, each: int, **config) -> None:
        # A LONG LOCK TIMEOUT for the group, and the reason is narrow: this test
        # is about lost entries, not about contention, and a refusal is a
        # documented outcome rather than a bug. On a slow enough machine 60
        # fsynced appends could outlast the default wait and one worker would
        # legitimately refuse, which would fail the test for a reason that has
        # nothing to do with what it measures. `test_a_wedged_writer_...` is
        # where the refusal behaviour is pinned.
        config.setdefault("lock_timeout", 60.0)
        children = [self.spawn(f"w{number}", "hammer", rule_id=f"w{number}",
                               count=each, **config)
                    for number in range(workers)]
        for child in children:
            child.release()
        self.children.extend(children)


class TheLockRefusesRatherThanLoses(ProcessHarness):
    """A second copy that wedges the file must cost a save, not an entry."""

    def test_a_wedged_writer_makes_the_save_refuse_instead_of_hang(self):
        self.seed(3)
        before = self.path.read_bytes()
        # The holder is still ALIVE and still holding: it is killed in cleanup,
        # which is what releases the lock. A dead holder would release it and
        # the save would simply succeed, which is the other test.
        holder = self.spawn("holder", "hold-lock", hold_s=PATIENCE_S)
        self.assertIsNone(holder.process.poll(),
                          "the holder exited, so it cannot wedge anything")
        self.await_signal("holding")

        original = history.LOCK_TIMEOUT_S
        history.LOCK_TIMEOUT_S = 0.25
        self.addCleanup(setattr, history, "LOCK_TIMEOUT_S", original)
        started = time.monotonic()
        with self.assertRaises(history.Refused) as caught:
            history.append(self.path, "author", "splunk", "r9", "t", "s", {})
        elapsed = time.monotonic() - started

        message = str(caught.exception)
        self.assertIn("another copy of RuleForge", message)
        self.assertIn("has NOT been saved", message)
        # It waited, but it did not hang, and it did not write.
        self.assertLess(elapsed, 10.0, "the save hung instead of refusing")
        self.assertEqual(self.path.read_bytes(), before,
                         "a refused save changed the history")
        self.assertNotIn("r9", self.ids())

    def test_a_dead_lock_holder_does_not_brick_the_history(self):
        """A process killed mid-append leaves a lock file behind and NOTHING
        else, because the operating system released the lock with its handles.

        A marker-file lock would fail this test, and that is why there is not
        one: the marker has to be deleted by the process that made it, and a
        process that was killed does not get to delete anything. The failure
        mode is not a slow save, it is a history that can never be written
        again.
        """
        self.seed(2)
        holder = self.spawn("holder", "hold-lock-then-die", exit_code=9)
        self.await_signal("holding")
        self.assertEqual(holder.process.wait(timeout=PATIENCE_S), 9,
                         "the holder was supposed to exit without cleaning up")
        self.assertTrue(history._lock_path(self.path).exists(),
                        "the lock file is left behind on purpose")
        history.append(self.path, "author", "splunk", "r-after-death",
                       "t", "s", {})
        self.assertIn("r-after-death", self.ids())

    def test_a_read_still_works_while_another_process_holds_the_lock(self):
        """Reads take no lock, and that is deliberate.

        The History tab is a read. If a wedged second copy could block it, the
        page an analyst opens to find out what happened would be the thing that
        hangs. `os.replace` is atomic and a torn tail is tolerated, which is
        what makes an unlocked read safe; the lock is for the writer, and only
        the writer needs it.
        """
        self.seed(4)
        holder = self.spawn("holder", "hold-lock", hold_s=PATIENCE_S)
        self.await_signal("holding")
        started = time.monotonic()
        newest = history.recent(self.path, limit=2)
        self.assertLess(time.monotonic() - started, 10.0)
        self.assertEqual([one["rule_id"] for one in newest], ["seed-3", "seed-2"])
        holder.process.kill()

    def test_the_lock_is_a_sidecar_and_not_the_history(self):
        """A lock taken on the history file itself would be a lock on an inode
        the trim path REPLACES, and the next appender would open the new inode
        and exclude nobody. The test states the design in one line so that
        changing it has to be a decision."""
        self.assertEqual(history._lock_path(self.path),
                         self.path.with_name(self.path.name + ".lock"))
        self.assertNotEqual(history._lock_path(self.path), self.path)
        self.seed(1)
        history.append(self.path, "author", "splunk", "r1", "t", "s", {})
        self.assertTrue(history._lock_path(self.path).exists())


class TheLockDidNotBreakThreads(ProcessHarness):
    def test_threads_still_append_without_losing_anything(self):
        """The threading lock is not redundant and not a regression risk: it is
        what stops two threads of one process fighting over the file lock. Four
        by ten is enough to interleave, and it is the cheapest test here."""
        self.seed(1)
        errors: list[BaseException] = []

        def worker(number: int) -> None:
            try:
                for index in range(10):
                    history.append(self.path, "author", "splunk",
                                   f"t{number}-{index}", "t", "s", {})
            except BaseException as exc:  # noqa: BLE001 - reported, not raised
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(number,))
                   for number in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=PATIENCE_S)
        self.assertEqual(errors, [])
        self.assertEqual(len(self.ids()), 41)


class RecentRefusesANonPositiveLimit(unittest.TestCase):
    """`entries[-0:]` is `entries[0:]`, so `limit=0` returned EVERYTHING.

    DECIDED: a non-positive limit RAISES `ValueError`, and the tests assert
    that rather than that it happens to be harmless. Clamping to "nothing" was
    rejected because an empty History tab for a full history file makes lost
    data LOOK like no data, which is the one thing this module refuses to do
    anywhere else; clamping to the cap is the bug with a different name. A
    `ValueError` fails where the mistake is, and nothing the analyst types can
    reach it -- `web.py` passes 100.
    """

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "history.json"
        for number in range(4):
            history.append(self.path, "author", "splunk", f"r{number}", "t", "s",
                           {})

    def test_limit_zero_raises_instead_of_returning_everything(self):
        with self.assertRaises(ValueError) as caught:
            history.recent(self.path, limit=0)
        self.assertIn("limit", str(caught.exception))

    def test_a_negative_limit_raises_too(self):
        with self.assertRaises(ValueError):
            history.recent(self.path, limit=-1)

    def test_the_guard_is_above_the_read_not_below_it(self):
        """On a DAMAGED file the two failures are distinguishable, and the
        limit is the caller's mistake rather than the analyst's file -- so the
        caller's mistake is what is reported. `Refused` is reserved for the
        file, and this pins which one a caller sees first."""
        damaged = self.path.with_name("damaged.json")
        damaged.write_text("{not json", encoding="utf-8")
        with self.assertRaises(ValueError):
            history.recent(damaged, limit=0)
        with self.assertRaises(history.Refused):
            history.recent(damaged, limit=10)

    def test_the_ordinary_limits_still_behave(self):
        self.assertEqual([one["rule_id"] for one in history.recent(self.path)],
                         ["r3", "r2", "r1", "r0"])
        self.assertEqual([one["rule_id"] for one in
                          history.recent(self.path, limit=1)], ["r3"])
        self.assertEqual(len(history.recent(self.path, limit=100)), 4,
                         "a limit over the size of the history returns all of "
                         "it, which is what the slice means and is not a clamp")


class ACompleteLastLineIsNotATornLine(ProcessHarness):
    """A missing trailing newline is not a torn write, and the difference is a
    whole entry.

    Found by the security review while reviewing the cross-process lock, and it
    is the SAME failure this work was about: an entry that was saved, was
    reported saved, and was then deleted by a later save that reported
    `dropped = 0`. Executed against the code before the fix:

        file: one complete entry, no trailing newline
        load  -> ['SAVED-BY-HAND']     the entry is there
        append returned ok, dropped = 0
        load  -> ['NEW']               the entry is gone

    `_truncate_torn_tail` assumed "no newline at the end" meant "the last write
    was interrupted", which is true of `_append_line` and false of a HAND EDIT,
    a `json.dump` and Notepad -- and this module explicitly invites the analyst
    to edit the file. On a one-entry file the truncation took the keep position
    to 0 and the entire history was replaced by the entry being saved.

    Both halves matter and neither is obvious, so both are pinned: the entry
    survives, and the bytes that survive are still readable afterwards. A fix
    that preserved the entry by rewriting the file would pass the first and fail
    the second, which is the difference between appending a newline and doing
    something much more expensive.
    """

    def test_a_hand_edited_entry_without_a_trailing_newline_survives_a_save(self):
        hand_edited = json.dumps(self.entry("SAVED-BY-HAND"), ensure_ascii=False)
        self.path.write_text(hand_edited, encoding="utf-8")   # no "\n"
        # THE PRECONDITION, asserted rather than assumed, because every
        # assertion below is about what happens to a file in this exact shape
        # and a setup that quietly drifted would make them all pass for free.
        self.assertFalse(self.path.read_bytes().endswith(b"\n"),
                         "the setup did not produce a file without a newline")
        self.assertEqual([one["rule_id"] for one in history.recent(self.path)],
                         ["SAVED-BY-HAND"],
                         "the setup did not produce a readable one-entry file")

        result = history.append(self.path, "author", "splunk", "NEW", "t", "s", {})

        self.assertEqual(result.dropped, 0, "the cap dropped nothing and says so")
        self.assertEqual([one["rule_id"] for one in history.load(self.path)],
                         ["SAVED-BY-HAND", "NEW"],
                         "a complete entry was deleted by a save that reported "
                         "success")
        # STILL A READABLE JSONL FILE, and the entry is not merely present but
        # intact: the repair terminates the line, it does not rewrite the file.
        raw = self.path.read_text(encoding="utf-8")
        self.assertTrue(raw.endswith("\n"), "the last line was left unterminated")
        self.assertIn(hand_edited, raw,
                      "the hand-edited bytes were rewritten rather than "
                      "terminated in place")
        self.assertEqual(len(raw.splitlines()), 2)

    def test_a_one_entry_file_is_not_emptied_by_a_save(self):
        """The worst shape of the same bug, and the one that loses everything:
        there is no previous newline, so a truncating repair takes the file to
        zero bytes and leaves the single entry the analyst had."""
        self.path.write_text(json.dumps(self.entry("ONLY-ENTRY"),
                                        ensure_ascii=False), encoding="utf-8")
        history.append(self.path, "author", "splunk", "SECOND", "t", "s", {})
        self.assertEqual([one["rule_id"] for one in history.load(self.path)],
                         ["ONLY-ENTRY", "SECOND"])

    def test_a_byte_order_mark_on_a_one_entry_file_is_not_a_torn_line(self):
        """PowerShell's `Set-Content -Encoding UTF8` and Notepad both write a BOM,
        which is why `load` reads `utf-8-sig`. The repair has to agree with it: a
        one-entry file with a BOM and no trailing newline is a COMPLETE entry,
        and decoding it as `utf-8` here would have thrown it away -- the same
        loss, arrived at from the other direction."""
        with self.path.open("wb") as stream:
            stream.write(b"\xef\xbb\xbf")
            stream.write(json.dumps(self.entry("BOM-ENTRY"),
                                    ensure_ascii=False).encode("utf-8"))
        history.append(self.path, "author", "splunk", "SECOND", "t", "s", {})
        self.assertEqual([one["rule_id"] for one in history.load(self.path)],
                         ["BOM-ENTRY", "SECOND"])

    def test_a_genuinely_torn_last_line_is_still_repaired(self):
        """The check must not have broken the thing it was added next to. A tail
        that does NOT parse is still discarded, and the entries before it are
        still kept -- that is the case `_truncate_torn_tail` was written for."""
        self.path.write_text(
            json.dumps(self.entry("GOOD-1")) + "\n"
            + json.dumps(self.entry("GOOD-2")) + "\n"
            + '{"kind": "author", "rule_',          # killed mid-write
            encoding="utf-8")
        history.append(self.path, "author", "splunk", "THIRD", "t", "s", {})
        self.assertEqual([one["rule_id"] for one in history.load(self.path)],
                         ["GOOD-1", "GOOD-2", "THIRD"],
                         "a torn tail was not repaired any more")


class AWriterThatDoesNotTakeTheLock(unittest.TestCase):
    """The re-read before the rename, which the lock does not cover.

    THIS EXISTS BECAUSE THE BLOCK WAS COMMENT-ONLY. `history.py` carries a
    fifteen-line comment on the re-read explaining that it is what stands between
    a hand edit and being silently overwritten, and a mutation that deleted the
    whole block -- replaced it with `if False:` -- left every test in the suite
    PASSING. Under this project's own rule, a promise in a comment needs a test
    that executes the case it promises, or it is decoration.

    The writer emulated here is a real one: something that appends to the file
    without taking the lock -- an older copy of RuleForge mid-upgrade, a script,
    a text editor. It is simulated at the seam the re-read exists for, which is
    between the two `load` calls, because that is the only moment the block acts
    and a test that cannot put a file change there cannot test anything.
    """

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        self.path = self.root / "history.json"
        self.cap = 40
        self.addCleanup(setattr, history, "MAX_ENTRIES", history.MAX_ENTRIES)
        history.MAX_ENTRIES = self.cap
        for number in range(self.cap):
            history.append(self.path, "author", "splunk", f"seed-{number}",
                           "t", "s", {})

    @staticmethod
    def _entry(rule_id: str) -> dict:
        return {"kind": "author", "dialect": "splunk", "rule_id": rule_id,
                "title": "t", "summary": "s", "payload": {},
                "created_at": "2026-01-01T00:00:00+00:00"}

    def test_a_change_made_while_this_process_was_deciding_is_not_overwritten(self):
        real_load = history.load
        seen: list[int] = []

        def load_with_an_outsider(path, _reap_torn_tail=False):
            entries = real_load(path, _reap_torn_tail)
            seen.append(len(entries))
            if len(seen) == 2:
                # BETWEEN THE TWO READS: a writer that takes no lock appends a
                # complete line, exactly as a pre-fix RuleForge or `>>` would.
                with path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(self._entry("OUTSIDER")) + "\n")
                return real_load(path, _reap_torn_tail)
            return entries

        with mock.patch.object(history, "load", load_with_an_outsider):
            history.append(self.path, "author", "splunk", "MINE", "t", "s", {})

        self.assertEqual(len(seen), 2,
                         "the re-read did not happen, so this run tested "
                         "nothing about it")
        survivors = [one["rule_id"] for one in real_load(self.path)]
        self.assertIn("OUTSIDER", survivors,
                      "an entry written while this save was deciding was "
                      "overwritten by a stale read")
        self.assertIn("MINE", survivors)
        self.assertEqual(len(survivors), self.cap,
                         "the cap was not enforced on the merged list")

    def test_a_change_that_replaces_an_entry_is_caught_too(self):
        """Compared IN FULL, not by length. A hand edit that rewrites one entry
        in place leaves the count identical, and a length comparison would take
        the stale copy and put it back."""
        real_load = history.load
        seen: list[int] = []
        # THE NEWEST entry, and that choice is the test. The cap drops the
        # OLDEST, so an edit to `seed-0` would be removed by the trim whether or
        # not the merge happened, and the assertion could not tell the two
        # apart. The newest seed survives the trim, so it is present if and only
        # if the content comparison saw the edit.
        victim = f"seed-{self.cap - 1}"

        def load_with_an_edited_entry(path, _reap_torn_tail=False):
            entries = real_load(path, _reap_torn_tail)
            seen.append(len(seen))
            if len(seen) == 1:
                return entries
            # Same number of entries, different content, between the reads.
            lines = path.read_text(encoding="utf-8").splitlines()
            rewritten = [json.dumps(self._entry("EDITED-BY-HAND"))
                         if json.loads(line)["rule_id"] == victim else line
                         for line in lines]
            path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
            return real_load(path, _reap_torn_tail)

        with mock.patch.object(history, "load", load_with_an_edited_entry):
            history.append(self.path, "author", "splunk", "MINE", "t", "s", {})

        survivors = [one["rule_id"] for one in real_load(self.path)]
        self.assertIn("EDITED-BY-HAND", survivors,
                      "a same-length edit was overwritten by the stale read, "
                      "which is what comparing lengths instead of contents "
                      "would have done")


class TheSidecarIsNotAPermanentProblem(unittest.TestCase):
    """The lock file is the one thing the fix adds that can go wrong on its own.

    Two failure modes, both of which would otherwise make the history
    UNWRITABLE rather than merely refused once, which is the outcome the module
    claims it cannot reach.
    """

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        self.path = self.root / "history.json"
        history.append(self.path, "author", "splunk", "r1", "t", "s", {})

    def test_a_lock_file_that_cannot_be_opened_refuses_and_says_why(self):
        """Something that is not a usable lock file -- a DIRECTORY is the case
        that works on every platform and needs no permissions to arrange."""
        sidecar = history._lock_path(self.path)
        # The setUp append already created it, and the point of this module is
        # that it is never unlinked -- so it has to be removed deliberately here
        # before a DIRECTORY can take its place.
        sidecar.unlink()
        sidecar.mkdir()
        with self.assertRaises(history.Refused) as caught:
            history.append(self.path, "author", "splunk", "r2", "t", "s", {})
        message = str(caught.exception)
        self.assertIn("lock file", message)
        self.assertIn("has not saved this entry", message)
        # And the refusal cost the history nothing.
        self.assertEqual([one["rule_id"] for one in history.load(self.path)],
                         ["r1"])

    def test_a_permission_error_on_the_lock_file_is_repaired_and_retried(self):
        """The RECOVERY BRANCH, on every platform.

        The test above proves the repair against a real `0444` sidecar, and it
        can only run on POSIX -- on Windows `os.chmod` has one bit and cannot
        make a file unwritable, so that half of the repair is unexecuted here and
        would stay unexecuted in this repository's Windows runs. This one drives
        the same branch by making the FIRST `os.open` fail the way a narrowed
        file does, which is the branch under test rather than the permission
        enforcement that produces it. Without it, the retry is a comment.
        """
        real_open = os.open
        attempts: list[str] = []
        sidecar = history._lock_path(self.path)

        def open_that_fails_once(path, flags, mode=0o777):
            attempts.append(str(path))
            if Path(path) == sidecar and len(attempts) == 1:
                raise PermissionError(13, "simulated narrowed sidecar")
            return real_open(path, flags, mode)

        with mock.patch.object(history.os, "open", open_that_fails_once):
            history.append(self.path, "author", "splunk", "r2", "t", "s", {})

        self.assertGreaterEqual(len(attempts), 2,
                                "the lock file was never opened twice, so the "
                                "retry did not happen")
        self.assertIn("r2", [one["rule_id"] for one in history.load(self.path)],
                      "the save did not recover from a sidecar it could not open")

    @unittest.skipIf(os.name == "nt",
                     "POSIX permission bits; on Windows os.chmod has one bit and "
                     "grants nothing, which the module states explicitly")
    def test_a_lock_file_whose_permissions_were_narrowed_repairs_itself(self):
        """A sidecar restored at 0444 from a backup, or caught by `chmod -R
        a-w data/`, cannot be opened for writing -- and without a repair every
        save from then on refuses forever, which is the one way this change
        could have made the history permanently unwritable without a crash."""
        sidecar = history._lock_path(self.path)
        self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600)
        sidecar.chmod(0o444)
        with self.assertRaises(OSError):
            os.open(str(sidecar), os.O_RDWR | os.O_CREAT, 0o600)
        history.append(self.path, "author", "splunk", "r2", "t", "s", {})
        self.assertIn("r2", [one["rule_id"] for one in history.load(self.path)])
        self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600,
                         "the sidecar was not narrowed back to 0600")


def _open_handle_count() -> int:
    """How many handles this process has open, for the leak test below."""
    if os.name == "nt":
        import ctypes
        count = ctypes.c_ulong()
        ctypes.windll.kernel32.GetProcessHandleCount(
            ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(count))
        return count.value
    return len(os.listdir("/proc/self/fd"))


class AppendsDoNotLeakHandles(unittest.TestCase):
    """The fix opens a file on EVERY append, which is a new way to leak.

    Deleting the `os.close` in `_exclusive` leaks one handle per save, and every
    other test in this file stays green -- the handle is closed by the garbage
    collector eventually, or by the process exiting, and nothing was counting.
    On a long-running local tool that is a slow exhaustion rather than a crash,
    which is the hardest kind to notice. 250 appends is far more handles than the
    default limit on either platform, so a leak cannot hide inside the noise.
    """

    def test_two_hundred_and_fifty_appends_leak_no_handles(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "history.json"
            for number in range(5):  # warm: first calls allocate things too
                history.append(path, "author", "splunk", f"w{number}", "t",
                               "s", {})
            before = _open_handle_count()
            for number in range(250):
                history.append(path, "author", "splunk", f"r{number}", "t", "s",
                               {})
            after = _open_handle_count()
        self.assertLessEqual(after - before, 2,
                             f"the handle count went from {before} to {after} "
                             f"over 250 appends, which is a leak of about one "
                             f"handle per save")


class TheParentDirectoryIsMadeDurableToo(unittest.TestCase):
    """`fsync` on a file flushes the file. It does not flush the DIRECTORY.

    A crash between the bytes reaching the disk and the directory entry
    reaching it can lose the NAME of a file whose data was already fsynced --
    and on the very first append that file is the entire history, so the entry
    the analyst was told was saved is not in anything. Chosen: fsync the parent
    directory on POSIX, and NOT on Windows, where there is no standard-library
    way to ask and NTFS journals the metadata instead. The test says which of
    the two platforms it is on rather than asserting the guarantee everywhere.
    """

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)
        self.path = self.root / "history.json"
        self.real_fsync = os.fsync
        self.directory_syncs: list[Path] = []
        patcher = mock.patch.object(history.os, "fsync", self._record)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _record(self, handle: int) -> None:
        # The REAL fsync still happens: the point is to watch the module's
        # durability, not to remove it for the duration of the test.
        self.real_fsync(handle)
        if stat.S_ISDIR(os.fstat(handle).st_mode):
            # The COUNT is the assertion, not the name of the directory. Which
            # directory it is follows from the only two call sites, both of
            # which pass `path.parent`.
            self.directory_syncs.append(self.path.parent)

    def append_one(self, rule_id: str) -> None:
        history.append(self.path, "author", "splunk", rule_id, "t", "s", {})

    @unittest.skipIf(os.name == "nt", "no POSIX directory fsync is attempted "
                                       "on Windows, and the test below asserts "
                                       "that it is not")
    def test_creating_the_history_fsyncs_the_directory_that_holds_it(self):
        self.append_one("r1")
        self.assertEqual(len(self.directory_syncs), 1,
                         "the first append created the name and did not make "
                         "it durable")
        self.directory_syncs.clear()
        self.append_one("r2")
        self.assertEqual(self.directory_syncs, [],
                         "an append that does not change the name must not "
                         "pay for a directory fsync")
        self.directory_syncs.clear()
        original = history.MAX_ENTRIES
        history.MAX_ENTRIES = 1
        self.addCleanup(setattr, history, "MAX_ENTRIES", original)
        self.append_one("r3")
        self.assertEqual(len(self.directory_syncs), 1,
                         "the trim path renames a new inode into the name, "
                         "which is a change to the directory")

    @unittest.skipIf(os.name != "nt", "the POSIX branch is not this platform")
    def test_windows_does_not_pretend_to_do_it(self):
        self.append_one("r1")
        self.assertEqual(self.directory_syncs, [],
                         "Windows must not claim a directory fsync it did "
                         "not perform")
        self.assertIsNone(history._fsync_directory(self.root))
        self.assertIsNone(history._fsync_directory(self.root / "not-there"),
                          "a directory that cannot be opened must not raise")
        # And the entry is still durable in the way this platform can manage:
        # the data itself is fsynced, which the POSIX test above also covers.
        self.assertIn("r1", [one["rule_id"] for one in history.load(self.path)])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()