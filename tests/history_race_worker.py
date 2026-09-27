"""A real, separate OS process, for the history race tests.

EXISTS BECAUSE A THREAD CANNOT REPRODUCE THE BUG THIS FILE IS ABOUT. The loss
was a rewrite unlinking an entry another PROCESS had already been told was
saved, and the `threading.Lock` in the process under test makes exactly that
interleaving impossible -- every arrangement of threads would pass against the
broken code. So the harness in `test_round8_history_race.py` runs this file as
`sys.executable history_race_worker.py <config.json>`, which is the only kind
of test that can fail.

THE SEAMS ARE THE POINT, and they live here rather than in the module under
test. `history` is given no test hook, because a hook is a promise that the
code is being observed rather than run; instead the two moments the race
depends on are wrapped HERE, in the child, after import:

  - `os.replace`  the rewrite's atomic-and-therefore-destructive moment
  - `_append_line` the ordinary append that must not be destroyed

BOTH SEAMS ARE WRAPPED WHERE BOTH ARE REACHABLE, and getting that wrong makes
the test vacuous rather than failing: a child that only watched `_append_line`
would report nothing at all once the entry cap pushed it onto the rewrite path,
and the test would pass against the broken code while testing nothing. So
"land-after-write" patches both and reports whichever fires.

WHAT THE TESTS ASSERT ABOUT THEM, in `test_round8_history_race.py`:

  - a child in `in-window` PAUSES between its own read and its own rename, and
    will only rename once it has seen proof that the other process's entry is
    on the file, so the destruction is ARRANGED rather than raced for
  - that proof appearing at all is a run of the BROKEN code. A run that never
    sees it is a run in which the other process could not get into the window,
    which is the fix. The test asserts the second, so it fails on the first.

Every mode records a JSON result file. Nothing here asserts anything; the test
does, because a child that asserted would report its failure through an exit
code nobody is reading.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# NOT `sys.path.insert`, and the reason is worth keeping: this repo has two
# tests that fail any test file which touches `sys.path`
# (`tests/test_engine.py::StandaloneTests::test_nothing_widens_the_import_path`
# and `::test_the_tests_themselves_do_not_reach_into_the_parent`), because six
# test files once did the insert and put the whole PARENT tree on the import
# path for the entire suite -- which is how a standalone tool stops being
# standalone with no import statement ever changing. There is an exemption list
# for the two files that legitimately need it, and
# `test_the_two_exempt_files_are_actually_guarded` exists so the list cannot
# quietly grow. So the parent puts the repository root on this child's
# PYTHONPATH instead, which is scoped to this one process and is the mechanism
# the environment provides for exactly this. Do not "fix" that by inserting.

import history  # noqa: E402  (the path is the environment's job, not this file's)


def _touch(path: Path, payload: str = "") -> None:
    path.write_text(payload, encoding="utf-8")


def _wait_for(path: Path, seconds: float) -> bool:
    """True when `path` appeared inside the window. One millisecond of polling,
    because a race harness that samples every five milliseconds is a race
    harness that misses things."""
    deadline = time.monotonic() + seconds
    while True:
        if path.exists():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.001)


def _patch_in_window(result: dict, signals: Path, wait_s: float) -> None:
    """Pause the rewrite between its read and its rename, and only rename once
    the other process's entry is provably on the file.

    The real `os.replace` is called LAST, so the file on disk when the test
    looks at it is the file the rename actually produced. Nothing about the
    rename's own behaviour is changed -- only when it happens.
    """
    real_replace = os.replace

    def replace(source, target):
        _touch(signals / "in_window",
               "the window between the read and the rename is open")
        result["in_window"] = True
        # The whole test turns on this line. `saw_landed` True means another
        # process got its entry onto the file inside the window, which is the
        # bug; False means the lock stopped it getting in there.
        result["saw_landed"] = _wait_for(signals / "landed", wait_s)
        real_replace(source, target)
        _touch(signals / "replaced", "the rename is done")
        result["replaced"] = True

    os.replace = replace


def _patch_land_after_write(result: dict, signals: Path, wait_s: float) -> None:
    """Report that this process's entry is ON DISK, and then stay inside
    `append` until the other process has finished renaming.

    Both write paths are covered, because which one this process takes depends
    on the cap and on the file's shape, and a seam that only fires on one of
    them turns the test into a test that passes without testing anything.
    """
    real_replace = os.replace
    real_append_line = history._append_line
    state = {"reported": False}

    def landed(rule_id: str) -> None:
        if state["reported"]:
            return
        state["reported"] = True
        _touch(signals / "landed", rule_id)
        result["landed"] = True
        # Returning only after the other process has renamed is the point
        # rather than a detail: this process is about to be told the entry was
        # saved, and the test needs "told saved" and "still there" to be two
        # separate questions instead of the same instant.
        result["saw_replaced"] = _wait_for(signals / "replaced", wait_s)

    def replace(source, target):
        real_replace(source, target)
        landed(str(result.get("rule_id", "")))

    def append_line(path, entry):
        real_append_line(path, entry)
        landed(entry.get("rule_id", ""))

    os.replace = replace
    history._append_line = append_line


def _append(config: dict) -> None:
    history.append(
        Path(config["history"]), kind="author", dialect="splunk",
        rule_id=config["rule_id"], title="t", summary="s",
        payload={"i": config["rule_id"]})


def main() -> int:
    config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    signals = Path(config["signals"])
    signals.mkdir(parents=True, exist_ok=True)
    result: dict = {"mode": config["mode"], "rule_id": config.get("rule_id"),
                    "pid": os.getpid()}
    if "max_entries" in config:
        history.MAX_ENTRIES = int(config["max_entries"])
    if "lock_timeout" in config:
        history.LOCK_TIMEOUT_S = float(config["lock_timeout"])
    wait_s = float(config.get("wait_s", 0.5))
    mode = config["mode"]

    try:
        # Warm up: interpreter started, module imported, constants applied. The
        # parent waits for this marker before it opens any window, so a window
        # is never spent paying for a cold start.
        _touch(signals / f"warm-{config['tag']}", str(os.getpid()))

        if mode == "hold-lock-then-die":
            with history._exclusive(Path(config["history"])):
                _touch(signals / "holding", "the cross-process lock is held")
                # Exit WITHOUT unwinding and WITHOUT unlinking the lock file.
                # This is what a killed process leaves behind, and the test
                # asserts the next save still works -- which is the entire
                # reason the lock is an OS lock and not a marker file.
                os._exit(int(config.get("exit_code", 7)))

        if mode == "hold-lock":
            with history._exclusive(Path(config["history"])):
                _touch(signals / "holding", "the cross-process lock is held")
                # Stay alive holding it, so the parent's save has to contend.
                # The gate is never opened; the parent kills this process in
                # cleanup, which releases the lock.
                _wait_for(Path(config["gate"]),
                          float(config.get("hold_s", 120.0)))
            # Return rather than fall through: the gate wait below would run a
            # SECOND time for the full patience period and then report "the gate
            # never opened", which is a misleading way for a holder to die when
            # it was killed on purpose. Both callers kill this process, so this
            # is normally unreachable -- which is exactly why it was wrong.
            return 0

        if not _wait_for(Path(config["gate"]),
                         float(config.get("gate_wait_s", 60.0))):
            result["error"] = f"the gate never opened for {config['tag']!r}"
            _touch(Path(config["result"]), json.dumps(result))
            return 3

        if mode == "hammer":
            saved = 0
            for number in range(int(config["count"])):
                _append({**config, "rule_id": f"{config['rule_id']}-{number}"})
                saved += 1
            result["saved"] = saved
        elif mode == "in-window":
            _patch_in_window(result, signals, wait_s)
            _append(config)
        elif mode == "land-after-write":
            _patch_land_after_write(result, signals, wait_s)
            _append(config)
        else:
            result["error"] = f"unknown mode {mode!r}"
    except history.Refused as exc:
        result["refused"] = str(exc)
    except Exception as exc:  # noqa: BLE001 - the test reads this, not pytest
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["ok"] = "error" not in result and "refused" not in result
    _touch(Path(config["result"]), json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())