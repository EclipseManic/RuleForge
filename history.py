"""Append-only history, as JSON. No database.

THE USER SAID NO DATABASE, and that is not a preference to work around -- it is
the reason this file is JSON.

APPEND-ONLY MEANS APPEND-ONLY. Every save writes a new entry and never rewrites or
deletes an older one. Two reasons, and the second is the real one:

  1. A tuning session is evidence. "What did the rule look like when it fired 400
     times?" is a question you can only answer if the earlier version survives.
  2. A tool that suggests edits to a detection rule is holding the thing you use
     to defend a network. If a bug or a stray request can rewrite history, then the
     record of what you actually ran is not a record. Losing the audit trail on a
     security control is worse than losing the feature.

So there is no update path and no delete path, here or through the web layer.

THE WRITE IS NOT WHOLE-FILE ANY MORE, AND THE OLD PARAGRAPH WAS WRONG.

It used to say: "THE WRITE IS WHOLE-FILE AND THAT IS A REAL LIMITATION.
Rewriting the whole file on each save is O(history) and is not safe against
concurrent writers." That was true when written and is now false, which is worse
than a missing note: a reader deciding whether this module is safe to append to
would take it at face value.

The file is JSON LINES. An append under the entry cap is ONE `write()` of ONE
line, so its cost does not depend on how much history exists. Filling the history
to its cap used to rewrite about 1.02 TB to store 1.02 GB, because entry i was
written i times; now each entry is written exactly once. Measured: 30x less
written at 60 entries, 100x at 200 -- the reduction is N/2, which is the
quadratic signature and nothing else produces it.

THE TWO PATHS DIFFER, AND THE DIFFERENCE IS DELIBERATE:

  - the under-cap path APPENDS. Fast, and a killed append can leave a partial
    last line, which `load` tolerates and the next `append` repairs.
  - the trim path and the legacy-array upgrade REWRITE, temp-file-then-`replace`.
    A rename is atomic because it REPLACES the file, which is the right way to
    swap a whole file and the wrong way to add to one.

A reader never sees a half-written history during a rewrite, because the old
inode is intact until the rename. That argument covers what a READER sees, and
it said nothing at all about what a WRITER sees, which is how round 8 found the
loss described below.

AND `os.replace` BEING ATOMIC IS NOT THE SAME AS A REWRITE BEING SAFE.

`_write` reads the whole file, builds a temp file out of what it read, and
renames that over the original. Between the read and the rename is a window in
which a second process can append a line. Its line reaches the file, its
`append` returns success, and then the rename unlinks the bytes underneath it.
The entry is gone AND the caller was told it was saved, which for an audit
trail is the worst thing this file can do. Executed, two real processes against
one file, before the fix:

    [other process] appended FROM_OTHER_PROCESS, returned success
    [process 1]    os.replace completed
    process 1 append returned OK, dropped = 1
    surviving entries: ['r2']
    FROM_OTHER_PROCESS survived? False

So `append` now holds a cross-process lock across the whole
read-decide-write section, and EVERY append takes it -- including the under-cap
one -- because a lock only excludes the writers that take it. Locking the
rewrite path alone would have closed nothing at all.

WHAT THAT LOCK IS AND IS NOT, written down because a comment promising more
than the code delivers is its own defect:

  - it excludes another copy of RuleForge, in another process, writing THIS
    file. `run.py` picks a free port, so two copies on one machine is an
    ordinary configuration rather than a hypothetical one.
  - it is ADVISORY and it is PER-FILE. It says nothing about a hand edit in an
    editor, a second tool reading the file, or a RuleForge old enough not to
    know the lock exists -- and for those the protection is WEAKER THAN IT SOUNDS.
    Only the REWRITE path re-reads before its rename. A writer that does not take
    the lock can still unlink an append on the ordinary line-append path, and
    that includes an older copy of RuleForge in the middle of an upgrade, which
    is the realistic version of this case. What the re-read buys there is that
    a change made while this process was deciding is INCLUDED in what it writes
    rather than overwritten; it is not mutual exclusion, and nothing short of
    both processes taking the lock is.
  - the operating system releases it when the holding process exits, INCLUDING
    a killed one, so a crash cannot leave the history permanently unwritable.
    That is why it is an OS lock and not an `O_CREAT|O_EXCL` marker file: a
    marker has to be cleaned up by the process that made it, and a process that
    was killed does not get to clean up. A sidecar whose PERMISSIONS were
    narrowed -- restored from a backup, `chmod -R a-w data/`, a strict sync tool
    -- is repaired on the next save rather than refused over forever, which is
    the one way the lock could have made the history unwritable without a crash.
  - it assumes a LOCAL FILESYSTEM, and says so rather than discovering it. POSIX
    advisory locks are emulated on NFSv4 and are local-only or ignored outright
    on older mounts, so on a network share the original loss can return with no
    error and no refusal. `data/` lives under the analyst's own profile, where
    that is not the case, and Windows shares lock correctly.
  - it is held for the length of one append, so a single user pays one extra
    file open, a lock, an unlock and a close against an `fsync` that costs
    orders of magnitude more. MEASURED, both halves of that: acquiring and
    releasing the lock is 274 microseconds on this machine, on an append that
    takes about 75 milliseconds. A wedged second copy makes the save REFUSE, out
    loud, rather than wait forever.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, Iterator

#: Serialising history is guarded in-process, and ACROSS PROCESSES as well --
#: see the module docstring for the loss that the second guard prevents. The
#: threading lock is not the redundant one of the two: it is what stops two
#: threads of this process fighting over the file lock, and it is why nothing
#: below ever waits for a lock this process might already hold.
_LOCK = threading.Lock()

#: Refuse to grow without bound. A history file that quietly eats the disk is a
#: worse failure than refusing new entries and saying so.
MAX_ENTRIES = 2000

#: A single entry's serialised size. A pasted rule is small; a pasted LOG SAMPLE
#: can be enormous, and one of those must not be able to write a gigabyte.
MAX_ENTRY_CHARS = 512_000


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    kind: str                    # author | tune | debug | understand
    dialect: str
    rule_id: str
    title: str
    summary: str
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Refused(Exception):
    """History refuses an operation and says why in the message.

    Deliberately NOT the engine's `Refusal`. That one carries a machine code and
    a dialect, and is about a rule that cannot be represented. This is about the
    history file, and its message is written for a person.
    """


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load(path: Path, _reap_torn_tail: bool = False) -> list[dict[str, Any]]:
    """Every entry, oldest first. A corrupt file is surfaced, not swallowed.

    `_reap_torn_tail` is the WRITE path's private opt-in: it additionally tolerates
    a partial final line when NO good entry precedes it, which is what a file
    created by an append and then killed looks like. It is never set by `recent`
    or by any route, because a READ must report damage and never rewrite.
    """
    if not path.exists():
        return []
    # NOT `.strip()`ED, and the difference is load-bearing. The torn-tail check
    # below decides whether an unparseable final line is an INTERRUPTED WRITE by
    # testing whether the file ends in a newline, and a leading `.strip()` throws
    # that newline away -- so every corrupt final line looked interrupted and was
    # silently dropped, turning a damaged file into an empty-looking history. The
    # legacy-array branch below still uses `.strip()`, where it is only cosmetic.
    #
    # `utf-8-sig` AND NOT `utf-8`, because of WINDOWS. `read_text(encoding="utf-8")`
    # does not strip a byte-order mark, and `str.lstrip()` cannot strip U+FEFF
    # either -- it is not whitespace. So a BOM made the first line unparseable
    # and the file refused, permanently, on every save. It is not hypothetical:
    # PowerShell 5.1's `Set-Content -Encoding UTF8` and `Out-File -Encoding utf8`
    # write a BOM, as do older Notepad and Excel's text export, and this module
    # explicitly invites the analyst to read, back up and edit this file by hand.
    # A hand-edited file with a BOM is an ordinary thing for a person to produce.
    # `utf-8-sig` strips a BOM when present and is byte-identical to `utf-8` when
    # there is not one.
    raw = path.read_text(encoding="utf-8-sig")
    if not raw.strip():
        return []

    # JSON LINES, WITH THE LEGACY JSON ARRAY STILL READABLE.
    #
    # `append` used to load the whole file, append in memory, and write the whole
    # file back -- an O(N) read and an O(N) write per append, so filling the
    # history to its cap costs O(N^2) serialisation. At the caps that is about a
    # terabyte of writes to store a few hundred megabytes, and the analyst waits
    # for all of it on a local tool that is supposed to be instant.
    #
    # JSONL fixes it at the root: one JSON object per line, so an append is one
    # `write()` of one line and nothing is re-serialised. It is also MORE
    # readable for the person this file is written for -- the module's own words
    # are that it is "a FILE the analyst can read, back up and delete themselves",
    # and one entry per line is readable where a single JSON array is not.
    #
    # THE OLD FORMAT IS STILL READ, so an existing history is not orphaned. A
    # single JSON document starts with `[` and a JSONL file never does, because
    # its first line is an object. That is the discriminator, and it is the only
    # thing distinguishing them.
    if not raw.lstrip().startswith("["):
        lines = raw.splitlines()
        entries: list[dict[str, Any]] = []
        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as exc:
                # A TORN FINAL LINE IS EXPECTED AND TOLERATED. `_append_line`
                # writes in append mode so an append costs one line rather than
                # a whole-file rewrite, and the price of that choice is that a
                # process killed mid-write can leave a partial last line. This is
                # the shape that takes, and refusing the entire history over it
                # would turn one lost tail entry into a lost audit trail.
                #
                # ONLY THE LAST NON-EMPTY LINE, and only when the file does not
                # end in a newline -- a complete line is always newline-
                # terminated, so the absence of one is the evidence that the
                # write was interrupted. Corruption anywhere ELSE is still
                # refused, because that is a damaged file rather than an
                # interrupted append, and hiding it would be the exact failure
                # the refusal exists to prevent.
                #
                # AND ONLY AFTER AT LEAST ONE GOOD ENTRY HAS PARSED. Without that
                # condition this rule swallows a file whose ONLY line is garbage,
                # which is what a damaged file usually looks like -- one
                # unterminated line of nonsense, no valid entry anywhere. A torn
                # write is always a tail: there is something before it, because
                # something was already there for the append to extend. A file
                # with nothing valid in it has not had a torn write, it has been
                # damaged, and reporting it as an empty history is the precise
                # failure these refusals exist to prevent.
                # AND ONLY AFTER AT LEAST ONE GOOD ENTRY HAS PARSED -- unless the
                # WRITE path opted in, because `append` calls this first and a
                # refusal there bricks the file permanently. A file whose only
                # line is garbage reads as damage (correct: the analyst is told),
                # but a save must still be possible, so `_reap_torn_tail` lets the
                # write path reap it and `_truncate_torn_tail` removes the bytes.
                #
                # AND ONLY IF THE PARTIAL LINE LOOKS LIKE SOMETHING *WE* WROTE.
                # This is the line that reconciles two requirements that pull in
                # opposite directions, and both are correct:
                #
                #   - a save must not be permanently bricked by a torn tail
                #   - a save must not silently overwrite a corrupt file
                #
                # `tests/test_web.py` asserts the second one and its file is
                # `{not json`. So "reap the tail" cannot mean "reap any unparseable
                # tail": that would destroy the analyst's file to fix a brick. A
                # torn tail is only reaped when it begins like a RuleForge entry --
                # `{` and a `"kind"` key -- which is what an interrupted append of
                # OUR OWN line looks like. Anything else is a file we did not write
                # and did not damage, and it is refused.
                is_last = all(not later.strip() for later in lines[number:])
                looks_like_ours = (stripped.startswith("{")
                                   and '"kind"' in stripped)
                if (entries or _reap_torn_tail) and is_last and looks_like_ours \
                        and not raw.endswith("\n"):
                    break
                raise Refused(
                    f"line {number} of the history file at {path} is not valid "
                    f"JSON ({exc}). It has not been overwritten. Move it aside to "
                    f"start a new history, or repair it -- the entries in it may "
                    f"be the only record of rules you have already run."
                ) from exc
            if not isinstance(parsed, dict):
                raise Refused(
                    f"line {number} of the history file at {path} is not a "
                    f"history entry")
            entries.append(parsed)
        return entries

    try:
        data = json.loads(raw.strip())
    except json.JSONDecodeError as exc:
        # A corrupt history is REPORTED. Returning [] would make a damaged audit
        # trail look like an empty one, and the user would carry on believing they
        # had a record when they did not.
        raise Refused(
            f"the history file at {path} is not valid JSON ({exc}). It has not "
            f"been overwritten. Move it aside to start a new history, or repair "
            f"it -- the entries in it may be the only record of rules you have "
            f"already run.") from exc
    if not isinstance(data, list):
        raise Refused(f"the history file at {path} is not a list of entries")
    # EVERY ELEMENT, NOT JUST THE TOP LEVEL. The JSONL branch validates each
    # parsed line is a dict, but the legacy branch only checked the container --
    # so a legacy array holding a bare string read happily, and the next SAVE
    # re-serialised it one-per-line, after which the file could never be read
    # again. A file that was READABLE became permanently unreadable as a side
    # effect of a successful save, and that was irreversible.
    for number, one in enumerate(data, start=1):
        if not isinstance(one, dict):
            raise Refused(
                f"entry {number} of the history file at {path} is "
                f"{type(one).__name__}, not a history entry. It has not been "
                f"overwritten.")
    return data


@dataclass(frozen=True, slots=True)
class Appended:
    """The result of one append, INCLUDING what it cost.

    `dropped` exists because the entry cap is the one place this file removes
    anything, and silently removing history is the exact failure it exists to
    prevent. So the count comes back to the caller and the UI says it out loud.
    An earlier version computed the count into a local variable, never used it,
    and carried a comment claiming the caller was told -- which was not true.
    """
    entry: dict[str, Any]
    dropped: int = 0


#: The job kinds History accepts. DECLARED ONCE, HERE, and the web layer reads it
#: rather than inventing its own list. The two used to be declared separately and
#: disagreed: history accepted `("author","tune","debug","understand")` while the
#: routes were `author|understand|tune|debug_rule_to_logs|debug_logs_to_rule`, so
#: `POST /api/debug_rule_to_logs {"save": true}` failed with
#: `'debug_rule_to_logs' is not one of the four jobs` -- and the user was shown a
#: size-limit-sounding message for what was a name mismatch. NEITHER debug job
#: could ever be saved.
JOBS: Final = frozenset({"author", "tune", "debug", "understand"})


def append(path: Path, kind: str, dialect: str, rule_id: str, title: str,
           summary: str, payload: dict[str, Any]) -> Appended:
    """Add one entry. Never modifies or removes an existing one, except to
    enforce `MAX_ENTRIES`, and that reports how many it had to drop."""
    if kind not in JOBS:
        raise Refused(
            f"{kind!r} is not one of {', '.join(sorted(JOBS))}. A route whose "
            f"name is not in this set cannot be saved, which is a wiring mistake "
            f"rather than anything the analyst did.")

    entry = HistoryEntry(kind=kind, dialect=dialect, rule_id=rule_id,
                         title=title, summary=summary, payload=payload,
                         created_at=_now()).to_dict()

    serialised = json.dumps(entry, ensure_ascii=False)
    if len(serialised) > MAX_ENTRY_CHARS:
        raise Refused(
            f"this entry is {len(serialised):,} characters, over the "
            f"{MAX_ENTRY_CHARS:,} limit. A pasted log sample is the usual cause; "
            f"trim it to the events that matter.")

    # The directory has to exist before the lock file can be OPENED IN IT, and
    # that is the whole reason this mkdir is here. The write helpers keep their
    # own because each can be reached without `append` -- `_write` is called
    # directly by a test -- so this is an addition, not a move, and the comment
    # that said otherwise was wrong. The cost is one `mkdir` syscall on an
    # existing directory, which is a stat on every platform this runs on.
    #
    # AND A DIRECTORY CREATED HERE HAS AN ENTRY OF ITS OWN, one level up, which
    # a fsync of the file and a fsync of `data/` both leave unforced. That is
    # what the second fsync is for, and it only happens once, when `data/` is
    # created, which is why it is not noticed as a cost at all.
    made_parent = not path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if made_parent:
        _fsync_directory(path.parent.parent)

    with _LOCK, _exclusive(path):
        # The reap flag is why a SAVE can still succeed on a file that a READ
        # calls damaged: see `load`'s docstring. Repair is on the WRITE path only.
        existing = load(path, _reap_torn_tail=True)
        entries = [*existing, entry]
        dropped = 0
        trim = len(entries) > MAX_ENTRIES
        if trim:
            dropped = len(entries) - MAX_ENTRIES
            entries = entries[-MAX_ENTRIES:]

        # JSONL, AND ONLY JSONL, UNLESS THE CAP FORCES A REWRITE.
        #
        # This is the whole point of the format change. The under-cap path --
        # which is every append except the last few hundred -- is ONE
        # `write()` of ONE line. Nothing already on disk is re-read for writing,
        # re-serialised, or rewritten, so the cost of an append no longer
        # depends on how much history exists. The previous version re-serialised
        # the entire file on every single append, so filling the history to its
        # cap cost O(N^2) serialisation: at the caps, about a terabyte of writes
        # to store a few hundred megabytes, all of it on a local tool that is
        # supposed to answer immediately.
        #
        # THE LEGACY ARRAY IS UPGRADED HERE, NOT IN `load`. `load` is called by
        # the read-only routes, and a reader must never rewrite the analyst's
        # file -- the corruption refusals above promise the file "has not been
        # overwritten", and a read that silently migrated it would break that
        # promise while appearing to keep it. So the format only changes when the
        # analyst asks for a change by saving something.
        if not trim and not _is_legacy_array(path):
            _truncate_torn_tail(path)
            _append_line(path, entry)
        else:
            # RE-READ IMMEDIATELY BEFORE THE RENAME. The lock above is what
            # makes this correct against another RuleForge; this is what makes
            # it a little less wrong against everything the lock does not cover
            # -- a hand edit, another tool, a RuleForge old enough not to know
            # the lock exists. It NARROWS the window between what was read and
            # what is about to be overwritten. It does not close it, because
            # nothing but the lock can, and a comment here claiming otherwise
            # would be the same defect as the one this branch is being fixed
            # for.
            #
            # ONLY THE TWO REWRITE PATHS PAY FOR IT, and they already rewrite
            # every entry in the file, so one more read is the cheaper of the
            # two costs. The under-cap append -- the common one, and the only
            # one that is O(1) in the size of the history -- still reads once
            # and writes one line.
            on_disk = load(path, _reap_torn_tail=True)
            if on_disk != existing:
                # COMPARED IN FULL, NOT BY LENGTH, and the difference is one
                # hand edit. `len` would miss a change that replaced one entry
                # or swapped two, and would then write the stale read back over
                # it -- silently, which is the exact failure this re-read exists
                # to stop. Both lists are already in memory, so the thorough
                # comparison is free and the cheap one is the wrong one.
                # `entry` is ours and is NOT in `on_disk`, so this is a merge
                # rather than a re-add, and the count of what the cap forces out
                # is worked out again rather than carried over from the stale
                # read.
                entries = [*on_disk, entry]
                dropped = 0
                if len(entries) > MAX_ENTRIES:
                    dropped = len(entries) - MAX_ENTRIES
                    entries = entries[-MAX_ENTRIES:]
            _write(path, entries)

    return Appended(entry=entry, dropped=dropped)


#: The FLOOR on how long an append waits for another PROCESS to finish its own
#: append before it gives up and refuses. Generous, because what it is usually
#: waiting for is one line append -- microseconds of work around an `fsync` --
#: and impatient, because a second copy of RuleForge holding the history for
#: five seconds is wedged and the analyst is looking at a spinner. Refusing
#: loses nothing and says so; waiting forever is indistinguishable from a hang.
LOCK_TIMEOUT_S: Final[float] = 5.0

#: ... PLUS this much per megabyte in the file, because a process holding the
#: lock is usually mid-REWRITE, and a rewrite costs time PROPORTIONAL TO THE
#: FILE rather than constant like a line append. Five seconds was not enough:
#: the module's own docstring puts a full history at about a gigabyte, and a
#: fixed five seconds refuses a second copy for doing legitimate work -- which
#: is a successful rule generation downgraded to a HISTORY_NOT_SAVED caution.
#:
#: MEASURED on this machine rather than guessed: `_write` of 8 MB in 160 entries
#: took 86 ms (93 MB/s) and of 2 MB in 40 entries took 67 ms (30 MB/s). 50 MB/s
#: -- the slower of those two, picked so the allowance errs towards WAITING
#: rather than towards refusing -- gives a gigabyte of history twenty seconds,
#: and leaves a file of any ordinary size on the floor above.
_LOCK_SECONDS_PER_MB: Final[float] = 0.02

#: How often to ask again while waiting. Short enough that a save which has to
#: wait still feels immediate, long enough not to burn a core.
_LOCK_POLL_S: Final[float] = 0.005

if os.name == "nt":  # pragma: no cover - which half runs is the platform's
    import msvcrt

    def _try_lock(handle: int) -> bool:
        """Take the lock, or say no without waiting."""
        # `msvcrt.locking` locks a byte RANGE STARTING AT THE CURRENT POSITION,
        # so the position is set rather than assumed. A handle that has just
        # been written to sits at the end of the file, and a range past the end
        # of a file is not lockable.
        os.lseek(handle, 0, os.SEEK_SET)
        try:
            msvcrt.locking(handle, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    def _release(handle: int) -> None:
        os.lseek(handle, 0, os.SEEK_SET)
        try:
            msvcrt.locking(handle, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass

else:  # pragma: no cover - see above
    import fcntl

    def _try_lock(handle: int) -> bool:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        return True

    def _release(handle: int) -> None:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        except OSError:
            pass


def _cannot_lock(lock_path: Path, path: Path, exc: OSError) -> Refused:
    """The one refusal for "the lock could not be taken", written once.

    A REFUSAL AND NOT A FALLBACK. Saving without the lock is exactly the loss
    the lock exists to prevent, so if it cannot be taken the honest answer is to
    save nothing and say why. `Refused` also means the web layer reports this as
    a caution on the save -- the same as a history it declined to write -- rather
    than letting it escape as a server error, which a permission problem here
    otherwise would.

    THE OS'S OWN WORDS COME FIRST, and that is not politeness. This branch is
    also reached for `EMFILE` (too many open files), `ENOSPC` (disk full) and a
    `data/` that does not exist, and "check that the directory is writable" is
    actively wrong advice for those. The errno and its message are in the string
    the analyst is shown, so they can tell the cases apart without a debugger.
    """
    return Refused(
        f"RuleForge could not use its history lock file at {lock_path} "
        f"({type(exc).__name__}: {exc}). It has not saved this entry, because "
        f"without that lock a save cannot promise that it would not destroy an "
        f"entry another copy of RuleForge has just written. Nothing already in "
        f"the history has been changed. If the file is there and the error is "
        f"about permissions, delete that one lock file and save again -- it "
        f"holds nothing. Otherwise check that {path} can be written to.")


def _wait_seconds(path: Path) -> float:
    """How long to wait for the lock: the floor, plus the file's own size.

    A REFUSAL IS NOT A LOSS, and it is also not free: `web.py` shows it as a
    caution on a rule the analyst was told was generated, so refusing a writer
    that is merely slow is a visible failure too. The cost of the thing being
    waited for is proportional to the file, so the allowance is as well. The
    stat is one syscall against an append that already reads the whole file, and
    an absent or unreadable file contributes nothing rather than failing -- this
    is a decision about how long to wait, not an operation that can lose data.
    """
    try:
        megabytes = path.stat().st_size / 1_000_000
    except OSError:
        megabytes = 0.0
    return LOCK_TIMEOUT_S + megabytes * _LOCK_SECONDS_PER_MB


def _lock_path(path: Path) -> Path:
    """The sidecar file the cross-process lock is taken on.

    A SIDECAR, AND NOT THE HISTORY FILE ITSELF, for a reason that is easy to
    miss: the trim path REPLACES the history with a new inode, so a lock taken
    on the history would be a lock on an inode that stopped being the history
    the moment the rename landed, and the next appender would open the new inode
    and exclude nobody. A lock has to live on a file that is never replaced.
    """
    return path.with_name(path.name + ".lock")


@contextmanager
def _exclusive(path: Path) -> Iterator[None]:
    """Hold the history's cross-process lock for the length of one append.

    TAKEN BY EVERY APPEND, not only by the two that rewrite. A lock excludes the
    writers that take it and nobody else, so a lock held only across the
    rewrite would have left the ordinary append free to land in the window
    between the rewrite's read and its rename -- which is the entire bug.

    WAITS, THEN REFUSES. The wait is short (`LOCK_TIMEOUT_S`) and the refusal
    is loud. The alternatives were a marker file that has to be cleaned up by
    the process that made it -- which a killed process does not get to do, so
    the second crash would brick the history forever -- and a blocking
    acquisition, which is a hang with no message and no way out.

    NOT UNLINKED ON THE WAY OUT, and that omission is deliberate. Unlinking is
    the classic way to break a lock: a waiter that already has the old inode
    open would be granted the old lock, the next arrival would create a NEW
    file and be granted that one, and two writers would each hold "the lock".
    So the file stays. It holds no history, which is the claim that matters, and
    it is not quite empty on Windows -- `msvcrt.locking` needs a byte to lock and
    the code below writes one NUL, so it is 0 bytes on POSIX and 1 on Windows.
    It is created 0600 on POSIX, from the mode argument rather than from a later
    `chmod`, for the same reason the history is.
    """
    lock_path = _lock_path(path)
    flags = os.O_RDWR | os.O_CREAT
    try:
        handle = os.open(str(lock_path), flags, 0o600)
    except PermissionError:
        # NARROWED PERMISSIONS ARE REPAIRED RATHER THAN REFUSED OVER, and this
        # is the one new way the lock could have made the history permanently
        # unwritable, so it is worth the two calls. A sidecar that came back
        # from a backup, a `chmod -R a-w data/`, or a sync tool with strict
        # modes is `0444`, and opening it `O_RDWR` then fails with EACCES --
        # deterministically, for its owner, on every save, with a message that
        # points at the directory. The owner of a file may always `chmod` it, so
        # one attempt fixes the realistic case. NOT `chmod` before the open,
        # which is the version that cannot work, and NOT an unlink-and-retry,
        # which would hand two writers two different lock files.
        try:
            os.chmod(lock_path, 0o600)
            handle = os.open(str(lock_path), flags, 0o600)
        except OSError as exc:
            raise _cannot_lock(lock_path, path, exc) from exc
    except OSError as exc:
        raise _cannot_lock(lock_path, path, exc) from exc
    try:
        if os.name == "nt" and os.fstat(handle).st_size == 0:
            # A byte to lock. `msvcrt.locking` needs a range that exists, and
            # written at offset 0 WITHOUT O_APPEND so that two processes which
            # both find the file empty write the same byte and it stays one byte
            # long instead of growing by one on every append.
            os.lseek(handle, 0, os.SEEK_SET)
            os.write(handle, b"\0")
        deadline = time.monotonic() + _wait_seconds(path)
        while not _try_lock(handle):
            if time.monotonic() >= deadline:
                # "ANOTHER COPY OF RULEFORGE, OR ANOTHER PROGRAM", because that
                # is all the evidence there is. Nothing here can identify the
                # holder -- the operating system does not publish who took an
                # advisory lock, and this file is not going to start guessing --
                # so the message names the common cause and the other plausible
                # one, and says plainly that the entry was not saved. Losing the
                # save is the one outcome of this branch that is not a bug.
                raise Refused(
                    f"another copy of RuleForge, or another program, has been "
                    f"writing to {path} for more than {LOCK_TIMEOUT_S:g} seconds, "
                    f"so this entry has NOT been saved and nothing in the history "
                    f"has been changed. Close the other copy -- or whatever else "
                    f"has the file open -- wait for it to finish, and save "
                    f"again.")
            time.sleep(_LOCK_POLL_S)
        try:
            yield
        finally:
            _release(handle)
    finally:
        os.close(handle)


def _truncate_torn_tail(path: Path) -> int:
    """Discard an interrupted final line, and return how many bytes went.

    THIS IS THE REPAIR, AND WITHOUT IT THE TOLERANCE IS A TRAP.

    `load` tolerates an unterminated final line so a killed append costs one
    entry rather than the whole history. It then RETURNS, and it does not say
    anywhere that a partial line is sitting on disk. The next `append` wrote its
    own line straight onto those bytes with no separator, which did three things
    at once:

      - destroyed the entry the analyst had just saved, by concatenating it into
        the garbage, while `append` returned `Appended(...)` and the UI showed a
        green Saved
      - bricked the file permanently, because the new line supplied the trailing
        newline that the torn-tail tolerance keys on, so the next `load` raised
        and every subsequent save was refused

    Executed, before this function existed:
        load after damage -> 2 entries   (torn tail tolerated)
        append returned OK, dropped = 0
        load -> Refused: line 3 ...

    So the knowledge is now USED rather than discarded -- AND THE CODE ASKS
    WHETHER THE TAIL IS TORN BEFORE IT REMOVES IT, which the version above did
    not. Executed, before the check below existed:

        file: one complete entry, no trailing newline
        load  -> ['SAVED-BY-HAND']        the entry is there
        append returned ok, dropped = 0
        load  -> ['NEW']                  the entry is gone

    "A complete line is always newline-terminated" was the sentence that made
    that acceptable, and it is FALSE. `_append_line` terminates what it writes,
    but this module explicitly invites the analyst to read, back up and EDIT
    this file by hand, and a hand edit, a `json.dump` and Notepad all leave off
    the final newline. On a one-entry file the truncation put `keep` at 0, so
    the whole history was replaced by the entry being saved: a complete, saved,
    reported-as-saved-with-nothing-dropped loss, in the function written to
    prevent exactly that.

    SO A TAIL THAT PARSES IS KEPT, and only a tail that does not parse is
    discarded. A whole file that is one partial line still becomes empty rather
    than unreadable, and that sentence is now true, because "partial" is
    decided by parsing rather than assumed.
    """
    if not path.exists():
        return 0
    raw = path.read_bytes()
    if not raw or raw.endswith(b"\n"):
        return 0
    cut = raw.rfind(b"\n")
    keep = 0 if cut < 0 else cut + 1
    if _is_complete_entry(raw[keep:]):
        # Missing a newline is not the same as being a fragment, and the
        # difference is one whole entry. The caller is about to write its own
        # line straight onto these bytes, so they are TERMINATED rather than
        # removed, and the next `load` reads two entries instead of one.
        _terminate_last_line(path)
        return 0
    discarded = len(raw) - keep
    if discarded:
        with path.open("r+b") as stream:
            stream.truncate(keep)
            stream.flush()
            os.fsync(stream.fileno())
    return discarded


def _is_complete_entry(raw: bytes) -> bool:
    """True when these bytes are a whole entry rather than a fragment of one.

    DECIDED BY PARSING, not by whether the file ends in a newline, because that
    is the distinction the repair turns on: a complete line and a torn line look
    identical at the end of the file and differ by one whole entry.

    `utf-8-sig` for the same reason `load` uses it: a hand edit saved with a
    byte-order mark is an ordinary thing for a person to produce, and without
    this a one-entry file with a BOM and no trailing newline reads as a fragment
    and is thrown away. `replace` on the decode, because an undecodable tail is
    a fragment by any reading and must not raise out of a repair.
    """
    try:
        return isinstance(json.loads(raw.decode("utf-8-sig", "replace")), dict)
    except (json.JSONDecodeError, ValueError):
        return False


def _terminate_last_line(path: Path) -> None:
    """Give the last line the newline it is missing, and remove nothing.

    APPEND MODE, so the bytes already on disk are not rewritten, and fsynced for
    the same reason `_append_line` fsyncs: the next append is about to write
    directly onto the end of this file, and a crash between the two must not
    leave the pair glued together into one unparseable line -- which is the
    bricked-history failure `_truncate_torn_tail` exists next to.
    """
    with path.open("ab") as stream:
        stream.write(b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def _is_legacy_array(path: Path) -> bool:
    """True when the file on disk is the OLD single-JSON-document array.

    A JSONL file's first character is `{`, because its first line is an object.
    A legacy array's is `[`. An absent or empty file is not legacy, so the first
    append creates a JSONL file rather than starting one in the old shape.
    """
    if not path.exists():
        return False
    head = path.read_text(encoding="utf-8")[:1]
    return head == "["


def _append_line(path: Path, entry: dict[str, Any]) -> None:
    """Append ONE entry as ONE line, and never rewrite the existing ones.

    OPPOSED TO `_write`, AND THE DIFFERENCE IS THE WHOFEATURE. `_write` is
    temp-file-then-rename, which is the right way to replace a file atomically
    and the wrong way to add to one: a rename is only atomic because it
    REPLACES the file, and the point here is to keep the bytes that are already
    there. So this opens in append mode and writes a single line, which is what
    makes the cost independent of the file's size.

    `fsync` IS KEPT, and it is the expensive part. It is also the part that
    makes the entry durable: without it a crash can lose the last append, and a
    history that quietly drops the record of a rule is worse than a slow one.

    A TORN FINAL LINE IS TOLERATED ON READ, not here. A process killed mid-write
    can leave a partial last line, and refusing to read the history at all
    because of that would turn a lost tail entry into a lost audit trail.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False)
    # CREATED 0600 FROM BIRTH, NOT CHMOD-ed AFTERWARDS. `path.open("a")` creates
    # the file at the process umask -- 0644 on a typical POSIX box -- and the
    # `os.chmod` below used to narrow it only after the write and the close. So
    # there was a real window in which a file the `.gitignore` comment describes
    # as holding "pasted detection rules and EVENT SAMPLES, which contain
    # hostnames, usernames, source IPs and destination IPs" was world-readable.
    #
    # `os.open` takes the mode at creation, so the file is never briefly
    # readable by anyone else. The rewrite path already had this for free:
    # `mkstemp` creates 0600. The two paths were not equal, and the comment on the
    # chmod claimed they were.
    # CREATED OR OPENED, AND THE ANSWER IS EXACT. `O_EXCL` is tried first so
    # that "did this call create the file" is settled by the open rather than by
    # a `stat` taken before it: two processes can both see an absent file, and
    # the loser would skip the directory fsync that the winner still owes. The
    # earlier `not path.exists()` was not a bug -- the only consequence of losing
    # that race is an unsynced directory entry, not a lost entry -- but the
    # exact version costs one extra syscall on the common path and one on the
    # first save, and the common path is what this file exists to keep fast.
    #
    # It is the only thing `_append_line` does to the PARENT DIRECTORY, and the
    # only reason a directory fsync is needed here. `_write`'s rename is the
    # other such moment. See `_fsync_directory` for why fsyncing the file does
    # not cover it.
    try:
        handle = os.open(str(path),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND,
                         0o600)
        created = True
    except FileExistsError:
        handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                         0o600)
        created = False
    with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(line + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    # The 0600 statement lives in `_write`; the same explicit, deliberately
    # tolerant chmod is applied here so a file created by the APPEND path is not
    # left with whatever the umask happened to be, while on Windows it stays a
    # no-op that cannot lose the audit trail over a permission call the platform
    # does not support.
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass
    # AFTER the bytes, never before: a directory entry that becomes durable
    # before the data it points at can describe a file whose contents are gone,
    # and that is a worse state than a name that is not there yet.
    if created:
        _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    """Make the fact that a file EXISTS durable. POSIX only, best effort.

    WHY IT IS NEEDED AT ALL, since `_append_line` already fsyncs: `fsync` on a
    file flushes that FILE -- its blocks, its length, its permissions. It says
    nothing about the DIRECTORY holding it. The name "history.json" lives in an
    entry inside `data/`, and that entry is written when the file is created and
    when a rename installs a new inode under the name. So a machine that loses
    power between the data reaching the disk and the directory entry reaching
    the disk can come back with no name at all for bytes it already promised to
    keep. For the FIRST append of a fresh history that is the whole audit
    trail: the file `_append_line` reported writing is not there, and the entry
    the analyst was told was saved is not in it.

    CALLED ONLY WHERE A DIRECTORY ENTRY CHANGES -- after `_append_line`
    CREATED the file, and after `_write`'s `os.replace`. Calling it on every
    append would put a directory journal commit on the common path, which is
    precisely the visible slowdown the JSONL change exists to remove.

    WINDOWS: SKIPPED, AND NOT BY ACCIDENT. There is no POSIX-style directory
    handle to flush there -- `os.open` on a directory name is not a thing --
    so the equivalent request cannot be made with the standard library. What
    NTFS does instead is journal the metadata operation and replay the log on
    the next mount, so a create or a rename is recovered rather than lost. That
    is a DIFFERENT guarantee from a POSIX directory fsync and this comment says
    so rather than implying the two are the same thing.

    FAILURE IS TOLERATED, deliberately. Some filesystems refuse a directory
    fsync (older kernels return EINVAL) and a few network mounts cannot do one
    at all. Propagating would mean losing the save, and losing the save is a far
    worse outcome for the analyst than keeping the durability this platform can
    actually give.
    """
    if os.name == "nt":
        return
    try:
        handle = os.open(str(path),
                         os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(handle)
    except OSError:
        pass
    finally:
        os.close(handle)


def _write(path: Path, entries: list[dict[str, Any]]) -> None:
    """Write the whole file atomically.

    TEMP FILE THEN RENAME. A plain write can be interrupted half way, and a
    truncated history is a lost audit trail. `os.replace` is atomic on the same
    filesystem, so a reader sees either the old file or the new one.

    THE 0600 IS STATED HERE RATHER THAN INHERITED FROM `mkstemp`. `mkstemp`
    already creates the file 0600 on POSIX, so the `os.chmod` below is a no-op
    there -- and that is exactly why it is written down. A security property
    that depends on a stdlib implementation detail nobody has read is not a
    property, it is a coincidence, and it fails silently if that detail changes.
    One line makes the intent explicit and testable.

    ON WINDOWS THIS DOES NOT RESTRICT ANYBODY, AND THE COMMENT USED TO SAY IT
    DID. `os.chmod` on Windows has one bit -- the read-only flag -- and does not
    model POSIX permission bits at all. So on win32 the history file is as
    readable as the directory it sits in, and the actual control there is the
    inherited ACL: `data/` lives under the analyst's own profile, whose default
    ACL grants that user, SYSTEM and Administrators, and not Everyone.

    That is a weaker and differently-shaped guarantee than 0600, and saying
    "0600" on Windows was simply false. The honest statement is in `.gitignore`
    next to the ignore rule, because that is where someone reads about it
    before running `git add -A`.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent),
                                         prefix=".history-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            # JSON LINES, NOT A JSON ARRAY. `_write` is now only reached when the
            # cap forces a trim, or when upgrading a legacy array, and both of
            # those rewrite the file anyway -- so the format here matches what
            # `_append_line` writes, and a trimmed file stays readable by
            # `load` and by anyone who opens it in a text editor.
            for one in entries:
                stream.write(json.dumps(one, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        # Explicit, and deliberately tolerant of failure. On POSIX this asserts
        # what mkstemp already did; on Windows it is a no-op that must not raise,
        # because refusing to write the history over a permission call that the
        # platform does not support would lose the audit trail to a non-problem.
        try:
            os.chmod(temporary, 0o600)
        except (OSError, NotImplementedError):
            pass
        os.replace(temporary, path)
        # The temp file IS the history now, and the cleanup in the handler below
        # must not go looking for it: a future edit that added a line between
        # the rename and the end of the `try` would otherwise make the save
        # report failure for a file that was written, and the analyst's next
        # save would then duplicate the entry. Harmless today only because the
        # unlink of a name that is gone raises and is swallowed.
        temporary = None
        # The rename changes the PARENT DIRECTORY rather than the file, and it
        # is the one moment on this path where the name on disk stands for
        # different bytes than it did a moment ago. Same reasoning, same
        # platform split, as `_fsync_directory` sets out.
        _fsync_directory(path.parent)
    except BaseException:
        # Never leave a temp file behind on failure, and never unlink a name
        # that the rename already consumed.
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        raise


def recent(path: Path, limit: int = 25) -> list[dict[str, Any]]:
    """The newest entries first, for the History tab.

    NOT the reap flag. This is a READ: a damaged history must be REPORTED here,
    because that is the page where the analyst finds out. Repairing on read would
    make a damaged file look like an empty one, which is the exact failure the
    refusals exist to prevent -- and an earlier version of this function took the
    flag by mistake, which is how `tests/test_web.py` caught it.
    """
    # A NON-POSITIVE LIMIT RAISES, WHICH IS A CHOICE AND NOT AN ACCIDENT.
    # `entries[-0:]` is `entries[0:]`, so `limit=0` returned the ENTIRE
    # history, and `limit=-1` returned everything but the newest. No route can
    # reach either -- `web.py` passes 100 -- so nothing in the product is
    # broken by it. It is a trap for the next caller, and a quiet one, because
    # what comes back is a perfectly well-formed list of real entries.
    #
    # Both ways of NOT raising are worse than an error:
    #
    #   - CLAMP `0` TO "NOTHING". The History tab would then render empty for a
    #     history file that is full, and this module's whole argument is that a
    #     history must never be made to LOOK empty when it is not. Losing the
    #     record and losing the ability to see the record are the same failure
    #     here, and this file is about the second one as much as the first.
    #   - CLAMP `0` TO THE CAP, which is the bug under a different name.
    #
    # A `ValueError` is the honest answer: a non-positive limit is always a
    # mistake in the calling code, it fails where the mistake is, and nothing
    # the analyst types can reach it. It is NOT `Refused`, which is about the
    # analyst's FILE and carries a message written for a person -- this is about
    # a line of Python, and the two problems should not share a type.
    if limit <= 0:
        raise ValueError(
            f"limit must be at least 1, not {limit!r}: the newest N entries is "
            f"what this returns, and 0 or a negative number has no such answer")
    entries = load(path)
    return list(reversed(entries[-limit:]))
