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

So the original safety argument still holds where it applied -- a reader never
sees a half-written history during a REWRITE, because the old inode is intact
until the rename -- and no longer holds for the append path, which instead has
the torn-tail tolerance described above. Neither path is unchecked.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

#: Serialising history is guarded in-process. Two tabs open at once would
#: otherwise interleave read-modify-write and lose an entry.
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

    with _LOCK:
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
            _write(path, entries)

    return Appended(entry=entry, dropped=dropped)


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

    So the knowledge is now USED rather than discarded. The partial bytes are
    provably not a complete entry -- a complete line is always newline-terminated
    -- so removing them cannot lose anything recoverable, and every good entry
    before them is kept. If the whole file is one partial line there are no good
    entries to keep, and the file becomes empty rather than unreadable, which is
    the honest description of its contents.
    """
    if not path.exists():
        return 0
    raw = path.read_bytes()
    if not raw or raw.endswith(b"\n"):
        return 0
    cut = raw.rfind(b"\n")
    keep = 0 if cut < 0 else cut + 1
    discarded = len(raw) - keep
    if discarded:
        with path.open("r+b") as stream:
            stream.truncate(keep)
            stream.flush()
            os.fsync(stream.fileno())
    return discarded


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
    handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
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
    except BaseException:
        # Never leave a temp file behind on failure.
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
    entries = load(path)
    return list(reversed(entries[-limit:]))
