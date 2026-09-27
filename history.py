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

THE WRITE IS WHOLE-FILE AND THAT IS A REAL LIMITATION. Rewriting the whole file
on each save is O(history) and is not safe against concurrent writers. For a
single-user local tool that is the right trade: a partial append can corrupt the
file, and losing the whole history to a torn write is the one failure this file
must not have. The write is a temp-file-then-rename, so a reader never sees a
half-written history and a crash mid-write leaves the old one intact.
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


def load(path: Path) -> list[dict[str, Any]]:
    """Every entry, oldest first. A corrupt file is surfaced, not swallowed."""
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
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
        entries = load(path)
        entries.append(entry)
        dropped = 0
        if len(entries) > MAX_ENTRIES:
            dropped = len(entries) - MAX_ENTRIES
            entries = entries[-MAX_ENTRIES:]
        _write(path, entries)

    return Appended(entry=entry, dropped=dropped)


def _write(path: Path, entries: list[dict[str, Any]]) -> None:
    """Write the whole file atomically.

    TEMP FILE THEN RENAME. A plain write can be interrupted half way, and a
    truncated history is a lost audit trail. `os.replace` is atomic on the same
    filesystem, so a reader sees either the old file or the new one.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent),
                                         prefix=".history-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(entries, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        # Never leave a temp file behind on failure.
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def recent(path: Path, limit: int = 25) -> list[dict[str, Any]]:
    """The newest entries first, for the History tab."""
    entries = load(path)
    return list(reversed(entries[-limit:]))
