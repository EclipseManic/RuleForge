"""Rule history, on SQLite.

The history tab is not a convenience. Tuning a detection is iterative -- widen
a condition, re-run it against samples, narrow it again -- and the question an
engineer actually asks is "what did this rule look like before I touched it,
and why did I change it?". A store that overwrites answers neither.

So this is APPEND-ONLY. Saving a tuned rule writes a NEW row that points at the
one it came from, and nothing is ever updated in place. The lineage that falls
out of `parent_id` is the audit trail: you can walk a rule from the version
pasted in off a blog post, through four tuning passes, to the one deployed.

`origin` records which of the three authoring paths produced a row, because
they carry very different trust:

    authored      built in the GUI from the IR outward
    imported      pasted in as vendor text and parsed
    synthesized   generated from a log sample

A rule synthesized from one log line is a hypothesis; a rule an engineer
authored deliberately is a decision. Flattening that distinction is how a
history tab becomes a list nobody trusts.

Rules are stored as codec JSON rather than as vendor text, because vendor text
is lossy in both directions -- `kql.py` cannot render annotations at all -- and
because a stored rule has to be re-openable in the builder, which needs the IR.
The original text is kept ALONGSIDE it, verbatim, so an imported rule can still
be shown exactly as the analyst pasted it.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from threading import RLock
from typing import Any, Final

from .codec import SCHEMA_VERSION, rule_from_json, rule_to_json
from .ir import Rule
from .values import Refusal

__all__ = [
    "Dataset",
    "ORIGINS",
    "Entry",
    "RuleStore",
    "TestRun",
    "default_store_path",
]

#: How a row came to exist. A closed set, because the UI shows it as a badge
#: and an unrecognised origin would render as a blank.
ORIGINS: Final[frozenset[str]] = frozenset({"authored", "imported", "synthesized"})

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS entries (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT    NOT NULL,
    rule_id        TEXT    NOT NULL,
    title          TEXT    NOT NULL DEFAULT '',
    dialect        TEXT    NOT NULL,
    origin         TEXT    NOT NULL,
    parent_id      INTEGER REFERENCES entries(id),
    note           TEXT    NOT NULL DEFAULT '',
    source_text    TEXT    NOT NULL DEFAULT '',
    rule_json      TEXT    NOT NULL,
    schema_version INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS entries_created ON entries(created_at DESC);
CREATE INDEX IF NOT EXISTS entries_rule_id ON entries(rule_id);
CREATE INDEX IF NOT EXISTS entries_parent  ON entries(parent_id);

CREATE TABLE IF NOT EXISTS datasets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT    NOT NULL,
    name           TEXT    NOT NULL,
    description    TEXT    NOT NULL DEFAULT '',
    format         TEXT    NOT NULL,
    table_name     TEXT    NOT NULL,
    source_type    TEXT    NOT NULL,
    labels_json    TEXT    NOT NULL DEFAULT '[]',
    event_count    INTEGER NOT NULL,
    time_start     TEXT    NOT NULL DEFAULT '',
    time_end       TEXT    NOT NULL DEFAULT '',
    raw_text       TEXT    NOT NULL,
    events_json    TEXT    NOT NULL,
    content_hash   TEXT    NOT NULL,
    warnings_json  TEXT    NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS datasets_created ON datasets(created_at DESC);
CREATE INDEX IF NOT EXISTS datasets_hash ON datasets(content_hash);

CREATE TABLE IF NOT EXISTS test_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    NOT NULL,
    rule_id         TEXT    NOT NULL,
    title           TEXT    NOT NULL DEFAULT '',
    rule_entry_id   INTEGER REFERENCES entries(id),
    rule_hash       TEXT    NOT NULL,
    dataset_id      INTEGER NOT NULL REFERENCES datasets(id),
    dataset_hash    TEXT    NOT NULL,
    expected_verdict TEXT   NOT NULL DEFAULT '',
    actual_verdict  TEXT    NOT NULL,
    matches_expected INTEGER,
    purpose         TEXT    NOT NULL DEFAULT 'manual',
    note            TEXT    NOT NULL DEFAULT '',
    rule_json       TEXT    NOT NULL,
    result_json     TEXT    NOT NULL,
    evaluator_version TEXT  NOT NULL DEFAULT '1'
);
CREATE INDEX IF NOT EXISTS test_runs_created ON test_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS test_runs_rule_hash ON test_runs(rule_hash);
CREATE INDEX IF NOT EXISTS test_runs_dataset ON test_runs(dataset_id);
"""


def _encode_json_value(value: Any, depth: int = 0) -> Any:
    """Tag containers too: a user object cannot impersonate a numeric tag."""
    if depth > 100:
        raise Refusal("STORE_DATASET_TOO_DEEP", "events nest more than 100 levels.", "store")
    if isinstance(value, (Decimal, float)):
        finite = value.is_finite() if isinstance(value, Decimal) else math.isfinite(value)
        if not finite:
            raise Refusal("STORE_DATASET_NUMBER", "event numbers must be finite.", "store")
        return ["decimal" if isinstance(value, Decimal) else "float", str(value)]
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return ["scalar", value]
    if isinstance(value, list):
        return ["array", [_encode_json_value(item, depth + 1) for item in value]]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return ["object", [[key, _encode_json_value(item, depth + 1)]
                           for key, item in value.items()]]
    raise Refusal("STORE_DATASET_VALUE_TYPE", "events must contain JSON values with string keys.", "store")


def _decode_json_value(value: Any, depth: int = 0) -> Any:
    if depth > 100 or not isinstance(value, list) or len(value) != 2:
        raise ValueError("invalid event encoding")
    tag, body = value
    if tag == "scalar" and (body is None or isinstance(body, (bool, int, str))):
        return body
    if tag in ("decimal", "float") and isinstance(body, str):
        number = Decimal(body) if tag == "decimal" else float(body)
        if not (number.is_finite() if isinstance(number, Decimal) else math.isfinite(number)):
            raise ValueError("nonfinite number")
        return number
    if tag == "array" and isinstance(body, list):
        return [_decode_json_value(item, depth + 1) for item in body]
    if tag == "object" and isinstance(body, list):
        result = {}
        for key, item in body:
            if not isinstance(key, str) or key in result:
                raise ValueError("invalid or repeated object key")
            result[key] = _decode_json_value(item, depth + 1)
        return result
    raise ValueError("unknown event encoding")


def rule_fingerprint(rule: Rule) -> str:
    """Fingerprint the exact codec snapshot, not just the displayed query."""
    return hashlib.sha256(rule_to_json(rule, indent=None).encode("utf-8")).hexdigest()


def default_store_path() -> Path:
    """`data/history.sqlite3` at the repository root, honouring an override.

    The `data/` directory sits beside `engine/`, not inside it: it is this
    machine's saved history, not part of the engine, and keeping it at the
    root means moving or repackaging the engine cannot silently relocate a
    user's rules. `parent.parent` is deliberate -- `parent` would put the
    database inside `engine/`.
    """
    override = os.environ.get("RULEFORGE_HOME")
    root = Path(override) if override else Path(__file__).resolve().parent.parent / "data"

    return root / "history.sqlite3"


@dataclass(frozen=True, slots=True)
class Entry:
    """One stored version of a rule.

    `rule_json` is kept as text rather than decoded eagerly: listing a hundred
    history rows should not decode and validate a hundred rules. Call
    `RuleStore.rule(entry_id)` for the Rule itself.
    """

    id: int
    created_at: str
    rule_id: str
    title: str
    dialect: str
    origin: str
    parent_id: int | None
    note: str
    source_text: str
    rule_json: str
    schema_version: int

    def as_dict(self, *, include_rule: bool = False) -> dict[str, Any]:
        """The shape the API hands a history list."""
        body: dict[str, Any] = {
            "id": self.id,
            "created_at": self.created_at,
            "rule_id": self.rule_id,
            "title": self.title,
            "dialect": self.dialect,
            "origin": self.origin,
            "parent_id": self.parent_id,
            "note": self.note,
            "has_source": bool(self.source_text),
        }
        if include_rule:
            body["source_text"] = self.source_text
            body["rule"] = json.loads(self.rule_json)
        return body


@dataclass(frozen=True, slots=True)
class Dataset:
    """One immutable local telemetry dataset.

    The raw text is retained beside a tagged representation of the normalized
    events. The hash covers the normalized payload and is used by test runs to
    prove exactly which evidence was evaluated.
    """

    id: int
    created_at: str
    name: str
    description: str
    format: str
    table_name: str
    source_type: str
    labels: tuple[str, ...]
    event_count: int
    time_start: str
    time_end: str
    raw_text: str
    events_json: str
    content_hash: str
    warnings: tuple[str, ...]

    def events(self) -> list[dict[str, Any]]:
        try:
            digest = hashlib.sha256(self.events_json.encode("utf-8")).hexdigest()
            payload = json.loads(self.events_json)
            if digest != self.content_hash:
                raise ValueError("hash mismatch")
            if isinstance(payload, dict) and payload.get("schema") == 1:
                decoded = _decode_json_value(payload["events"])
            elif isinstance(payload, list):
                # Rows written before the tagged envelope stored the event list
                # directly. The hash still covers that text, so these are as
                # verifiable as a current row -- refusing them would condemn a
                # user's existing evidence for its age, not its contents.
                decoded = payload
            else:
                raise ValueError("schema mismatch")
            if (not isinstance(decoded, list) or len(decoded) != self.event_count
                    or not all(isinstance(event, dict) for event in decoded)):
                raise ValueError("event count or type mismatch")
        except (ValueError, TypeError, KeyError, AttributeError, InvalidOperation,
                RecursionError) as exc:
            raise Refusal("STORE_DATASET_CORRUPT",
                          f"dataset {self.id} failed integrity validation.", "store") from exc
        return decoded

    def as_dict(self, *, include_events: bool = False) -> dict[str, Any]:
        body: dict[str, Any] = {
            "id": self.id,
            "created_at": self.created_at,
            "name": self.name,
            "description": self.description,
            "format": self.format,
            "table": self.table_name,
            "source_type": self.source_type,
            "labels": list(self.labels),
            "event_count": self.event_count,
            "time_start": self.time_start,
            "time_end": self.time_end,
            "content_hash": self.content_hash,
            "warnings": list(self.warnings),
        }
        if include_events:
            body["raw_text"] = self.raw_text
        return body


@dataclass(frozen=True, slots=True)
class TestRun:
    """An immutable evaluation with rule and dataset fingerprints."""

    id: int
    created_at: str
    rule_id: str
    title: str
    rule_entry_id: int | None
    rule_hash: str
    dataset_id: int
    dataset_hash: str
    expected_verdict: str
    actual_verdict: str
    matches_expected: bool | None
    purpose: str
    note: str
    rule_json: str
    result_json: str
    evaluator_version: str

    def as_dict(self, *, include_result: bool = False) -> dict[str, Any]:
        body: dict[str, Any] = {
            "id": self.id,
            "created_at": self.created_at,
            "rule_id": self.rule_id,
            "title": self.title,
            "rule_entry_id": self.rule_entry_id,
            "rule_hash": self.rule_hash,
            "dataset_id": self.dataset_id,
            "dataset_hash": self.dataset_hash,
            "expected_verdict": self.expected_verdict,
            "actual_verdict": self.actual_verdict,
            "matches_expected": self.matches_expected,
            "purpose": self.purpose,
            "note": self.note,
            "evaluator_version": self.evaluator_version,
        }
        if include_result:
            body["rule"] = json.loads(self.rule_json)
            body["result"] = json.loads(self.result_json)
        return body



def _owner_only(path: Path, mode: int) -> None:
    """Restrict `path` to its owner. Best effort: Windows ignores POSIX modes."""
    try:
        if path.exists():
            os.chmod(path, mode)
    except OSError:
        pass


class RuleStore:
    """Append-only rule history.

    A short-lived connection per call rather than one long-lived handle. The
    API server is threaded, and a shared sqlite3 connection across threads is
    either a crash or a lock held across a request -- neither of which is worth
    saving a few microseconds on a local tool.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self._lock = RLock()
        self.path = Path(path) if path is not None else default_store_path()
        self._in_memory = str(self.path) == ":memory:"
        self._memory: sqlite3.Connection | None = None
        if self._in_memory:
            # An in-memory database exists exactly as long as its connection,
            # so this one handle is kept open for the store's lifetime.
            self._memory = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory.execute("PRAGMA foreign_keys = ON")
        else:
            existed = self.path.parent.exists()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not existed:
                _owner_only(self.path.parent, 0o700)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        if not self._in_memory:
            # The store holds the log samples an analyst pasted -- which carry
            # usernames, hostnames and sometimes credentials -- in plain text.
            # SQLite creates the file with the umask's default (0644), readable
            # by every account on a shared jump host. Owner-only, always.
            for suffix in ("", "-wal", "-shm", "-journal"):
                _owner_only(Path(str(self.path) + suffix), 0o600)

    # -- plumbing ---------------------------------------------------------

    def _connect(self) -> "_Session":
        if self._memory is not None:
            return _Session(self._memory, close=False, lock=self._lock)
        conn = sqlite3.connect(str(self.path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return _Session(conn, close=True, lock=None)

    @staticmethod
    def _row_to_entry(row: Any) -> Entry:
        return Entry(
            id=row["id"],
            created_at=row["created_at"],
            rule_id=row["rule_id"],
            title=row["title"],
            dialect=row["dialect"],
            origin=row["origin"],
            parent_id=row["parent_id"],
            note=row["note"],
            source_text=row["source_text"],
            rule_json=row["rule_json"],
            schema_version=row["schema_version"],
        )

    @staticmethod
    def _row_to_dataset(row: Any) -> Dataset:
        return Dataset(
            id=row["id"],
            created_at=row["created_at"],
            name=row["name"],
            description=row["description"],
            format=row["format"],
            table_name=row["table_name"],
            source_type=row["source_type"],
            labels=tuple(json.loads(row["labels_json"])),
            event_count=row["event_count"],
            time_start=row["time_start"],
            time_end=row["time_end"],
            raw_text=row["raw_text"],
            events_json=row["events_json"],
            content_hash=row["content_hash"],
            warnings=tuple(json.loads(row["warnings_json"])),
        )

    @staticmethod
    def _row_to_test_run(row: Any) -> TestRun:
        matches = row["matches_expected"]
        return TestRun(
            id=row["id"],
            created_at=row["created_at"],
            rule_id=row["rule_id"],
            title=row["title"],
            rule_entry_id=row["rule_entry_id"],
            rule_hash=row["rule_hash"],
            dataset_id=row["dataset_id"],
            dataset_hash=row["dataset_hash"],
            expected_verdict=row["expected_verdict"],
            actual_verdict=row["actual_verdict"],
            matches_expected=(None if matches is None else bool(matches)),
            purpose=row["purpose"],
            note=row["note"],
            rule_json=row["rule_json"],
            result_json=row["result_json"],
            evaluator_version=row["evaluator_version"],
        )

    # -- writing ----------------------------------------------------------

    def save(
        self,
        rule: Rule,
        *,
        origin: str,
        source_text: str = "",
        note: str = "",
        parent_id: int | None = None,
        title: str | None = None,
    ) -> Entry:
        """Append a version. Never updates; never overwrites.

        `parent_id` is what makes a tuning session legible later: each save
        during a tuning pass points at the version it was derived from.
        """
        if not isinstance(rule, Rule):
            raise Refusal(
                "STORE_NOT_A_RULE",
                f"`{type(rule).__name__}` is not a Rule.",
                "store",
            )
        if origin not in ORIGINS:
            raise Refusal(
                "STORE_ORIGIN_UNKNOWN",
                f"`{origin}` is not how a rule can come to exist. Use one of: "
                f"{', '.join(sorted(ORIGINS))}. The origin is shown to the "
                f"analyst, because a rule generated from one log line is a "
                f"hypothesis and an authored rule is a decision.",
                "store",
            )

        # Encoded before the row is opened, so a rule the codec refuses never
        # leaves a half-written history behind.
        rule_json = rule_to_json(rule, indent=None)
        dialect = rule.metadata.get("dialect", "")
        resolved_title = (
            title if title is not None else (rule.annotations.title or "")
        )

        with self._connect() as conn:
            if parent_id is not None:
                found = conn.execute(
                    "SELECT id FROM entries WHERE id = ?", (parent_id,)
                ).fetchone()
                if found is None:
                    raise Refusal(
                        "STORE_PARENT_UNKNOWN",
                        f"entry {parent_id} is not in this history, so a rule "
                        f"cannot be recorded as derived from it.",
                        "store",
                    )
            cursor = conn.execute(
                "INSERT INTO entries (created_at, rule_id, title, dialect, "
                "origin, parent_id, note, source_text, rule_json, "
                "schema_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    rule.rule_id,
                    resolved_title,
                    dialect,
                    origin,
                    parent_id,
                    note,
                    source_text,
                    rule_json,
                    SCHEMA_VERSION,
                ),
            )
            new_id = int(cursor.lastrowid or 0)
            row = conn.execute(
                "SELECT * FROM entries WHERE id = ?", (new_id,)
            ).fetchone()
        return self._row_to_entry(row)

    def forget(self, entry_id: int) -> None:
        """Remove one version.

        Deliberately narrow: it refuses to orphan a lineage. Deleting the
        version a later one was tuned from would leave a history that reads as
        if the rule appeared fully formed.
        """
        with self._connect() as conn:
            evidence = conn.execute(
                "SELECT id FROM test_runs WHERE rule_entry_id = ? LIMIT 1",
                (entry_id,),
            ).fetchone()
            if evidence is not None:
                raise Refusal(
                    "STORE_ENTRY_HAS_EVIDENCE",
                    f"entry {entry_id} has saved test evidence. Deleting it would "
                    f"break the evidence trail.",
                    "store",
                )
            children = conn.execute(
                "SELECT id FROM entries WHERE parent_id = ? LIMIT 1", (entry_id,)
            ).fetchone()
            if children is not None:
                raise Refusal(
                    "STORE_ENTRY_HAS_CHILDREN",
                    f"entry {entry_id} is the version later ones were tuned "
                    f"from. Deleting it would leave a lineage whose history "
                    f"starts in the middle.",
                    "store",
                )
            cursor = conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
            if cursor.rowcount == 0:
                raise Refusal(
                    "STORE_ENTRY_UNKNOWN",
                    f"entry {entry_id} is not in this history.",
                    "store",
                )

    # -- reading ----------------------------------------------------------

    def entry(self, entry_id: int) -> Entry:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM entries WHERE id = ?", (entry_id,)
            ).fetchone()
        if row is None:
            raise Refusal(
                "STORE_ENTRY_UNKNOWN",
                f"entry {entry_id} is not in this history.",
                "store",
            )
        return self._row_to_entry(row)

    def rule(self, entry_id: int) -> Rule:
        """The stored Rule, decoded and re-validated on the way out."""
        return rule_from_json(self.entry(entry_id).rule_json)

    def history(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        dialect: str = "",
        origin: str = "",
        query: str = "",
    ) -> list[Entry]:
        """Newest first. Every filter is a bound parameter, never interpolated."""
        if limit < 1 or limit > 500:
            raise Refusal(
                "STORE_LIMIT_INVALID",
                f"`{limit}` is not a page size between 1 and 500.",
                "store",
            )
        if offset < 0:
            raise Refusal(
                "STORE_OFFSET_INVALID", f"`{offset}` is a negative offset.", "store"
            )

        clauses: list[str] = []
        params: list[Any] = []
        if dialect:
            clauses.append("dialect = ?")
            params.append(dialect)
        if origin:
            if origin not in ORIGINS:
                raise Refusal(
                    "STORE_ORIGIN_UNKNOWN",
                    f"`{origin}` is not an origin. Use one of: "
                    f"{', '.join(sorted(ORIGINS))}.",
                    "store",
                )
            clauses.append("origin = ?")
            params.append(origin)
        if query:
            # LIKE with an escaped pattern, so a rule titled "100% CPU" is
            # searchable rather than matching everything.
            pattern = f"%{_escape_like(query)}%"
            clauses.append(
                "(title LIKE ? ESCAPE '\\' OR rule_id LIKE ? ESCAPE '\\' "
                "OR note LIKE ? ESCAPE '\\' OR source_text LIKE ? ESCAPE '\\')"
            )
            params.extend([pattern] * 4)

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM entries{where} "
                f"ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._row_to_entry(r) for r in rows]

    # -- datasets ----------------------------------------------------------

    def save_dataset(
        self,
        *,
        name: str,
        raw_text: str,
        format: str,
        events: list[dict[str, Any]],
        table_name: str = "events",
        description: str = "",
        source_type: str = "imported",
        labels: tuple[str, ...] = (),
        time_start: str = "",
        time_end: str = "",
        warnings: tuple[str, ...] = (),
    ) -> Dataset:
        """Persist an immutable normalized event dataset."""
        if not name.strip():
            raise Refusal(
                "STORE_DATASET_NAME_EMPTY",
                "a dataset needs a name so a test run can identify its evidence.",
                "store",
            )
        if not events:
            raise Refusal(
                "STORE_DATASET_EMPTY",
                "a dataset needs at least one event.",
                "store",
            )
        if not all(isinstance(event, dict) for event in events):
            raise Refusal(
                "STORE_DATASET_EVENT_TYPE",
                "every dataset event must be an object.",
                "store",
            )
        events_json = json.dumps(
            {"schema": 1, "events": _encode_json_value(events)},
            sort_keys=True,
            separators=(",", ":"),
        )
        content_hash = hashlib.sha256(events_json.encode("utf-8")).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO datasets (created_at, name, description, format, "
                "table_name, source_type, labels_json, event_count, time_start, "
                "time_end, raw_text, events_json, content_hash, warnings_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    timestamp,
                    name.strip(),
                    description,
                    format.strip().lower(),
                    table_name.strip() or "events",
                    source_type.strip() or "imported",
                    json.dumps(sorted(set(labels)), separators=(",", ":")),
                    len(events),
                    time_start,
                    time_end,
                    raw_text,
                    events_json,
                    content_hash,
                    json.dumps(list(warnings), separators=(",", ":")),
                ),
            )
            dataset_id = int(cursor.lastrowid or 0)
            row = conn.execute(
                "SELECT * FROM datasets WHERE id = ?", (dataset_id,)
            ).fetchone()
        return self._row_to_dataset(row)

    def dataset(self, dataset_id: int) -> Dataset:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM datasets WHERE id = ?", (dataset_id,)
            ).fetchone()
        if row is None:
            raise Refusal(
                "STORE_DATASET_UNKNOWN",
                f"dataset {dataset_id} is not in this workbench.",
                "store",
            )
        return self._row_to_dataset(row)

    def datasets(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        query: str = "",
        format: str = "",
    ) -> list[Dataset]:
        if limit < 1 or limit > 500:
            raise Refusal(
                "STORE_LIMIT_INVALID",
                f"`{limit}` is not a page size between 1 and 500.",
                "store",
            )
        if offset < 0:
            raise Refusal(
                "STORE_OFFSET_INVALID", f"`{offset}` is a negative offset.", "store"
            )
        clauses: list[str] = []
        params: list[Any] = []
        if query:
            pattern = f"%{_escape_like(query)}%"
            clauses.append(
                "(name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' "
                "OR table_name LIKE ? ESCAPE '\\')"
            )
            params.extend([pattern] * 3)
        if format:
            clauses.append("format = ?")
            params.append(format)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM datasets{where} ORDER BY created_at DESC, id DESC "
                "LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._row_to_dataset(row) for row in rows]

    def dataset_count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM datasets").fetchone()
        return int(row["n"])

    # -- test runs ---------------------------------------------------------

    def save_test_run(
        self,
        *,
        rule: Rule,
        result: dict[str, Any],
        dataset_id: int,
        expected_verdict: str = "",
        purpose: str = "manual",
        note: str = "",
        rule_entry_id: int | None = None,
        evaluator_version: str = "1",
    ) -> TestRun:
        dataset = self.dataset(dataset_id)
        rule_json = rule_to_json(rule, indent=None)
        rule_hash = rule_fingerprint(rule)
        actual = str(result.get("verdict") or "")
        valid_verdicts = {"matched", "no_match", "not_evaluated", "refused"}
        if actual not in valid_verdicts:
            raise Refusal(
                "STORE_TEST_RUN_VERDICT",
                f"`{actual}` is not a supported test verdict.",
                "store",
            )
        if expected_verdict and expected_verdict not in valid_verdicts:
            raise Refusal(
                "STORE_TEST_RUN_VERDICT",
                f"`{expected_verdict}` is not a supported expected verdict.",
                "store",
            )
        matches_expected = (
            None if not expected_verdict else actual == expected_verdict
        )
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        result_json = json.dumps(result, sort_keys=True, separators=(",", ":"))

        with self._connect() as conn:
            if rule_entry_id is not None:
                found = conn.execute(
                    "SELECT id, rule_json FROM entries WHERE id = ?", (rule_entry_id,)
                ).fetchone()
                if found is None:
                    raise Refusal(
                        "STORE_PARENT_UNKNOWN",
                        f"rule entry {rule_entry_id} is not in this history.",
                        "store",
                    )
                if hashlib.sha256(found["rule_json"].encode("utf-8")).hexdigest() != rule_hash:
                    raise Refusal(
                        "STORE_RULE_VERSION_MISMATCH",
                        f"rule entry {rule_entry_id} does not contain the rule being "
                        f"tested. Save the current rule as a new version first.",
                        "store",
                    )
            cursor = conn.execute(
                "INSERT INTO test_runs (created_at, rule_id, title, rule_entry_id, "
                "rule_hash, dataset_id, dataset_hash, expected_verdict, "
                "actual_verdict, matches_expected, purpose, note, rule_json, "
                "result_json, evaluator_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, "
                "?, ?, ?, ?, ?, ?, ?)",
                (
                    timestamp,
                    rule.rule_id,
                    rule.annotations.title,
                    rule_entry_id,
                    rule_hash,
                    dataset_id,
                    dataset.content_hash,
                    expected_verdict,
                    actual,
                    None if matches_expected is None else int(matches_expected),
                    purpose,
                    note,
                    rule_json,
                    result_json,
                    evaluator_version,
                ),
            )
            run_id = int(cursor.lastrowid or 0)
            row = conn.execute(
                "SELECT * FROM test_runs WHERE id = ?", (run_id,)
            ).fetchone()
        return self._row_to_test_run(row)

    def test_run(self, run_id: int) -> TestRun:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM test_runs WHERE id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise Refusal(
                "STORE_TEST_RUN_UNKNOWN",
                f"test run {run_id} is not in this workbench.",
                "store",
            )
        return self._row_to_test_run(row)

    def test_runs(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        rule_hash: str = "",
        dataset_id: int | None = None,
    ) -> list[TestRun]:
        if limit < 1 or limit > 500:
            raise Refusal(
                "STORE_LIMIT_INVALID",
                f"`{limit}` is not a page size between 1 and 500.",
                "store",
            )
        if offset < 0:
            raise Refusal(
                "STORE_OFFSET_INVALID", f"{offset} is a negative offset.", "store"
            )
        clauses: list[str] = []
        params: list[Any] = []
        if rule_hash:
            clauses.append("rule_hash = ?")
            params.append(rule_hash)
        if dataset_id is not None:
            clauses.append("dataset_id = ?")
            params.append(dataset_id)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM test_runs{where} ORDER BY created_at DESC, id DESC "
                "LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._row_to_test_run(row) for row in rows]

    def test_run_count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM test_runs").fetchone()
        return int(row["n"])

    def lineage(self, entry_id: int) -> list[Entry]:
        """The chain from the earliest ancestor down to `entry_id`.

        Oldest first, because that is the order the tuning happened in and the
        order an analyst reads it.
        """
        chain: list[Entry] = []
        seen: set[int] = set()
        current: int | None = entry_id
        while current is not None:
            if current in seen:
                # parent_id is set by this module and should never cycle, but a
                # hand-edited database must not spin forever.
                raise Refusal(
                    "STORE_LINEAGE_CYCLE",
                    f"entry {current} is its own ancestor, so this history has "
                    f"been edited outside the tool.",
                    "store",
                )
            seen.add(current)
            found = self.entry(current)
            chain.append(found)
            current = found.parent_id
        return list(reversed(chain))

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM entries").fetchone()
        return int(row["n"])

    def close(self) -> None:
        """Release the in-memory handle.

        File-backed stores close their connection after every call, so this is
        a no-op for them. It matters for `:memory:`, whose one handle is held
        open for the store's lifetime.
        """
        if self._memory is not None:
            self._memory.close()
            self._memory = None


def _escape_like(text: str) -> str:
    """Escape LIKE wildcards so a search for `%` searches for `%`."""
    return (
        text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )


class _Session:
    """A connection scoped to one operation.

    `with sqlite3.connect(...) as conn` commits the transaction and does NOT
    close the connection -- a genuine sqlite3 trap. Left as-is, every call here
    leaked a handle, and on Windows the leaked handle holds a lock on the
    database file, so the next open fails with a permission error that looks
    like a filesystem problem rather than a bug in this module.
    """

    __slots__ = ("conn", "_close", "_lock")

    def __init__(self, conn: sqlite3.Connection, *, close: bool, lock: Any) -> None:
        self.conn = conn
        self.conn.row_factory = sqlite3.Row
        self._close = close
        self._lock = lock

    def __enter__(self) -> sqlite3.Connection:
        if self._lock is not None:
            self._lock.acquire()
        return self.conn

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        try:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
        finally:
            if self._close:
                self.conn.close()
            if self._lock is not None:
                self._lock.release()

    def close(self) -> None:
        """Release the in-memory handle. File sessions close themselves."""
        self.conn.close()
