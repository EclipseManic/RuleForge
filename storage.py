"""Persistent local history for the RuleForge workbench.

SQLite keeps the prototype self-contained. A production deployment should move
this repository behind authenticated API endpoints and a managed database.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


class RuleStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with closing(self._connection()) as connection, connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS rule_history (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    title TEXT NOT NULL,
                    siem TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )"""
            )
            for column in ("sigma_yaml TEXT DEFAULT ''", "fidelity TEXT DEFAULT ''",
                           "version INTEGER DEFAULT 1", "parent_id TEXT DEFAULT ''"):
                try:
                    connection.execute(f"ALTER TABLE rule_history ADD COLUMN {column}")
                except sqlite3.OperationalError as error:
                    if "duplicate column name" not in str(error).lower():
                        raise
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(rule_history)").fetchall()}
            missing = {"sigma_yaml", "fidelity", "version", "parent_id"} - columns
            if missing:
                raise RuntimeError(f"rule_history migration failed; missing columns: {sorted(missing)}.")

    def record_history(
        self,
        kind: str,
        title: str,
        siem: str,
        summary: str,
        payload: dict[str, Any],
        details: dict[str, Any],
        parent_id: str = "",
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        history_id = f"H-{uuid4().hex[:10].upper()}"
        with closing(self._connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT COALESCE(MAX(version), 0) AS v, MAX(created_at) AS latest FROM rule_history WHERE title = ?",
                    (title,),
                ).fetchone()
                try:
                    version = int(row["v"]) + 1
                except (TypeError, ValueError):
                    version = 1
                parent_row = connection.execute(
                    "SELECT id FROM rule_history WHERE title = ? ORDER BY version DESC, rowid DESC LIMIT 1",
                    (title,),
                ).fetchone()
                if not parent_id:
                    parent_id = parent_row["id"] if parent_row else ""
                record = {
                    "id": history_id,
                    "kind": kind,
                    "title": title,
                    "siem": siem,
                    "summary": summary,
                    "created_at": now,
                    "version": version,
                    "parent_id": parent_id,
                }
                connection.execute(
                    """INSERT INTO rule_history
                       (id, kind, title, siem, summary, payload_json, details_json, created_at, version, parent_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (history_id, kind, title, siem, summary, json.dumps(payload), json.dumps(details), now, version, parent_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return record

    def next_version(self, title: str) -> int:
        with closing(self._connection()) as connection, connection:
            row = connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS v FROM rule_history WHERE title = ?", (title,)
            ).fetchone()
        try:
            return int(row["v"]) + 1 if row else 1
        except (TypeError, ValueError):
            return 1

    def latest_id(self, title: str) -> str:
        with closing(self._connection()) as connection, connection:
            row = connection.execute(
                "SELECT id FROM rule_history WHERE title = ? ORDER BY version DESC, rowid DESC LIMIT 1", (title,)
            ).fetchone()
        return row["id"] if row else ""

    def list_history(self, limit: int = 50) -> list[dict[str, Any]]:
        with closing(self._connection()) as connection, connection:
            rows = connection.execute(
                "SELECT id, kind, title, siem, summary, payload_json, details_json, created_at, "
                "COALESCE(sigma_yaml,'') AS sigma_yaml, COALESCE(fidelity,'') AS fidelity, "
                "COALESCE(version,1) AS version, COALESCE(parent_id,'') AS parent_id "
                "FROM rule_history ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        records = []
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
                details = json.loads(row["details_json"])
            except (json.JSONDecodeError, TypeError, KeyError):
                continue  # quarantine corrupt rows instead of failing whole history
            records.append({**dict(row), "payload": payload, "details": details})
        return records

    def clear_history(self) -> None:
        with closing(self._connection()) as connection, connection:
            connection.execute("DELETE FROM rule_history")


class FixtureStore:
    """Per-rule test fixtures: the detection-as-code loop (P1-A).

    A fixture pins events plus their expected verdicts for a named rule so every
    later edit can be replayed to prove the rule still behaves as intended.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with closing(self._connection()) as connection, connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS rule_fixtures (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    siem TEXT NOT NULL DEFAULT '',
                    events_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )"""
            )

    def save_fixture(self, title: str, events: list[dict[str, Any]], siem: str = "") -> dict[str, Any]:
        if not isinstance(title, str) or not title.strip():
            raise ValueError("Fixture title is required.")
        if not isinstance(events, list) or not events:
            raise ValueError("Fixture needs at least one event.")
        if len(events) > 5000:
            raise ValueError("Fixture is limited to 5000 events.")
        if any(not isinstance(event, dict) for event in events):
            raise ValueError("Every fixture event must be a JSON object.")
        normalized = []
        for event in events:
            entry = {str(k): v for k, v in event.items() if isinstance(k, str) and k}
            if "_expected" not in entry:
                raise ValueError("Every fixture event needs an _expected label (true/false).")
            entry["_expected"] = bool(entry["_expected"]) if isinstance(entry["_expected"], bool) else \
                str(entry["_expected"]).strip().lower() in {"true", "yes", "1", "malicious", "expected"}
            normalized.append(entry)
        now = datetime.now(timezone.utc).isoformat()
        fixture_id = f"F-{uuid4().hex[:10].upper()}"
        with closing(self._connection()) as connection, connection:
            connection.execute(
                "INSERT INTO rule_fixtures (id, title, siem, events_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (fixture_id, title.strip()[:140], str(siem or "")[:40], json.dumps(normalized), now),
            )
        return {"id": fixture_id, "title": title.strip()[:140], "siem": str(siem or "")[:40],
                "events": len(normalized), "created_at": now}

    def list_fixtures(self, limit: int = 100) -> list[dict[str, Any]]:
        with closing(self._connection()) as connection:
            rows = connection.execute(
                "SELECT id, title, siem, events_json, created_at FROM rule_fixtures "
                "ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        records = []
        for row in rows:
            try:
                events = json.loads(row["events_json"])
            except (json.JSONDecodeError, TypeError):
                continue  # quarantine corrupt fixtures
            if not isinstance(events, list):
                continue
            records.append({**dict(row), "events": events, "event_count": len(events)})
        return records

    def delete_fixture(self, fixture_id: str) -> bool:
        with closing(self._connection()) as connection, connection:
            cursor = connection.execute("DELETE FROM rule_fixtures WHERE id = ?", (str(fixture_id),))
        return cursor.rowcount > 0
