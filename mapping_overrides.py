"""Persistent analyst field-mapping overrides.

Every real detection team has organization-specific field names: a custom Splunk
CIM alias, a Falcon log source that renames CommandLine, an internal ECS namespace.
The professional answer is not "the tool knows every schema" - it is "the tool lets
the analyst pin the mapping once and it persists."

Overrides are stored in data/mappings/overrides.json, which is merged on top of the
generated mappings (rule_engine._load_field_mappings). Every override records who
pinned it and why, so a later reader can tell an intentional org convention from a
generated guess. Invalid entries are rejected at write time rather than silently
dropped at load time.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from models.correlation import LOGIC  # noqa: F401  (kept import surface stable)

FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,254}$")
# A native field name is interpolated directly into generated query text, so it must look
# like a field identifier in every target dialect. Allowing quotes would let a stored
# override close a string literal and append arbitrary boolean clauses to every rule the
# analyst later generates - silently, long after the override was saved.
NATIVE_FIELD_RE = re.compile(r"^[A-Za-z_@][A-Za-z0-9_.@-]{0,127}$")
KNOWN_TARGETS = frozenset({
    "sigma", "elastic", "splunk", "sentinel", "google_secops", "falcon", "wazuh", "qradar",
})


class OverrideError(ValueError):
    """Raised when an override is malformed; the message is shown to the analyst."""


def _path(root: Path) -> Path:
    return root / "data" / "mappings" / "overrides.json"


def load_overrides(root: Path) -> dict[str, dict[str, str]]:
    """target -> {canonical_field: native_field}. A missing or corrupt file yields {}.

    Persisted values are re-validated on load, not trusted. Write-time validation can
    be bypassed by a hand-edited, stale, or migrated overrides.json, and a value
    containing a quote is interpolated straight into generated query text - so a
    malformed file must not be able to reintroduce injection.
    """
    path = _path(root)
    if not path.exists():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    tables = document.get("mappings") if isinstance(document, dict) else None
    if not isinstance(tables, dict):
        return {}
    out: dict[str, dict[str, str]] = {}
    for target, table in tables.items():
        if not isinstance(target, str) or not isinstance(table, dict):
            continue
        clean: dict[str, str] = {}
        for key, value in table.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            if not FIELD_RE.match(key) or not NATIVE_FIELD_RE.match(value):
                continue
            clean[key] = value
        if clean:
            out[target] = clean
    return out


def load_provenance(root: Path) -> dict[str, Any]:
    path = _path(root)
    if not path.exists():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    notes = document.get("notes") if isinstance(document, dict) else None
    return notes if isinstance(notes, dict) else {}


def validate_target(target: Any) -> str:
    name = str(target or "").strip().lower()
    if name not in KNOWN_TARGETS:
        raise OverrideError(f"Unknown target {target!r}. Known targets: {', '.join(sorted(KNOWN_TARGETS))}.")
    return name


def validate_pair(canonical: Any, native: Any) -> tuple[str, str]:
    source = str(canonical or "").strip()
    target = str(native or "").strip()
    if not FIELD_RE.match(source):
        raise OverrideError(f"Canonical field {canonical!r} must be dotted field notation (e.g. process.command_line).")
    if not NATIVE_FIELD_RE.match(target):
        raise OverrideError(
            f"Native field {native!r} must be a bare field identifier: letters, digits, _ . - @ only. "
            "Quotes, spaces and operators are rejected because the name is inserted into query text.")
    return source, target


def write_override(root: Path, target: Any, canonical: Any, native: Any,
                   reason: str = "", author: str = "analyst") -> dict[str, Any]:
    """Pin one org-specific mapping. Rejects malformed input before touching disk."""
    target_name = validate_target(target)
    source, mapped = validate_pair(canonical, native)
    note = str(reason or "").strip()[:280]
    who = str(author or "").strip()[:64] or "analyst"
    path = _path(root)
    document: dict[str, Any] = {"mappings": {}, "notes": {}}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                document = loaded
        except (OSError, json.JSONDecodeError):
            document = {"mappings": {}, "notes": {}}
    tables = document.setdefault("mappings", {})
    notes = document.setdefault("notes", {})
    table = tables.setdefault(target_name, {})
    table[source] = mapped
    notes[f"{target_name}:{source}"] = {"native": mapped, "reason": note, "author": who}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=1, sort_keys=True), encoding="utf-8")
    return {"target": target_name, "canonical_field": source, "native_field": mapped,
            "reason": note, "author": who, "total_overrides": sum(len(t) for t in tables.values())}


def clear_override(root: Path, target: Any, canonical: Any) -> dict[str, Any]:
    """Remove a single override so the generated mapping applies again."""
    target_name = validate_target(target)
    source = str(canonical or "").strip()
    if not FIELD_RE.match(source):
        raise OverrideError(f"Canonical field {canonical!r} is not valid dotted field notation.")
    path = _path(root)
    if not path.exists():
        return {"removed": False, "target": target_name, "canonical_field": source}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"removed": False, "target": target_name, "canonical_field": source}
    tables = document.get("mappings") if isinstance(document, dict) else None
    if not isinstance(tables, dict) or source not in (tables.get(target_name) or {}):
        return {"removed": False, "target": target_name, "canonical_field": source}
    del tables[target_name][source]
    if not tables[target_name]:
        del tables[target_name]
    if isinstance(document.get("notes"), dict):
        document["notes"].pop(f"{target_name}:{source}", None)
    path.write_text(json.dumps(document, indent=1, sort_keys=True), encoding="utf-8")
    return {"removed": True, "target": target_name, "canonical_field": source,
            "total_overrides": sum(len(t) for t in tables.values())}


def override_tables(root: Path) -> dict[str, dict[str, str]]:
    """Public alias used by the loader."""
    return load_overrides(root)
