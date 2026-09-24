"""Offline match-tester: evaluate LogicNode/sequences/joins against pasted JSON events.

No SIEM connection. Lookups are stubbed as needs-table.
"""
from __future__ import annotations

import json
import re
from typing import Any

from models.correlation import CorrelationModel, LogicNode, Predicate


def _get(event: dict[str, Any], field: str) -> Any:
    if field in event:
        return event[field]
    # dotted lookup
    current: Any = event
    for part in field.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def match_predicate(pred: Predicate, event: dict[str, Any]) -> tuple[bool, str]:
    if pred.operator == "exists":
        present = _get(event, pred.field) is not None
        want = str(pred.value).lower() in {"true", "1", "yes"}
        ok = present == want
        return ok, f"{pred.field} {'present' if present else 'absent'} (exists={want})"
    actual = _get(event, pred.field)
    if actual is None:
        return False, f"{pred.field} missing in event"
    text = str(actual)
    op, val = pred.operator, pred.value
    if op == "in_list" and isinstance(val, list):
        ok = text in [str(v) for v in val] or any(str(v).lower() == text.lower() for v in val)
        return ok, f"{pred.field}={text!r} {'in' if ok else 'not in'} list"
    if op == "equals" and isinstance(val, list):
        ok = any(text == str(v) or text.lower() == str(v).lower() for v in val)
        return ok, f"{pred.field}={text!r} {'in' if ok else 'not in'} list"
    target = str(val[0]) if isinstance(val, list) else str(val)
    low, tlow = text.lower(), target.lower()
    if op == "equals":        ok = low == tlow
    elif op == "contains":
        ok = tlow.strip("*") in low
    elif op == "starts_with":
        ok = low.startswith(tlow)
    elif op == "ends_with":
        ok = low.endswith(tlow)
    elif op == "regex":
        try:
            ok = re.search(target, text) is not None
        except re.error as error:
            return False, f"bad regex {target}: {error}"
    elif op == "exists":
        ok = str(val).lower() in {"true", "1", "yes"}
        return ok, f"{pred.field} {'present' if ok else 'checked absent'} in event"
    elif op == "windash":
        variants = {target, target.replace("-", "/"), target.replace("/", "-")}
        ok = any(v.lower() in low for v in variants)
        return ok, f"{pred.field}={text!r} {'matches' if ok else 'does not match'} -// variant of {target!r}"
    elif op in {"base64", "base64offset"}:
        ok = target in text  # case-sensitive: encodings are case-sensitive
        return ok, f"{pred.field}={text!r} {'matches' if ok else 'does not match'} encoded {target!r}"
    elif op == "wildcard":
        pattern = "^" + re.escape(target).replace(r"\*", ".*").replace(r"\?", ".") + "$"
        ok = re.match(pattern, text, re.IGNORECASE) is not None
    elif op == "cidr":
        import ipaddress
        try:
            ok = ipaddress.ip_address(text) in ipaddress.ip_network(target, strict=False)
        except ValueError as error:
            return False, f"bad CIDR {target}: {error}"
        return ok, f"{pred.field}={text!r} {'inside' if ok else 'outside'} {target!r}"
    else:
        ok = tlow in low
    return ok, f"{pred.field}={text!r} {'matches' if ok else 'does not match'} {op} {target!r}"


def match_node(node: Any, event: dict[str, Any]) -> tuple[bool, list[str]]:
    if isinstance(node, Predicate):
        ok, reason = match_predicate(node, event)
        return ok, [reason]
    if isinstance(node, LogicNode):
        if node.op not in {"and", "or", "not"}:
            raise ValueError(f"Unsupported logic operator: {node.op}.")
        results = [match_node(c, event) for c in node.children or ()]
        reasons = [r for _, rs in results for r in rs]
        if node.op == "and":
            return all(ok for ok, _ in results), reasons
        if node.op == "or":
            return any(ok for ok, _ in results), reasons
        if node.op == "not":
            if len(results) != 1:
                raise ValueError("NOT requires exactly one child.")
            return not results[0][0], reasons
    return False, ["empty logic"]


def _parse_ts(value: Any) -> float | None:
    """Accept epoch seconds or ISO-8601; None when absent/unparseable."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number / 1000.0 if number > 1e12 else number
    try:
        from datetime import datetime, timezone
        text = str(value).strip()
        if re.fullmatch(r"[+-]?\d+(\.\d+)?", text):
            number = float(text)
            return number / 1000.0 if number > 1e12 else number
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (ValueError, TypeError):
        return None


def _window_seconds(window: str) -> tuple[int, bool]:
    """Return (seconds, valid). Supports s/m/h/d up to 999."""
    import re as _re
    match = _re.fullmatch(r"(\d{1,3})([smhd])", str(window or "5m").lower())
    if not match or int(match.group(1)) < 1:
        return 300, False
    return int(match.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)], True


def _is_empty_logic(node: Any) -> bool:
    if node is None:
        return True
    from models.correlation import LogicNode as _LN
    if isinstance(node, _LN):
        return len(node.children or ()) == 0
    return False


MAX_INGEST_CHARS = 2_000_000
MAX_INGEST_EVENTS = 5000
MAX_DISCOVERED_FIELDS = 200


def _discover_fields(events: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Dotted field paths across the corpus (depth<=4, _expected excluded). Returns (fields, warnings)."""
    found: dict[str, None] = {}
    warnings: list[str] = []

    def walk(value: Any, prefix: str, depth: int) -> None:
        if depth > 4 or len(found) >= MAX_DISCOVERED_FIELDS:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str) or not key:
                    continue
                path = f"{prefix}.{key}" if prefix else key
                if path == "_expected":
                    continue
                found[path] = None
                walk(item, path, depth + 1)

    for event in events:
        walk(event, "", 1)
    fields = sorted(found)
    if len(found) >= MAX_DISCOVERED_FIELDS:
        warnings.append(f"Field discovery capped at {MAX_DISCOVERED_FIELDS} fields.")
    return fields, warnings


def _parse_json_events(text: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"Not a JSON array: {error}") from error
    if not isinstance(document, list) or not document:
        raise ValueError("JSON input must be a non-empty array of event objects.")
    if any(not isinstance(item, dict) for item in document):
        raise ValueError("Every event must be a JSON object.")
    return document


def _parse_ndjson_events(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    bad = 0
    shown: list[str] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            item = None
        if not isinstance(item, dict):
            bad += 1
            if len(shown) < 10:
                shown.append(f"line {lineno}")
            continue
        events.append(item)
    warnings = [f"Skipped {bad} non-object line(s): {', '.join(shown)}{'...' if bad > len(shown) else ''}."] if bad else []
    if not events:
        raise ValueError("No valid NDJSON event objects found.")
    return events, warnings


def _parse_csv_events(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    import csv as _csv
    import io as _io
    try:
        rows = list(_csv.DictReader(_io.StringIO(text)))
    except _csv.Error as error:
        raise ValueError(f"Not parseable CSV: {error}") from error
    if not rows:
        raise ValueError("CSV has no data rows.")
    warnings: list[str] = []
    label_keys = [k for k in (rows[0] or {}) if isinstance(k, str) and k.strip().lower() in {"_expected", "expected", "label"}]
    label_key = label_keys[0] if label_keys else None
    if label_key and label_key != "_expected":
        warnings.append(f"Column {label_key!r} mapped to _expected labels.")
    events: list[dict[str, Any]] = []
    dropped = 0
    for row in rows:
        event: dict[str, Any] = {}
        for key, value in (row or {}).items():
            if not isinstance(key, str) or not key.strip():
                continue
            if key == label_key:
                event["_expected"] = value
                continue
            if value is None or (isinstance(value, str) and not value.strip()):
                dropped += 1
                continue
            event[key.strip()] = value
        if event:
            events.append(event)
    if dropped:
        warnings.append(f"Dropped {dropped} empty cell(s) — empty strings would match everything.")
    if not events:
        raise ValueError("CSV yielded no usable events.")
    return events, warnings


def ingest_events(content: Any, format: str = "auto") -> dict[str, Any]:
    """Parse pasted sample data (F8: JSON array, NDJSON, or CSV) into tester-ready events
    plus dotted field discovery. Everything stays local. Raises ValueError with a clear
    message on bad input. Caps: 2MB content, 5000 events, 200 discovered fields."""
    text = content if isinstance(content, str) else ""
    if not text.strip():
        raise ValueError("Paste sample events first (JSON array, NDJSON, or CSV).")
    if len(text) > MAX_INGEST_CHARS:
        raise ValueError(f"Sample data exceeds {MAX_INGEST_CHARS // 1_000_000}MB; split it into smaller batches.")
    kind = str(format or "auto").lower()
    if kind not in {"auto", "json", "ndjson", "csv"}:
        raise ValueError("Format must be auto, json, ndjson, or csv.")
    warnings: list[str] = []
    events: list[dict[str, Any]] = []
    detected = kind
    if kind in {"auto", "json"}:
        try:
            events = _parse_json_events(text)
            detected = "json"
        except ValueError:
            if kind == "json":
                raise
    if not events and kind in {"auto", "ndjson"}:
        try:
            events, warnings = _parse_ndjson_events(text)
            detected = "ndjson"
        except ValueError:
            if kind == "ndjson":
                raise
    if not events:
        if kind == "csv":
            events, warnings = _parse_csv_events(text)
            detected = "csv"
        elif kind == "auto":
            try:
                events, warnings = _parse_csv_events(text)
                detected = "csv"
            except ValueError:
                raise ValueError("Could not parse as JSON array, NDJSON, or CSV.")
        else:
            raise ValueError("No events found.")
    if len(events) > MAX_INGEST_EVENTS:
        raise ValueError(f"Too many events ({len(events)}); limit is {MAX_INGEST_EVENTS} per batch.")
    fields, field_warnings = _discover_fields(events)
    return {"events": events, "count": len(events), "fields": fields,
            "warnings": warnings + field_warnings, "format": detected}


def test_events(model: CorrelationModel, events: list[dict[str, Any]]) -> dict[str, Any]:
    per_event = []
    matched = 0
    empty_logic = _is_empty_logic(model.logic)
    for idx, event in enumerate(events):
        if empty_logic:
            per_event.append({"index": idx, "matched": False, "reasons": ["no logic"]})
            continue
        ok, reasons = match_node(model.logic, event)
        suppressed = False
        for excl in model.exclusions:
            eok, ereasons = match_node(excl, event)
            reasons.extend(f"exclusion: {r}" for r in ereasons)
            if eok:
                suppressed = True
        fired = ok and not suppressed
        if fired:
            matched += 1
        per_event.append({"index": idx, "matched": fired, "suppressed_by_exclusion": suppressed and ok, "reasons": reasons})
    threshold = model.threshold or 1
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError(f"Threshold must be a whole number >= 1, got {model.threshold!r}.")
    group_by = model.group_by
    if isinstance(group_by, str):
        group_by = [group_by]
    elif not isinstance(group_by, list):
        group_by = []
    notes = []
    # group-by partitions: threshold applies per partition tuple (SIEM semantics)
    group_keys = [k for k in (group_by or []) if k]
    partitions: dict[str, int] = {}
    for entry, event in zip(per_event, events):
        if entry["matched"]:
            if group_keys:
                parts = [str(_get(event, k)) if _get(event, k) is not None else "missing" for k in group_keys]
                key = "|".join(parts)
            else:
                key = "all"
            partitions[key] = partitions.get(key, 0) + 1
    best_partition = max(partitions.items(), key=lambda kv: kv[1], default=("—", 0))
    firing_count = best_partition[1] if partitions else matched
    # temporal window: sliding check per partition — any `threshold` matches inside window
    window_s, window_valid = _window_seconds(model.window)
    if not window_valid:
        notes.append(f"Window {model.window!r} is not valid (use like 30s, 5m, 1h, 1d); defaulted to 5m for this test.")
    window_ok = True
    if threshold > 1:
        window_ok = False
        by_partition: dict[str, list[float]] = {}
        for entry, event in zip(per_event, events):
            if not entry["matched"]:
                continue
            ts = _parse_ts(event.get("timestamp"))
            pkey = "|".join(str(_get(event, k)) if _get(event, k) is not None else "missing" for k in group_keys) if group_keys else "all"
            by_partition.setdefault(pkey, []).append(ts if ts is not None else float("-inf"))
        for stamps in by_partition.values():
            ordered = sorted(s for s in stamps if s != float("-inf"))
            timeless = len(stamps) - len(ordered)
            if timeless >= threshold:
                window_ok = True
                break
            for i in range(len(ordered) - threshold + 1):
                if ordered[i + threshold - 1] - ordered[i] <= window_s:
                    window_ok = True
                    break
            if window_ok:
                break
        if not window_ok:
            notes.append(f"No partition has {threshold} matches inside window {model.window}; rule would not fire as a threshold detection.")
    would_fire = firing_count >= threshold and window_ok
    suppressed_only = matched > 0 and all(e.get("suppressed_by_exclusion") for e in per_event if not e["matched"])
    if would_fire:
        verdict, count_detail = "would-fire", f"{firing_count}/{threshold} in best partition"
    elif suppressed_only:
        verdict, count_detail = "suppressed", f"{matched} matched but excluded"
    elif matched:
        verdict, count_detail = "no-match", f"count {firing_count}/{threshold} — under threshold"
    else:
        verdict, count_detail = "no-match", f"0/{threshold}"
    if model.sequences:
        notes.append("Sequence order/maxspan must be checked in native SIEM; tester counts single-event matches only.")
    if model.joins:
        notes.append("Joins need multi-stream data; tester evaluates per-event predicates only.")
    if model.lookups:
        notes.append("Lookups need their tables; treated as needs-table, not executed.")
    from models.correlation import LogicNode as _LN, Predicate as _P

    def _has_op(node: Any, ops: set[str]) -> bool:
        if isinstance(node, _P):
            return node.operator in ops
        if isinstance(node, _LN):
            return any(_has_op(c, ops) for c in node.children or ())
        return False

    if _has_op(model.logic, {"base64", "base64offset"}):
        notes.append("base64 matched on encoded text only; verify against decoded samples too.")
    # G5+G9: TP/FP scoring + volume sense from _expected labels
    scoring = _score(per_event, events)
    if model.threshold and model.threshold > 1 and not any(e.get("timestamp") is not None for e in events):
        notes.append("No timestamps on sample events; window check skipped (counts only).")
    return {"matched": matched, "total": len(events), "threshold": threshold, "would_fire": would_fire,
            "verdict": verdict, "count_detail": count_detail, "per_event": per_event, "notes": notes,
            "partitions": partitions, "window_ok": window_ok, "window_valid": window_valid,
            "scoring": scoring}


def replay_fixture(model: CorrelationModel, events: list[dict[str, Any]]) -> dict[str, Any]:
    """P1-A detection-as-code replay: evaluate a fixture and list every event that
    did not behave as pinned. A fixture passes only when no expectation is violated."""
    from evaluator.match_tester import test_events as _run  # self-reference clarity
    result = _run(model, events)
    mismatches = []
    for entry, event in zip(result["per_event"], events):
        expected = _coerce_expected(event.get("_expected"))
        if expected is None:
            mismatches.append({"index": entry["index"], "expected": None, "actual": bool(entry["matched"]),
                               "reasons": entry.get("reasons", [])[:3]})
        elif bool(entry["matched"]) != expected:
            mismatches.append({"index": entry["index"], "expected": expected,
                               "actual": bool(entry["matched"]), "reasons": entry.get("reasons", [])[:3]})
    scoring = result["scoring"]
    return {"passed": not mismatches, "event_count": len(events), "mismatches": mismatches,
            "scoring": scoring, "would_fire": result["would_fire"], "verdict": result["verdict"]}


def _coerce_expected(value: Any) -> bool | None:
    if value is True or value is False:
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return True if value == 1 else (False if value == 0 else None)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"true", "yes", "y", "1", "expected", "malicious"}:
            return True
        if low in {"false", "no", "n", "0", "benign", "unexpected"}:
            return False
    return None


def _score(per_event: list[dict[str, Any]], events: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = fn = tn = unlabeled = 0
    for entry, event in zip(per_event, events):
        expected = _coerce_expected(event.get("_expected"))
        if expected is True:
            if entry["matched"]:
                tp += 1
            else:
                fn += 1
        elif expected is False:
            if entry["matched"]:
                fp += 1
            else:
                tn += 1
        else:
            unlabeled += 1
    labeled = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    benign_fire_rate = fp / (fp + tn) if (fp + tn) else None
    volume_note = ""
    benign_n = fp + tn
    if benign_n == 1 and fp == 1:
        volume_note = "Single benign sample matched — add more benign samples before trusting this signal."
    elif benign_fire_rate is not None and benign_fire_rate >= 0.5 and benign_n >= 2:
        volume_note = f"High benign fire rate ({benign_fire_rate:.0%} of benign samples match) — expect noise; add exclusions or raise the threshold."
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "unlabeled": unlabeled,
            "precision": precision, "recall": recall, "benign_fire_rate": benign_fire_rate,
            "volume_note": volume_note}
