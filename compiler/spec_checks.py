"""Spec-grounded Sigma validation inventory (G1) + technique-ID/ATT&CK guidance (G8).

Mirrors pySigma's validator taxonomy offline: identifier, title, dangling
refs, filename, modifiers, wildcards, enums — each finding carries a
LOW/MEDIUM/HIGH severity. No new dependencies.
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
STATUS_VALUES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVEL_VALUES = {"informational", "low", "medium", "high", "critical"}
KNOWN_MODIFIERS = {"contains", "startswith", "endswith", "re", "base64", "base64offset",
                   "windash", "cidr", "exists", "all", "expand", "utf16", "utf16le", "utf16be", "wide"}

# G8: per-technique detection guidance surfaced to the analyst (seed; extended from data file below).
_BUILTIN_TECHNIQUE_GUIDANCE = {
    "T1110": "Brute force: correlate repeated failures with a later success; group by user+source IP; baseline normal logon volume first.",
    "T1059.001": "PowerShell: watch encoded (-enc) and hidden (-w hidden) switches; allowlist admin automation accounts explicitly.",
    "T1027": "Obfuscation: encoded payloads often decode at runtime — match on both the encoded token and decoded artifacts.",
    "T1059": "Command execution: parent/child process relationships beat command-line substrings for precision.",
    "T1098": "Persistence via accounts: alert on group-membership deltas, not snapshots; exclude provisioning service accounts.",
}


def _load_technique_guidance() -> dict[str, str]:
    """Guidance from data/techniques.json (fp_guidance per MITRE id) over the seed (F7)."""
    guidance = dict(_BUILTIN_TECHNIQUE_GUIDANCE)
    try:
        document = json.loads((Path(__file__).resolve().parent.parent / "data" / "techniques.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return guidance
    entries = document.get("techniques") if isinstance(document, dict) else None
    if not isinstance(entries, dict):
        return guidance
    for entry in entries.values():
        if not isinstance(entry, dict):
            continue
        text = entry.get("fp_guidance") or entry.get("description")
        if not text:
            continue
        for technique in entry.get("mitre", []) or []:
            guidance[str(technique)] = str(text)
    return guidance


TECHNIQUE_GUIDANCE = _load_technique_guidance()


def validate_sigma_inventory(yaml_text: str) -> list[dict[str, str]]:
    """Return findings [{id, severity, message}]. Empty = clean."""
    from parsers.sigma_parser import parse_sigma

    findings: list[dict[str, str]] = []
    if not (yaml_text or "").strip():
        return [{"id": "empty_document", "severity": "HIGH", "message": "Sigma YAML is empty."}]
    try:
        _, meta = parse_sigma(yaml_text)
    except ValueError as error:
        return [{"id": "unparseable", "severity": "HIGH", "message": str(error)}]
    title = str(meta.get("title", ""))
    if not title:
        findings.append({"id": "missing_title", "severity": "HIGH", "message": "Missing 'title'."})
    elif not 10 <= len(title) <= 256:
        findings.append({"id": "title_length", "severity": "MEDIUM",
                         "message": f"Title length {len(title)} outside 10–256 characters."})
    rule_id = meta.get("id")
    if rule_id is None:
        findings.append({"id": "identifier_existence", "severity": "MEDIUM",
                         "message": "No 'id' — add a UUIDv4 so the rule is referenceable."})
    elif not UUID_RE.match(str(rule_id)):
        findings.append({"id": "identifier_format", "severity": "MEDIUM",
                         "message": f"'id' {rule_id!r} is not UUIDv4."})
    if not meta.get("logsource"):
        findings.append({"id": "missing_logsource", "severity": "HIGH",
                         "message": "Missing 'logsource' (product/category/service)."})
    status = str(meta.get("status", "test")).lower()
    if status not in STATUS_VALUES:
        findings.append({"id": "status_enum", "severity": "MEDIUM",
                         "message": f"status {status!r} not in {sorted(STATUS_VALUES)}."})
    level = str(meta.get("level", "medium")).lower()
    if level not in LEVEL_VALUES:
        findings.append({"id": "level_enum", "severity": "MEDIUM",
                         "message": f"level {level!r} not in {sorted(LEVEL_VALUES)}."})
    # dangling detection <-> condition both directions (token boundaries, not substrings)
    detection = meta.get("detection_raw") or {}
    condition_raw = str(meta.get("sigma_condition", "selection"))
    condition_tokens = set(t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", condition_raw))
    for name in detection:
        if name != "condition" and name.lower() not in condition_tokens and not any(
                t == name.lower() or t.startswith(name.lower() + "_") or name.lower().startswith(t.rstrip("*") + "_") for t in condition_tokens):
            # '1 of selection_*' style references cover whole families
            if not re.search(r"\b(?:1|any|all)\s+of\s+" + re.escape(name.lower().rstrip("_")) + r"[\s_*]", condition_raw.lower()):
                findings.append({"id": "dangling_detection", "severity": "HIGH",
                                 "message": f"Detection '{name}' is never referenced by condition."})
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_*]*", condition_raw):
        low = token.lower()
        if low in {"and", "or", "not", "of", "all", "any", "them", "selection", "filter"} or token in {"1"}:
            continue
        stem = token.rstrip("*").rstrip("_")
        if stem not in {k.lower() for k in detection} and not any(k.lower() == stem or k.lower().startswith(stem + "_") for k in detection):
            findings.append({"id": "dangling_condition", "severity": "HIGH",
                             "message": f"Condition references unknown selection '{token}'."})
    # modifier + wildcard hygiene from raw YAML text
    for raw_field in re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_.-]*(?:\|[A-Za-z0-9]+)+)\s*:", yaml_text, re.MULTILINE | re.IGNORECASE):
        for modifier in raw_field.split("|")[1:]:
            if modifier.lower() not in KNOWN_MODIFIERS:
                findings.append({"id": "unknown_modifier", "severity": "MEDIUM",
                                 "message": f"Unknown modifier '|{modifier}' on '{raw_field}'."})
                break
    for raw_field, value in re.findall(r"^\s*([A-Za-z_.]+)\s*:\s*(?:-\s*)?['\"]?(\*[^'\"\n]*|[^'\"\n]*\*)['\"]?\s*$", yaml_text, re.MULTILINE):
        if "|" not in raw_field and ("*" in value):
            findings.append({"id": "wildcards_instead_of_modifiers", "severity": "LOW",
                             "message": f"Field '{raw_field}' uses * wildcards; prefer |contains/|startswith/|endswith modifiers."})
            break
    # encoding modifiers that break queries
    if re.search(r"\|(utf16|utf16le|utf16be|wide)\b", yaml_text, re.IGNORECASE):
        findings.append({"id": "encoding_modifier", "severity": "MEDIUM",
                         "message": "utf16/wide modifiers produce byte sequences most backends cannot query; verify target support."})
    return findings


def check_technique_ids(ids: list[str]) -> list[dict[str, str]]:
    """Validate MITRE technique IDs + attach detection guidance (G8)."""
    findings = []
    for technique in ids:
        if not TECHNIQUE_RE.match(str(technique)):
            findings.append({"id": "technique_format", "severity": "MEDIUM", "kind": "finding",
                             "message": f"{technique!r} is not a T####(.###) technique ID."})
            continue
        base = str(technique).split(".")[0]
        guidance = TECHNIQUE_GUIDANCE.get(str(technique)) or TECHNIQUE_GUIDANCE.get(base)
        if guidance:
            findings.append({"id": "technique_guidance", "severity": "LOW", "kind": "guidance",
                             "message": f"{technique}: {guidance}"})
    return findings
