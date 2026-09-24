"""Vendor-aware rule rendering for RuleForge.

The output intentionally uses common-normalized fields. Analysts should map those
fields to their own data model and validate in a non-production environment.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
import yaml
from html import escape as xml_escape
from dataclasses import dataclass, field as dataclass_field, replace
from pathlib import Path
from typing import Any

from detection_model import DetectionDocument


def _load_catalog(filename: str) -> dict[str, Any]:
    """Load a JSON data file from data/; {} when missing or invalid (offline-safe)."""
    try:
        document = json.loads((Path(__file__).resolve().parent / "data" / filename).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return document if isinstance(document, dict) else {}


class RuleValidationError(ValueError):
    pass


SIEMS = {
    "sigma": {"name": "Sigma (vendor-neutral)", "language": "Sigma YAML", "accent": "#d8e58a"},
    "splunk": {"name": "Splunk Enterprise Security", "language": "SPL", "accent": "#75e0a7"},
    "sentinel": {"name": "Microsoft Sentinel", "language": "KQL", "accent": "#5c9cff"},
    "elastic": {"name": "Elastic Security", "language": "EQL", "accent": "#f5b74e"},
    "qradar": {"name": "IBM QRadar", "language": "AQL", "accent": "#d596ff"},
    "google_secops": {"name": "Google SecOps", "language": "YARA-L 2.0", "accent": "#ff8875"},
    "falcon": {"name": "CrowdStrike Falcon LogScale", "language": "CQL", "accent": "#46d9cf"},
    "wazuh": {"name": "Wazuh", "language": "Ruleset XML", "accent": "#7fb3ff"},
}

_BUILTIN_TECHNIQUES = {
    "failed_logins": {
        "label": "Repeated failed sign-ins",
        "default_field": "user.name",
        "default_value": "*",
        "event_category": "authentication",
        "event_filter": "event.outcome == \"failure\"",
        "mitre": ["T1110"],
        "description": "Detects repeated unsuccessful authentication attempts for the same account.",
    },
    "encoded_powershell": {
        "label": "Encoded PowerShell execution",
        "default_field": "process.command_line",
        "default_value": "-enc",
        "event_category": "process",
        "event_filter": "process.name == \"powershell.exe\"",
        "mitre": ["T1059.001", "T1027"],
        "description": "Detects PowerShell started with an encoded command switch.",
    },
    "suspicious_process": {
        "label": "Suspicious process command",
        "default_field": "process.command_line",
        "default_value": "*",
        "event_category": "process",
        "event_filter": "event.type == \"start\"",
        "mitre": ["T1059"],
        "description": "Detects a process start matching a command-line indicator.",
    },
    "new_admin": {
        "label": "Privileged group membership change",
        "default_field": "group.name",
        "default_value": "Administrators",
        "event_category": "iam",
        "event_filter": "event.action == \"group-member-added\"",
        "mitre": ["T1098"],
        "description": "Detects an account being added to a privileged group.",
    },
    "custom": {
        "label": "Custom event match",
        "default_field": "process.name",
        "default_value": "example.exe",
        "event_category": "any",
        "event_filter": "true",
        "mitre": [],
        "description": "Build a rule from a normalized field, operator, and value.",
    },
}

_TECHNIQUE_KEYS = ("label", "default_field", "default_value", "event_category",
                   "event_filter", "mitre", "description")


def _load_techniques() -> dict[str, dict[str, Any]]:
    """Catalog from data/techniques.json over the builtin quick starts (F7). Entries missing
    renderer keys are skipped so a bad row can never 500 a render."""
    catalog: dict[str, dict[str, Any]] = {key: dict(value) for key, value in _BUILTIN_TECHNIQUES.items()}
    document = _load_catalog("techniques.json")
    entries = document.get("techniques")
    if not isinstance(entries, dict):
        return catalog
    for key, entry in entries.items():
        if not isinstance(entry, dict) or any(k not in entry for k in _TECHNIQUE_KEYS):
            continue
        catalog[str(key)] = {k: entry[k] for k in (*_TECHNIQUE_KEYS, "tactic", "fp_guidance") if k in entry}
    return catalog


TECHNIQUES = _load_techniques()
# Canonical input fields are translated when a well-known native field exists.
# Unknown custom fields remain untouched and are flagged to the reviewer.
_BUILTIN_FIELD_MAPPINGS = {
    "sigma": {field: field for field in ("process.command_line", "process.name", "user.name", "group.name", "host.name", "source.ip", "destination.ip")},
    "splunk": {"process.command_line": "process_command_line", "process.name": "process_name", "user.name": "user", "group.name": "group_name", "host.name": "host", "source.ip": "src_ip", "destination.ip": "dest_ip"},
    "sentinel": {"process.command_line": "ProcessCommandLine", "process.name": "FileName", "user.name": "Account", "group.name": "GroupName", "host.name": "Computer", "source.ip": "IPAddress", "destination.ip": "DestinationIP"},
    "elastic": {"process.command_line": "process.command_line", "process.name": "process.name", "user.name": "user.name", "group.name": "group.name", "host.name": "host.name", "source.ip": "source.ip", "destination.ip": "destination.ip"},
    "qradar": {"process.command_line": "UTF8(payload)", "process.name": "processName", "user.name": "username", "group.name": "groupName", "host.name": "hostname", "source.ip": "sourceIP", "destination.ip": "destinationIP"},
    "google_secops": {"process.command_line": "target.process.command_line", "process.name": "target.process.file.full_path", "user.name": "principal.user.userid", "group.name": "target.group.group_display_name", "host.name": "principal.hostname", "source.ip": "principal.ip", "destination.ip": "target.ip"},
    "falcon": {"process.command_line": "CommandLine", "process.name": "ImageFileName", "user.name": "UserName", "group.name": "GroupName", "host.name": "ComputerName", "source.ip": "RemoteAddressIP4", "destination.ip": "LocalAddressIP4"},
    "wazuh": {"process.command_line": "win.eventdata.commandLine", "process.name": "win.eventdata.image", "user.name": "user", "group.name": "win.eventdata.groupName", "host.name": "agent.name", "source.ip": "srcip", "destination.ip": "dstip"},
}


def _load_field_mappings() -> dict[str, dict[str, str]]:
    """Taxonomy from data/mappings/fields.json over the builtin seed (F6). File wins;
    builtins fill gaps so a partial file can never remove a working mapping.

    Analyst overrides (data/mappings/overrides.json) win over both: an org-specific
    alias pinned by the detection team is authoritative for that organization.
    """
    document = _load_catalog("mappings/fields.json")
    file_tables = document.get("mappings")
    if not isinstance(file_tables, dict):
        file_tables = {}
    merged: dict[str, dict[str, str]] = {}
    for siem in dict.fromkeys([*_BUILTIN_FIELD_MAPPINGS, *file_tables]):
        table = dict(_BUILTIN_FIELD_MAPPINGS.get(siem, {}))
        file_table = file_tables.get(siem, {})
        if isinstance(file_table, dict):
            table.update({str(k): str(v) for k, v in file_table.items()})
        merged[str(siem)] = table
    from pathlib import Path as _Path
    from mapping_overrides import load_overrides

    for siem, table in load_overrides(_Path(__file__).resolve().parent).items():
        merged.setdefault(str(siem), {}).update(table)
    return merged


FIELD_MAPPINGS = _load_field_mappings()

# Targets whose vendors publish no fixed field schema. Their mappings are well-known
# conventions rather than documented columns, so every rule translated for them is
# labelled as inferred for the analyst to confirm in their own environment.
INFERRED_TARGETS = frozenset({"wazuh", "qradar"})


def mapping_provenance() -> dict[str, Any]:
    """Per-target schema version, documentation URL and confidence for every mapping
    table, so a reviewer can audit a cell instead of trusting it blindly."""
    document = _load_catalog("mappings/fields.json")
    provenance = document.get("provenance")
    meta = document.get("meta") if isinstance(document, dict) else {}
    return {
        "targets": provenance if isinstance(provenance, dict) else {},
        "policy": str((meta or {}).get("policy", "")),
        "provenance_policy": str((meta or {}).get("provenance_policy", "")),
        "mapped_fields": int((meta or {}).get("mapped_fields", 0) or 0),
    }


def _load_ecs_fields() -> list[str]:
    """Full ECS field list for autocomplete (Gap 3). Mapped fields come first; the rest
    pass through and are flagged unmapped rather than translated wrongly."""
    document = _load_catalog("ecs_fields.json")
    fields = document.get("fields")
    if not isinstance(fields, list):
        return []
    mapped = FIELD_MAPPINGS.get("sigma", {})
    extra = sorted({str(f) for f in fields if isinstance(f, str) and f not in mapped})
    return sorted(mapped.keys()) + extra


ECS_FIELDS = _load_ecs_fields()

_ATTACK_CATALOG = _load_catalog("attack_catalog.json")
ATTACK_TECHNIQUES: dict[str, dict[str, Any]] = (
    _ATTACK_CATALOG.get("techniques") if isinstance(_ATTACK_CATALOG.get("techniques"), dict) else {}
)


def attack_techniques() -> list[dict[str, Any]]:
    """Reference ATT&CK catalog (id, name, tactics, summary) for mapping and guidance."""
    return [dict(entry) for entry in ATTACK_TECHNIQUES.values() if isinstance(entry, dict)]


# ATT&CK reference metadata (name/tactics/summary) attached to buildable templates so the
# UI shows real technique context without pretending every ATT&CK ID is a ready template.
for _key, _entry in list(TECHNIQUES.items()):
    for _tid in _entry.get("mitre", []) or []:
        _ref = ATTACK_TECHNIQUES.get(str(_tid))
        if isinstance(_ref, dict):
            _entry.setdefault("tactic", _ref.get("tactics", [""])[0] if _ref.get("tactics") else "")
            _entry.setdefault("reference", _ref.get("url", ""))
            if not _entry.get("fp_guidance"):
                _entry["fp_guidance"] = _ref.get("summary", "")


@dataclass(frozen=True)
class RuleRequest:
    title: str
    description: str
    severity: str
    technique: str
    field: str
    operator: str
    value: str
    threshold: int | None
    timeframe: str
    group_by: str
    data_source: str
    wazuh_rule_id: int
    wazuh_parent_rule: str
    siems: list[str]
    conditions: list[dict[str, str]]
    condition_logic: str
    exclude_conditions: list[dict[str, str]]
    sequences: list[Any] = dataclass_field(default_factory=list)
    joins: list[Any] = dataclass_field(default_factory=list)
    aggregations: list[Any] = dataclass_field(default_factory=list)
    lookups: list[Any] = dataclass_field(default_factory=list)
    strict: bool = False


def supported_siems() -> list[dict[str, str]]:
    return [{"id": key, **value} for key, value in SIEMS.items()]


OPERATOR_ALIASES = {"endswith": "ends_with", "startswith": "starts_with"}
CANONICAL_OPERATORS = {"contains", "equals", "starts_with", "ends_with", "regex", "in_list",
                       "wildcard", "windash", "base64", "exists", "cidr"}


def _canonical_operator(value: Any, default: str = "contains") -> str:
    text = str(value if value is not None else default).strip().lower()
    return OPERATOR_ALIASES.get(text, text)


def _plain(value: Any, label: str, limit: int = 500) -> str:
    text = "" if value is None else str(value).strip()
    if not text:
        raise RuleValidationError(f"{label} is required.")
    if len(text) > limit or any(char in text for char in "\r\n\x00"):
        raise RuleValidationError(f"{label} contains unsupported characters.")
    return text


def _ident(value: Any, label: str) -> str:
    text = _plain(value, label, 120)
    if not re.fullmatch(r"[A-Za-z_@][A-Za-z0-9_.@-]*", text):
        raise RuleValidationError(f"{label} must be a field name (letters, digits, _, ., @, or -).")
    return text


def _rule_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        raise RuleValidationError("Rule text is required.")
    if len(text) > 20000 or "\x00" in text:
        raise RuleValidationError("Rule text contains unsupported characters.")
    return text


def _timeframe(value: Any) -> str:
    text = _plain(value, "Time window", 10).lower()
    if not re.fullmatch(r"\d{1,5}[smhd]", text):
        raise RuleValidationError("Time window must look like 30s, 5m, 1h, or 1d.")
    if int(text[:-1]) < 1:
        raise RuleValidationError("Time window must be at least 1s, 1m, 1h, or 1d.")
    return text


def _duration_from_seconds(seconds: int) -> str:
    """Canonical window text for an exact second count, coarsest exact unit first.

    Wazuh stores its timeframe in seconds, so importing one has to round-trip the value
    rather than approximate it: 61s must not come back as 1m, and a valid 99999s must not
    be rejected as too long for the window grammar.
    """
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0 and seconds // size >= 1:
            return f"{seconds // size}{unit}"
    return f"{max(1, seconds)}s"


def _strict_flag(value: Any) -> bool:
    """Strict mode (Sigma correlation spec 2.1.0): refuse must-features a target
    cannot express instead of shipping a silently lossy query. Accepts bool or
    the usual form strings so the HTML form can post it."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "strict"}


def parse_request(payload: dict[str, Any]) -> RuleRequest:
    technique = str(payload.get("technique", "custom"))
    if technique not in TECHNIQUES:
        raise RuleValidationError("Choose a supported detection pattern.")
    operator = _canonical_operator(payload.get("operator", "contains"))
    if operator not in CANONICAL_OPERATORS:
        raise RuleValidationError("Choose a supported match operator.")
    threshold_value = payload.get("threshold")
    use_threshold = payload.get("use_threshold", True)
    if isinstance(use_threshold, str):
        use_threshold = use_threshold.lower() not in {"false", "0", "off", ""}
    if use_threshold:
        if isinstance(threshold_value, bool):
            raise RuleValidationError("Threshold must be a whole number.")
        if isinstance(threshold_value, float) and not threshold_value.is_integer():
            raise RuleValidationError("Threshold must be a whole number.")
        try:
            threshold = int(threshold_value if threshold_value not in {None, ""} else 1)
        except (TypeError, ValueError) as error:
            raise RuleValidationError("Threshold must be a whole number.") from error
        if not 1 <= threshold <= 10000:
            raise RuleValidationError("Threshold must be between 1 and 10,000.")
    else:
        threshold = None
    siems = payload.get("siems", [])
    if not isinstance(siems, list) or not siems:
        raise RuleValidationError("Select at least one SIEM.")
    if any(not isinstance(siem, str) or siem not in SIEMS for siem in siems):
        raise RuleValidationError("An unsupported SIEM was selected.")
    if isinstance(payload.get("wazuh_rule_id", 100100), bool):
        raise RuleValidationError("Wazuh rule ID must be a whole number.")
    try:
        wazuh_rule_id = int(payload.get("wazuh_rule_id", 100100))
    except (TypeError, ValueError) as error:
        raise RuleValidationError("Wazuh rule ID must be a whole number.") from error
    if "wazuh" in siems and not 100000 <= wazuh_rule_id <= 120000:
        raise RuleValidationError("Wazuh custom rule IDs must be between 100000 and 120000.")
    wazuh_parent_rule = str(payload.get("wazuh_parent_rule", "")).strip()
    if wazuh_parent_rule and not wazuh_parent_rule.isdigit():
        raise RuleValidationError("Wazuh parent rule ID must contain digits only.")
    def parse_conditions(raw: Any, fallback: dict[str, Any], label: str) -> list[dict[str, str]]:
        if label == "Exclusion" and raw == []:
            return []
        entries = raw if raw is not None else [fallback]
        if not isinstance(entries, list) or not entries or len(entries) > 20:
            raise RuleValidationError(f"{label} must contain between 1 and 20 conditions.")
        parsed = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise RuleValidationError(f"Each {label.lower()} entry must be an object.")
            entry_operator = _canonical_operator(entry.get("operator", operator))
            if entry_operator not in CANONICAL_OPERATORS:
                raise RuleValidationError(f"Choose a supported operator for {label.lower()}.")
            entry_value = entry.get("value")
            if entry_operator == "exists":
                value = str(entry_value).strip() if entry_value not in (None, "") else "true"
            else:
                if isinstance(entry_value, (list, dict)):
                    raise RuleValidationError(f"{label} value must be text, not a list or object.")
                value = _plain(entry_value, f"{label} value")
            parsed.append({
                "field": _ident(entry.get("field"), f"{label} field"),
                "operator": entry_operator,
                "value": value,
            })
        return parsed
    raw_conditions = payload.get("conditions")
    if raw_conditions is not None and (not isinstance(raw_conditions, list) or any(not isinstance(e, dict) for e in raw_conditions)):
        raise RuleValidationError("Each condition entry must be an object.")
    first_condition = raw_conditions[0] if isinstance(raw_conditions, list) and raw_conditions else {}
    if first_condition and not isinstance(first_condition, dict):
        raise RuleValidationError("Each condition entry must be an object.")
    conditions = parse_conditions(payload.get("conditions"), {"field": payload.get("field") or first_condition.get("field"), "operator": operator, "value": payload.get("value") or first_condition.get("value")}, "Condition")
    exclude_conditions = []
    if payload.get("exclude_conditions") is not None:
        exclude_conditions = parse_conditions(payload.get("exclude_conditions"), {"field": "process.name", "operator": "equals", "value": "example.exe"}, "Exclusion")
    from models.correlation import parse_correlation
    try:
        sequences, joins, aggregations, lookups = parse_correlation(payload.get("correlation"))
    except ValueError as error:
        raise RuleValidationError(str(error)) from error
    condition_logic = str(payload.get("condition_logic", "all")).lower()
    if condition_logic not in {"all", "any"}:
        raise RuleValidationError("Condition logic must be all or any.")
    primary_condition = conditions[0]
    severity = str(payload.get("severity", "medium")).lower()
    if severity not in {"low", "medium", "high", "critical"}:
        raise RuleValidationError("Severity must be low, medium, high, or critical.")
    return RuleRequest(
        title=_plain(payload.get("title"), "Rule name", 140),
        description=_plain(payload.get("description"), "Description", 500),
        severity=severity,
        technique=technique,
        field=_ident(payload.get("field") or primary_condition["field"], "Match field"),
        operator=_canonical_operator(payload.get("operator") or primary_condition["operator"]),
        value=_plain(payload.get("value") or primary_condition["value"], "Match value"),
        threshold=threshold,
        timeframe=_timeframe(payload.get("timeframe", "5m")),
        group_by=_ident(payload.get("group_by", "user.name"), "Group-by field"),
        data_source=_plain(payload.get("data_source", "*"), "Data source", 160),
        wazuh_rule_id=wazuh_rule_id,
        wazuh_parent_rule=wazuh_parent_rule,
        siems=list(dict.fromkeys(siems)),
        conditions=conditions,
        condition_logic=condition_logic,
        exclude_conditions=exclude_conditions,
        sequences=sequences,
        joins=joins,
        aggregations=aggregations,
        lookups=lookups,
        strict=_strict_flag(payload.get("strict", False)),
    )


def _q(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _s(value: str) -> str:
    return value.replace("'", "\\'")


WAZUH_MAX_FREQUENCY = 9999
WAZUH_MAX_TIMEFRAME_SECONDS = 99999


def _wazuh_attribute_problems(threshold: int | None, timeframe: str) -> list[str]:
    """Wazuh-validity of a count, per the vendor's ruleset XML specification.

    `frequency` is documented as 2-9999 and is meaningless at 1 (a rule that must match
    once is just a rule with no frequency). `timeframe` is in SECONDS and is capped at
    99999. Neither is enforced by the generic parser, so without this a request can
    return HTTP 200 carrying attribute values Wazuh will reject or silently misread.

    Both attributes are only emitted when a count is actually turned on, so with no
    count neither is checked: refusing a Wazuh rule for a window its output does not
    contain would cost the analyst the target for no reason.
    """
    problems: list[str] = []
    if threshold is None or threshold <= 1:
        return problems
    if threshold > WAZUH_MAX_FREQUENCY:
        problems.append(
            f"Wazuh frequency allows at most {WAZUH_MAX_FREQUENCY} matches; "
            f"threshold {threshold} is out of range")
    seconds = _timeframe_seconds(timeframe)
    if seconds > WAZUH_MAX_TIMEFRAME_SECONDS:
        problems.append(
            f"Wazuh timeframe allows at most {WAZUH_MAX_TIMEFRAME_SECONDS} seconds; "
            f"{timeframe} is {seconds}s")
    return problems


def _timeframe_seconds(timeframe: str) -> int:
    """Exact seconds for a window, for targets whose attribute counts in seconds.

    Wazuh's `timeframe` is a seconds count, so 30s must stay 30. `_minutes` exists for
    QRadar's `LAST n MINUTES`, which can only express whole minutes and so rounds up -
    using it for Wazuh silently doubled a 30s window to 60 and turned a count window
    into a different count window.
    """
    quantity, unit = int(timeframe[:-1]), timeframe[-1]
    return quantity * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def _minutes(timeframe: str) -> int:
    quantity, unit = int(timeframe[:-1]), timeframe[-1]
    if unit == "s":
        return max(1, -(-quantity // 60))  # ceiling to whole minutes
    return quantity * {"m": 1, "h": 60, "d": 1440}[unit]


def _match_value(field: str, operator: str, value: str, syntax: str) -> str:
    if syntax == "spl":
        operators = {"contains": f'{field}="*{_q(value)}*"', "equals": f'{field}="{_q(value)}"', "starts_with": f'{field}="{_q(value)}*"', "regex": f'| regex {field}="{_q(value)}"'}
    elif syntax == "kql":
        operators = {"contains": f'{field} contains "{_q(value)}"', "equals": f'{field} == "{_q(value)}"', "starts_with": f'{field} startswith "{_q(value)}"', "regex": f'{field} matches regex @"{_q(value)}"'}
    elif syntax == "eql":
        operators = {"contains": f'{field} : "*{_q(value)}*"', "equals": f'{field} == "{_q(value)}"', "starts_with": f'{field} : "{_q(value)}*"', "regex": f'{field} regex~ "{_q(value)}"'}
    elif syntax == "aql":
        operators = {"contains": f"{field} ILIKE '%{_s(value)}%'", "equals": f"{field} = '{_s(value)}'", "starts_with": f"{field} ILIKE '{_s(value)}%'", "regex": f"{field} MATCHES '{_s(value)}'"}
    elif syntax == "yara":
        operators = {"contains": f'$e.{field} = /{value.replace("/", "\\/")}/ nocase', "equals": f'$e.{field} = "{_q(value)}"', "starts_with": f'$e.{field} = /^{value.replace("/", "\\/")}/ nocase', "regex": f'$e.{field} = /{value.replace("/", "\\/")}/'}
    elif syntax == "cql":
        operators = {"contains": f'{field}="*{_q(value)}*"', "equals": f'{field}="{_q(value)}"', "starts_with": f'{field}=/{re.escape(value).replace("/", chr(92)+"/")}/', "regex": f'{field}=/{value}/'}
    else:
        operators = {"contains": f'{field}="*{_q(value)}*"', "equals": f'{field}="{_q(value)}"', "starts_with": f'{field}="{_q(value)}*"', "regex": f'{field}=~"{_q(value)}"'}
    if operator == "ends_with":
        fallbacks = {"spl": f'{field}="*{_q(value)}"', "kql": f'{field} endswith "{_q(value)}"',
                     "eql": f'{field} : "*{_q(value)}"', "aql": f"{field} ILIKE '%{_s(value)}'",
                     "yara": f'$e.{field} = /{value.replace("/", chr(92)+"/")}$/ nocase',
                     "cql": f'{field}=/{re.escape(value).replace("/", chr(92)+"/")}$/'}
        return fallbacks.get(syntax, f'{field}="*{_q(value)}"')
    if operator == "exists":
        fallbacks = {"spl": f"{field}=*", "kql": f"isnotempty({field})", "eql": f"{field} != null",
                     "aql": f"{field} IS NOT NULL", "yara": f'$e.{field} != ""', "cql": f"{field} = *"}
        return fallbacks.get(syntax, f"{field}=*")
    if operator == "in_list":
        items = value if isinstance(value, list) else [value]
        if syntax == "kql":
            return f"{field} in ({', '.join(chr(34) + _q(str(v)) + chr(34) for v in items)})"
        if syntax == "aql":
            return f"{field} IN ({', '.join(chr(39) + _s(str(v)) + chr(39) for v in items)})"
        if syntax == "eql":
            return "(" + " or ".join(f'{field} == "{_q(str(v))}"' for v in items) + ")"
        if syntax == "yara":
            return f"$e.{field} = /({'|'.join(str(v).replace('/', chr(92)+'/') for v in items)})/ nocase"
        if syntax == "cql":
            return f"in({field}, values=[{', '.join(chr(34) + _q(str(v)) + chr(34) for v in items)}])"
        return "(" + " OR ".join(f'{field}="{_q(str(v))}"' for v in items) + ")"
    if operator == "wildcard":
        text = str(value)
        if "*" not in text and "?" not in text:
            return _match_value(field, "contains", text, syntax)
        if syntax == "kql":
            return f'{field} matches wildcard "{_q(text)}"'
        if syntax == "cql":
            return f'wildcard({field}, pattern="{_q(text)}")'
        if syntax == "aql":
            return f"{field} LIKE '{_s(text).replace('*', '%').replace('?', '_')}'"
        if syntax == "yara":
            escaped = re.escape(text).replace(r"\*", ".*").replace(r"\?", ".")
            return f'$e.{field} = /{escaped.replace("/", chr(92)+"/")}/ nocase'
        if syntax == "eql":
            return f'{field} : "{_q(text)}"'
        return f'{field}="{_q(text)}"'
    if operator == "windash":
        return _match_value(field, "contains", str(value).lstrip("-/"), syntax)
    if operator == "base64":
        return _match_value(field, "contains", str(value), syntax)
    if operator == "cidr":
        if syntax == "kql":
            return f'ipv4_is_in_range({field}, "{_q(str(value))}")'
        if syntax == "cql":
            return f'cidr({field}, subnet="{_q(str(value))}")'
        if syntax == "eql":
            return f'cidrMatch({field}, "{_q(str(value))}")'
        return _match_value(field, "contains", str(value), syntax)
    return operators[operator]


def _match(request: RuleRequest, syntax: str) -> str:
    return _match_value(request.field, request.operator, request.value, syntax)


def _condition_expression(request: RuleRequest, syntax: str) -> str:
    expressions = [_match_value(item["field"], item["operator"], item["value"], syntax) for item in request.conditions]
    joiner = " and " if request.condition_logic == "all" else " or "
    expression = joiner.join(expressions)
    if len(expressions) > 1:
        expression = f"({expression})"
    if request.exclude_conditions:
        exclusions = " and ".join(_match_value(item["field"], item["operator"], item["value"], syntax) for item in request.exclude_conditions)
        expression = f"{expression} and not ({exclusions})"
    return expression


def _base_filter(request: RuleRequest, syntax: str) -> str:
    tech = TECHNIQUES[request.technique]
    native = tech["event_filter"]
    if native == "true":
        return _condition_expression(request, syntax)
    syntax_siem = {"spl": "splunk", "kql": "sentinel", "eql": "elastic", "aql": "qradar", "yara": "google_secops", "cql": "falcon"}.get(syntax)
    if syntax_siem:
        for canonical, mapped in FIELD_MAPPINGS.get(syntax_siem, {}).items():
            native = native.replace(canonical, mapped)
    qradar_filters = {
        "failed_logins": "eventName ILIKE '%fail%'",
        "encoded_powershell": "processName ILIKE '%powershell%'",
        "suspicious_process": "1=1",
        "new_admin": "eventName ILIKE '%group%member%added%'",
    }
    replacements = {
        "spl": native.replace(" == ", "=") + " " + _condition_expression(request, syntax),
        "kql": native + " and " + _condition_expression(request, syntax),
        "eql": native + " and " + _condition_expression(request, syntax),
        "aql": qradar_filters.get(request.technique, "1=1") + " AND " + _condition_expression(request, syntax),
        "yara": _condition_expression(request, syntax),
        "cql": native.replace(" == ", "=") + " " + _condition_expression(request, syntax),
    }
    return replacements[syntax]


def _metadata(request: RuleRequest) -> str:
    attack = ", ".join(TECHNIQUES[request.technique]["mitre"]) or "Not mapped"
    return f"Name: {request.title}\nSeverity: {request.severity.title()}\nMITRE ATT&CK: {attack}\nWindow: {request.timeframe} (lookback / count window - not a schedule)"


def _commented(request: RuleRequest, prefix: str) -> str:
    """Comment every metadata line. Prefixing only the first line left unprefixed
    header text in the output, which is not valid SPL/AQL/CQL."""
    return "\n".join(f"{prefix} {line}" for line in _metadata(request).splitlines())


def _native_request(request: RuleRequest, siem: str) -> tuple[RuleRequest, dict[str, str | bool]]:
    fields = FIELD_MAPPINGS.get(siem, {})
    mapped_field = fields.get(request.field, request.field)
    mapped_group = fields.get(request.group_by, request.group_by)
    mapped_conditions = [replace_condition(item, fields) for item in request.conditions]
    mapped_exclusions = [replace_condition(item, fields) for item in request.exclude_conditions]
    unmapped = [item["field"] for item in request.conditions + request.exclude_conditions if item["field"] not in fields]
    if request.group_by not in fields:
        unmapped.append(request.group_by)
    # Targets with no published schema (Wazuh, QRadar) carry inferred mappings. They are
    # useful, but they are not verified, so they are reported separately rather than being
    # folded into `mapped: true` where the analyst would take them at face value.
    inferred = sorted({item["field"] for item in request.conditions + request.exclude_conditions
                       if item["field"] in fields and siem in INFERRED_TARGETS})
    if request.group_by in fields and siem in INFERRED_TARGETS:
        inferred.append(request.group_by)
    return replace(request, field=mapped_field, group_by=mapped_group, conditions=mapped_conditions, exclude_conditions=mapped_exclusions), {
        "canonical_field": request.field,
        "native_field": mapped_field,
        "canonical_group_by": request.group_by,
        "native_group_by": mapped_group,
        "mapped": not unmapped,
        "unmapped_fields": sorted(set(unmapped)),
        "inferred_fields": sorted(set(inferred)),
        # Confidence describes THIS FIELD's provenance, not the vendor's schema maturity.
        # It previously read "documented" for any target that was not Wazuh/QRadar, so a
        # field with no mapping at all - a Sigma field name passed through, say - was
        # labelled with the highest confidence the tool emits while `mapped` was False.
        "mapping_confidence": _mapping_confidence(siem, unmapped, inferred),
        "inferred_target": siem if siem in INFERRED_TARGETS else "",
    }


def _mapping_confidence(siem: str, unmapped: list[str], inferred: list[str]) -> str:
    """How much to trust the field names in this output.

    unmapped   - the field has no entry in this target's mapping table at all, so the name
                 in the output is whatever the analyst typed. Least trustworthy.
    inferred   - the target publishes no schema (Wazuh, QRadar), so the name is a plausible
                 convention rather than a documented column.
    documented - the field came from this target's published mapping table.
    """
    if unmapped:
        return "unmapped"
    if inferred or siem in INFERRED_TARGETS:
        return "inferred"
    return "documented"


def replace_condition(condition: dict[str, str], fields: dict[str, str]) -> dict[str, str]:
    return {**condition, "field": fields.get(condition["field"], condition["field"])}


def quality_gates(request: RuleRequest, mappings: list[dict[str, str | bool]]) -> list[dict[str, str]]:
    gates = [{"level": "pass", "title": "Required context provided", "detail": "Name, description, severity, detection logic, and target SIEMs are present."}]
    if request.data_source in {"*", "logs-*"}:
        gates.append({"level": "warn", "title": "Data source needs scoping", "detail": "Replace the broad default source before production deployment to reduce cost and false positives."})
    else:
        gates.append({"level": "pass", "title": "Data source declared", "detail": f"The templates are scoped to: {request.data_source}. Verify this exists in every selected SIEM."})
    unmapped = []
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        unmapped.extend(mapping.get("unmapped_fields", []) or ([mapping.get("canonical_field", "?")] if not mapping.get("mapped", True) else []))
    if unmapped:
        gates.append({"level": "warn", "title": "Custom field mapping needed", "detail": f"No built-in mapping exists for: {', '.join(dict.fromkeys(unmapped))}. Review every target’s schema."})
    else:
        gates.append({"level": "pass", "title": "Native field mapping applied", "detail": "Known canonical fields were translated to each target platform’s common schema."})
    inferred = {m["inferred_target"] for m in mappings
                if isinstance(m, dict) and m.get("mapping_confidence") == "inferred"
                and m.get("inferred_target")}
    if inferred:
        gates.append({"level": "warn", "title": "Inferred field mapping",
                      "detail": f"{', '.join(sorted(inferred))} publish no fixed field schema, so these mappings are "
                                "inferred conventions, not verified columns. Confirm them against your own "
                                "environment before deploying."})
    if request.threshold is None:
        gates.append({"level": "pass", "title": "Single-event mode", "detail": "No count threshold will be applied; each matching event can produce a detection."})
    elif request.threshold == 1:
        gates.append({"level": "info", "title": "Single-event alert", "detail": "Consider a threshold or suppression key if this behavior is expected to be noisy."})
    if len(request.conditions) > 1 or request.exclude_conditions:
        gates.append({"level": "pass", "title": "Compound logic preserved", "detail": f"The draft contains {len(request.conditions)} detection condition(s) and {len(request.exclude_conditions)} exclusion condition(s). Review operator precedence in each target dialect."})
    return gates


def render_splunk(request: RuleRequest) -> str:
    condition = _base_filter(request, "spl")
    threshold = f" | stats count by {request.group_by} | where count >= {request.threshold}" if request.threshold and request.threshold > 1 else ""
    return f"{_commented(request, '#')}\nindex={request.data_source} earliest=-{request.timeframe}\n| search {condition}{threshold}\n| eval rule_name=\"{_q(request.title)}\", severity=\"{request.severity}\""


SIGMA_SUFFIX = {"contains": "|contains", "starts_with": "|startswith", "ends_with": "|endswith",
                "regex": "|re", "windash": "|windash|contains", "base64": "|base64|contains",
                "cidr": "|cidr", "exists": "|exists", "wildcard": "", "in_list": "", "equals": ""}


def render_sigma(request: RuleRequest) -> str:
    """Faithful Sigma emit: modifiers preserved, multi-condition structure kept."""
    joiner = " and " if request.condition_logic == "all" else " or "
    names = []
    detection: dict[str, Any] = {}
    for index, condition in enumerate(request.conditions):
        name = f"selection_{index}" if len(request.conditions) > 1 else "selection"
        names.append(name)
        suffix = SIGMA_SUFFIX.get(condition["operator"], "")
        detection[name] = {f"{condition['field']}{suffix}": condition["value"]}
    condition_expr = joiner.join(names) if len(names) > 1 else "selection"
    technique = TECHNIQUES.get(request.technique, {})
    document: dict[str, Any] = {
        "title": request.title,
        "status": "test",
        "description": request.description,
        "author": "RuleForge",
        "logsource": {"category": request.data_source},
        "detection": {**detection, "condition": condition_expr},
        "falsepositives": ["Review against local telemetry before enabling."],
        "level": request.severity,
    }
    if technique.get("mitre"):
        document["tags"] = [f"attack.{t.lower()}" for t in technique["mitre"]]
    if request.exclude_conditions:
        used_filter_names: list[str] = []
        for index, item in enumerate(request.exclude_conditions):
            key = "filter" if index == 0 else f"filter_{index}"
            if key in document["detection"]:
                key = f"filter_{index}"
            used_filter_names.append(key)
            document["detection"][key] = {f"{item['field']}{SIGMA_SUFFIX.get(item['operator'], '')}": item["value"]}
        filters_clause = " and ".join(f"not {name}" for name in used_filter_names)
        document["detection"]["condition"] = f"({condition_expr}) and {filters_clause}"
    return yaml.safe_dump(document, sort_keys=False, allow_unicode=False)


# Sentinel output uses Microsoft Sentinel ASIM normalized column names (TargetProcessName,
# TargetUsername, DvcHostname, ...). Those columns are produced by an ASIM parser and do
# NOT exist in the legacy SecurityEvent table, which carries Account/CommandLine/Image.
# Defaulting to a real table name therefore emitted a rule that referenced columns its own
# table did not contain. Rather than substitute a different guess, an unsupplied table
# becomes an explicit placeholder the analyst must replace with the table their ASIM
# parser actually writes to.
ASIM_TABLE_PLACEHOLDER = "ASIMTable_ReplaceMe"
# Tables that carry the legacy SecurityEvent/DeviceProcessEvents column names
# (Account, CommandLine, Image) and therefore CANNOT be used with ASIM columns.
SENTINEL_LEGACY_TABLES = frozenset({"SecurityEvent", "SecurityEvents", "WindowsEvent",
                                    "CommonSecurityEvent", "DeviceProcessEvents",
                                    "DeviceNetworkEvents", "Syslog"})
ASIM_TABLE_NOTE = (
    f"\n// Replace {ASIM_TABLE_PLACEHOLDER} with the table your ASIM parser writes to."
    "\n// The column names below are ASIM normalized names. The legacy SecurityEvent table uses"
    "\n// different columns (Account, CommandLine, Image) and will NOT work with this query."
)


def _sentinel_table(source: str) -> tuple[str, str]:
    """Resolve the table for Sentinel output, refusing legacy tables outright.

    Substituting a different guess would repeat the very error this tool exists to
    avoid, so a legacy table is replaced with the same explicit placeholder rather than
    quietly emitting ASIM columns against a table that does not contain them.
    """
    name = str(source or "").strip()
    if not name or name == "*" or name.lower() in {t.lower() for t in SENTINEL_LEGACY_TABLES}:
        return ASIM_TABLE_PLACEHOLDER, ASIM_TABLE_NOTE
    return name, ""


def render_sentinel(request: RuleRequest) -> str:
    condition = _base_filter(request, "kql")
    table, table_note = _sentinel_table(request.data_source)
    aggregation = f"\n| summarize EventCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by {request.group_by}\n| where EventCount >= {request.threshold}" if request.threshold and request.threshold > 1 else ""
    return f"{_commented(request, '//')}\n{table}{table_note}\n| where TimeGenerated >= ago({request.timeframe})\n| where {condition}{aggregation}"


def render_elastic(request: RuleRequest) -> str:
    condition = _base_filter(request, "eql")
    category = TECHNIQUES[request.technique]["event_category"]
    # EQL only accepts its own event categories. Our catalog also uses analysis-oriented
    # categories (iam, cloud) that have no EQL equivalent, so map them to the category
    # whose event stream actually carries the data and say so, rather than emitting an
    # invalid query or silently pretending the mapping is exact.
    from compiler.dialects import EQL_EVENT_CATEGORIES
    notes_extra = ""
    if category not in EQL_EVENT_CATEGORIES:
        fallback = {"iam": "authentication", "cloud": "network"}.get(category, "any")
        notes_extra = (f"# EQL has no '{category}' event category; mapped to '{fallback}'. "
                       "Set the real category for your event stream.\n")
        category = fallback
    if category == "any":
        category = "process"
        notes_extra += "# Category defaulted to process; replace with the real event category.\n"
    notes = f"{_commented(request, '#')}\n# Rule type: EQL; configure index pattern: {request.data_source}\n" + notes_extra
    if request.threshold and request.threshold > 1:
        return notes + f"# EQL does not aggregate. Use an Elastic threshold rule grouped by {request.group_by}.\n# Threshold: {request.threshold} within {request.timeframe}\n{category} where {condition}"
    return notes + f"{category} where {condition}"


def render_qradar(request: RuleRequest) -> str:
    condition = _base_filter(request, "aql")
    minutes = _minutes(request.timeframe)
    threshold = f" HAVING COUNT(*) >= {request.threshold}" if request.threshold and request.threshold > 1 else ""
    return f"{_commented(request, '--')}\n-- Scope this query to the appropriate log source(s): {request.data_source}\nSELECT {request.group_by}, COUNT(*) AS event_count\nFROM events\nWHERE {condition}\nGROUP BY {request.group_by}\nLAST {minutes} MINUTES{threshold}"


def render_google_secops(request: RuleRequest) -> str:
    condition = _base_filter(request, "yara")
    tech = TECHNIQUES[request.technique]
    grouping = f"\n    $e.{request.group_by} = $group" if request.threshold and request.threshold > 1 else ""
    from compiler.sigma_compiler import _yaral_span
    match = f"\n  match:\n    $group over {_yaral_span(request.timeframe)}" if request.threshold and request.threshold > 1 else ""
    outcome = f"\n    $risk_score = { {'low': 20, 'medium': 50, 'high': 75, 'critical': 95}[request.severity] }"
    condition_block = f"$e and #e >= {request.threshold}" if request.threshold and request.threshold > 1 else "$e"
    rule_name = re.sub(r'[^A-Za-z0-9_]', '_', request.title.lower())
    if not re.match(r'^[A-Za-z_]', rule_name):
        rule_name = f"rule_{rule_name}"
    tech_filter = TECHNIQUES[request.technique]["event_filter"]
    tech_note = "" if tech_filter == "true" else f"\n    // Technique context ({request.technique}): {tech_filter} — map to UDM fields."
    return f"rule {rule_name} {{\n  meta:\n    author = \"RuleForge\"\n    description = \"{_q(request.description)}\"\n    severity = \"{request.severity}\"\n    mitre_attack = \"{','.join(tech['mitre'])}\"\n    data_source = \"{_q(request.data_source)}\"\n  events:\n    // Map the normalized field below to its UDM equivalent.\n    {condition}{tech_note}{grouping}{match}\n  outcome:{outcome}\n  condition:\n    {condition_block}\n}}"


def render_falcon(request: RuleRequest) -> str:
    condition = _base_filter(request, "cql")
    threshold = f" | groupBy([{request.group_by}], function=count()) | _count>={request.threshold}" if request.threshold and request.threshold > 1 else ""
    return f"{_commented(request, '//')}\n#repo={request.data_source}\n| {condition}{threshold}"


def _wazuh_field_pattern(field: str, operator: str, value: str) -> str:
    """PCRE2 pattern for one Wazuh <field> element."""
    pattern = value if operator == "regex" else re.escape(str(value))
    if operator == "equals":
        return f"(?i)^{pattern}$"
    if operator == "starts_with":
        return f"(?i)^{pattern}"
    if operator in {"ends_with", "endswith"}:
        return f"(?i){pattern}$"
    if operator == "exists":
        return ".+"
    if operator == "windash":
        return f"(?i)[-/]{re.escape(str(value).lstrip('-/'))}"
    return pattern if operator == "regex" else f"(?i){pattern}"


def _wazuh_pattern(request: RuleRequest) -> str:
    """Return a PCRE2 field pattern while preserving a user-selected regex."""
    return _wazuh_field_pattern(request.field, request.operator, request.value)


def render_wazuh(request: RuleRequest) -> str:
    """Render a conservative local custom-rule template for Wazuh manager."""
    attack_ids = "\n".join(f"      <id>{technique}</id>" for technique in TECHNIQUES[request.technique]["mitre"])
    mitre = f"\n    <mitre>\n{attack_ids}\n    </mitre>" if attack_ids else ""
    severity = {"low": 4, "medium": 7, "high": 10, "critical": 14}[request.severity]
    frequency = ""
    correlator = ""
    # Wazuh's frequency is 2-9999 and timeframe is capped at 99999 seconds. The generic
    # parser allows a larger threshold and a 999d window, so refuse THIS target rather
    # than emitting attribute values the manager will reject. Other selected targets are
    # unaffected, because a multi-target compile must not fail wholesale.
    problems = _wazuh_attribute_problems(request.threshold, request.timeframe)
    if problems:
        raise RuleValidationError(" ".join(problems))
    if request.threshold and request.threshold > 1:
        frequency = f' frequency="{request.threshold}" timeframe="{_timeframe_seconds(request.timeframe)}"'
        static_group_fields = {
            "user": "<same_user />", "user.name": "<same_user />",
            "srcip": "<same_srcip />", "source.ip": "<same_srcip />",
            "dstip": "<same_dstip />", "destination.ip": "<same_dstip />",
        }
        correlator = static_group_fields.get(request.group_by, f"<!-- Add same_* or <same_field>{xml_escape(request.group_by)}</same_field> as appropriate. -->")
    parent = f"\n    <if_sid>{request.wazuh_parent_rule}</if_sid>" if request.wazuh_parent_rule else ""
    field = xml_escape(request.field, quote=True)
    pattern = xml_escape(_wazuh_pattern(request), quote=False)
    extra_fields = ""
    for item in request.conditions[1:]:
        extra_fields += f"\n    <field name=\"{xml_escape(item['field'], quote=True)}\" type=\"pcre2\">{xml_escape(_wazuh_field_pattern(item['field'], item['operator'], item['value']), quote=False)}</field>"
    for item in request.exclude_conditions:
        extra_fields += f"\n    <field name=\"{xml_escape(item['field'], quote=True)}\" negate=\"yes\" type=\"pcre2\">{xml_escape(_wazuh_field_pattern(item['field'], item['operator'], item['value']), quote=False)}</field>"
    or_note = ""
    if request.condition_logic == "any" and len(request.conditions) > 1:
        or_note = "\n    <!-- Wazuh ANDs <field> elements; split OR branches into separate rules. -->"
    title = xml_escape(request.title, quote=False)
    description = xml_escape(request.description, quote=False)
    return f"<!-- Data source: {xml_escape(request.data_source)}. Save under /var/ossec/etc/rules/. Test with wazuh-logtest before restarting wazuh-manager. -->\n<group name=\"local,ruleforge,attack,\">\n  <rule id=\"{request.wazuh_rule_id}\" level=\"{severity}\"{frequency}>{parent}\n    <field name=\"{field}\" type=\"pcre2\">{pattern}</field>{extra_fields}{or_note}\n    {correlator}\n    <description>{title}: {description}</description>{mitre}\n    <group>ruleforge,attack,</group>\n  </rule>\n</group>"


RENDERERS = {"sigma": render_sigma, "splunk": render_splunk, "sentinel": render_sentinel, "elastic": render_elastic, "qradar": render_qradar, "google_secops": render_google_secops, "falcon": render_falcon, "wazuh": render_wazuh}


def generate_rules(payload: dict[str, Any]) -> list[dict[str, str]]:
    from compiler.pipeline import compile_request

    request = parse_request(payload)
    rules = []
    for siem in request.siems:
        rules.append(compile_request(request, siem))
    return rules


def generate_workbench(payload: dict[str, Any]) -> dict[str, Any]:
    request = parse_request(payload)
    rules = generate_rules(payload)
    source_document = None
    if payload.get("source_analysis"):
        source_document = DetectionDocument.from_analysis(payload["source_analysis"])
    preserve_wanted = payload.get("preserve_source_rule") is True and bool(payload.get("source_rule"))
    preservation_possible = (preserve_wanted
                             and isinstance(payload.get("source_siem"), str)
                             and payload.get("source_siem") in SIEMS)
    preservation_applied = False
    if preservation_possible:
        for rule in rules:
            if rule["siem"] != payload["source_siem"]:
                continue
            if rule.get("refused"):
                # Preserving over a refusal would hand a consumer a non-empty Wazuh rule on
                # an item still marked refused/validation failed. The refusal is the truth.
                rule["review_note"] = (
                    "This target refused the requested settings, so the source rule was not "
                    "restored onto it. Fix the settings, or deploy the source rule as-is from "
                    "where it came from.")
                continue
            source_text = str(payload["source_rule"])
            # `query` must not keep describing the generated draft. Every downstream check,
            # warning and validation verdict below was computed against the draft, so they
            # cannot be carried over to text this tool did not produce.
            rule["rule"] = source_text
            rule["query"] = source_text
            rule["fidelity"] = "exact"
            rule["equivalent_recompile"] = True
            rule["preserved_source"] = True
            rule["checks"] = ["Original source preserved verbatim. This tool did not re-validate this text, so the checks and warnings for the generated draft do not apply to it."]
            rule["warnings"] = []
            rule["validation"] = "unverified"
            rule["review_note"] = "Original source rule preserved exactly. Generated alternatives for other SIEMs are normalized drafts."
            preservation_applied = True
    elif payload.get("source_rule"):
        for rule in rules:
            if rule.get("refused"):
                continue
            rule["fidelity"] = "partial"
            rule["equivalent_recompile"] = False
            rule["review_note"] = "The imported rule was edited. This is a normalized draft; compare it with the original before using it."
    gates = quality_gates(request, [rule["field_mapping"] for rule in rules])
    if preserve_wanted and not preservation_applied:
        target = payload.get("source_siem")
        refused_source = any(r["siem"] == target and r.get("refused") for r in rules)
        if refused_source:
            detail = (f"{target} refused the requested settings, so the original rule was not preserved onto it; "
                      "nothing in this bundle is the source artifact.")
        elif not (isinstance(target, str) and target in SIEMS):
            detail = (f"Preservation was requested for {target!r}, which is not a SIEM this tool targets; "
                      "no output preserves the original source.")
        else:
            detail = (f"Preservation was requested for {target} but it is not among the selected targets; "
                      "no output preserves the original source.")
        gates.append({"level": "warn", "title": "Source preservation skipped", "detail": detail})
    decision = (source_document.compile_decision(
        preserve_source=payload.get("preserve_source_rule") is True,
        target_siem=payload.get("source_siem", ""),
    ) if source_document else {"mode": "generated", "fidelity": "native", "equivalent": True})
    if preserve_wanted and not preservation_applied and decision.get("mode") == "preserve_source":
        # The contract describes the request's intent. Reality wins: if the source target
        # never got an artifact, nothing here is the preserved source and claiming exact
        # preservation would be the same false claim as a 200 on an invalid Wazuh rule.
        decision = {"mode": "preserve_source_not_applied", "fidelity": "unsupported",
                    "equivalent": False,
                    "reason": [f"No output for {payload.get('source_siem')} exists to carry the original rule, so the original was not preserved."]}
    return {
        "rules": rules,
        "quality_gates": gates,
        "compile_contract": {"source": decision},
        "compile_allowed": not (
            (source_document
             and not payload.get("preserve_source_rule")
             and not source_document.equivalent_recompile)
            or (preserve_wanted and not preservation_applied)
        ),
    }


def _logic_text(text: str, target: str, native_sections: dict[str, str]) -> str:
    """Rule text scoped to logic-bearing parts (comments, descriptions, literals removed)."""
    if target == "wazuh":
        return ""
    if target == "google_secops":
        return native_sections.get("events", "")
    if target == "sigma":
        return native_sections.get("sigma_condition", "")
    scoped = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("#", "//", "--")):
            continue
        scoped.append(re.sub(r'"[^"]*"|\'[^\']*\'', '""', line))
    return "\n".join(scoped)


def _boolean_structure(text: str) -> dict[str, Any]:
    """Count boolean structure with quote/paren awareness (Gap 5).

    The legacy detector matched words like "and" inside quoted values or identifiers
    ("error and abort"), producing false 'boolean branching' flags. Stripping string
    literals first means the count reflects real query structure, so the regex-based
    dialects can be labeled honestly instead of guessing.
    """
    import re as _re
    bare = _re.sub(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', '""', text)
    words = [w.upper() for w in _re.findall(r"\b(?:AND|OR|NOT|EXCEPT)\b", bare, _re.IGNORECASE)]
    depth = 0
    max_depth = 0
    for char in bare:
        if char in "([":
            depth += 1
            max_depth = max(max_depth, depth)
        elif char in ")]":
            depth = max(0, depth - 1)
    return {"operators": words, "operator_count": len(words), "group_depth": max_depth}


def _json_conditions(node: Any, prefix: str = "", depth: int = 0) -> list[dict[str, str]]:
    """Flatten a parsed JSON event into dotted field/value conditions.

    An engineer pastes one Elastic event to see what the tool can draft from it, so the
    nested document must become the same flat field/value shape the editor uses.

    A multi-valued ECS field such as event.category is addressed by its own name, never
    by an invented positional path: `event.type.0` is not a field that exists in any
    index, so a rule built on it would deploy and never match. Scalar arrays therefore
    collapse into one `in_list` condition on the real field name. Depth is bounded so a
    pathological document cannot recurse without limit.
    """
    out: list[dict[str, str]] = []
    if depth > 8 or not isinstance(node, dict):
        return out
    for key, value in node.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.extend(_json_conditions(value, f"{path}.", depth + 1))
        elif isinstance(value, list):
            scalars = [item for item in value
                       if item is not None and not isinstance(item, (dict, list, bool))]
            if scalars:
                out.append({"field": path, "operator": "in_list",
                            "value": [str(item) for item in scalars]})
            # Objects inside a list are not addressable as real fields; they are skipped
            # rather than turned into invented paths.
        elif value is not None and not isinstance(value, bool):
            out.append({"field": path, "operator": "equals", "value": str(value)})
    return out


def _structured_event_conditions(text: str, target: str, allow_token_scan: bool = True) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Extract conditions from a raw *event* (not a query) in a structured format.

    Detection engineers routinely paste a single event copied out of their console. That
    is not a query, so the query-oriented regexes find nothing. These three formats are
    handled natively instead of returning an empty result and telling the analyst to
    start from scratch.

    Format sniffing is used rather than a "does it look like a query" probe: JSON and XML
    are unambiguous by their first character, whereas the token scan (used for QRadar
    events) is ambiguous against a real AQL query, so it is only attempted when the
    caller says no query structure was detected. A JSON event whose *value* contains a
    pipe character - `cmd /c "dir | findstr"` - would otherwise be misread as a query and
    yield nothing.
    """
    stripped = text.strip()
    if not stripped:
        return []
    if stripped[0] in "{[":
        try:
            document = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            document = None
        except RecursionError:
            # json.loads recurses on deeply nested documents; the input cap usually
            # catches this first, but never let it escape as a crash.
            raise RuleValidationError("JSON event is nested too deeply to parse safely.") from None
        if isinstance(document, dict):
            return _json_conditions(document), []
        return [], []
    if target == "wazuh" and stripped.startswith("<"):
        return _wazuh_xml_conditions(stripped)
    if target == "qradar" and allow_token_scan:
        return _bracket_event_conditions(stripped), []
    return [], []


# Directives that scope or select a search rather than describe an event. Treating them
# as detection conditions produces false positives (e.g. #repo="falcon" as a condition
# called "repo"), so they are recorded separately and never offered as match logic.
_SCOPE_DIRECTIVES = frozenset({"repo", "index", "from", "table", "let", "where", "join",
                               "search", "select", "stats", "summarize", "group_by"})


def _wazuh_xml_conditions(text: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Conditions and exclusions from a Wazuh <event> or <rule> XML fragment.

    Returns (conditions, exclusions). A <field negate="yes"> is an exclusion: importing
    it as a positive match would silently invert the rule's meaning, which is worse than
    a wrong field name because the rule looks correct and does the opposite.
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return [], []
    conditions: list[dict[str, str]] = []
    exclusions: list[dict[str, str]] = []
    for node in root.iter():
        name = node.attrib.get("name")
        if not name or node.text is None or not node.text.strip():
            continue
        entry = {"field": name, "operator": "equals", "value": node.text.strip()}
        (exclusions if str(node.attrib.get("negate", "")).strip().lower() == "yes" else conditions).append(entry)
    return conditions, exclusions


def _bracket_event_conditions(text: str) -> list[dict[str, str]]:
    """Conditions from a QRadar/AQL-style raw event line.

    QRadar events are tab/space separated with bracketed key:value pairs and bare
    key=value tokens, e.g. `... WIN_DEFEND PROTECTION_HISTORY 1 10.0.0.5 [User: admin]
    [CommandLine: "Add-MpPreference"]`. Positional columns (timestamp, event id, source
    ip) have no key, so only keyed tokens become conditions; a keyed token we cannot
    interpret is left out rather than guessed.
    """
    out: list[dict[str, str]] = []
    # Bracketed labels are scanned with an explicit depth counter rather than a regex.
    # A regex over `[Label: value]` is quadratic on unterminated input, and it cannot
    # distinguish the inner `]` of `[CommandLine: "cmd /c echo [x]"]` from the label's
    # own closing bracket. Depth counting handles both in a single linear pass.
    index = 0
    length = len(text)
    while index < length:
        if text[index] != "[":
            index += 1
            continue
        label_start = index + 1
        # Bounded forward scan for the label colon. A bare `text.find(":", start)` on
        # input with no colon rescans the remaining suffix from every unmatched `[`,
        # which is quadratic; stopping at 64 characters keeps it linear and matches the
        # maximum label length actually accepted.
        limit = min(length, label_start + 64)
        colon = -1
        for probe in range(label_start, limit):
            if text[probe] == ":":
                colon = probe
                break
        if colon == -1:
            index = label_start
            continue
        label = text[label_start:colon].strip()
        if not label or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_. ]*", label):
            index += 1
            continue
        value_start = colon + 1
        depth = 1
        cursor = value_start
        quote: str | None = None
        while cursor < length:
            char = text[cursor]
            if quote is not None:
                if char == "\\":
                    cursor += 2
                    continue
                if char == quote:
                    quote = None
            elif char in "\"'":
                quote = char
            elif char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
                if depth == 0:
                    break
            cursor += 1
        if depth != 0:
            break  # unterminated; stop rather than rescan from every position
        out.append({"field": label, "operator": "equals",
                    "value": text[value_start:cursor].strip().strip('"')})
        index = cursor + 1
    # Bare key=value tokens are only read from the parts of the line OUTSIDE the
    # bracketed values. Scanning the whole line invented fields out of command-line
    # content: `[CommandLine: "cmd /c foo=bar"]` produced a phantom field `foo` that
    # exists in no QRadar schema, which is exactly the silent-failure class this tool
    # must never produce.
    bracketed_spans: list[tuple[int, int]] = []
    for start in re.finditer(r"\[[A-Za-z_][A-Za-z0-9_. ]*\s*:", text):
        end = text.find("]", start.end())
        bracketed_spans.append((start.start(), len(text) if end == -1 else end + 1))
    residue = "".join(
        " " if any(start <= i < end for start, end in bracketed_spans) else char
        for i, char in enumerate(text)
    )
    for match in re.finditer(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_.]*)=(\"[^\"]*\"|'[^']*'|\S+)", residue):
        field = match.group(1)
        if field.lower() in _SCOPE_DIRECTIVES:
            continue
        out.append({"field": field, "operator": "equals", "value": match.group(2).strip('"\'')})
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for entry in out:
        key = (entry["field"], entry["value"])
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return unique


def _unescape_literal(field: str, value: str) -> tuple[str, str]:
    """Resolve backslash escapes inside a query literal.

    AQL/SPL write an embedded quote as \\' and a literal backslash as \\\\, so the raw
    text is not the value. Leaving the escape in place would carry a stray backslash
    into the analyst's rule and make it match nothing.
    """
    resolved = re.sub(r"\\(['\\])", r"\1", value)
    return field, resolved


def analyze_rule(rule_text: Any, siem: Any) -> dict[str, Any]:
    """Extract useful parts of a pasted rule without claiming full parsing."""
    text = _rule_text(rule_text)
    target = str(siem or "").strip().lower()
    detection = detect_siem(text)
    if target in {"", "auto", "auto-detect"}:
        target = detection["siem"]
    if target not in SIEMS:
        raise RuleValidationError("Choose a supported SIEM or use Auto-detect.")

    conditions: list[dict[str, str]] = []
    exclusions: list[dict[str, str]] = []
    native_sections: dict[str, str] = {}
    sequences: list[dict[str, Any]] = []
    joins: list[dict[str, str]] = []
    aggregations: list[dict[str, str]] = []
    lookups: list[dict[str, str]] = []
    native_metadata: dict[str, Any] = {}
    event_streams: list[dict[str, str]] = []
    time_constraints: list[str] = []
    # Defaults are set before the per-target extraction below. Wazuh sets these inside
    # its XML block, so a document that parses but contains no <rule> (a bare <event>)
    # used to leave them unbound and raise UnboundLocalError at the return statement.
    group_by = "user.name"
    threshold = 1
    timeframe = "5m"
    wazuh_mixed_layout = False
    if target == "sigma":
        from safe_yaml import safe_yaml_load

        try:
            sigma = safe_yaml_load(text)
        except ValueError as error:
            raise RuleValidationError(str(error)) from error
        if not isinstance(sigma, dict) or not isinstance(sigma.get("detection"), dict):
            raise RuleValidationError("Sigma rule must contain a detection section.")
        native_metadata = {key: sigma.get(key) for key in ("title", "id", "status", "author", "tags", "falsepositives", "level") if key in sigma}
        native_sections = {key: yaml.safe_dump(value, sort_keys=False).strip() for key, value in sigma.items() if key in {"logsource", "detection", "references"}}
        detection_block = sigma["detection"]
        from parsers.sigma_parser import _split_field as _sigma_split
        skipped_null_fields = []
        for name, selection in detection_block.items():
            if name == "condition" or not isinstance(selection, dict):
                continue
            for field, value in selection.items():
                base, modifier = _sigma_split(str(field))
                values = value if isinstance(value, list) else [value]
                for item in values:
                    if item is None:
                        skipped_null_fields.append(base)
                        continue
                    conditions.append({"field": base, "operator": modifier, "value": str(item)})
        if skipped_null_fields:
            native_metadata["skipped_null_fields"] = sorted(set(skipped_null_fields))
        native_sections["sigma_condition"] = str(detection_block.get("condition", ""))
    if target == "wazuh":
        try:
            root = ET.fromstring(text)
            rule_node = root.find(".//rule")
            if rule_node is not None:
                native_metadata = {key: value for key, value in rule_node.attrib.items()}
                native_metadata["parent_rules"] = [node.text for node in rule_node.findall("if_matched_sid") + rule_node.findall("if_sid") if node.text]
                native_metadata["same_fields"] = [node.tag for node in rule_node if node.tag.startswith("same_")]
                native_metadata["mitre"] = [node.text for node in rule_node.findall(".//mitre/id") if node.text]
                for tag in ("field", "match", "program_name"):
                    nodes = rule_node.findall(tag)
                    for node in nodes:
                        field = node.attrib.get("name", tag)
                        if node.text:
                            entry = {"field": field, "operator": "regex" if tag in {"field", "match"} else "equals", "value": node.text}
                            if str(node.attrib.get("negate", "")).strip().lower() == "yes":
                                exclusions.append(entry)
                            else:
                                conditions.append(entry)
                if "frequency" in native_metadata:
                    threshold = int(native_metadata["frequency"])
                if "timeframe" in native_metadata:
                    timeframe = _duration_from_seconds(int(native_metadata["timeframe"]))
                group_map = {"same_srcip": "source.ip", "same_dstip": "destination.ip", "same_user": "user.name"}
                group_by = next((group_map[tag] for tag in native_metadata["same_fields"] if tag in group_map), "user.name")
                native_sections["rule"] = ET.tostring(rule_node, encoding="unicode")
        except (ET.ParseError, ValueError):
            native_metadata["parse_error"] = "Invalid Wazuh XML"
    condition_text = text
    raw_event_conditions: list[dict[str, str]] = []
    if target == "wazuh":
        condition_text = ""
    if target == "google_secops":
        events_match = re.search(r"\bevents:\s*(.*?)(?:\n\s*(?:outcome|condition):|\Z)", text, re.IGNORECASE | re.DOTALL)
        if events_match:
            condition_text = events_match.group(1)
    # A pasted raw *event* is not a query, so the query patterns find nothing in it.
    # Attempt structured extraction alongside them rather than instead of them: JSON and
    # XML identify themselves by their first character, and a JSON value that happens to
    # contain a pipe must not suppress extraction.
    # A pasted raw *event* is not a query, so the query patterns find nothing in it. When
    # the dialect-specific extractor above found nothing, fall back to structured parsing.
    # The fallback is skipped when it already has results so a dialect's own semantics
    # are never double-counted - but for Wazuh a mixed layout (a positive <field> plus a
    # negated one inside <match>) would leave the exclusion unrepresented, so Wazuh
    # always runs the fallback to collect anything the rule block did not.
    if not conditions and not exclusions:
        query_pattern_probe = re.search(r"(?:\|\s*\w+|->|\bwhere\b|\bsearch\b|\bSELECT\b|\bprocess\s+where\b|\bdetection:)", condition_text, re.IGNORECASE)
        event_conditions, event_exclusions = _structured_event_conditions(
            text, target, allow_token_scan=not query_pattern_probe)
        for entry in event_conditions:
            if entry not in conditions:
                conditions.append(entry)
        for entry in event_exclusions:
            if entry not in exclusions:
                exclusions.append(entry)
    elif target == "wazuh":
        event_conditions, event_exclusions = _structured_event_conditions(text, target)
        known_exclusions = {(e["field"], e["value"]) for e in exclusions}
        recovered = False
        for entry in event_exclusions:
            if (entry["field"], entry["value"]) not in known_exclusions:
                exclusions.append(entry)
                known_exclusions.add((entry["field"], entry["value"]))
                recovered = True
        # A negation recovered from outside <match> means the import was not complete;
        # record it so the result is not reported as a faithful round trip.
        wazuh_mixed_layout = recovered
    patterns = [
        (r"([A-Za-z_@][A-Za-z0-9_.@-]*)\s+contains\s+\"([^\"]+)\"", "contains"),
        (r"([A-Za-z_@][A-Za-z0-9_.@-]*)\s+startswith\s+\"([^\"]+)\"", "starts_with"),
        (r"([A-Za-z_@][A-Za-z0-9_.@-]*)\s+(?:==|=|=~)\s+\"([^\"]+)\"", "equals"),
        (r"([A-Za-z_@][A-Za-z0-9_.@-]*)\s+(?:has_any|in~?)\s*\(\s*\"([^\"]+)\"", "contains"),
        (r"([A-Za-z_@][A-Za-z0-9_.@-]*)\s+ILIKE\s+'%([^']+)%'", "contains"),
        (r"([A-Za-z_@][A-Za-z0-9_.@-]*)\s+IN\s*\(\s*'([^']+)'", "equals"),
        # AQL literals are single-quoted, so `sourceip = '1.2.3.4'` needs an explicit
        # match; without it an AQL WHERE clause was invisible and the analyst imported
        # an empty rule. The negated forms are matched first and routed to exclusions:
        # `NOT x = 'v'`, `not (x = 'v')` and `x != 'v'` are all negation in AQL, and
        # treating any of them as a positive equality would invert the rule on recompile.
        (r"NOT\s*(?:\(\s*)?([A-Za-z_@][A-Za-z0-9_.@-]*)\s*(?:==|=|!=|<>)\s*'((?:[^'\\]|\\.)*)'", "not_equals"),
        (r"([A-Za-z_@][A-Za-z0-9_.@-]*)\s*(?:!=|<>)\s*'((?:[^'\\]|\\.)*)'", "not_equals"),
        (r"([A-Za-z_@][A-Za-z0-9_.@-]*)\s*(?:==|=)\s*'((?:[^'\\]|\\.)*)'", "equals"),
        (r"([A-Za-z_@][A-Za-z0-9_.@-]*)=\"\*([^\"]+)\*\"", "contains"),
        (r"([A-Za-z_@][A-Za-z0-9_.@-]*)=\"([^\"*]+)\"", "equals"),
        (r"([A-Za-z_@][A-Za-z0-9_.@-]*)\s*=\s*/([^/]+)/[a-z]*", "regex"),
        (r"([A-Za-z_@][A-Za-z0-9_.@-]*)\s*/([^/]+)/[a-z]*", "regex"),
    ]
    # Negation is resolved first and its character spans recorded, because a negated
    # comparison such as `NOT username = 'admin'` also contains a positive `=` that the
    # positive patterns would otherwise re-match, putting the same field in both lists.
    negated_spans: list[tuple[int, int]] = []
    for pattern, operator in patterns:
        if operator != "not_equals":
            continue
        for match in re.finditer(pattern, condition_text, re.IGNORECASE):
            negated_spans.append(match.span())
            field, value = _unescape_literal(match.group(1), match.group(2))
            if target == "google_secops":
                field = re.sub(r"^e\.", "", field, flags=re.IGNORECASE)
            condition = {"field": field, "operator": "equals", "value": value}
            if condition not in exclusions:
                exclusions.append(condition)

    for pattern, operator in patterns:
        if operator == "not_equals":
            continue
        for match in re.finditer(pattern, condition_text, re.IGNORECASE):
            if any(start <= match.start() < end for start, end in negated_spans):
                continue  # already captured as an exclusion
            field, value = match.group(1), match.group(2)
            if target == "google_secops":
                field = re.sub(r"^e\.", "", field, flags=re.IGNORECASE)
            condition = {"field": field, "operator": operator, "value": value}
            if condition not in conditions:
                conditions.append(condition)

    if target == "elastic":
        sequence_match = re.search(r"sequence\s+by\s+([^\s]+)\s+with\s+maxspan\s*=\s*([^\s\[]+)(.*)", text, re.IGNORECASE | re.DOTALL)
        if sequence_match:
            stages = []
            for stage in re.findall(r"(!?)\[\s*([^\]]+)\]", sequence_match.group(3)):
                negated, body = stage[0] == "!", stage[1]
                stages.append({"event": body.split(" where ", 1)[0].strip(), "condition": body.split(" where ", 1)[1].strip() if " where " in body else "", "negated": negated})
            sequences.append({"join_by": sequence_match.group(1), "maxspan": sequence_match.group(2).strip(), "stages": stages})
            native_sections["sequence"] = sequence_match.group(0).strip()
    if target == "sentinel":
        for stream_match in re.finditer(r"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", text, re.IGNORECASE):
            event_streams.append({"name": stream_match.group(1), "source": stream_match.group(2)})
        for join_match in re.finditer(r"\bjoin\s+kind\s*=\s*(\w+)\s+(\w+)\s+on\s+([A-Za-z0-9_.$]+(?:\s*,\s*[A-Za-z0-9_.$]+)*)", text, re.IGNORECASE):
            joins.append({"kind": join_match.group(1), "right": join_match.group(2), "on": join_match.group(3)})
        for summary in re.finditer(r"\bsummarize\b(.*?)(?:\bby\b|$)", text, re.IGNORECASE | re.DOTALL):
            for aggregate in re.finditer(r"(?:(\w+)\s*=\s*)?(count|min|max|sum|avg|dcount|make_set|arg_min|arg_max)\s*\(\s*([^)]*?)\s*\)", summary.group(1), re.IGNORECASE):
                aggregations.append({"function": aggregate.group(2), "field": aggregate.group(3), "alias": aggregate.group(1) or ""})
        time_constraints = re.findall(r"\b[A-Za-z_][A-Za-z0-9_.]*\s+between\s*\([^\n]+\)", text, re.IGNORECASE)
        native_sections["let_bindings"] = "\n".join(line for line in text.splitlines() if line.strip().lower().startswith("let "))
    if target == "splunk":
        for lookup_match in re.finditer(r"\|\s*lookup\s+([^\s]+)([^\n]*)", text, re.IGNORECASE):
            lookups.append({"name": lookup_match.group(1), "arguments": lookup_match.group(2).strip()})
        for stats_line in re.finditer(r"\|\s*(?:stats|eventstats|streamstats)\s+([^\n|]+)", text, re.IGNORECASE):
            for aggregate in re.finditer(r"\b(count|dc|values|sum)\s*\(?\s*([A-Za-z0-9_.]*)\)?(?:\s+as\s+([A-Za-z0-9_]+))?", stats_line.group(1), re.IGNORECASE):
                aggregations.append({"function": aggregate.group(1), "field": aggregate.group(2), "alias": aggregate.group(3) or ""})
    if target == "falcon":
        for lookup_match in re.finditer(r"\|\s*lookup\s*\(\s*\[([^\]]+)\]([^|\n]*)", text, re.IGNORECASE):
            lookups.append({"name": lookup_match.group(1).strip().strip('"'), "arguments": lookup_match.group(2).strip()})
        for aggregate in re.finditer(r"groupBy\s*\(\s*\[([^\]]*)\][^)]*function\s*=\s*\[([^\]]*)\]", text, re.IGNORECASE | re.DOTALL):
            for func in re.finditer(r"count\s*\(\s*(?:field\s*=\s*([A-Za-z0-9_.]+)\s*,?\s*)?(?:distinct\s*=\s*true\s*,?\s*)?(?:as\s*=\s*([A-Za-z0-9_]+))?\s*\)", aggregate.group(2), re.IGNORECASE):
                aggregations.append({"function": "count", "field": func.group(1) or "", "alias": func.group(2) or ""})
        repo_match = re.search(r"#repo\s*=\s*([^\s|]+)", text)
        native_sections["repo"] = repo_match.group(1) if repo_match else ""
        # #repo is a repository scope, not a match condition. Remove it if the generic
        # extractor picked it up so the analyst does not draft a rule on the log source.
        conditions[:] = [c for c in conditions if c["field"].lower() not in _SCOPE_DIRECTIVES]
        native_sections["pipeline"] = "\n".join(line.strip() for line in text.splitlines() if line.strip())
    if target == "qradar":
        for xforce in re.finditer(r"\b(XFORCE_[A-Z_]+)\s*\(([^)]*)\)", text, re.IGNORECASE):
            lookups.append({"name": xforce.group(1).upper(), "arguments": xforce.group(2).strip()})
        for aggregate in re.finditer(r"\b(COUNT|SUM|AVG|MIN|MAX)\s*\(\s*([^)]+)\)\s*(?:AS\s+([A-Za-z0-9_]+))?", text, re.IGNORECASE):
            aggregations.append({"function": aggregate.group(1), "field": aggregate.group(2).strip(), "alias": aggregate.group(3) or ""})
        last_match = re.search(r"\bLAST\s+(\d+)\s+(MINUTES|HOURS|DAYS)", text, re.IGNORECASE)
        if last_match:
            timeframe = f"{last_match.group(1)}{'m' if last_match.group(2).lower().startswith('min') else 'h' if last_match.group(2).lower().startswith('hour') else 'd'}"
        native_sections["where"] = (re.search(r"\bWHERE\s+(.*?)(?:\bGROUP BY\b|\bHAVING\b|\bLAST\b|$)", text, re.IGNORECASE | re.DOTALL) or type("Match", (), {"group": lambda self, _: ""})()).group(1).strip()
    if target == "google_secops":
        for section in ("meta", "events", "match", "outcome", "condition"):
            section_match = re.search(rf"\b{section}:\s*(.*?)(?=\n\s*(?:meta|events|match|outcome|condition):|\n\s*}})", text, re.IGNORECASE | re.DOTALL)
            if section_match:
                native_sections[section] = section_match.group(1).strip()
        native_metadata["outcome"] = native_sections.get("outcome", "")
        # placeholder joins: same $placeholder bound on >=2 event variables
        placeholder_events: dict[str, set[str]] = {}
        for line in native_sections.get("events", "").splitlines():
            assignment = re.match(r"\s*(\$[A-Za-z_][A-Za-z0-9_]*)\.[^\n=]*=\s*(\$[A-Za-z_][A-Za-z0-9_]*)\s*$", line)
            if assignment:
                event_var, placeholder = assignment.group(1), assignment.group(2)
                placeholder_events.setdefault(placeholder, set()).add(event_var)
        for placeholder, event_vars in placeholder_events.items():
            if len(event_vars) > 1:
                ordered = sorted(event_vars)
                joins.append({"kind": "equality", "left": ordered[0], "right": ordered[-1], "on": placeholder})

    wazuh_native = target == "wazuh" and "frequency" in native_metadata
    threshold = 1
    threshold_detected = wazuh_native
    if wazuh_native:
        threshold = int(native_metadata["frequency"])
    else:
        threshold_match = re.search(r"(?:\bwhere\b[^\n]*?(?:EventCount|count)\s*>=?|EventCount\s*>=?|frequency\s*=\s*\"?|#\w+\s*>=?)\s*(\d+)", text, re.IGNORECASE)
        if threshold_match:
            threshold = int(threshold_match.group(1))
            threshold_detected = True
    timeframe_match = re.search(r"(?:ago\(|over\s+|-)(\d{1,3}[mhd])\)?", text, re.IGNORECASE)
    if timeframe_match:
        timeframe = timeframe_match.group(1).lower()
    elif not (target == "wazuh" and "timeframe" in native_metadata):
        seconds_match = re.search(r"timeframe\s*=\s*[\"'](\d+)[\"']", text, re.IGNORECASE)
        seconds = int(seconds_match.group(1)) if seconds_match else 300
        timeframe = f"{max(1, round(seconds / 60))}m"
    if target == "qradar":
        qradar_last = re.search(r"\bLAST\s+(\d+)\s+(MINUTES|HOURS|DAYS)", text, re.IGNORECASE)
        if qradar_last:
            timeframe = f"{qradar_last.group(1)}{'m' if qradar_last.group(2).lower().startswith('min') else 'h' if qradar_last.group(2).lower().startswith('hour') else 'd'}"
    source_match = re.search(r"\bindex=([^\s|]+)|#repo=([^\s|]+)|\bFROM\s+(events|flows)\b|\b(?:index pattern|table)\s*[:=]\s*([^\s]+)", text, re.IGNORECASE)
    data_source = next((value for value in source_match.groups() if value), "*") if source_match else "*"
    group_match = re.search(r"(?:stats\s+[^\n]*?\bby|summarize\s+[^\n]*?\bby|GROUP\s+BY)\s+([A-Za-z_@][A-Za-z0-9_.@-]*)", text, re.IGNORECASE)
    if target == "wazuh":
        pass  # group_by already set from same_* tags above; generic match must not overwrite it
    else:
        group_by = group_match.group(1) if group_match else "user.name"

    logic_text = _logic_text(text, target, native_sections)
    feature_patterns = {
        "ordered sequence": r"\bsequence\b|\bmaxspan\b|\[\s*(?:process|network|authentication|file)\s+where",
        "cross-event join": r"\bjoin\b|\bsame_[a-z]+\b|\bif_matched_(?:sid|group)\b|\$[A-Za-z_][A-Za-z0-9_]*\.[^\n]+\$[A-Za-z_][A-Za-z0-9_]*",
        "lookup or enrichment": r"\blookup\b|\bXFORCE_[A-Z_]+\b|\bexternaldata\b|\bmake_set\b",
    }
    unsupported_features = [name for name, pattern in feature_patterns.items() if re.search(pattern, logic_text, re.IGNORECASE)]
    # A real structural parse replaces guesswork: run the dialect's own parser over the
    # imported text and report what it found. This is evidence, not inference, so a rule
    # that is genuinely single-event and well-formed is no longer labelled partial just
    # because a boolean word appeared inside a quoted value.
    from compiler.dialects import PARSERS as _PARSERS, structure_check as _structure_check, structure_summary as _structure_summary

    parse_problems: list[str] = []
    parse_summary: dict[str, Any] = {}
    if target in _PARSERS:
        parse_problems = _structure_check(target, text)
        parse_summary = _structure_summary(target, text)
    elif target == "wazuh":
        from compiler.validators import target_check as _target_check
        parse_problems = _target_check("wazuh", text)
        parse_summary = {"dialect": "wazuh", "structured": False}

    if target != "wazuh":
        structure = _boolean_structure(logic_text)
        boolean_hits = structure["operators"]
        # F5-route-b: ANY boolean keyword means structure may have been flattened or missed
        # (single-extract + OR was previously exact yet wrong). Structured Sigma/Wazuh paths
        # already flag multi-condition cases; this closes the single-hit regex hole.
        if len(conditions) > 1 or boolean_hits:
            unsupported_features.append("boolean branching")
            if target not in {"sigma", "wazuh"} and len(conditions) <= 1:
                # A boolean operator in the source but only one extracted condition means
                # the OR/AND structure did not survive extraction. That is lossy regardless
                # of whether the original query was syntactically valid, so it stays flagged.
                unsupported_features.append("regex-extracted — verify boolean structure")
        if structure["group_depth"] > 1 and target not in {"sigma", "wazuh"}:
            unsupported_features.append("nested grouping — regex extraction flattens parentheses")
        if parse_problems:
            unsupported_features.extend(f"structural parse: {problem}" for problem in parse_problems)
    complex_aggregation = any(item["function"].lower() != "count" for item in aggregations)
    if sequences or joins or complex_aggregation or lookups:
        unsupported_features.extend(name for name, present in (("sequence model", bool(sequences)), ("join model", bool(joins)), ("aggregation model", complex_aggregation), ("lookup model", bool(lookups))) if present)
    if native_metadata.get("parent_rules") or native_metadata.get("same_fields"):
        unsupported_features.append("Wazuh chained correlation")
    unsupported_features = list(dict.fromkeys(unsupported_features))
    if wazuh_mixed_layout:
        unsupported_features.append("mixed Wazuh layout: a negated field was found outside <match>")
    is_advanced = len(conditions) > 1 or bool(unsupported_features)
    fidelity = "exact" if not unsupported_features else "partial"
    if not conditions:
        fidelity = "unsupported"
    suggestions = [
        "Confirm every extracted field exists in the selected SIEM's data model.",
        "Test the imported logic against known matching and non-matching events.",
    ]
    if is_advanced:
        suggestions.insert(0, "Advanced boolean or correlation logic was detected; review each clause manually before compiling.")
    if unsupported_features:
        suggestions.insert(1, f"The analyzer identified: {', '.join(unsupported_features)}. These features are preserved as analyst notes, not auto-translated.")
    if not conditions:
        suggestions.insert(0, "No simple field comparison was recognized. Use the raw rule as a reference and configure the conditions manually.")

    first = conditions[0] if conditions else {"field": "process.name", "operator": "contains", "value": ""}
    return {
        "siem": target,
        "detected_siem": detection["siem"],
        "detection_confidence": detection["confidence"],
        "detection_reason": detection["reason"],
        "mode": "advanced" if is_advanced else "simple",
        "confidence": "partial" if is_advanced or not conditions else "high",
        "conditions": conditions,
        "exclusions": exclusions,
        "unsupported_features": unsupported_features,
        "raw_rule": text,
        "native_sections": native_sections,
        "native_metadata": native_metadata,
        "sequences": sequences,
        "joins": joins,
        "aggregations": aggregations,
        "lookups": lookups,
        "event_streams": event_streams,
        "time_constraints": time_constraints,
        "fidelity": fidelity,
        "equivalent_recompile": fidelity == "exact",
        "structure": parse_summary,
        "structure_problems": parse_problems,
        "threshold": threshold,
        "threshold_detected": threshold_detected,
        "timeframe": timeframe,
        "data_source": data_source,
        "group_by": group_by,
        "suggestions": suggestions,
        "payload_defaults": {
            "field": first["field"],
            "operator": first["operator"],
            "value": first["value"],
            "threshold": threshold,
            "use_threshold": threshold_detected,
            "timeframe": timeframe,
            "data_source": data_source,
            "group_by": group_by,
        },
    }


def detect_siem(rule_text: str) -> dict[str, str]:
    """Identify a likely source dialect using distinctive syntax markers."""
    signatures = [
        ("sigma", r"(?:^|\n)\s*(?:title|logsource|detection|falsepositives):\s*", "Sigma YAML rule sections"),
        ("wazuh", r"<\s*(?:group|rule|if_sid|field)\b", "Wazuh XML rule elements"),
        ("google_secops", r"\brule\s+[A-Za-z0-9_]+\s*\{|\bmeta:\s|\bevents:\s|\bmatch:\s", "YARA-L rule sections"),
        ("elastic", r"\bsequence\s+by\b|\bmaxspan\s*=|\b(?:process|network|file|authentication)\s+where\b", "Elastic EQL sequence or event syntax"),
        ("qradar", r"\bSELECT\b.+\bFROM\s+(?:events|flows)\b|\bLAST\s+\d+\s+(?:MINUTES|HOURS)\b", "QRadar AQL SELECT/FROM/LAST syntax"),
        ("sentinel", r"\b(?:summarize|extend|project|datatable|Device[A-Za-z]+Events)\b|\bago\s*\(", "Kusto query operators or Sentinel tables"),
        ("splunk", r"(?:^|\n)\s*\|\s*[A-Za-z_]+|\bindex\s*=|\bsourcetype\s*=|\bstats\s+count\b", "Splunk search pipeline or index syntax"),
        ("falcon", r"(?:^|\n)\s*\|\s*(?:groupBy|test|case|collect|readFile)|\b_repo\s*=|\b#repo=", "Falcon LogScale pipeline syntax"),
    ]
    matches = [(siem, reason) for siem, pattern, reason in signatures if re.search(pattern, rule_text, re.IGNORECASE | re.MULTILINE | re.DOTALL)]
    if not matches:
        return {"siem": "splunk", "confidence": "low", "reason": "No distinctive vendor syntax was found; Splunk is used as the editable fallback."}
    if len(matches) == 1:
        return {"siem": matches[0][0], "confidence": "high", "reason": matches[0][1]}
    # Prefer highly distinctive structured formats over generic query operators.
    priority = {"wazuh": 7, "google_secops": 6, "elastic": 5, "qradar": 4, "sentinel": 3, "falcon": 2, "splunk": 1}
    selected = max(matches, key=lambda item: priority[item[0]])
    return {"siem": selected[0], "confidence": "medium", "reason": f"Multiple dialect markers found; selected {selected[0]} from {selected[1]}."}
