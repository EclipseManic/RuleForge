"""Validators: sigma check (no new deps) + per-target syntax sanity."""
from __future__ import annotations

import re

from compiler.dialects import PARSERS as DIALECT_STRUCTURED, _drop_comments, strip_literals


def sigma_check(yaml_text: str) -> list[str]:
    """Lightweight Sigma validation without pySigma dependency."""
    from parsers.sigma_parser import parse_sigma

    errors: list[str] = []
    if not (yaml_text or "").strip():
        return ["Sigma YAML is empty."]
    try:
        _, meta = parse_sigma(yaml_text)
    except ValueError as error:
        return [str(error)]
    if not meta.get("title"):
        errors.append("Missing 'title'.")
    if not meta.get("logsource"):
        errors.append("Missing 'logsource' (product/category/service).")
    # detection presence already proven by successful parse_sigma above
    return errors


# Dialects with a real structural parser (compiler.dialects) do not need the legacy
# keyword probes: the parser knows the grammar and produces a better message. Kept for
# targets with no parser, where a presence check is still worth something.
TARGET_CHECKS = {
    "wazuh": (r"<\s*rule\b", "Wazuh XML should contain a <rule> element."),
    "sigma": (r"detection\s*:", "Sigma should contain a detection section."),
}


def target_check(siem: str, query: str) -> list[str]:
    """Validate generated output for one target.

    Dialects with a structural parser get a real grammar check. Wazuh gets a real
    XML parse plus the range checks that catch the mistakes that actually happen
    (rule id outside the custom range, non-integer level).
    """
    from compiler.dialects import PARSERS, structure_check

    if siem in PARSERS:
        return structure_check(siem, query)
    pattern, message = TARGET_CHECKS.get(siem, ("", ""))
    if not pattern:
        return [f"Unknown target: {siem}."]
    if not re.search(pattern, query, re.IGNORECASE | re.DOTALL):
        return [message]
    if siem == "wazuh":
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(query)
        except ET.ParseError:
            return ["Wazuh output is not well-formed XML."]
        rule_node = root if root.tag == "rule" else root.find(".//rule")
        if rule_node is None:
            return ["Wazuh output has no <rule> element."]
        try:
            rule_id = int(rule_node.attrib.get("id", "0"))
            level = int(rule_node.attrib.get("level", "-1"))
        except ValueError:
            return ["Wazuh rule id/level must be integers."]
        if not 100000 <= rule_id <= 120000:
            return ["Wazuh custom rule IDs must be between 100000 and 120000."]
        if not 0 <= level <= 15:
            return ["Wazuh level must be between 0 and 15."]
    if siem == "sigma":
        from safe_yaml import safe_yaml_load
        try:
            doc = safe_yaml_load(query)
        except ValueError as error:
            return [f"Sigma output is not valid YAML: {error}."]
        if not isinstance(doc, dict) or "detection" not in doc:
            return ["Sigma output has no detection section."]
    return []


def faithfulness(conditions: list[dict], exclusions: list[dict], query: str, fidelity: str) -> dict:
    """Round-trip check (F5-route-b, offline): does the recompiled query still carry
    every analyzed condition? Returns {"badge": "faithful"|"lossy", "reasons": [...]}.
    Field presence is checked literally and by trailing component (mapped fields rename)."""
    reasons: list[str] = []
    lowered = (query or "").lower()
    for entry in list(conditions or []) + list(exclusions or []):
        if not isinstance(entry, dict):
            continue
        field = str(entry.get("field", "")).lower()
        if not field:
            continue
        if field not in lowered and field.split(".")[-1] not in lowered:
            reasons.append(f"field {entry.get('field')} not found in recompiled query")
    if fidelity in ("partial", "unsupported"):
        reasons.append(f"recompile fidelity is {fidelity}")
    return {"badge": "lossy" if reasons else "faithful", "reasons": reasons}


def validation_level(siem: str, checks: list[str], py_sigma: bool = False) -> str:
    """How strongly an output was validated (F9).

    "grammar-checked"  = real parser from the reference implementation (pySigma) or a
                         full grammar parse (Wazuh XML, Sigma YAML).
    "structure-parsed" = our dialect parser walked the grammar shape: pipeline stages,
                         clause order, event categories, balanced groups, dangling
                         booleans, undefined variable references.
    "sanity-checked"   = keyword presence only. Weaker, and labelled as such.

    Non-empty checks always means failed, regardless of tier.
    pySigma output is authoritative even when our own scope checks flag a placeholder
    such as index=*, because the reference implementation produced it.
    """
    if py_sigma:
        return "grammar-checked"
    if checks:
        return "failed"
    if siem in ("sigma", "wazuh"):
        return "grammar-checked"
    if siem in DIALECT_STRUCTURED:
        return "structure-parsed"
    return "sanity-checked"


def target_warnings(siem: str, query: str) -> list[str]:
    """Non-blocking per-dialect authoring hints (G7)."""
    warnings: list[str] = []
    if siem == "splunk" and re.search(r"index=\*", query):
        warnings.append("Unscoped index=* — replace with a real index before enabling.")
    if siem == "sentinel":
        from rule_engine import ASIM_TABLE_PLACEHOLDER, SENTINEL_LEGACY_TABLES
        if ASIM_TABLE_PLACEHOLDER in query:
            warnings.append(
                f"Table is the placeholder {ASIM_TABLE_PLACEHOLDER}. Replace it with the table your ASIM "
                "parser writes to; the legacy SecurityEvent table uses different column names and will "
                "not work with ASIM columns.")
        else:
            lowered_tables = {t.lower() for t in SENTINEL_LEGACY_TABLES}
            for line in _drop_comments(strip_literals(query)).splitlines():
                head = line.strip()
                if head and not head.startswith("|") and head.split()[0].lower() in lowered_tables:
                    warnings.append(
                        f"'{head.split()[0]}' is a legacy Sentinel table with Account/CommandLine/Image "
                        "columns and will NOT work with the ASIM columns in this query. Point the rule at "
                        "the table your ASIM parser writes to.")
                    break
    if siem == "sentinel" and not re.search(r"ago\(|TimeGenerated", query):
        warnings.append("No TimeGenerated bound — scheduled rules need a lookback window.")
    from compiler.dialects import structure_advice
    warnings.extend(structure_advice(siem, query))
    if siem == "elastic" and "threshold" in query.lower():
        warnings.append("Elastic threshold semantics differ from EQL sequences; confirm rule type.")
    if siem == "qradar" and not re.search(r"\bLAST\s+\d+", query, re.IGNORECASE):
        warnings.append("No LAST time window — AQL will scan unbounded history.")
    if siem == "google_secops" and not re.search(r"\bmatch\s*:", query, re.IGNORECASE):
        warnings.append("No match: block — single-event rule has no grouping window.")
    if siem == "falcon" and not re.search(r"#repo\s*=", query):
        warnings.append("No #repo scope — LogScale needs a repository.")
    if siem == "wazuh" and 'frequency="' not in query:
        warnings.append("No frequency/timeframe — single-event rule fires on every match.")
    return warnings
