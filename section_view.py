"""Section view: split a raw native rule into labeled analyst blocks per dialect.

Powers the tabbed section viewer in the UI so every SIEM — including
YARA-L (meta/events/match/outcome/condition) — is shown structure-first,
not as one opaque <pre> blob.
"""
from __future__ import annotations

import re
from html import escape as xml_escape

import yaml


def section_blocks(raw_rule: str, siem: str) -> list[dict[str, str]]:
    text = raw_rule or ""
    if siem == "google_secops":
        return _yara_sections(text)
    if siem == "sigma":
        return _sigma_sections(text)
    if siem in ("splunk", "falcon"):
        return _pipeline_sections(text, siem)
    if siem == "sentinel":
        return _kql_sections(text)
    if siem == "elastic":
        return _eql_sections(text)
    if siem == "qradar":
        return _aql_sections(text)
    if siem == "wazuh":
        return _wazuh_sections(text)
    return [{"title": "Rule", "code": text}]


def _yara_sections(text: str) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []
    for section in ("meta", "events", "match", "outcome", "condition"):
        match = re.search(rf"^(\s*{section}\s*:)(.*?)(?=^\s*(?:meta|events|match|outcome|condition)\s*:|^\s*}})",
                          text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        if match:
            blocks.append({"title": section, "code": (match.group(1) + match.group(2)).strip()})
    if not blocks:
        blocks = [{"title": "Rule", "code": text}]
    head = text.split("meta:")[0].strip() if "meta:" in text else ""
    if head:
        blocks.insert(0, {"title": "rule header", "code": head})
    return blocks


def _sigma_sections(text: str) -> list[dict[str, str]]:
    from safe_yaml import safe_yaml_load

    try:
        doc = safe_yaml_load(text)
    except Exception:
        return [{"title": "Rule", "code": text}]
    if not isinstance(doc, dict):
        return [{"title": "Rule", "code": text}]
    blocks = []
    meta = {k: v for k, v in doc.items() if k not in ("logsource", "detection")}
    if meta:
        blocks.append({"title": "metadata", "code": yaml.safe_dump(meta, sort_keys=False).strip()})
    for key in ("logsource", "detection"):
        if key in doc:
            blocks.append({"title": key, "code": yaml.safe_dump({key: doc[key]}, sort_keys=False).strip()})
    return blocks or [{"title": "Rule", "code": text}]


def _pipeline_sections(text: str, siem: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines()]
    header = [line for line in lines if re.match(r"^\s*(#|//|--|index=|#repo=)", line)]
    rest = [line for line in lines if line not in header]
    stages = [line.strip() for line in rest if line.strip().startswith("|")]
    base = [line.strip() for line in rest if line.strip() and not line.strip().startswith("|")]
    blocks = []
    if header:
        blocks.append({"title": "scope", "code": "\n".join(header)})
    for line in base:
        blocks.append({"title": "base filter", "code": line})
    for i, stage in enumerate(stages, 1):
        blocks.append({"title": f"stage {i}", "code": stage})
    return blocks or [{"title": "Rule", "code": text}]


def _kql_sections(text: str) -> list[dict[str, str]]:
    blocks = []
    lets = [line for line in text.splitlines() if line.strip().lower().startswith("let ")]
    rest = [line for line in text.splitlines() if not line.strip().lower().startswith("let ") and line.strip()]
    if lets:
        blocks.append({"title": "event streams (let)", "code": "\n".join(lets)})
    if rest:
        blocks.append({"title": "query", "code": "\n".join(rest)})
    return blocks or [{"title": "Rule", "code": text}]


def _eql_sections(text: str) -> list[dict[str, str]]:
    seq = re.search(r"sequence\s+by\s+([^\s]+)\s+with\s+maxspan\s*=\s*([^\n]+)", text, re.IGNORECASE)
    blocks = []
    if seq:
        blocks.append({"title": "correlation", "code": seq.group(0).strip()})
    for i, (neg, stage) in enumerate(re.findall(r"(!?)\[\s*([^\]]*?where[^\]]*)\]", text, re.IGNORECASE), 1):
        blocks.append({"title": f"stage {i}" + (" (negated)" if neg else ""), "code": f"{'!' if neg else ''}[{stage.strip()}]"})
    return blocks or [{"title": "Rule", "code": text}]


def _aql_sections(text: str) -> list[dict[str, str]]:
    blocks = []
    for title, pattern in (("select", r"SELECT\s+.*?(?=\bFROM\b)"), ("from", r"FROM\s+\w+"),
                           ("where", r"WHERE\s+.*?(?=\bGROUP BY\b|\bHAVING\b|\bLAST\b|$)"),
                           ("group by", r"GROUP\s+BY\s+[^\n]+"), ("having", r"HAVING\s+.*?(?=\bLAST\b|$)"),
                           ("time window", r"LAST\s+\d+\s+\w+")):
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            blocks.append({"title": title, "code": match.group(0).strip()})
    comments = [line for line in text.splitlines() if line.strip().startswith("--")]
    if comments:
        blocks.insert(0, {"title": "notes", "code": "\n".join(comments)})
    return blocks or [{"title": "Rule", "code": text}]


def _wazuh_sections(text: str) -> list[dict[str, str]]:
    import xml.etree.ElementTree as ET

    blocks = []
    comments = [line.strip() for line in text.splitlines() if line.strip().startswith("<!--")]
    if comments:
        blocks.append({"title": "deployment note", "code": "\n".join(comments)})
    try:
        root = ET.fromstring(text)
        rule_node = root if root.tag == "rule" else root.find(".//rule")
        if rule_node is not None:
            attrib = " ".join(f'{k}="{xml_escape(v, quote=True)}"' for k, v in rule_node.attrib.items())
            blocks.append({"title": "rule identity", "code": f"<rule {attrib}>"})
            for child in rule_node:
                blocks.append({"title": child.tag, "code": ET.tostring(child, encoding="unicode").strip()})
    except ET.ParseError:
        pass
    return blocks or [{"title": "Rule", "code": text}]
