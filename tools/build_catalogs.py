"""One-time ingest: build compact local catalogs from authoritative sources.

- MITRE ATT&CK Enterprise STIX bundle -> data/attack_catalog.json (technique reference:
  id, name, tactics, summary). This is REFERENCE metadata for mapping/guidance, not a
  renderer template - the curated data/techniques.json stays the buildable set.
- Elastic ECS generated fields -> data/ecs_fields.json (field names for autocomplete).

Run:  python tools/build_catalogs.py
Both outputs are committed so the tool stays fully offline and local.
"""
from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
ECS_URL = "https://raw.githubusercontent.com/elastic/ecs/main/generated/beats/fields.ecs.yml"


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=180) as response:  # noqa: S310 - fixed https sources
        return response.read().decode("utf-8", errors="replace")


def clean(text: str, limit: int = 400) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text[:limit]


def build_attack() -> dict:
    print("downloading ATT&CK STIX bundle (about 54MB)...")
    bundle = json.loads(fetch(ATTACK_URL))
    techniques: dict[str, dict] = {}
    revoked: set[str] = set()
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern" and obj.get("revoked"):
            for ref in obj.get("external_references", []):
                if str(ref.get("external_id", "")).startswith("T"):
                    revoked.add(ref["external_id"])
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in obj.get("external_references", []) if str(r.get("external_id", "")).startswith("T")), None)
        if not ext:
            continue
        tid = ext["external_id"]
        tactics = [p.get("phase_name") for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        techniques[tid] = {
            "id": tid,
            "name": clean(obj.get("name"), 120),
            "tactics": sorted({t for t in tactics if t}),
            "summary": clean(obj.get("description"), 400),
            "url": ext.get("url", ""),
            "platforms": obj.get("x_mitre_platforms", [])[:6],
        }
    payload = {
        "meta": {
            "source": "MITRE ATT&CK Enterprise (attack-stix-data, master)",
            "license": "ATT&CK terms of use; see attack.mitre.org",
            "note": "Reference catalog for technique mapping and guidance. Buildable detection templates live in data/techniques.json.",
            "technique_count": len(techniques),
        },
        "techniques": dict(sorted(techniques.items())),
    }
    (DATA / "attack_catalog.json").write_text(json.dumps(payload, indent=1, sort_keys=False), encoding="utf-8")
    return payload["meta"]


def build_ecs() -> dict:
    """Extract real ECS field names as full dotted paths.

    Generated layout is a tree: ``- key: <group>`` then nested ``fields: - name: <leaf>``,
    with object-typed leaves recursing one level deeper. Walking the indentation gives
    the true path (e.g. process.name, dns.question.name) instead of group labels.
    """
    print("downloading ECS field list...")
    text = fetch(ECS_URL)
    lines = text.splitlines()
    names: list[str] = []
    stack: list[tuple[int, str]] = []  # (indent, group key)

    def is_group(index: int) -> bool:
        """A '- name: x' entry is a GROUP when a deeper 'fields:' block follows it."""
        base = len(lines[index]) - len(lines[index].lstrip())
        for follow in lines[index + 1:]:
            if not follow.strip() or follow.lstrip().startswith("#"):
                continue
            indent = len(follow) - len(follow.lstrip())
            if indent <= base:
                return False
            if follow.strip() == "fields:":
                return True
        return False

    for index, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if stripped.startswith("- key:"):
            key = stripped.split(":", 1)[1].strip()
            if not stack and key == "ecs":
                continue  # document root, not a field-path segment
            stack.append((indent, key))
            continue
        if stripped.startswith("- name:"):
            leaf = stripped.split(":", 1)[1].strip().strip("'\"")
            if is_group(index):
                stack.append((indent, leaf))
                continue
            prefix = [k for _, k in stack]
            path = ".".join(prefix + [leaf])
            if path and path not in names:
                names.append(path)
            continue
    payload = {
        "meta": {
            "source": "Elastic Common Schema (elastic/ecs, generated/beats/fields.ecs.yml)",
            "note": "Canonical field names offered for autocomplete. Only fields with a known target mapping translate automatically; the rest pass through and are flagged unmapped.",
            "field_count": len(names),
        },
        "fields": sorted(names),
    }
    (DATA / "ecs_fields.json").write_text(json.dumps(payload, indent=1), encoding="utf-8")
    return payload["meta"]


if __name__ == "__main__":
    DATA.mkdir(parents=True, exist_ok=True)
    print("attack:", build_attack())
    print("ecs:", build_ecs())
