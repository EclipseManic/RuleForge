"""Clause-level diff for tune iterations."""
from __future__ import annotations

from typing import Any


def _flatten(node: Any, out: list[str]) -> None:
    if node is None:
        return
    if isinstance(node, list):
        for item in node:
            _flatten(item, out)
        return
    if not isinstance(node, dict):
        try:
            from models.correlation import LogicNode, Predicate
            if isinstance(node, Predicate):
                value = node.value
                if isinstance(value, list):
                    value = f"[{', '.join(sorted(str(v) for v in value))}]"
                out.append(f"{node.field} {node.operator} {value}")
                return
            if isinstance(node, LogicNode):
                if node.op == "not":
                    out.append("NOT (...)")
                for child in node.children or ():
                    _flatten(child, out)
                if node.op == "or":
                    out.append("__or__")
                return
        except ImportError:
            pass
        return
    if "field" in node:
        value = node.get("value")
        if isinstance(value, list):
            value = f"[{', '.join(sorted(str(v) for v in value))}]"
        out.append(f"{node['field']} {node.get('operator')} {value}")
    elif "op" in node:
        op = node.get("op", "and")
        if op == "not":
            out.append("NOT (...)")
        for child in node.get("children", []) or []:
            _flatten(child, out)
        if op == "or":
            out.append("__or__")


def diff_models(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    b_clauses: list[str] = []
    a_clauses: list[str] = []
    _flatten(before.get("logic"), b_clauses)
    _flatten(after.get("logic"), a_clauses)
    added = [c for c in a_clauses if c not in b_clauses]
    removed = [c for c in b_clauses if c not in a_clauses]
    changed_keys = []
    for key in ("threshold", "window", "group_by", "fidelity"):
        if before.get(key) != after.get(key):
            changed_keys.append({"setting": key, "before": before.get(key), "after": after.get(key)})
    return {"added": added, "removed": removed, "setting_changes": changed_keys,
            "before_count": len(b_clauses), "after_count": len(a_clauses)}
