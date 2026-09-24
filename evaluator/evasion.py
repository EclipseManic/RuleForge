"""Evasion self-tests (G11): mutate a matching event and report what still matches.

Covers cheap attacker variations: case flips, slash direction, dash styles,
known binary renames, whitespace padding. A variant that stops matching is
an evasion the analyst should close (e.g. equals -> contains, add windash).
"""
from __future__ import annotations

from typing import Any

from evaluator.match_tester import match_node
from models.correlation import CorrelationModel, LogicNode, Predicate


def _predicates(node: Any) -> list[Predicate]:
    if isinstance(node, Predicate):
        return [node]
    if isinstance(node, LogicNode):
        out: list[Predicate] = []
        for child in node.children or ():
            out.extend(_predicates(child))
        return out
    return []


def _variants(field: str, value: str) -> list[tuple[str, dict[str, str]]]:
    variants = [("original", {field: value})]
    if not isinstance(value, str):
        return variants
    if value != value.upper():
        variants.append(("case-flip", {field: value.upper()}))
    if "\\" in value:
        variants.append(("slash-swap", {field: value.replace("\\", "/")}))
    if value.startswith("-"):
        variants.append(("dash-to-slash", {field: "/" + value[1:]}))
    if value.startswith("/"):
        variants.append(("slash-to-dash", {field: "-" + value[1:]}))
    if "powershell" in value.lower():
        variants.append(("binary-rename", {field: value.lower().replace("powershell", "pwsh")}))
    if value and not value.startswith(" "):
        variants.append(("whitespace-pad", {field: f"  {value}  "}))
    return variants


def evasion_report(model: CorrelationModel, event: dict[str, Any]) -> dict[str, Any]:
    base_ok, _ = match_node(model.logic, event)
    if not base_ok:
        return {"base_matched": False, "variants_tested": 0, "evasions": 0, "findings": [],
                "verdict": "Base event does not match — provide a matching event first."}
    findings: list[dict[str, Any]] = []
    attempted = 0
    tested: set[tuple[str, str, str, str]] = set()
    for pred in _predicates(model.logic):
        if not isinstance(pred.value, str):
            continue
        for name, mutation in _variants(pred.field, pred.value):
            if name == "original":
                continue
            key = (pred.field, pred.operator, pred.value, name)
            if key in tested:
                continue
            tested.add(key)
            attempted += 1
            trial = dict(event)
            trial.update(mutation)
            ok, _ = match_node(model.logic, trial)
            if not ok:
                findings.append({"field": pred.field, "variant": name, "mutated_value": mutation[pred.field],
                                 "evades": True,
                                 "fix": f"Predicate on {pred.field} evaded by {name}; consider contains/windash or a second predicate."})
    evasions = sum(1 for f in findings if f["evades"])
    return {"base_matched": base_ok, "variants_tested": attempted, "evasions": evasions, "findings": findings,
            "verdict": f"{evasions} evasion(s) found" if evasions else "No trivial evasions found"}
