"""Plain-English explainer: 12 teaching-workflow questions from the corpus."""
from __future__ import annotations

from typing import Any

from models.correlation import CorrelationModel, LogicNode, Predicate


def explain(model: CorrelationModel, dialect: str = "unknown", raw_rule: str = "") -> dict[str, Any]:
    bullets: list[str] = []
    flags: list[str] = []
    n = model.predicate_count()
    bullets.append(f"Behavior: {n} field predicate(s) in a {'multi-event' if model.is_multi_event() else 'single-event'} rule ({dialect}).")
    bullets.append(f"Predicates: { _summarize_logic(model.logic) }." if model.logic is not None else "Predicates: none recognized — configure manually.")
    if model.exclusions:
        bullets.append(f"Exclusions/allowlist: {len(model.exclusions)} exclusion block(s) applied with NOT.")
    else:
        bullets.append("Exclusions/allowlist: none — confirm noise expectations.")
    if model.threshold and model.threshold > 1:
        bullets.append(f"Threshold: ≥{model.threshold} events in {model.window} grouped by {', '.join(model.group_by) or 'event'}.")
    else:
        bullets.append("Threshold: single-event (each match can fire).")
    if model.sequences:
        for seq in model.sequences:
            bullets.append(f"Ordered sequence: {len(seq.stages)} stage(s) by {seq.join_by}, maxspan {seq.maxspan}.")
            flags.append("ordered sequence")
    if model.joins:
        for join in model.joins:
            bullets.append(f"Join: {join.kind} {join.right} on {join.on}.")
            flags.append("cross-event join")
    if model.aggregations:
        for agg in model.aggregations:
            bullets.append(f"Aggregation: {agg.function}({agg.field or '*'}){f' as {agg.alias}' if agg.alias else ''}.")
            if agg.function.lower() not in ("count", ""):
                flags.append("complex aggregation")
    if model.lookups:
        for lookup in model.lookups:
            bullets.append(f"Lookup/enrichment: {lookup.name} — needs its table in the target; not executed here.")
            flags.append("lookup or enrichment")
    if model.event_streams:
        bullets.append(f"Event streams: {', '.join(s.get('name','?') for s in model.event_streams)}.")
    if model.time_constraints:
        bullets.append(f"Time relationships: {'; '.join(model.time_constraints)}.")
    if model.outcome:
        bullets.append(f"Outcome/risk output: {model.outcome}. Portable intent; rebuild scoring natively.")
    if model.unsupported_features:
        flags.extend(f for f in model.unsupported_features if f not in flags)
    if model.native_sections:
        bullets.append(f"Native sections preserved: {', '.join(model.native_sections.keys())}.")
    bullets.append("Portable vs native: field predicates are portable; ordering/windows/joins/scoring must be rebuilt per SIEM.")
    fidelity = "safe_normalized" if not flags and n else ("partial" if flags or n > 1 else "safe_normalized")
    if n == 0:
        fidelity = "unsupported"
    return {"summary": bullets[0], "bullets": bullets, "lossy_flags": sorted(set(flags)), "fidelity": fidelity,
            "multi_event": model.is_multi_event(), "predicate_count": n}


def _summarize_logic(node: Any) -> str:
    if isinstance(node, Predicate):
        return node.describe()
    if isinstance(node, LogicNode):
        inner = ", ".join(_summarize_logic(c) for c in node.children)
        return f"{node.op.upper()}({inner})"
    return "?"
