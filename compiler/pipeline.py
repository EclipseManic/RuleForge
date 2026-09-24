"""Unified compilation pipeline (G3) + per-(family x target) capability matrix (G2).

Single truth for model/request -> native query. Both /api/generate and
/api/compile flow through here. Capability data is grounded in backend
realities (no pySigma dependency): only some targets support chained
correlations, ES|QL thresholds use clock-aligned buckets, UDM/ECS/CIM
mapping is per-pipeline.
"""
from __future__ import annotations

from typing import Any

from rule_engine import RuleValidationError


# family -> siem -> (support, note). support in exact/partial/unsupported.
CAPABILITY: dict[str, dict[str, tuple[str, str]]] = {
    "single": {s: ("exact", "") for s in ("sigma", "splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon", "wazuh")},
    "boolean": {s: ("exact", "") for s in ("sigma", "splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon", "wazuh")},
    "lists": {s: ("exact", "") for s in ("sigma", "splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon", "wazuh")},
    "exclusion": {s: ("exact", "") for s in ("sigma", "splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon", "wazuh")},
    "count": {
        "sigma": ("exact", "Sigma correlation event_count."),
        "splunk": ("exact", "stats count."),
        "sentinel": ("exact", "summarize count."),
        "elastic": ("partial", "Elastic threshold rules use clock-aligned buckets — events straddling a boundary can false-negative; prefer a true sliding window check."),
        "qradar": ("exact", "HAVING COUNT."),
        "google_secops": ("exact", "#event count in condition."),
        "falcon": ("exact", "groupBy count."),
        "wazuh": ("exact", "frequency/timeframe."),
    },
    "group": {s: ("exact", "") for s in ("sigma", "splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon", "wazuh")},
    "sequence": {
        "sigma": ("exact", "Sigma correlation temporal/temporal_ordered."),
        "splunk": ("partial", "transaction/streamstats approximates ordering; maxspan semantics differ."),
        "sentinel": ("partial", "Rebuild with timestamp-ordered joins; no native sequence operator."),
        "elastic": ("exact", "EQL sequence by/maxspan."),
        "qradar": ("partial", "Historical/correlation search required."),
        "google_secops": ("exact", "Ordered event variables + timestamps."),
        "falcon": ("partial", "Ordered pipeline stages only; no maxspan primitive."),
        "wazuh": ("partial", "Parent/chained rules approximate staging."),
    },
    "join": {
        "sigma": ("partial", "Correlation metadata only."),
        "splunk": ("partial", "join/lookup subsearch with row limits."),
        "sentinel": ("exact", "join/union/leftanti."),
        "elastic": ("partial", "Multi-event sequence with shared keys."),
        "qradar": ("partial", "Subquery/function relationship."),
        "google_secops": ("exact", "Placeholder equality across event variables."),
        "falcon": ("partial", "join/lookup stage."),
        "wazuh": ("partial", "if_sid/if_matched relationships."),
    },
    "aggregation": {
        "sigma": ("exact", "Correlation aggregation."),
        "splunk": ("exact", "stats/dc/values/sum."),
        "sentinel": ("exact", "summarize/make_set/dcount."),
        "elastic": ("partial", "Threshold rule or EQL outcome; dc/values need DSL."),
        "qradar": ("exact", "SUM/COUNT/AVG with aliases."),
        "google_secops": ("exact", "Outcome aggregates."),
        "falcon": ("exact", "groupBy functions."),
        "wazuh": ("partial", "Frequency counters only."),
    },
    "lookup": {
        "sigma": ("partial", "Pipeline/lookup metadata, not executable."),
        "splunk": ("exact", "lookup/inputlookup."),
        "sentinel": ("exact", "Watchlist/externaldata."),
        "elastic": ("partial", "Enrich integration; index-dependent."),
        "qradar": ("exact", "X-Force/reference sets."),
        "google_secops": ("partial", "Entity Graph joins."),
        "falcon": ("exact", "Lookup files/packages."),
        "wazuh": ("partial", "CDB/decoder context."),
    },
    "absence": {
        "sigma": ("partial", "Negative correlation."),
        "splunk": ("partial", "transaction with missing end event."),
        "sentinel": ("exact", "leftanti/anti-join."),
        "elastic": ("exact", "Negated sequence stage/until."),
        "qradar": ("partial", "NOT/subquery correlation."),
        "google_secops": ("exact", "!$event in events."),
        "falcon": ("partial", "Negated pipeline branch."),
        "wazuh": ("partial", "Chained negative conditions."),
    },
    "outcome": {
        "sigma": ("exact", "metadata/level."),
        "splunk": ("partial", "eval risk fields; RBA separate."),
        "sentinel": ("partial", "extend/entity mapping/custom details."),
        "elastic": ("partial", "Rule risk metadata."),
        "qradar": ("partial", "Magnitude/category functions."),
        "google_secops": ("exact", "outcome section."),
        "falcon": ("partial", "case/eval output."),
        "wazuh": ("partial", "level/description/groups."),
    },
    "anomaly": {s: ("unsupported", "Statistical/baselined behavior has no portable equivalent; rebuild natively.") for s in ("sigma", "splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon", "wazuh")},
    "composite": {s: ("partial", "Combine existing detections natively; reference by rule id/name.") for s in ("sigma", "splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon", "wazuh")},
    "ioc": {s: ("partial", "Threat-intel join is target-side enrichment; map feed then join.") for s in ("sigma", "splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon", "wazuh")},
    "chained": {
        "sigma": ("exact", "Correlation chain."),
        "splunk": ("exact", "transaction/correlation search."),
        "sentinel": ("partial", "Analytic-rule chaining by alert id."),
        "elastic": ("exact", "Chained detection sequence."),
        "qradar": ("partial", "Custom rule/offense chaining."),
        "google_secops": ("partial", "Composite detections."),
        "falcon": ("unsupported", "No chained-query primitive; use scheduled alert correlation."),
        "wazuh": ("partial", "if_sid/if_matched_sid chains."),
    },
    "window": {s: ("exact", "") for s in ("sigma", "splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon", "wazuh")},
    "entity": {s: ("exact", "") for s in ("sigma", "splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon", "wazuh")},
}

_RANK = {"exact": 0, "safe_normalized": 1, "partial": 2, "unsupported": 3}


def _has_advanced(request: Any) -> bool:
    """True when the request carries authorable multi-event correlation (F4)."""
    return bool(getattr(request, "sequences", None) or getattr(request, "joins", None)
                or getattr(request, "aggregations", None) or getattr(request, "lookups", None))


def involved_families(request: Any) -> list[str]:
    """Which RF families a RuleRequest touches (flat + authorable advanced, F4)."""
    families = ["single"]
    if len(request.conditions) > 1:
        families.append("boolean")
    if any(c.get("operator") in {"in_list", "regex", "wildcard", "ends_with", "endswith", "cidr", "windash", "base64", "exists"} for c in request.conditions):
        families.append("lists")
    if request.exclude_conditions:
        families.append("exclusion")
    if request.threshold and request.threshold > 1:
        families.append("count")
    if request.group_by and request.group_by != "user.name":
        families.append("group")
    for seq in getattr(request, "sequences", None) or []:
        families.append("sequence")
        if any(getattr(stage, "negated", False) for stage in getattr(seq, "stages", ()) or ()):
            families.append("absence")
    if getattr(request, "joins", None):
        families.append("join")
    if getattr(request, "aggregations", None):
        families.append("aggregation")
    if getattr(request, "lookups", None):
        families.append("lookup")
    families.append("window")
    return families


def capability_for(request: Any, siem: str) -> dict[str, Any]:
    """Worst-case support across involved families + notes."""
    worst = "exact"
    notes: list[str] = []
    per_family: dict[str, str] = {}
    for family in involved_families(request):
        support, note = CAPABILITY.get(family, {}).get(siem, ("partial", "No capability data; manual review required."))
        per_family[family] = support
        if _RANK[support] > _RANK[worst]:
            worst = support
        if note and note not in notes:
            notes.append(f"{family}: {note}")
    fidelity = worst if worst in {"partial", "unsupported"} else "safe_normalized"
    # legacy templates are normalized drafts, never byte-exact source
    return {"fidelity": fidelity, "per_family": per_family, "notes": notes}


def _request_to_model(request: Any) -> Any:
    """RuleRequest -> CorrelationModel for advanced (multi-event) renders (F4)."""
    from models.correlation import CorrelationModel, flat_conditions_to_logic

    model = CorrelationModel()
    model.logic = flat_conditions_to_logic(
        [{"field": c["field"], "operator": c["operator"], "value": c["value"]} for c in request.conditions],
        request.condition_logic)
    excl = [flat_conditions_to_logic([c], "all") for c in request.exclude_conditions]
    model.exclusions = [e for e in excl if e is not None]
    model.threshold = request.threshold
    model.window = request.timeframe
    model.group_by = [request.group_by]
    model.source = str(getattr(request, "data_source", "*") or "*")
    model.native_metadata = {"title": str(getattr(request, "title", "") or "")}
    model.sequences = list(getattr(request, "sequences", None) or [])
    model.joins = list(getattr(request, "joins", None) or [])
    model.aggregations = list(getattr(request, "aggregations", None) or [])
    model.lookups = list(getattr(request, "lookups", None) or [])
    return model


def compile_request(request: Any, siem: str) -> dict[str, Any]:
    """Single-truth native compile for a RuleRequest. Used by all routes."""
    from rule_engine import RENDERERS, SIEMS, TECHNIQUES, _native_request
    from compiler.validators import target_check, target_warnings, validation_level
    from section_view import section_blocks

    if not isinstance(siem, str) or siem not in RENDERERS:
        raise ValueError(f"Unsupported SIEM for compile: {siem!r}.")

    native_request, mapping = _native_request(request, siem)
    capability = capability_for(request, siem)
    # P0-A strict mode (Sigma correlation spec 2.1.0: a backend must error rather than
    # emit a query whose semantics differ from the rule). Refuse per-target so one
    # unsupported target never sinks the whole multi-target compile. Any lossy family
    # (partial or unsupported) qualifies: the spec's "must" tier covers semantic drift,
    # not just total incapability.
    if getattr(request, "strict", False) and capability["fidelity"] in {"partial", "unsupported"}:
        blocked = sorted({n.split(":")[0] for n in capability["notes"] if n.split(":")[0] in capability["per_family"]})
        reasons = [n for n in capability["notes"] if n.split(":")[0] in blocked]
        return {
            "siem": siem, "name": SIEMS[siem]["name"], "language": SIEMS[siem]["language"],
            "rule": "", "query": "", "refused": True,
            "refusal_reason": f"Strict mode: {', '.join(blocked) or 'this rule'} has no faithful "
                              f"{SIEMS[siem]['name']} equivalent. " + " ".join(reasons[:3]),
            "review_note": "Strict mode refuses lossy conversions. Disable strict mode to get a labelled partial draft.",
            "technique_label": TECHNIQUES[request.technique]["label"],
            "field_mapping": mapping, "fidelity": "unsupported",
            "capability": capability["per_family"], "capability_notes": capability["notes"],
            "checks": ["Strict mode refused this target: no faithful equivalent for "
                       f"{', '.join(blocked) or 'the requested family'}."],
            "warnings": [], "validation": "failed", "section_blocks": [],
        }
    if _has_advanced(request):
        # F4: multi-event renders come from the canonical model so dialects with native
        # sequence support emit real correlations; fidelity is the worse of both layers.
        # The model MUST be built from the translated request, not the original: building
        # it from `request` emitted canonical fields (process.name) while field_mapping
        # reported the native one (TargetProcessName), so the API claimed a translation
        # the rule did not contain - a rule that deploys and never matches.
        from compiler.sigma_compiler import compile_model
        model = _request_to_model(native_request)
        query, cm_fidelity, cm_notes = compile_model(model, siem)
        if _RANK[cm_fidelity] > _RANK[capability["fidelity"]]:
            capability["fidelity"] = cm_fidelity
        capability["notes"] = [*capability["notes"], *[n for n in cm_notes if n not in capability["notes"]]]
    else:
        # A target may refuse on its own constraints (Wazuh's frequency/timeframe ranges).
        # Refuse THIS target, exactly as strict mode does, so selecting six targets and
        # getting one Wazuh-specific 400 would cost the analyst the other five rules too.
        try:
            query = RENDERERS[siem](native_request)
        except RuleValidationError as error:
            return {
                "siem": siem, "name": SIEMS[siem]["name"], "language": SIEMS[siem]["language"],
                "rule": "", "query": "", "refused": True,
                "refusal_reason": str(error),
                "review_note": "This target's own limits reject the requested settings. "
                               "Adjust them or drop this target; the other targets are unaffected.",
                "technique_label": TECHNIQUES[request.technique]["label"],
                "field_mapping": mapping, "fidelity": "unsupported",
                "capability": capability["per_family"], "capability_notes": capability["notes"],
                "checks": [str(error)], "warnings": [], "validation": "failed",
                "section_blocks": [],
            }
    if siem == "wazuh" and request.condition_logic == "any" and len(request.conditions) > 1:
        capability["fidelity"] = "partial"
        capability["notes"] = [*capability["notes"], "boolean: OR branches render as ANDed <field> elements — split into separate rules."]
    technique = TECHNIQUES[request.technique]
    if siem == "wazuh":
        review_note = "Use an unused custom ID in the 100000–120000 range, map fields to your decoder output, test with wazuh-logtest, then restart the Wazuh manager."
    else:
        review_note = f"Map normalized fields to your {SIEMS[siem]['name']} data model and test against known benign and malicious events before enabling."
    checks = target_check(siem, query)
    warnings = target_warnings(siem, query)
    return {
        "siem": siem,
        "name": SIEMS[siem]["name"],
        "language": SIEMS[siem]["language"],
        "rule": query,
        "query": query,
        "review_note": review_note,
        "technique_label": technique["label"],
        "field_mapping": mapping,
        "fidelity": capability["fidelity"],
        "capability": capability["per_family"],
        "capability_notes": capability["notes"],
        "checks": checks,
        "warnings": warnings,
        "validation": validation_level(siem, checks),
        "section_blocks": section_blocks(query, siem),
    }
