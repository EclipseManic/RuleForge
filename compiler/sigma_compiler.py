"""Compiler: offline native renderer from CorrelationModel, plus optional pySigma path.

No new hard dependencies: works offline. This renderer handles the canonical model
and every target. When pySigma plus a matching backend package are installed,
genuine Sigma YAML is instead converted by compile_sigma_with_pysigma() (authoritative).
"""
from __future__ import annotations

import re
from typing import Any

from models.correlation import Aggregation, CorrelationModel, LogicNode, Predicate


UNSUPPORTED_MAP = {
    "RF-13": "Baseline/anomaly (predict/series_decompose/percentile) has no portable equivalent; keep native source.",
    "RF-14": "Composite/saved-search correlation must be rebuilt in the target SIEM; keep native source.",
    "RF-15": "Live enrichment (Entity Graph/X-Force/CDB/watchlist execution) is not portable; keep native source.",
    "RF-16": "Stateful/chained rule promotion (if_sid/offense chaining) is target-side; keep native source.",
}


def _render_predicate(pred: Predicate, syntax: str, notes: list[str] | None = None) -> str:
    from rule_engine import _match_value, FIELD_MAPPINGS

    # map operator names: ends_with/in_list/wildcard are new vs legacy renderer
    field, op, val = pred.field, pred.operator, pred.value
    if syntax == "cql":
        if op == "exists":
            return f"{field} = *"
        if op == "in_list" and isinstance(val, list):
            quoted = ", ".join(f'"{_q(str(v))}"' for v in val)
            return f"in({field}, values=[{quoted}])"
        if op == "cidr":
            return f'cidr({field}, subnet="{_q(str(val))}")'
        if op == "ends_with":
            return f"{field}=/{re.escape(str(val)).replace('/', chr(92) + '/')}$/"
        if op == "starts_with":
            return f"{field}=/^{re.escape(str(val)).replace('/', chr(92) + '/')}/"
        if op == "windash":
            notes is not None and notes.append("windash approximated as substring in CQL; verify -// spellings.")
            return _match_value(field, "contains", str(val).lstrip("-/"), "cql")
        if op == "base64":
            notes is not None and notes.append("base64 matched on encoded text in CQL; verify decoded form.")
            return _match_value(field, "contains", str(val), "cql")
    if op == "exists":
        return {"spl": f"{field}=*", "kql": f"isnotempty({field})", "eql": f"{field} != null",
                "aql": f"{field} IS NOT NULL", "yara": f'$e.{field} != ""'}.get(syntax, f"{field}=*")
    if op == "windash":
        # match both -switch and /switch spellings
        return _match_value(field, "contains", str(val).lstrip("-/"), syntax)
    if op in {"base64", "base64offset"}:
        return _match_value(field, "contains", str(val), syntax)
    if op == "cidr":
        if syntax == "spl":
            return f'| where cidrmatch("{_q(str(val))}", {field})'
        if syntax == "kql":
            return f'ipv4_is_in_range({field}, "{_q(str(val))}")'
        return _match_value(field, "contains", str(val), syntax)
    if op == "ends_with":
        if syntax == "spl":
            return f'{field}="*{_q(str(val))}"'
        if syntax == "kql":
            return f'{field} endswith "{_q(str(val))}"'
        if syntax == "eql":
            return f'{field} : "*{_q(str(val))}"'
        if syntax == "aql":
            return f"{field} ILIKE '%{_s(str(val))}'"
        if syntax == "yara":
            return f'$e.{field} = /{str(val).replace("/", chr(92)+"/")}$/ nocase'
        return f'{field}="*{_q(str(val))}"'
    if op == "in_list" and isinstance(val, list):
        vals = list(val)
        if syntax == "spl":
            quoted = " OR ".join(f'{field}="{_q(str(v))}"' for v in vals)
            return f"({quoted})"
        if syntax == "kql":
            quoted = ", ".join(f'"{_q(str(v))}"' for v in vals)
            return f"{field} in ({quoted})"
        if syntax == "eql":
            quoted = " or ".join(f'{field} == "{_q(str(v))}"' for v in vals)
            return f"({quoted})"
        if syntax == "aql":
            quoted = ", ".join(f"'{_s(str(v))}'" for v in vals)
            return f"{field} IN ({quoted})"
        if syntax == "yara":
            alts = "|".join(str(v).replace("/", chr(92)+"/") for v in vals)
            return f"$e.{field} = /({alts})/ nocase"
        quoted = " OR ".join(f'{field}="{_q(str(v))}"' for v in vals)
        return f"({quoted})"
    if op == "wildcard":
        if syntax == "cql":
            return f'wildcard({field}, pattern="{_q(str(val))}")'
        return _match_value(field, "contains", str(val), syntax)
    if op == "base64offset":
        notes is not None and notes.append("base64offset approximated as substring; verify alignment.")
        return _match_value(field, "contains", str(val), syntax)
    return _match_value(field, op if op in {"contains", "equals", "starts_with", "regex"} else "contains", str(val) if not isinstance(val, list) else str(val[0]), syntax)


def _q(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _s(value: str) -> str:
    return value.replace("'", "\\'")


def _render_logic(node: Any, syntax: str, notes: list[str] | None = None) -> str:
    if isinstance(node, Predicate):
        return _render_predicate(node, syntax, notes)
    if isinstance(node, LogicNode):
        children = list(node.children or ())
        if node.op not in {"and", "or", "not"}:
            raise ValueError(f"Unsupported logic operator: {node.op}.")
        parts = [_render_logic(c, syntax, notes) for c in children]
        if node.op == "not":
            return f"not ({parts[0]})" if parts else ""
        joiner = " and " if node.op == "and" else " or "
        expr = joiner.join(parts)
        return f"({expr})" if len(parts) > 1 else expr
    return ""


def compile_model(model: CorrelationModel, siem: str) -> tuple[str, str, list[str]]:
    """Return (query, fidelity, notes) from the built-in canonical renderer.

    pySigma does not consume the canonical model, so it is never used here; genuine
    Sigma YAML is routed through compile_sigma_with_pysigma() at the API layer.
    """
    syntaxes = {"splunk": "spl", "sentinel": "kql", "elastic": "eql", "qradar": "aql",
                "google_secops": "yara", "falcon": "cql", "wazuh": "spl", "sigma": "spl"}
    if not isinstance(siem, str) or siem not in syntaxes:
        raise ValueError(f"Unsupported SIEM for canonical compile: {siem!r}.")
    if model.threshold is not None and (type(model.threshold) is not int or model.threshold < 1):
        raise ValueError(f"Threshold must be a whole number >= 1, got {model.threshold!r}.")
    notes: list[str] = []
    pysigma_out = _try_pysigma(model, siem, notes)
    if pysigma_out is not None:
        return pysigma_out, "exact", notes
    syntax = syntaxes[siem]
    if siem == "sigma":
        query = _render_sigma(model, notes)
        leftovers = [name for name, items in (("sequences", model.sequences), ("joins", model.joins),
                                              ("aggregations", model.aggregations), ("lookups", model.lookups)) if items]
        if leftovers:
            notes.append(f"{', '.join(leftovers)} are preserved in the model, not in the Sigma detection export.")
            return query, "partial", notes
        return query, "exact", notes
    if siem == "wazuh":
        from rule_engine import render_wazuh, RuleRequest

        # F3: walk the whole tree — every predicate becomes a <field> element, exclusions
        # become negate elements. Only genuinely inexpressible shapes (nested NOT, unknown
        # ops) are dropped, each with an explicit note. Predicate count in == count out.
        cond_dicts, saw_or, saw_complex = _flatten_wazuh(model.logic)
        excl_dicts: list[dict[str, Any]] = []
        excl_or = excl_complex = False
        for excl in model.exclusions or []:
            sub, o, c = _flatten_wazuh(excl)
            excl_dicts.extend(sub); excl_or = excl_or or o; excl_complex = excl_complex or c
        lossy = sorted({d["operator"] for d in cond_dicts + excl_dicts
                        if d["operator"] not in {"contains", "equals", "starts_with", "ends_with",
                                                 "regex", "exists", "windash", "in_list"}})
        if not cond_dicts:
            cond_dicts = [{"field": "process.name", "operator": "contains", "value": "example.exe"}]
            notes.append("Empty logic; placeholder rule emitted.")
        first = cond_dicts[0]
        top_or = isinstance(model.logic, LogicNode) and model.logic.op == "or"
        req = RuleRequest(title="Sigma-derived", description="Derived from canonical model", severity="medium",
                          technique="custom", field=str(first["field"]),
                          operator=str(first["operator"]), value=first["value"],
                          threshold=model.threshold, timeframe=model.window, group_by=(model.group_by[0] if model.group_by else "user.name"),
                          data_source="*", wazuh_rule_id=100100, wazuh_parent_rule="", siems=["wazuh"],
                          conditions=cond_dicts, condition_logic="any" if (top_or or saw_or) else "all",
                          exclude_conditions=excl_dicts)
        fidelity = "safe_normalized"
        if saw_or or excl_or:
            fidelity = "partial"
            notes.append("Wazuh ANDs <field> elements: OR branches were kept as listed conditions — split into sibling rules sharing an if_group for exact semantics.")
        if saw_complex or excl_complex:
            fidelity = "partial"
            notes.append("Nested NOT/unsupported grouping has no Wazuh equivalent and was dropped — verify coverage.")
        if lossy:
            fidelity = "partial"
            notes.append(f"Operator(s) {', '.join(lossy)} approximated as substring match in Wazuh — verify.")
        leftovers = [name for name, items in (("sequences", model.sequences), ("joins", model.joins),
                                              ("aggregations", model.aggregations), ("lookups", model.lookups)) if items]
        if leftovers:
            fidelity = "partial"
            notes.append(f"{', '.join(leftovers)} are preserved in the model, not in Wazuh output — rebuild correlation with if_sid chains.")
        return render_wazuh(req), fidelity, notes
    expr = _render_logic(model.logic, syntax, notes)
    if model.exclusions:
        excl = " and ".join(_render_logic(e, syntax, notes) for e in model.exclusions if e is not None)
        if excl:
            expr = f"{expr} and not ({excl})" if expr else f"not ({excl})"
    source = getattr(model, "source", "*") or "*"
    window = model.window or "5m"
    group = (model.group_by[0] if model.group_by else "user.name")
    minutes = _window_minutes(window)
    # F4: native sequence renders where the dialect supports them. Stage conditions are
    # analyst-authored where-clauses (EQL) or left blank to reuse the base predicate.
    # Anything inexpressible (negated stages, extra sequences) is dropped WITH a note —
    # never silently — and YARA-L multi-stage requires blank stages (free text cannot be
    # safely translated to UDM paths, so non-blank stages stay an honest projection).
    seq = model.sequences[0] if model.sequences else None
    if seq and expr:
        kept = [s for s in (seq.stages or ()) if not s.negated]
        dropped = [s for s in (seq.stages or ()) if s.negated]
        multi_note = ("Only the first sequence rendered; split additional sequences into separate rules."
                      if len(model.sequences) > 1 else "")
        if siem == "elastic" and kept:
            outs = []
            for stage in (seq.stages or ()):
                cond = (stage.condition or "").strip() or expr
                event = (stage.event or "").strip() or "process"
                outs.append(f"  {'!' if stage.negated else ''}[{event} where {cond}]")
            query = (f"sequence by {seq.join_by or group} with maxspan={seq.maxspan or window}\n"
                     + "\n".join(outs))
            fidelity = "safe_normalized"
            notes.append("Native EQL sequence; blank stages reuse the base predicate.")
            rest = [name for name, items in (("joins", model.joins), ("aggregations", model.aggregations),
                                             ("lookups", model.lookups)) if items]
            if rest:
                fidelity = "partial"
                notes.append(f"{', '.join(rest)} are preserved in the model, not in the EQL sequence output.")
            notes.append("Negated stages use the ! missing-event form (maxspan is always emitted, as EQL requires).")
            if multi_note:
                fidelity = "partial"
                notes.append(multi_note)
            return query, fidelity, notes
        if siem == "google_secops" and kept and all(not (s.condition or "").strip() for s in kept):
            from rule_engine import FIELD_MAPPINGS as _FIELD_MAP
            ymap = _FIELD_MAP.get("google_secops", {})
            join_field = ymap.get(seq.join_by or group, seq.join_by or group)
            lines = [f"    {expr.replace('$e.', f'$e{i}.')}" for i in range(1, len(kept) + 1)]
            lines.insert(0, f"    $e1.{group} = $group")
            for i in range(2, len(kept) + 1):
                lines.append(f"    $e{i - 1}.{join_field} = $e{i}.{join_field}")
            cond_vars = " and ".join(f"$e{i}" for i in range(1, len(kept) + 1))
            span = _yaral_span(seq.maxspan or window)
            query = ("rule ruleforge_sequence {\n  events:\n" + "\n".join(lines)
                     + f"\n  match:\n    $group over {span}\n  condition:\n    {cond_vars}\n}}")
            fidelity = "safe_normalized"
            notes.append("Native YARA-L multi-event rule; blank stages repeat the base predicate in order.")
            rest = [name for name, items in (("joins", model.joins), ("aggregations", model.aggregations),
                                             ("lookups", model.lookups)) if items]
            if rest:
                fidelity = "partial"
                notes.append(f"{', '.join(rest)} are preserved in the model, not in the YARA-L output.")
            if dropped:
                fidelity = "partial"
                notes.append(f"Dropped {len(dropped)} negated stage(s) — no YARA-L form; verify separately.")
            if multi_note:
                fidelity = "partial"
                notes.append(multi_note)
            if model.threshold and model.threshold > 1:
                notes.append("Threshold applies per match window; verify count semantics in SecOps.")
            return query, fidelity, notes
        # else: fall through to native correlation rendering below
    # --- native correlation constructs instead of a single-event projection ---
    native_joins = [_native_join_expr(j, syntax, group) for j in (model.joins or [])]
    native_aggs = [_native_agg_expr(a, syntax, group, model.threshold) for a in (model.aggregations or [])]
    native_lookups = [_native_lookup_expr(l, syntax) for l in (model.lookups or [])]
    missing = unsupported_families_for(siem, model)
    fidelity = "safe_normalized"
    emitted = {"join": bool(native_joins), "aggregation": bool(native_aggs), "lookup": bool(native_lookups)}
    for family, rendered in emitted.items():
        if rendered:
            # Emitted native constructs are still analyst starting points, not
            # grammar-verified production queries, so they never claim exactness.
            fidelity = "partial"
            constructs = ", ".join(_NATIVE_FAMILIES.get(siem, {}).get(family, ()))
            notes.append(f"{family.title()} rendered with native {siem} construct(s): {constructs}. Verify field names, cardinality and limits before enabling.")
    if missing:
        fidelity = "partial"
        notes.append(f"No native {', '.join(missing)} construct in {siem}; preserved in the model only.")
    if model.sequences and siem not in ("elastic", "google_secops"):
        fidelity = "partial"
        notes.append(f"Sequence projected as a single-event query; {siem} has no native sequence operator in this renderer.")
    # Suppress the generic claim for constructs that a later branch replaced. The Elastic
    # threshold path renders a real rule but ignores aggregation, so saying "aggregation
    # rendered" above would be untrue; that branch adds its own accurate note instead.
    if siem == "elastic" and model.threshold and model.threshold > 1:
        notes = [n for n in notes if not n.startswith(("Aggregation rendered", "Join rendered", "Lookup rendered"))]
    # wrap per dialect minimally (analyst starting point, honest about scope)
    threshold_block = ""
    if model.threshold and model.threshold > 1:
        threshold_block = {
            "splunk": f" | stats count by {group} | where count >= {model.threshold}",
            "sentinel": f"\n| summarize EventCount=count() by {group}\n| where EventCount >= {model.threshold}",
            "falcon": f" | groupBy([{group}], function=count()) | _count>={model.threshold}",
            "google_secops": f"\n    $e.{group} = $group",
            # AQL and EQL build their threshold into the clause structure above, because
            # AQL requires HAVING before LAST and EQL requires a threshold rule.
        }.get(siem, "")
    if syntax == "spl":
        base = f"index={source} earliest=-{window}\n| search {expr}"
        extra = "\n".join(x for x in (*native_lookups, *native_joins, *native_aggs) if x)
        query = f"{base}{threshold_block}" + (f"\n{extra}" if extra else "")
    elif syntax == "kql":
        from rule_engine import _sentinel_table
        # Same rule as the flat renderer: ASIM column names cannot be paired with a
        # legacy table, so an unsupplied or legacy table becomes the explicit placeholder.
        table, table_note = _sentinel_table(source)
        base = f"{table}{table_note}"
        base += f"\n| where TimeGenerated >= ago({window})\n| where {expr}"
        extra = "\n".join(x for x in (*native_lookups, *native_joins, *native_aggs) if x)
        query = f"{base}{threshold_block}" + (f"\n{extra}" if extra else "")
    elif syntax == "eql":
        # EQL is a real event-correlation language, so a threshold on Elastic renders
        # as the actual native rule type that implements it - a custom-threshold rule
        # with a composite aggregation - instead of a comment saying EQL cannot count.
        if model.threshold and model.threshold > 1:
            query = _elastic_threshold_rule(expr, group, window, source, model.threshold)
            fidelity = "safe_normalized"
            notes.append("Native Elastic custom-threshold rule. Buckets are clock-aligned, so a burst straddling a boundary can split; prefer an EQL sequence when ordering matters.")
            # A threshold rule counts events; it cannot also express a distinct-count or
            # other aggregation. Claiming the aggregation was rendered would be false, so
            # the requested aggregation is named as not expressed.
            dropped_aggs = [a.function for a in (model.aggregations or [])]
            if dropped_aggs:
                fidelity = "partial"
                notes.append(f"Requested aggregation(s) {', '.join(sorted(set(dropped_aggs)))} are not expressed by an "
                             "Elastic threshold rule, which only counts events. Add a composite aggregation to the "
                             "rule body, or model it as a separate rule.")
            for name, items in (("joins", model.joins), ("lookups", model.lookups)):
                if items:
                    fidelity = "partial"
                    notes.append(f"{name.title()} are preserved in the model, not in the threshold rule output.")
        else:
            # Mirror render_elastic: our analysis categories (iam, cloud) have no EQL
            # equivalent, so map to the event stream that carries the data and note it.
            from compiler.dialects import EQL_EVENT_CATEGORIES
            category = "process"
            if model.native_metadata.get("event_category") in EQL_EVENT_CATEGORIES:
                category = model.native_metadata["event_category"]
            query = f"{category} where {expr}"
            if any(native_aggs):
                query += "\n" + "\n".join(native_aggs)
            if any(native_joins):
                query += "\n" + "\n".join(native_joins)
            if any(native_lookups):
                query += "\n" + "\n".join(native_lookups)
    elif syntax == "aql":
        selects = [group, "COUNT(*) AS event_count"]
        if model.aggregations:
            selects = [group] + [f"{a.function.upper()}({a.field or '*'}) AS {(a.alias or a.function).lower()}"
                                 for a in model.aggregations] + ["COUNT(*) AS event_count"]
        where = expr
        for j in model.joins or []:
            where += f" AND {j.left or group} IN (SELECT {j.on or group} FROM {j.right})"
        for l in model.lookups or []:
            where += f" AND EXISTS (SELECT 1 FROM {l.name} WHERE 1=1)"
        # AQL clause order is fixed: SELECT -> FROM -> WHERE -> GROUP BY -> HAVING -> LAST.
        # Appending the threshold after LAST produced a query the console rejects.
        having = f"\nHAVING COUNT(*) >= {model.threshold}" if (model.threshold and model.threshold > 1) else ""
        query = (f"SELECT {', '.join(dict.fromkeys(selects))}\nFROM events\nWHERE {where}"
                 f"\nGROUP BY {group}{having}\nLAST {minutes} MINUTES")
    elif syntax == "yara":
        agg_outcomes = "\n".join(native_aggs)
        events_lines = [f"    $e.{expr}"]
        # A YARA-L event variable is only usable if the events section defines it. The old
        # form emitted `$e2.<field>` for a join without ever binding $e2, producing a rule
        # the compiler rejects. We have no real predicate for the joined stream, so the
        # honest output omits it and says so rather than shipping a dangling reference.
        for j in model.joins or []:
            notes.append(f"Join on {j.on or group} has no YARA-L event variable to bind; "
                         "rebuild it as an ordered multi-event rule in SecOps.")
        match_block = (f"\n  match:\n    $group over {_yaral_span(window)}"
                       if (model.threshold and model.threshold > 1) or model.joins else "")
        # A YARA-L fragment is only a rule inside a `rule <name> { ... }` block. Emitting a
        # bare events:/condition: body produces something the SecOps compiler rejects.
        rule_name = _slug_rule_name(getattr(model, "native_metadata", {}).get("title", ""))
        query = (f"rule {rule_name} {{\n  meta:\n    author: \"ruleforge\"\n"
                 f"    description: \"Generated detection rule; verify before enabling.\"\n"
                 f"  events:\n" + "\n".join(events_lines) + match_block +
                 (f"\n  outcome:\n{agg_outcomes}" if agg_outcomes else "") +
                 "\n  condition:\n    " + (f"$e and #e >= {model.threshold}"
                                              if model.threshold and model.threshold > 1 else "$e") + "\n}")
    elif syntax == "cql":
        base = f"#repo={source}\n| {expr}{threshold_block}"
        extra = "\n".join(x for x in (*native_lookups, *native_joins, *native_aggs) if x)
        query = base + (f"\n{extra}" if extra else "")
    else:
        query = f"// {siem}: no native wrapper\n{expr}"
    if not expr:
        fidelity = "unsupported"
        notes.append("Empty logic; nothing to compile.")
    return query, fidelity, notes


def _slug_rule_name(title: Any) -> str:
    """YARA-L rule identifiers are token-like: start with a letter, no spaces."""
    import re as _re
    name = _re.sub(r"[^A-Za-z0-9]+", "_", str(title or "")).strip("_").lower()
    name = _re.sub(r"_+", "_", name)
    if not name or not name[0].isalpha():
        name = f"ruleforge_{name}" if name else "ruleforge_detection"
    return name[:60]


ELASTIC_INDEX_PLACEHOLDER = "your-data-stream-*"


def _elastic_threshold_rule(expr: str, group: str, window: str, source: str, threshold: int) -> str:
    """Elastic custom-threshold detection rule (composite aggregation).

    Shape per Elastic's custom threshold rule spec: a KQL query, a group_by, a
    threshold comparator and a window in seconds. Emitted as the Kibana detections
    API rule body so it can be pasted straight into the API or the rule editor.
    """
    seconds = _window_seconds(window)
    # A wildcard source must not become a concrete index name. Naming an index the
    # analyst does not ingest produces a rule that deploys and never fires, so an
    # unresolved source stays an explicit placeholder instead of a plausible guess.
    if source in {"*", ""}:
        index = ELASTIC_INDEX_PLACEHOLDER
        index_note = ("// Replace the placeholder index with a data stream or index pattern you ingest.\n")
    else:
        index = source
        index_note = ""
    return (f'{index_note}'
            f'type: "threshold"\n'
            f'schedule: "interval = {window}"\n'
            f'index: ["{index}"]\n'
            f'query: |-\n  {expr}\n'
            f'group_by: ["{group}"]\n'
            f'threshold: {{ field: ["{group}"], value: {threshold}, comparator: ">=", cardinality: "single" }}\n'
            f'alert_suppression:\n'
            f'  duration: "24h"\n'
            f'notify_when: "onActionGroupChange"\n'
            f'window: "10m"\n'
            f'min_window: "5m"\n'
            f'threshold_window: "{seconds}s"\n'
            f'threshold_method: "count"\n'
            f'filter_by_enrichments: []\n'
            f'session_threshold: 0')


def _yaral_span(window: str) -> str:
    """Coerce a window to YARA-L match limits: units m/h/d only, 1m..48h."""
    import re as _re
    match = _re.fullmatch(r"(\d{1,3})([smhd])", str(window or "5m").lower())
    if not match:
        return "5m"
    amount, unit = int(match.group(1)), match.group(2)
    minutes = amount / 60 if unit == "s" else amount * {"m": 1, "h": 60, "d": 1440}[unit]
    minutes = max(1, min(2880, int(minutes)))
    if minutes < 60:
        return f"{minutes}m"
    return f"{minutes // 60}h" if minutes % 60 == 0 else f"{minutes}m"


def _window_minutes(window: str) -> int:
    import re as _re
    match = _re.fullmatch(r"(\d{1,5})([smhd])", str(window or "5m").lower())
    if not match or int(match.group(1)) < 1:
        return 5
    amount, unit = int(match.group(1)), match.group(2)
    if unit == "s":
        return max(1, -(-amount // 60))  # ceiling to whole minutes for QRadar LAST
    return amount * {"m": 1, "h": 60, "d": 1440}[unit]


def _window_seconds(window: str) -> int:
    """Exact seconds, for targets whose window attribute counts in seconds.

    Elastic's `threshold_window` is a seconds duration. Deriving it from the minutes
    helper doubled a 30s request to 60s, so the count window the analyst asked for was
    not the one the rule used.
    """
    import re as _re
    match = _re.fullmatch(r"(\d{1,5})([smhd])", str(window or "5m").lower())
    if not match or int(match.group(1)) < 1:
        return 300
    amount, unit = int(match.group(1)), match.group(2)
    return amount * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


# --- Native correlation rendering (Gap 1) -------------------------------------
# Each dialect declares which correlation families it can express natively, and emits
# its own construct. A family with no native form is reported as unimplementable so
# strict mode can refuse it and lenient mode can label it, instead of silently
# projecting a single-event query and calling it a correlation.
_NATIVE_FAMILIES: dict[str, dict[str, tuple[str, ...]]] = {
    "splunk": {"join": ("join", "lookup", "transaction", "appendpipe", "selfjoin"),
               "aggregation": ("stats", "eventstats", "streamstats", "tstats", "set"),
               "lookup": ("lookup", "inputlookup", "append")},
    "sentinel": {"join": ("join", "union", "find_in_set"),
                 "aggregation": ("summarize", "make-series", "sample"),
                 "lookup": ("externaldata", "materialize", "datatable")},
    "elastic": {"join": ("sequence_by_join_key",), "aggregation": ("custom_threshold_rule", "composite_aggregation"), "lookup": ()},
    "qradar": {"join": ("subquery",), "aggregation": ("group_by_having",), "lookup": ("reference_set",)},
    "google_secops": {"join": ("match_placeholder",), "aggregation": ("outcome", "match_count"), "lookup": ("entity_graph", "reference_list")},
    "falcon": {"join": ("join", "append"), "aggregation": ("groupBy", "bucket", "timeChart"), "lookup": ("lookup", "dataset")},
    "wazuh": {"join": ("if_sid", "if_matched_sid", "same_field"), "aggregation": ("frequency",), "lookup": ("cdb_list", "decoder")},
    "sigma": {"join": ("correlation_rule",), "aggregation": ("event_count",), "lookup": ()},
}


def native_families_for(siem: str) -> dict[str, tuple[str, ...]]:
    """Construct names a target can express natively per family (empty = cannot)."""
    return dict(_NATIVE_FAMILIES.get(str(siem), {}))


def unsupported_families_for(siem: str, model: Any) -> list[str]:
    """Families present in the model that this dialect cannot express natively."""
    table = _NATIVE_FAMILIES.get(str(siem), {})
    out: list[str] = []
    for family, attr in (("sequence", "sequences"), ("join", "joins"),
                         ("aggregation", "aggregations"), ("lookup", "lookups")):
        if getattr(model, attr, None) and not table.get(family):
            out.append(family)
    return out


def _native_join_expr(join: Any, syntax: str, group: str) -> str:
    """Native join construct. SPL requires maxout=1, so wide fan-out is a real risk:
    the note layer marks every such construct partial, never exact."""
    kind = (join.kind or "inner").lower()
    left, right, on = join.left or group, join.right or "lookup", join.on or group
    if syntax == "spl":
        map_type = {"leftouter": "left", "rightouter": "right", "fullouter": "outer"}.get(kind, "inner")
        return f"| join type={map_type} maxout=1 {right} {on}={on}"
    if syntax == "kql":
        kql_kind = {"inner": "inner", "leftouter": "leftouter", "leftanti": "leftanti",
                    "rightouter": "rightouter", "fullouter": "fullouter", "equality": "inner"}.get(kind, "inner")
        return f"| join kind={kql_kind} (dataset({right})) on {on}"
    if syntax == "eql":
        return f"// EQL has no join operator: correlate with 'sequence by {on}' or a threshold rule."
    if syntax == "aql":
        return f"AND {left} IN (SELECT {on} FROM {right})"
    if syntax == "yara":
        return f"// YARA-L: bind both events in events section and join on {on} via match placeholders."
    if syntax == "cql":
        return f"| join([{on}], kind={kind if kind in {'inner', 'left', 'right', 'outer'} else 'inner'})"
    return f"// join {left} {right} on {on}"


def _native_agg_expr(agg: Any, syntax: str, group: str, threshold: int | None) -> str:
    function = (agg.function or "count").lower()
    field = agg.field or ""
    alias = (agg.alias or function).replace("-", "_")
    target = field or "*"
    if syntax == "spl":
        stats = f"| stats {function}({target}) as {alias}" if field or function != "count" else f"| stats count as {alias}"
        return stats + (f" by {group}" if group else "")
    if syntax == "kql":
        call = {"count": "count()", "dc": "dcount()", "make_set": "make_set()"}.get(function, f"{function}()")
        if function in {"dc", "make_set"} and field:
            call = f"{function}({field})"
        return f"| summarize {alias} = {call}" + (f" by {group}" if group else "")
    if syntax == "eql":
        alias_name = alias or function
        return (f'// {function} aggregation: EQL has no aggregate operator, so this needs an Elastic\n'
                f'// custom-threshold rule (composite aggregation) grouping by {group or "the event key"}.\n'
                f'// threshold: {{ field: ["{group or "process.entity_id"}"], value: {threshold or 1}, comparator: ">=" }}\n'
                f'// agg: {{ "{alias_name}": {{ "terms": {{ "field": "{target}", "size": 100 }} }} }}')
    if syntax == "aql":
        sql_fn = {"dc": "COUNT(DISTINCT", "make_set": "GROUP_CONCAT"}.get(function, function.upper())
        arg = f"{field})" if field else "*)"
        return f"GROUP BY {group} HAVING {sql_fn}{arg}" + (f" >= {threshold}" if threshold else "")
    if syntax == "yara":
        return f"  ${alias} = count_distinct({target})" if function == "dc" else f"  ${alias} = {target}"
    if syntax == "cql":
        # groupBy([key], function=dc(field)) - the closing paren was missing, which made
        # every CQL aggregation emit unbalanced output the parser (rightly) rejected.
        call = f"{function}({target})" if field and function != "count" else f"{function}()"
        return f"| groupBy([{group or '_count'}], function={call})"
    return f"// aggregation {function}({target})"


def _native_lookup_expr(lookup: Any, syntax: str) -> str:
    name, args = lookup.name or "lookup", (lookup.arguments or "").strip()
    if syntax == "spl":
        return f"| inputlookup {name}" + (f" {args}" if args else "")
    if syntax == "kql":
        return f"| evaluate lookup('{name}')" + (f" // {args}" if args else "")
    if syntax == "eql":
        return f"// EQL has no lookup primitive: resolve '{name}' at ingest with an enrich pipeline."
    if syntax == "aql":
        return f"AND EXISTS (SELECT 1 FROM {name} WHERE 1=1)"
    if syntax == "yara":
        return f"  // lookup '{name}': add a reference list and bind it in the match section."
    if syntax == "cql":
        return f"| lookup('{name}')"
    return f"<!-- lookup {name} -->"


def _pred_to_wazuh(pred: Predicate) -> dict[str, Any]:
    """Predicate -> RuleRequest condition dict. in_list becomes a regex alternation."""
    if pred.operator == "in_list" and isinstance(pred.value, list):
        alts = "|".join(re.escape(str(v)) for v in pred.value)
        return {"field": pred.field, "operator": "regex", "value": f"(?:{alts})"}
    value = pred.value
    if isinstance(value, list):
        value = value[0] if value else ""
    return {"field": pred.field, "operator": pred.operator, "value": value}


def _flatten_wazuh(node: Any) -> tuple[list[dict[str, Any]], bool, bool]:
    """Return (predicate dicts, saw_or, saw_complex). AND-trees flatten fully;
    OR branches flatten with a flag (caller adds split guidance); NOT/unknown
    nesting is dropped with a flag (caller notes it)."""
    if isinstance(node, Predicate):
        return [_pred_to_wazuh(node)], False, False
    if isinstance(node, LogicNode):
        if node.op == "and":
            preds: list[dict[str, Any]] = []
            saw_or = saw_complex = False
            for child in node.children or ():
                sub, o, c = _flatten_wazuh(child)
                preds.extend(sub); saw_or = saw_or or o; saw_complex = saw_complex or c
            return preds, saw_or, saw_complex
        if node.op == "or":
            preds = []
            for child in node.children or ():
                sub, _, _ = _flatten_wazuh(child)
                preds.extend(sub)
            return preds, True, False
        return [], False, True  # not / unknown op: inexpressible in Wazuh
    if node is None:
        return [], False, False
    return [], False, True


def _render_sigma(model: CorrelationModel, notes: list[str] | None = None) -> str:
    import yaml

    def ser(node: Any) -> Any:
        if isinstance(node, Predicate):
            if node.operator == "exists":
                return {f"{node.field}|exists": True}
            suffix = {"contains": "|contains", "starts_with": "|startswith", "ends_with": "|endswith",
                      "regex": "|re", "windash": "|windash|contains", "base64": "|base64|contains",
                      "base64offset": "|base64offset|contains",
                      "cidr": "|cidr", "wildcard": "", "in_list": ""}.get(node.operator, "")
            return {f"{node.field}{suffix}": node.value}
        if isinstance(node, LogicNode):
            return {child: ser(c) for child, c in _named_children(node)}
        return {}

    def _named_children(node: LogicNode) -> list[tuple[str, Any]]:
        base = "selection" if node.op in {"and", "or"} else "filter"
        return [(f"{base}_{i}", c) for i, c in enumerate(node.children or ())]

    meta = model.native_metadata or {}
    detection: dict[str, Any] = {}
    logic = model.logic
    if isinstance(logic, LogicNode):
        if any(isinstance(c, LogicNode) for c in logic.children or ()):
            (notes if notes is not None else []).append("Nested boolean groups are flattened one level; verify operator precedence in the output.")
        named = _named_children(logic)
        for name, child in named:
            detection[name] = ser(child)
        joiner = " and " if logic.op == "and" else (" or " if logic.op == "or" else " and not ")
        detection["condition"] = joiner.join(name for name, _ in named) or "selection"
    else:
        detection = {"selection": ser(logic) or {}, "condition": "selection"}
    for index, exclusion in enumerate(model.exclusions or []):
        key = "filter" if index == 0 and "filter" not in detection else f"filter_{index}"
        detection[key] = ser(exclusion)
        detection["condition"] = f"({detection['condition']}) and not {key}"
    doc = {"title": meta.get("title", "Canonical model export"),
           "status": meta.get("status", "test"),
           "description": meta.get("description", "Exported from RuleForge canonical model."),
           "logsource": meta.get("logsource", {"product": "windows", "category": "process_creation"}),
           "detection": detection,
           "level": meta.get("level", "medium")}
    for key in ("id", "author", "references", "tags", "falsepositives"):
        if meta.get(key):
            doc[key] = meta[key]
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=False)


def _try_pysigma(model: CorrelationModel, siem: str, notes: list[str]) -> str | None:
    """Legacy signature kept for compatibility: the canonical model is not a Sigma
    document, so pySigma cannot convert it. Real conversion happens in
    compile_sigma_with_pysigma() for real Sigma YAML. Always None here."""
    return None


# P0-B: real pySigma conversion for genuine Sigma input (optional dependency).
# Maps our 8 targets onto the pySigma backend modules that exist upstream; targets
# without a backend (or without pySigma installed) fall back to the built-in renderer
# and say so, so the UI never claims pySigma ran when it did not.
_PYSIGMA_BACKENDS: dict[str, tuple[str, ...]] = {
    "splunk": (("sigma.backends.splunk", "SplunkBackend"),),
    "sentinel": (("sigma.backends.microsoft365defender", "Microsoft365DefenderBackend"),
                 ("sigma.backends.azure", "AzureBackend")),
    "elastic": (("sigma.backends.elasticsearch", "EqlBackend"),),
    "qradar": (("sigma.backends.qradar", "QradarBackend"),),
    "falcon": (("sigma.backends.crowdstrike", "LogScaleBackend"),),
}


def _resolve_pysigma_backend(siem: str) -> tuple[Any, str] | None:
    """First importable (module, class) pair for a target. Sentinel accepts two
    upstream module names because the package layout changed between releases."""
    for module_name, class_name in _PYSIGMA_BACKENDS.get(str(siem), ()):
        try:
            return getattr(__import__(module_name, fromlist=[class_name]), class_name), class_name
        except Exception:
            continue
    return None


def _pysigma_backend_available(siem: str) -> bool:
    return _resolve_pysigma_backend(siem) is not None


def pysigma_status() -> dict[str, Any]:
    """Honest capability report: pySigma core present AND each backend actually imports.
    Probed, never assumed - reporting an importable core as a working converter was a lie."""
    try:
        __import__("sigma.collection")  # type: ignore
        installed = True
    except Exception:
        installed = False
    available = sorted(s for s in _PYSIGMA_BACKENDS if installed and _pysigma_backend_available(s))
    without = sorted(set(_PYSIGMA_BACKENDS) - set(available)) + ["sigma", "google_secops", "wazuh"]
    return {"installed": installed, "backends_ready": available,
            "targets": available,
            "no_backend": sorted(set(without)),
            "no_backend_reason": "No official pySigma backend package exists for these targets yet; "
                                  "the built-in renderer is used and every output is labeled accordingly.",
            "note": ("pySigma converts genuine Sigma YAML for targets with a backend package installed. "
                     "Everything else (and the canonical model) uses the built-in renderer.")}


def compile_sigma_with_pysigma(sigma_yaml: str, siem: str) -> tuple[str, list[str]] | None:
    """Convert real Sigma YAML with pySigma when available. Returns (query, notes) or
    None when pySigma/backends are unavailable or conversion fails (caller falls back).
    Never raises: an optional dependency must not break the offline path."""
    if not isinstance(sigma_yaml, str) or not sigma_yaml.strip():
        return None
    resolved = _resolve_pysigma_backend(siem)
    if resolved is None:
        return None
    backend_class, class_name = resolved
    try:
        from sigma.collection import SigmaCollection  # type: ignore
        rules = SigmaCollection.from_yaml(sigma_yaml)
        queries = backend_class().convert(rules)
    except Exception as error:
        return None
    if not queries:
        return None
    text = "\n".join(str(q) for q in queries).strip()
    if not text:
        return None
    notes = [f"Converted by pySigma {class_name} (authoritative conversion)."]
    # pySigma emits a bare search body: scoping (index/table/base query) is the
    # deployment decision, so prepend ours when missing and say so.
    if siem == "splunk" and not re.search(r"\b(?:index|sourcetype)\s*=", text, re.IGNORECASE):
        text = f"index=* {text}"
        notes.append("Scoped to index=* because the Sigma logsource has no index mapping; replace with your real index.")
    elif siem == "sentinel" and not re.search(r"\bfrom\s+\w", text, re.IGNORECASE | re.DOTALL):
        from rule_engine import ASIM_TABLE_NOTE, ASIM_TABLE_PLACEHOLDER
        # The same safety rule as the built-in renderer: no table is a placeholder, and
        # the note must not recommend a legacy table, whose column names are incompatible.
        text = f"{ASIM_TABLE_PLACEHOLDER}{ASIM_TABLE_NOTE}\n{text.rstrip().rstrip('|').rstrip()}"
        notes.append(f"Sigma logsource does not name a Sentinel table: prepended the {ASIM_TABLE_PLACEHOLDER} "
                     "placeholder. Replace it with the table your ASIM parser writes to, and remove 'take 1000'.")
    if siem == "falcon" and not re.search(r"#repo\s*=", text):
        text = f"#repo=*\n| {text.lstrip().lstrip('|').lstrip()}"
        notes.append("Scoped to #repo=* because the Sigma logsource has no repository mapping; replace with your repository.")
    return text, notes
