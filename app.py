"""RuleForge - multi-SIEM detection rule generator."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from models.correlation import Predicate

from flask import Flask, jsonify, render_template, request

from rule_engine import (FIELD_MAPPINGS, OPERATOR_ALIASES, SIEMS, TECHNIQUES, RuleValidationError, analyze_rule,
                         detect_siem, generate_rules, generate_workbench, supported_siems)
from storage import RuleStore
from section_view import section_blocks
from compiler.validators import faithfulness, sigma_check, target_check
from compiler.spec_checks import check_technique_ids, validate_sigma_inventory as validate_inventory
from compiler.sigma_compiler import UNSUPPORTED_MAP, compile_model, compile_sigma_with_pysigma, pysigma_status
from models.correlation import CorrelationModel, flat_conditions_to_logic
from explainer import explain
from evaluator.match_tester import test_events
from diff_tool import diff_models

_SIGMA_FIELD_NOTE = (
    "Fields in this output were NOT checked against your SIEM schema. They come from the "
    "Sigma rule as written{fields}. Rules built in the studio are translated to vendor "
    "columns and labelled with the mapping; this one is not. Confirm every field against a "
    "real event before enabling it."
)

# Bounds for the illustrative scan. The disclosure is unconditional, so these only
# limit the annotation, never the caveat itself.
_SIGMA_SCAN_LIMIT = 20000
_SIGMA_FIELD_LIMIT = 8


def _sigma_native_fields(query: str) -> list[str]:
    """Field-looking identifiers in a pySigma output, purely ILLUSTRATIVE.

    This is a lexical scan, so it cannot be authoritative in either direction: it misses
    short, quoted, hyphenated and non-ASCII field names, and it picks up SELECT aliases,
    table placeholders and rule names. The unverified-field disclosure therefore does NOT
    depend on this list being correct - it is shown unconditionally, and this only
    annotates it. Do not add more stopwords chasing precision; the note is the guarantee,
    not the inventory.
    """
    if not isinstance(query, str) or not query.strip():
        return []
    body = query[:_SIGMA_SCAN_LIMIT]
    found: list[str] = []
    # finditer with an early exit, and a hard per-token cap, so a pathological query
    # cannot be amplified into megabytes of echoed identifiers across the response and
    # the history record.
    for match in re.finditer(r"[A-Za-z_][A-Za-z0-9_.\-]{1,60}", body):
        token = match.group(0).strip(".-")
        if not token or len(token) < 2:
            continue
        # A match that begins immediately after a dot continues an existing path, so
        # ".foo" is a fragment of "a.foo", not a standalone field. Requiring the preceding
        # character to be absent or a delimiter keeps dotted paths intact and drops
        # fragments; a trailing dot is stripped below rather than rejected.
        if match.start() > 0 and body[match.start() - 1] in "_.":
            continue
        if match.start() > 0 and body[match.start() - 1].isalnum():
            continue
        # A match that runs into more identifier characters is a truncated long token.
        if match.end() < len(body) and (body[match.end()].isalnum() or body[match.end()] in "_."):
            continue
        # A run longer than the match window is one pathological token, not several. Skip
        # the rest of it so a 200k-character run cannot become a list of 60-char slices.
        if match.end() < len(body) and body[match.end()].isalnum():
            continue
        parts = token.split(".")
        if any(not part for part in parts) or len(parts) > 8:
            continue
        if len(found) >= _SIGMA_FIELD_LIMIT:
            break
        if token not in found:
            found.append(token)
    return found





def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    app.config["RULEFORGE_DB"] = "data/ruleforge.db"
    store = RuleStore(app.config["RULEFORGE_DB"])
    from storage import FixtureStore
    fixtures = FixtureStore(app.config["RULEFORGE_DB"])

    TECHNIQUE_ORDER = ["failed_logins", "encoded_powershell", "suspicious_process", "new_admin", "custom"]

    def technique_catalog() -> list[dict[str, Any]]:
        ordered = [key for key in TECHNIQUE_ORDER if key in TECHNIQUES]
        ordered += sorted(key for key in TECHNIQUES if key not in ordered)
        catalog = []
        for key in ordered:
            entry = TECHNIQUES[key]
            catalog.append({"id": key, "label": str(entry.get("label", key)),
                            "mitre": [str(m) for m in entry.get("mitre", []) or []],
                            "tactic": str(entry.get("tactic", "")),
                            "default_field": str(entry.get("default_field", "")),
                            "default_value": str(entry.get("default_value", "")),
                            "description": str(entry.get("description", ""))})
        return catalog

    def field_taxonomy() -> list[str]:
        from rule_engine import ECS_FIELDS
        return list(ECS_FIELDS)

    @app.get("/")
    def index() -> str:
        catalog = technique_catalog()
        return render_template("index.html", siems=supported_siems(), techniques=catalog,
                               field_names=field_taxonomy(),
                               techniques_json={t["id"]: {"field": t["default_field"], "value": t["default_value"],
                                                          "description": t["description"]} for t in catalog})

    @app.get("/api/siems")
    def siems() -> Any:
        status = pysigma_status()
        return jsonify({"siems": supported_siems(), "pysigma": status,
                        "verification_note": "Outputs are checked by pySigma (where available) or by "
                                             "structural validation. Nothing here is executed against a live "
                                             "SIEM engine: test in your environment before enabling."})

    @app.get("/api/techniques")
    def techniques() -> Any:
        from rule_engine import INFERRED_TARGETS, mapping_provenance
        taxonomy = field_taxonomy()
        # `mapped_field_count` used to be the length of ONE target's table (sigma) while the
        # UI labelled it "verified field translations", which reads as a global coverage
        # figure and happens to equal elastic's count. Each target has its own table and
        # they differ, so the count is published per target alongside the denominator.
        by_target = {siem: len(table) for siem, table in sorted(FIELD_MAPPINGS.items())}
        return jsonify({"techniques": technique_catalog(), "fields": taxonomy,
                        "field_count": len(taxonomy),
                        "mapped_field_count": by_target.get("sigma", 0),
                        "field_mappings_by_target": by_target,
                        "inferred_field_targets": sorted(INFERRED_TARGETS),
                        "provenance": mapping_provenance()})

    @app.get("/api/mappings/overrides")
    def mapping_overrides_get() -> Any:
        """Analyst-pinned org-specific field aliases, with the reason for each."""
        from pathlib import Path as _P
        from mapping_overrides import KNOWN_TARGETS, load_overrides, load_provenance
        root = _P(__file__).resolve().parent
        tables = load_overrides(root)
        return jsonify({"overrides": tables, "notes": load_provenance(root),
                        "count": sum(len(t) for t in tables.values()),
                        "targets": sorted(KNOWN_TARGETS)})

    @app.post("/api/mappings/overrides")
    def mapping_overrides_post() -> Any:
        """Pin an org-specific field alias. Validated before any write."""
        from pathlib import Path as _P
        from mapping_overrides import OverrideError, write_override
        payload = request.get_json(silent=True) or {}
        try:
            saved = write_override(
                _P(__file__).resolve().parent,
                payload.get("target"), payload.get("canonical_field"),
                payload.get("native_field"), payload.get("reason", ""),
                payload.get("author", "analyst"))
        except OverrideError as error:
            return jsonify({"error": str(error)}), 400
        refresh_field_mappings()
        return jsonify({"saved": saved})

    @app.delete("/api/mappings/overrides")
    def mapping_overrides_delete() -> Any:
        """Remove an override so the generated mapping applies again."""
        from pathlib import Path as _P
        from mapping_overrides import OverrideError, clear_override
        payload = request.get_json(silent=True) or {}
        try:
            removed = clear_override(
                _P(__file__).resolve().parent,
                payload.get("target"), payload.get("canonical_field"))
        except OverrideError as error:
            return jsonify({"error": str(error)}), 400
        refresh_field_mappings()
        return jsonify({"cleared": removed})

    def refresh_field_mappings() -> None:
        """Reload mappings after an override changes, so the next compile uses it."""
        from rule_engine import _load_field_mappings
        FIELD_MAPPINGS.clear()
        FIELD_MAPPINGS.update(_load_field_mappings())

    @app.get("/api/attack")
    def attack_catalog() -> Any:
        """Full MITRE ATT&CK reference catalog with per-technique buildability."""
        from rule_engine import TECHNIQUES as _techs, attack_techniques
        buildable: dict[str, list[str]] = {}
        for key, entry in _techs.items():
            for tid in entry.get("mitre", []) or []:
                buildable.setdefault(str(tid), []).append(key)
        rows = [{**t, "templates": buildable.get(t["id"], []),
                 "buildable": bool(buildable.get(t["id"]))} for t in attack_techniques()]
        return jsonify({"techniques": rows, "total": len(rows),
                        "buildable": sum(1 for r in rows if r["buildable"])})

    _coverage_cache: dict[str, Any] = {"key": None, "value": None}

    def _coverage_cache_key() -> tuple:
        from pathlib import Path as _P
        data = _P(__file__).resolve().parent / "data"
        stamps = []
        for name in ("techniques.json", "attack_catalog.json", "mappings/fields.json"):
            try:
                stamps.append(int((data / name).stat().st_mtime))
            except OSError:
                stamps.append(0)
        return tuple(stamps)

    @app.get("/api/coverage")
    def coverage() -> Any:
        """P1-B: what this tool can actually build and deploy per target, right now.

        Every catalog technique is compiled against every target through the real
        pipeline, so the matrix reports measured fidelity instead of claims. The result
        is memoized and invalidated when the data files change: the full matrix is
        thousands of compiles, far too slow to repeat on every page load.
        """
        from compiler.pipeline import compile_request
        from rule_engine import parse_request
        key = _coverage_cache_key()
        if _coverage_cache["key"] == key and _coverage_cache["value"] is not None:
            return jsonify(_coverage_cache["value"])
        targets = [t["id"] for t in supported_siems()]
        rows = []
        for entry in technique_catalog():
            request = parse_request({"title": entry["label"][:140] or "Coverage probe",
                                     "description": "coverage probe", "severity": "medium",
                                     "technique": entry["id"], "field": entry["default_field"] or "process.name",
                                     "operator": "equals", "value": entry["default_value"] or "x",
                                     "threshold": 1, "timeframe": "5m", "group_by": "host.name",
                                     "data_source": "*", "siems": targets,
                                     "conditions": [{"field": entry["default_field"] or "process.name",
                                                     "operator": "equals", "value": entry["default_value"] or "x"}]})
            row = {"id": entry["id"], "label": entry["label"], "mitre": entry["mitre"], "targets": {}}
            for siem in targets:
                try:
                    output = compile_request(request, siem)
                    row["targets"][siem] = {"fidelity": output["fidelity"], "validation": output["validation"]}
                except (ValueError, KeyError) as error:
                    row["targets"][siem] = {"fidelity": "unsupported", "validation": "failed", "error": str(error)[:120]}
            rows.append(row)
        summary = {siem: {"exact": 0, "safe_normalized": 0, "partial": 0, "unsupported": 0}
                   for siem in targets}
        for row in rows:
            for siem, cell in row["targets"].items():
                if cell["fidelity"] in summary[siem]:
                    summary[siem][cell["fidelity"]] += 1
        # Advanced families: where fidelity actually varies per target. Each probe is
        # compiled through the real pipeline so the numbers are measured, never claimed.
        probes = {
            "threshold + group": {"threshold": 5, "group_by": "user.name"},
            "sequence": {"correlation": {"sequences": [{"join_by": "host.name", "maxspan": "5m",
                                                        "stages": [{"event": "a", "condition": ""},
                                                                   {"event": "b", "condition": ""}]}]}},
            "join": {"correlation": {"joins": [{"kind": "inner", "left": "a", "right": "b", "on": "host.name"}]}},
            "aggregation": {"correlation": {"aggregations": [{"function": "count", "field": "*", "alias": "c"}]}},
            "absence": {"correlation": {"sequences": [{"join_by": "host.name", "maxspan": "5m",
                                                       "stages": [{"event": "a", "condition": ""},
                                                                  {"event": "b", "condition": "", "negated": True}]}]}},
        }
        families = []
        for label, extra in probes.items():
            row = {"label": label, "targets": {}}
            for siem in targets:
                try:
                    output = compile_request(parse_request({
                        "title": "Family probe", "description": "family probe", "severity": "medium",
                        "technique": "custom", "field": "a", "operator": "equals", "value": "1",
                        "threshold": 1, "timeframe": "5m", "group_by": "host.name", "data_source": "*",
                        "siems": [siem], "conditions": [{"field": "a", "operator": "equals", "value": "1"}],
                        **extra}), siem)
                    row["targets"][siem] = {"fidelity": output["fidelity"], "validation": output["validation"]}
                except (ValueError, KeyError) as error:
                    row["targets"][siem] = {"fidelity": "unsupported", "validation": "failed", "error": str(error)[:120]}
            families.append(row)
        # The technique sweep alone flatters every target: a single-event template compiles
        # to a faithful normalized projection everywhere, so the summary would read as full
        # coverage with a reassuring word in it. The advanced families are where fidelity
        # actually drops, so they are aggregated here too and the denominator is published
        # next to every count. A reader must not have to know this to trust the number.
        advanced = {siem: {"exact": 0, "safe_normalized": 0, "partial": 0, "unsupported": 0,
                          "validation_failed": 0} for siem in targets}
        for row in families:
            for siem, cell in row["targets"].items():
                if cell.get("fidelity") in advanced[siem]:
                    advanced[siem][cell["fidelity"]] += 1
                if cell.get("validation") == "failed":
                    advanced[siem]["validation_failed"] += 1
        legend = [
            {"level": "exact",
             "meaning": "The target's own construct, not a projection. Nothing to translate."},
            {"level": "safe_normalized",
             "meaning": "Semantics preserved as a normalized projection. It will match the "
                        "same events, but it is not the vendor's native construct, so you still "
                        "map fields and set the rule's own scheduling."},
            {"level": "partial",
             "meaning": "Some of the rule's meaning is lost or reordered. A drafting aid, not an "
                        "equivalent rule - read the capability notes before trusting it."},
            {"level": "unsupported",
             "meaning": "No faithful equivalent in this dialect. Rebuild it natively."},
        ]
        payload = {"techniques": rows, "targets": targets, "summary": summary,
                   "families": families, "advanced": advanced, "legend": legend,
                   "denominator": {"techniques": len(rows), "families": len(families)},
                   "total": len(rows)}
        _coverage_cache["key"] = _coverage_cache_key()
        _coverage_cache["value"] = payload
        return jsonify(payload)

    @app.post("/api/generate")
    def generate() -> Any:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Send a JSON request body."}), 400
        # A pasted Sigma rule is converted by the vendor-authored backend when one exists,
        # because rebuilding it from the form's Sigma field names produced a draft with no
        # mapping at all. The UI can only reach this through /api/generate, so the Sigma
        # path has to live here too or it is unreachable in practice.
        use_sigma = bool(str(payload.get("sigma", "")).strip()) and payload.get("sigma_authoritative", True) is not False
        try:
            workbench = (_sigma_workbench(payload, [s for s in payload.get("siems", []) if isinstance(s, str)])
                         if use_sigma else generate_workbench(payload))
        except (RuleValidationError, ValueError, RecursionError) as error:
            return jsonify({"error": str(error)}), 400
        generated_at = datetime.now(timezone.utc).isoformat()
        for rule in workbench["rules"]:
            try:
                rule["section_blocks"] = section_blocks(rule.get("rule", ""), rule.get("siem", ""))
            except Exception:
                rule["section_blocks"] = [{"title": "Rule", "code": rule.get("rule", "")}]
        try:
            store.record_history(
                "generated",
                str(payload.get("title", "Untitled rule")),
                ", ".join(s for s in payload.get("siems", []) if isinstance(s, str)),
                f"Generated {len(workbench['rules'])} SIEM template(s)",
                payload,
                workbench,
            )
        except Exception:
            pass
        return jsonify({
            **workbench,
            "generated_at": generated_at,
        })

    @app.post("/api/analyze")
    def analyze() -> Any:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Send a JSON request body."}), 400
        try:
            result = analyze_rule(payload.get("rule"), payload.get("siem", "auto"))
        except RuleValidationError as error:
            return jsonify({"error": str(error)}), 400
        # One vocabulary out of this endpoint. Sigma modifiers arrive as `endswith` /
        # `startswith`, but the form's operator <select> holds `ends_with` /
        # `starts_with`, so writing the raw modifier into it selected NOTHING: the row
        # went out with an empty operator, /api/explain and /api/compile both answered 400,
        # and the UI swallowed both. Normalize here so no consumer has to know the alias table.
        for entry in [*(result.get("conditions") or []), *(result.get("exclusions") or [])]:
            if isinstance(entry, dict) and isinstance(entry.get("operator"), str):
                entry["operator"] = OPERATOR_ALIASES.get(entry["operator"], entry["operator"])
        defaults = result.get("payload_defaults")
        if isinstance(defaults, dict) and isinstance(defaults.get("operator"), str):
            defaults["operator"] = OPERATOR_ALIASES.get(defaults["operator"], defaults["operator"])
        # Analyst upgrade: full-model explainer attached (additive, legacy keys kept)
        try:
            model = _analysis_to_model(result)
            result["correlation_model"] = model.to_dict()
            result["explanation"] = explain(model, dialect=result.get("siem", "unknown"), raw_rule=result.get("raw_rule", ""))
            result["sections_parsed"] = sorted(result.get("native_sections", {}).keys())
            result["section_blocks"] = section_blocks(result.get("raw_rule", ""), result.get("siem", ""))
            try:
                query, fidelity, notes = compile_model(model, result.get("siem", "unknown"))
                result["faithfulness"] = faithfulness(result.get("conditions", []),
                                                      result.get("exclusions", []), query, fidelity)
            except Exception:
                result.setdefault("faithfulness", {"badge": "lossy", "reasons": ["recompile unavailable for this dialect"]})
        except Exception:
            result.setdefault("correlation_model", {})
            result.setdefault("explanation", {"summary": "Explanation unavailable for this rule.", "bullets": [], "lossy_flags": [], "fidelity": result.get("fidelity", "partial")})
            result.setdefault("sections_parsed", [])
            result.setdefault("section_blocks", [{"title": "Rule", "code": result.get("raw_rule", "")}])
        try:
            store.record_history(
                "analyzed",
                f"Imported {result.get('siem', 'unknown')} rule",
                str(result.get("siem", "")),
                f"Analyzed {len(result.get('conditions', []))} condition(s)",
                {"rule": payload.get("rule"), "siem": payload.get("siem")},
                result,
            )
        except Exception:
            pass
        return jsonify(result)

    @app.post("/api/validate")
    def validate() -> Any:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Send a JSON request body."}), 400
        sigma_yaml = str(payload.get("sigma", ""))
        from compiler.sigma_compiler import pysigma_status
        if sigma_yaml.strip() and not pysigma_status()["installed"]:
            return jsonify({"error": "Sigma validation needs pySigma. Install pysigma to validate Sigma rules."}), 503
        findings = validate_inventory(sigma_yaml)
        techniques = payload.get("techniques", []) or []
        if not isinstance(techniques, list) or any(not isinstance(t, str) for t in techniques):
            return jsonify({"error": "techniques must be a list of strings."}), 400
        for technique in techniques:
            findings.extend(check_technique_ids([technique]))
        errors = [f"[{f['severity']}] {f['message']}" for f in findings]
        return jsonify({"valid": not any(f["severity"] == "HIGH" for f in findings),
                        "errors": errors, "findings": findings})

    @app.post("/api/compile")
    def compile_canonical() -> Any:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Send a JSON request body."}), 400
        targets = payload.get("siems") or []
        if not targets:
            return jsonify({"error": "Select at least one SIEM."}), 400
        effective = payload
        if payload.get("sigma") and "conditions" not in payload and "logic" not in payload:
            # Sigma-first compile: derive the form-shaped request from the pasted rule so
            # analysts can convert pure Sigma without filling the studio form.
            try:
                effective = {**payload, **_request_from_sigma(str(payload["sigma"]))}
            except (ValueError, RecursionError) as error:
                return jsonify({"error": str(error)}), 400
        try:
            model, det_request = _payload_to_model(effective)
        except (RuleValidationError, ValueError, RecursionError) as error:
            return jsonify({"error": str(error)}), 400
        outputs = []
        from compiler.pipeline import compile_request
        from compiler.validators import target_warnings
        for siem in targets:
            if payload.get("sigma"):
                from compiler.validators import validation_level
                # P0-B: authoritative pySigma conversion when available, built-in otherwise.
                converted = compile_sigma_with_pysigma(str(payload.get("sigma", "")), siem)
                py_sigma = converted is not None
                if py_sigma:
                    query, notes = converted
                    fidelity = "exact"
                else:
                    try:
                        query, fidelity, notes = compile_model(model, siem)
                    except RuleValidationError as refusal:
                        # Same per-target contract as compile_request: a target that refuses
                        # its own settings must not 500 the whole Sigma compile.
                        outputs.append({"siem": siem, "name": SIEMS.get(siem, {}).get("name", siem),
                                        "language": SIEMS.get(siem, {}).get("language", ""),
                                        "query": "", "rule": "", "fidelity": "unsupported",
                                        "refused": True, "refusal_kind": "target_constraint",
                                        "refusal_reason": str(refusal),
                                        "review_note": "This target's own limits reject the requested settings. Adjust them or drop this target; the other targets are unaffected.",
                                        "notes": [str(refusal)], "capability_notes": [str(refusal)],
                                        "checks": [str(refusal)], "warnings": [],
                                        "validation": "failed", "section_blocks": [],
                                        "field_mapping": {"canonical_field": "Sigma rule fields, built-in renderer",
                                                          "native_field": "not emitted",
                                                          "mapping_confidence": "unverified",
                                                          "mapping_source": "sigma-built-in"}})
                        continue
                    if not pysigma_status()["installed"]:
                        notes = [*notes, "pySigma is not installed: built-in renderer used. Install pysigma plus a backend package for authoritative Sigma conversion."]
                checks = target_check(siem, query)
                # pySigma emits Sigma field names (Image, CommandLine) verbatim. That is
                # right for Sigma, but it is NOT the vocabulary the built-in renderer emits
                # (TargetProcessCommandLine, process.command_line), and this path carried no
                # field_mapping at all, so the UI showed a mapping chip for one entry path
                # and silence for the other. Disclose the difference instead of implying the
                # imported columns were checked against any schema.
                # pySigma emits Sigma field names (Image, CommandLine) verbatim. The
                # built-in renderer maps canonical ECS fields to vendor columns and says
                # which ones. This path does neither, so it must say so unconditionally -
                # not only when the illustrative field list happens to be non-empty,
                # which is the case a regex scan cannot guarantee.
                sigma_fields = _sigma_native_fields(query) if py_sigma else []
                if py_sigma:
                    # The caveat stands alone. The scanned names are an annotation that
                    # helps, not the disclosure - a lexical scan cannot be authoritative,
                    # so it must never gate whether the analyst is warned.
                    notes = [*notes, _SIGMA_FIELD_NOTE.format(
                        fields=(f" Field names seen: {', '.join(sigma_fields)}."
                                if sigma_fields else ""))]
                    mapping = {
                        "canonical_field": "Sigma rule fields, passed through",
                        "native_field": ", ".join(sigma_fields) or "not enumerated",
                        "mapping_confidence": "unverified",
                        "mapping_source": "sigma-pysigma",
                    }
                else:
                    # Built-in fallback for targets with no pySigma backend. Do NOT claim
                    # pySigma provenance for output it did not produce.
                    mapping = {
                        "canonical_field": "Sigma rule fields, built-in renderer",
                        "native_field": "see output",
                        "mapping_confidence": "unverified",
                        "mapping_source": "sigma-built-in",
                    }
                outputs.append({"siem": siem, "query": query, "rule": query, "fidelity": fidelity,
                                "notes": notes, "checks": checks,
                                "warnings": target_warnings(siem, query),
                                "validation": validation_level(siem, checks, py_sigma),
                                "capability_notes": notes,
                                "field_mapping": mapping,
                                "section_blocks": section_blocks(query, siem)})
            else:
                outputs.append(compile_request(det_request, siem))
        if payload.get("sigma"):
            for output in outputs:
                output.setdefault("notes", []).append(
                    "Sigma correlation blocks are not compiled to native correlation; threshold/window/group-by come from the form.")
        try:
            store.record_history("compiled", str(payload.get("title", "Canonical compile")), ", ".join(s for s in targets if isinstance(s, str)),
                                 f"Compiled {len(outputs)} target(s)", payload, {"outputs": outputs})
        except Exception:
            pass
        return jsonify({"outputs": outputs, "model": model.to_dict(),
                        "explanation": explain(model, dialect="canonical")})

    @app.post("/api/explain")
    def explain_route() -> Any:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Send a JSON request body."}), 400
        try:
            model = _payload_to_model(payload)[0] if "conditions" in payload or "logic" in payload else _analysis_to_model(
                analyze_rule(payload.get("rule", ""), payload.get("siem", "auto")))
        except (RuleValidationError, ValueError, RecursionError) as error:
            return jsonify({"error": str(error)}), 400
        return jsonify(explain(model, dialect=str(payload.get("siem", "canonical"))))

    @app.post("/api/test_match")
    def test_match() -> Any:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Send a JSON request body."}), 400
        events = payload.get("events", [])
        if not isinstance(events, list) or not events:
            return jsonify({"error": "Provide events: [{...}, ...]."}), 400
        if any(not isinstance(event, dict) for event in events):
            return jsonify({"error": "Each event must be a JSON object."}), 400
        try:
            model = _payload_to_model(payload)[0] if "conditions" in payload or "logic" in payload else _analysis_to_model(
                analyze_rule(payload.get("rule", ""), payload.get("siem", "auto")))
        except (RuleValidationError, ValueError, RecursionError) as error:
            return jsonify({"error": str(error)}), 400
        # Allow a direct threshold/window override for tune iterations, but never resurrect
        # a threshold the request explicitly disabled. parse_request() turns
        # use_threshold=false into threshold=None, and the generated rule then carries no
        # count clause at all. Overriding here made Test report "suppressed" against a rule
        # that fires on its first event.
        if payload.get("use_threshold") is not False and payload.get("threshold") is not None:
            override = payload["threshold"]
            if type(override) is not int or override < 1 or override > 10000:
                return jsonify({"error": "Threshold override must be a whole number between 1 and 10000."}), 400
            model.threshold = override
        if payload.get("window") is not None:
            window = str(payload["window"]).lower()
            if not re.fullmatch(r"\d{1,3}[smhd]", window) or int(window[:-1]) < 1:
                return jsonify({"error": "Window override must look like 30s, 5m, 1h, or 1d."}), 400
            model.window = window
        try:
            result = test_events(model, events)
        except (RuleValidationError, ValueError, RecursionError) as error:
            return jsonify({"error": str(error)}), 400
        return jsonify(result)

    @app.post("/api/ingest")
    def ingest_route() -> Any:
        from evaluator.match_tester import ingest_events
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Send a JSON request body."}), 400
        try:
            return jsonify(ingest_events(payload.get("content", ""), payload.get("format", "auto")))
        except (ValueError, RecursionError) as error:
            return jsonify({"error": str(error)}), 400

    @app.get("/api/fixtures")
    def list_fixtures() -> Any:
        return jsonify({"fixtures": [{k: v for k, v in f.items() if k != "events"} for f in fixtures.list_fixtures()]})

    @app.post("/api/fixtures")
    def create_fixture() -> Any:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Send a JSON request body."}), 400
        try:
            return jsonify(fixtures.save_fixture(payload.get("title", ""), payload.get("events", []),
                                                  payload.get("siem", ""))), 201
        except (ValueError, TypeError) as error:
            return jsonify({"error": str(error)}), 400

    @app.delete("/api/fixtures/<fixture_id>")
    def delete_fixture(fixture_id: str) -> Any:
        return jsonify({"deleted": fixtures.delete_fixture(fixture_id)})

    @app.post("/api/fixtures/replay")
    def replay_fixture() -> Any:
        from evaluator.match_tester import replay_fixture as _replay
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Send a JSON request body."}), 400
        try:
            model = _payload_to_model(payload)[0] if "conditions" in payload or "logic" in payload else _analysis_to_model(
                analyze_rule(payload.get("rule", ""), payload.get("siem", "auto")))
        except (RuleValidationError, ValueError, RecursionError) as error:
            return jsonify({"error": str(error)}), 400
        ids = payload.get("fixture_ids")
        if ids is not None:
            if not isinstance(ids, list) or any(not isinstance(i, str) for i in ids) or len(ids) > 100:
                return jsonify({"error": "fixture_ids must be a list of up to 100 ids."}), 400
            stored = {f["id"]: f for f in fixtures.list_fixtures()}
            results = []
            for fixture_id in ids:
                fixture = stored.get(fixture_id)
                if fixture is None:
                    continue
                try:
                    outcome = _replay(model, fixture["events"])
                except (RuleValidationError, ValueError, RecursionError) as error:
                    outcome = {"passed": False, "event_count": len(fixture["events"]),
                               "mismatches": [{"index": -1, "expected": None, "actual": None,
                                               "reasons": [str(error)[:120]]}],
                               "scoring": {}, "would_fire": False, "verdict": "error"}
                results.append({"id": fixture_id, "title": fixture["title"], **outcome})
            return jsonify({"results": results, "total": len(results),
                            "passed_count": sum(1 for r in results if r.get("passed"))})
        events = payload.get("events")
        if not isinstance(events, list) or not events or any(not isinstance(e, dict) for e in events):
            return jsonify({"error": "Provide fixture_ids or events: [{...}, ...] with _expected labels."}), 400
        try:
            return jsonify(_replay(model, events))
        except (RuleValidationError, ValueError, RecursionError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/evade")
    def evade_route() -> Any:
        from evaluator.evasion import evasion_report
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Send a JSON request body."}), 400
        event = payload.get("event", {})
        if not isinstance(event, dict) or not event:
            return jsonify({"error": "Provide event: {...} that matches the rule."}), 400
        try:
            model = _payload_to_model(payload)[0] if "conditions" in payload or "logic" in payload else _analysis_to_model(
                analyze_rule(payload.get("rule", ""), payload.get("siem", "auto")))
        except (RuleValidationError, ValueError, RecursionError) as error:
            return jsonify({"error": str(error)}), 400
        try:
            return jsonify(evasion_report(model, event))
        except (RuleValidationError, ValueError, RecursionError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/diff")
    def diff_route() -> Any:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Send a JSON request body."}), 400
        before = payload.get("before", {})
        after = payload.get("after", {})
        if not isinstance(before, dict) or not isinstance(after, dict):
            return jsonify({"error": "Provide before/after model dicts."}), 400
        try:
            result = diff_models(before, after)
        except (ValueError, RecursionError) as error:
            return jsonify({"error": f"Unable to diff models: {error}"}), 400
        events = payload.get("events", [])
        if events:
            if not isinstance(events, list) or any(not isinstance(e, dict) for e in events):
                return jsonify({"error": "events must be a list of JSON objects."}), 400
            from models.correlation import model_from_dict
            try:
                before_v = test_events(model_from_dict(before), events)
                after_v = test_events(model_from_dict(after), events)
            except (RuleValidationError, ValueError, RecursionError) as error:
                return jsonify({"error": str(error)}), 400
            result["verdict_before"] = before_v["verdict"]
            result["verdict_after"] = after_v["verdict"]
            result["verdict_changed"] = before_v["verdict"] != after_v["verdict"]
            result["scoring_before"] = before_v["scoring"]
            result["scoring_after"] = after_v["scoring"]
        return jsonify(result)

    @app.get("/api/rf-families")
    def rf_families() -> Any:
        return jsonify({"unsupported": UNSUPPORTED_MAP,
                        "note": "RF-13..RF-16 have no portable equivalent and are preserved as exact source."})

    @app.get("/api/history")
    def history() -> Any:
        return jsonify({"history": store.list_history()})

    @app.delete("/api/history")
    def clear_history() -> Any:
        store.clear_history()
        return jsonify({"cleared": True})

    return app


def _analysis_to_model(result: dict[str, Any]) -> CorrelationModel:
    from models.correlation import Aggregation, Join, Lookup, Sequence, SequenceStage

    def _dicts(items: Any) -> list[dict[str, Any]]:
        return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []

    model = CorrelationModel()
    model.logic = flat_conditions_to_logic(result.get("conditions", []), "all")
    raw_rule = str(result.get("raw_rule", ""))
    bare_rule = re.sub(r'"[^"]*"|\'[^\']*\'', '""', raw_rule)
    if len(result.get("conditions", [])) > 1 and re.search(r"\bor\b", bare_rule, re.IGNORECASE):
        model.unsupported_features.append("boolean-or-flattened")
    model.exclusions = [flat_conditions_to_logic([c], "all") for c in result.get("exclusions", [])]
    model.exclusions = [e for e in model.exclusions if e is not None]
    try:
        model.threshold = int(result.get("threshold", 1))
    except (TypeError, ValueError):
        model.threshold = 1
    model.window = str(result.get("timeframe", "5m"))
    group_by = result.get("group_by", "user.name")
    model.group_by = [group_by] if isinstance(group_by, str) else [str(g) for g in group_by] if isinstance(group_by, list) else ["user.name"]
    model.source = str(result.get("data_source", "*"))
    model.sequences = [Sequence(join_by=s.get("join_by", ""), maxspan=s.get("maxspan", ""),
                                stages=tuple(SequenceStage(event=st.get("event", ""), condition=st.get("condition", ""), negated=bool(st.get("negated", False))) for st in s.get("stages", []) if isinstance(st, dict)))
                       for s in _dicts(result.get("sequences", []))]
    model.joins = [Join(kind=j.get("kind", "inner"), left=str(j.get("left", "")), right=str(j.get("right", "")), on=str(j.get("on", ""))) for j in _dicts(result.get("joins", []))]
    model.aggregations = [Aggregation(function=a.get("function", "count"), field=str(a.get("field", "")), alias=str(a.get("alias", ""))) for a in _dicts(result.get("aggregations", []))]
    model.lookups = [Lookup(name=str(l.get("name", "")), arguments=str(l.get("arguments", ""))) for l in _dicts(result.get("lookups", []))]
    model.event_streams = _dicts(result.get("event_streams", []))
    model.time_constraints = [str(t) for t in result.get("time_constraints", []) if isinstance(result.get("time_constraints"), list)]
    model.native_sections = result.get("native_sections", {}) if isinstance(result.get("native_sections"), dict) else {}
    model.native_metadata = result.get("native_metadata", {}) if isinstance(result.get("native_metadata"), dict) else {}
    raw_unsupported = result.get("unsupported_features", [])
    model.unsupported_features = [str(u) for u in raw_unsupported] if isinstance(raw_unsupported, list) else []
    model.fidelity = str(result.get("fidelity", "partial"))
    return model


def _iter_predicates(node: Any) -> list[Any]:
    from models.correlation import Predicate
    found: list[Any] = []
    stack = [node]
    while stack:
        current = stack.pop(0)
        if isinstance(current, Predicate):
            found.append(current)
        elif hasattr(current, "children"):
            stack.extend(list(current.children))
    return found


def _sigma_workbench(payload: dict[str, Any], targets: list[str]) -> dict[str, Any]:
    """Workbench-shaped results for a pasted Sigma rule.

    An analyst could paste real Sigma YAML, get a draft assembled from Sigma field names
    with no mapping, and never reach the vendor-authored backend that was already wired
    into /api/compile. This reuses that path and reshapes it into the `rules` contract the
    UI already renders, so the form and the API agree on which conversion is authoritative.
    """
    from compiler.sigma_compiler import compile_model, compile_sigma_with_pysigma, pysigma_status
    from compiler.validators import target_warnings, validation_level

    sigma_yaml = str(payload.get("sigma", ""))
    model, _ = _payload_to_model({**payload, **_request_from_sigma(sigma_yaml)})
    rules: list[dict[str, Any]] = []
    authoritative = 0
    for siem in targets:
        meta = SIEMS.get(siem, {"name": siem, "language": ""})
        converted = compile_sigma_with_pysigma(sigma_yaml, siem)
        if converted is not None:
            query, notes = converted
            fidelity = "exact"
            authoritative += 1
            seen = _sigma_native_fields(query)
            notes = [*notes, _SIGMA_FIELD_NOTE.format(
                fields=(f" Field names seen: {', '.join(seen)}." if seen else ""))]
            mapping = {"canonical_field": "Sigma rule fields, passed through",
                       "native_field": ", ".join(seen) or "not enumerated",
                       "mapping_confidence": "unverified", "mapping_source": "sigma-pysigma"}
        else:
            try:
                query, fidelity, notes = compile_model(model, siem)
            except RuleValidationError as refusal:
                rules.append({"siem": siem, "name": meta.get("name", siem),
                              "language": meta.get("language", ""), "rule": "", "query": "",
                              "fidelity": "unsupported", "refused": True,
                              "refusal_kind": "target_constraint",
                              "refusal_reason": str(refusal),
                              "review_note": "This target's own limits reject the requested settings. "
                                             "Adjust them or drop this target; the other targets are unaffected.",
                              "capability_notes": [str(refusal)], "checks": [str(refusal)],
                              "warnings": [], "validation": "failed", "section_blocks": [],
                              "field_mapping": {"canonical_field": "Sigma rule fields, built-in renderer",
                                                "native_field": "not emitted",
                                                "mapping_confidence": "unverified",
                                                "mapping_source": "sigma-built-in"}})
                continue
            if not pysigma_status()["installed"]:
                notes = [*notes, "pySigma is not installed: built-in renderer used. Install pysigma "
                                 "plus a backend package for authoritative Sigma conversion."]
            mapping = {"canonical_field": "Sigma rule fields, built-in renderer",
                       "native_field": "see output", "mapping_confidence": "unverified",
                       "mapping_source": "sigma-built-in"}
        # Both halves: target_warnings is where the placeholder-scope caveats live (an
        # unscoped index=*, the Sentinel table placeholder). Dropping it hid exactly the
        # warnings that say the output is not deployable as written.
        checks = target_check(siem, query)
        warnings = target_warnings(siem, query)
        rules.append({
            "siem": siem, "name": meta.get("name", siem), "language": meta.get("language", ""),
            "rule": query, "query": query, "fidelity": fidelity,
            "review_note": (f"Converted from your Sigma rule by the vendor-authored "
                            f"{meta.get('name', siem)} backend. Field names are whatever that "
                            "backend emitted - map them to your data model before enabling."),
            "capability_notes": notes, "checks": checks, "warnings": warnings,
            "validation": validation_level(siem, checks, converted is not None),
            "field_mapping": mapping, "section_blocks": [],
        })
    gates: list[dict[str, Any]] = []
    if authoritative and authoritative < len(targets):
        gates.append({"level": "warn", "title": "Partial authoritative conversion",
                      "detail": f"{authoritative} of {len(targets)} targets were converted by a "
                                "vendor-authored backend; the rest used the built-in renderer, "
                                "which is a draft, not an equivalent rule."})
    elif not authoritative:
        gates.append({"level": "warn", "title": "No vendor backend for these targets",
                      "detail": "None of the selected targets has a pySigma backend here, so the "
                                "built-in renderer produced these. Treat them as drafts."})
    return {
        "rules": rules,
        "quality_gates": gates,
        "compile_contract": {"source": {
            "mode": "sigma_native" if authoritative else "sigma_built_in",
            "fidelity": "exact" if authoritative and authoritative == len(targets) else "partial",
            "equivalent": authoritative == len(targets)}},
        "compile_allowed": bool(rules),
    }


def _request_from_sigma(sigma_yaml: str) -> dict[str, Any]:
    """Derive a form-shaped request from pasted Sigma YAML (Sigma-first compile)."""
    from parsers.sigma_parser import parse_sigma
    from models.correlation import Predicate

    sigma_model, meta = parse_sigma(sigma_yaml)
    first: Predicate | None
    stack = [sigma_model.logic]
    first = None
    while stack:
        node = stack.pop(0)
        if isinstance(node, Predicate):
            first = node
            break
        if hasattr(node, "children"):
            stack.extend(list(node.children))
    conditions: list[dict[str, Any]] = []
    # Sigma multi-value selections (OR of one modifier) collapse to ONE faithful regex
    # condition: validating a list value is impossible, and ANDing expanded items would
    # invert the logic, so the OR is preserved in a single anchored pattern.
    from parsers.sigma_parser import _split_field
    modifiers: dict[str, str] = {}
    for selection in (meta.get("detection_raw") or {}).values():
        if isinstance(selection, dict):
            for raw_field in selection:
                base, modifier = _split_field(str(raw_field))
                modifiers[base] = modifier
    for node in _iter_predicates(sigma_model.logic):
        value = node.value
        if isinstance(value, list):
            modifier = modifiers.get(node.field, "equals")
            items = [str(v) for v in value if str(v)]
            alts = "|".join(v if modifier == "regex" else re.escape(v) for v in items)
            pattern = {"contains": alts, "starts_with": f"^(?:{alts})",
                       "ends_with": f"(?:{alts})$"}.get(modifier, f"^(?:{alts})$")
            conditions.append({"field": node.field, "operator": "regex", "value": pattern})
        else:
            conditions.append({"field": node.field, "operator": node.operator, "value": value})
    if not conditions:
        conditions = [{"field": "process.name", "operator": "contains", "value": "example.exe"}]
    exclusions = []
    for excl in sigma_model.exclusions or []:
        stack = [excl]
        while stack:
            node = stack.pop(0)
            if isinstance(node, Predicate):
                exclusions.append({"field": node.field, "operator": node.operator, "value": node.value})
                break
            if hasattr(node, "children"):
                stack.extend(list(node.children))
    severity = str(meta.get("level") or "medium").lower()
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "medium"
    group_by = sigma_model.group_by[0] if sigma_model.group_by else "host.name"
    return {
        "title": str(meta.get("title") or "Sigma rule")[:140],
        "description": str(meta.get("description") or "Converted from Sigma YAML.")[:500],
        "severity": severity,
        "technique": "custom",
        "field": conditions[0]["field"] if conditions else "process.name",
        "operator": conditions[0]["operator"] if conditions else "contains",
        "value": conditions[0]["value"] if conditions else "example.exe",
        "conditions": conditions or [{"field": "process.name", "operator": "contains", "value": "example.exe"}],
        "condition_logic": "all",
        "exclude_conditions": exclusions,
        "threshold": sigma_model.threshold or 1,
        "timeframe": sigma_model.window or "5m",
        "group_by": group_by,
        "data_source": "*",
    }


def _payload_to_model(payload: dict[str, Any]) -> tuple[CorrelationModel, Any]:
    from rule_engine import parse_request

    request = parse_request(payload)
    model = CorrelationModel()
    model.logic = flat_conditions_to_logic(
        [{"field": c["field"], "operator": c["operator"], "value": c["value"]} for c in request.conditions],
        request.condition_logic)
    excl = [flat_conditions_to_logic([c], "all") for c in request.exclude_conditions]
    model.exclusions = [e for e in excl if e is not None]
    model.threshold = request.threshold
    model.window = request.timeframe
    model.group_by = [request.group_by]
    model.source = str(payload.get("data_source", "*"))
    # F4: authorable multi-event correlation rides the same validated parse as RuleRequest.
    model.sequences = list(request.sequences or [])
    model.joins = list(request.joins or [])
    model.aggregations = list(request.aggregations or [])
    model.lookups = list(request.lookups or [])
    # Sigma canonical passthrough: if caller sends sigma YAML, parse it fully
    if payload.get("sigma"):
        from parsers.sigma_parser import parse_sigma

        sigma_model, _ = parse_sigma(str(payload["sigma"]))
        if sigma_model.logic is not None:
            model.logic = sigma_model.logic
            model.exclusions = sigma_model.exclusions or model.exclusions
    return model, request


app = create_app()


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000, use_reloader=False)
