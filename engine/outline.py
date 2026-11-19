"""A readable summary of a rule, for the CLI and the builder's outline pane.

This lived in `web/api.py`, which meant `engine/cli.py` had to import from
`web/` to print an outline -- a violation of the one layering rule this project
states: the engine never imports the web layer. The function is pure engine
work (it reads the IR and calls `render_expr`), so it belongs here and both
callers import it from the engine side.
"""

from __future__ import annotations

from typing import Any

from .ir import Rule, render_expr

__all__ = ["outline", "span_text"]


def span_text(duration: Any) -> str:
    """A Duration as the span an analyst would write.

    `str(Duration)` is a debugging repr, and `Duration(300s)` leaking into the
    outline pane reads as a bug rather than as five minutes.
    """
    seconds = int(duration.seconds)
    for suffix, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size and seconds % size == 0:
            return f"{seconds // size}{suffix}"
    return f"{seconds}s"


def outline(rule: Rule) -> dict[str, Any]:
    """A readable summary of a rule, for the builder's outline pane.

    `render_expr` is display text and explicitly NOT re-parseable dialect
    syntax -- see its docstring in `ir.py`. It is used here for exactly the
    purpose it was written for: showing an analyst what a condition says.
    """
    def stage(node: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            "id": node.id,
            "kind": type(node).__name__,
            "capability": node.capability.value,
            "note": node.note,
        }
        condition = getattr(node, "condition", None)
        if condition is not None:
            body["condition"] = render_expr(condition)
        predicate = getattr(node, "predicate", None)
        if predicate is not None:
            body["predicate"] = render_expr(predicate)

        # A stage whose meaning is in its SETTINGS rather than in a condition
        # used to print as a bare word: a Correlation showed no frequency, no
        # timeframe and no group key, so the clause that makes the rule a rule
        # was invisible while the pane claimed nothing had been lost.
        table = getattr(node, "table", None)
        if table is not None:
            body["table"] = table
            selector = getattr(node, "selector", "")
            if selector:
                body["selector"] = selector
            time_field = getattr(node, "time_field", "")
            if time_field:
                body["time_field"] = time_field

        parent = getattr(node, "parent", None)
        if parent is not None:
            body["parent"] = parent
            body["frequency"] = getattr(node, "frequency", None)
            timeframe = getattr(node, "timeframe", None)
            body["timeframe"] = span_text(timeframe) if timeframe is not None else ""
            body["group_by"] = [ref.full for ref in getattr(node, "group_by", ())]
            body["count_subject"] = getattr(node, "count_subject", "")

        measures = getattr(node, "measures", None)
        if measures is not None:
            body["measures"] = [
                {
                    "name": measure.name,
                    "function": measure.function,
                    "field": measure.field.full if measure.field else "",
                    "distinct": bool(measure.distinct),
                }
                for measure in measures
            ]
            body["keys"] = [ref.full for ref in getattr(node, "keys", ())]
            window = getattr(node, "window", None)
            if window is not None:
                # `window` is a Window (kind + size), not a Duration: the size
                # is the span an analyst would write.
                body["window"] = span_text(window.size)
                if getattr(window, "kind", ""):
                    body["window_kind"] = window.kind

        keeps = getattr(node, "keeps", None)
        if keeps is not None:
            body["keeps"] = [ref.full for ref in keeps]
            body["dedupe_by"] = [ref.full for ref in getattr(node, "dedupe_by", ())]

        keys = getattr(node, "keys", None)
        if keys is not None and measures is None:
            # Sort and Distinct both key on fields; Sort pairs each key with a
            # direction, which is the part a reader needs to see.
            described = []
            for key in keys:
                if (isinstance(key, tuple) and len(key) == 2
                        and hasattr(key[0], "full")):
                    described.append(
                        {"field": key[0].full, "descending": bool(key[1])})
                elif hasattr(key, "full"):
                    described.append(key.full)
            body["keys"] = described

        # A Sequence carries its conditions on its STEPS, not on a `condition`
        # attribute, so the generic lookups above find nothing and the most
        # complex stage in the model rendered as a bare word. The ordering is
        # the entire point of the node, and an outline that does not show it
        # leaves the analyst reading the raw IR to find out what the rule
        # waits for.
        steps = getattr(node, "steps", None)
        if steps is not None:
            body["steps"] = [
                {
                    "position": index,
                    "condition": render_expr(step.condition),
                    "runs": step.runs,
                }
                for index, step in enumerate(steps, start=1)
            ]
            body["ordered"] = True
            body["by"] = [ref.full for ref in getattr(node, "by", ())]
            maxspan = getattr(node, "maxspan", None)
            body["maxspan"] = span_text(maxspan) if maxspan is not None else ""
            until = getattr(node, "until", None)
            if until is not None:
                body["until"] = render_expr(until)
        return body

    return {
        "rule_id": rule.rule_id,
        "dialect": rule.metadata.get("dialect", ""),
        "language": rule.metadata.get("language", ""),
        "annotations": {
            "title": rule.annotations.title,
            "description": rule.annotations.description,
            "severity": rule.annotations.severity,
            "author": rule.annotations.author,
            "mitre_attack": [
                {"tactic": tactic, "techniques": list(techniques)}
                for tactic, techniques in rule.annotations.mitre_attack
            ],
            "references": list(rule.annotations.references),
            "false_positives": list(rule.annotations.false_positives),
        },
        "bindings": [
            {"name": b.name, "stages": [stage(n) for n in b.pipeline],
             "guard": render_expr(b.guard) if b.guard is not None else None}
            for b in rule.bindings
        ],
        "pipeline": [stage(n) for n in rule.pipeline],
    }
