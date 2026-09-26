"""The four jobs.

  author     paste a native rule, understand it, edit it, render it back
  tune       structural review always; behavioural review when events are supplied
  debug      rule -> the query that finds the triggering events
             log  -> a candidate rule, and what it cannot know
  understand explain the rule, its graph, its cost, and its refusals

THE RULE THAT SHAPES ALL FOUR: NEVER CLAIM WHAT WAS NOT CHECKED.

A detection rule is a security control. A tool that tells you a rule is fine when
it has not checked is worse than one that says nothing, because you will believe
it. So every function here returns findings that are either verified against
something, or explicitly marked as unverified with the reason.

Concretely, that means:

  * Structural findings are always available -- they need only the rule text.
  * Behavioural findings need EVENTS, and without them this module says so
    instead of estimating. No "this will match ~3% of events" from a static read.
  * A `debug log -> rule` result is a CANDIDATE, because a single sample cannot
    establish intent. It states what the sample supports and what it cannot.
  * Nothing here reports a match count that was not counted.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .dialects import (
    AQL_DIALECT,
    KQL_DIALECT,
    SPL_DIALECT,
    TARGETS,
    WAZUH_DIALECT,
    YARAL_DIALECT,
    lower_aql,
    lower_kql,
    lower_spl,
    lower_wazuh,
    lower_yaral,
    parse_aql,
    parse_kql,
    parse_yaral,
    render_aql,
    render_kql,
    render_spl,
    render_wazuh,
    render_yaral,
)
from .engine import evaluate
from .engine.values import Refusal

#: Dialect key -> everything needed for that dialect. ONE TABLE, so the web layer
#: cannot disagree with this module about which dialects exist or how to call them.
#: An earlier shape kept parse/lower/render in separate dicts, and adding a dialect
#: meant editing four places -- so a dialect could be parseable and unrenderable
#: with nothing complaining.
#:
#: `lower_text` EXISTS BECAUSE THE THREE GENERATIONS OF DIALECT DISAGREE ON HOW TO
#: BE CALLED. AQL and KQL take a PARSED object plus a rule id; YARA-L takes a
#: parsed object and no rule id; Wazuh and SPL take raw text. My first table
#: assumed one signature and every one of the five failed on first use. The
#: adapters are here, in one place, so the web layer never has to know.
def _lower_aql_text(text: str, rule_id: str, **_: Any):
    return lower_aql(parse_aql(text), rule_id)


def _lower_yaral_text(text: str, rule_id: str, **_: Any):
    return lower_yaral(parse_yaral(text))


def _lower_kql_text(text: str, rule_id: str, **_: Any):
    return lower_kql(parse_kql(text), rule_id)


def _lower_wazuh_text(text: str, rule_id: str, **options: Any):
    return lower_wazuh(text, rule_id, **options)


def _lower_spl_text(text: str, rule_id: str, **options: Any):
    return lower_spl(text, rule_id, **options)


#: Re-exported so the web layer reads one module. `TARGETS` lists every syntax
#: this project must eventually handle; `DIALECTS` is the subset that works
#: today. The home page shows the difference rather than claiming parity.
TARGETS = TARGETS

DIALECTS: dict[str, dict[str, Any]] = {
    "qradar": {
        "label": "QRadar AQL", "dialect": AQL_DIALECT,
        "lower_text": _lower_aql_text, "render": render_aql,
    },
    "yaral": {
        "label": "YARA-L 2.0", "dialect": YARAL_DIALECT,
        "lower_text": _lower_yaral_text, "render": render_yaral,
    },
    "sentinel": {
        "label": "Sentinel KQL", "dialect": KQL_DIALECT,
        "lower_text": _lower_kql_text, "render": render_kql,
    },
    "wazuh": {
        "label": "Wazuh Ruleset XML", "dialect": WAZUH_DIALECT,
        "lower_text": _lower_wazuh_text, "render": render_wazuh,
    },
    "splunk": {
        "label": "Splunk SPL", "dialect": SPL_DIALECT,
        "lower_text": _lower_spl_text, "render": render_spl,
    },
}


@dataclass
class Finding:
    """One observation about a rule.

    `severity` is one of `problem`, `caution`, `note`. `verified` says whether
    this was CHECKED against something or merely read off the text, and
    `evidence` is what it was checked against. A finding with no evidence is a
    reading of the rule, not a result, and the UI shows that difference.
    """
    code: str
    severity: str          # problem | caution | note
    message: str
    verified: bool = False
    evidence: str = ""


@dataclass
class Outcome:
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    rendered: str = ""
    graph: dict[str, Any] = field(default_factory=dict)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    refusal: dict[str, str] | None = None
    result: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "findings": [as_finding(f) for f in self.findings],
            "rendered": self.rendered,
            "graph": self.graph,
            "diagnostics": self.diagnostics,
            "refusal": self.refusal,
            "result": self.result,
        }


def as_finding(finding: Finding) -> dict[str, Any]:
    return {
        "code": finding.code,
        "severity": finding.severity,
        "message": finding.message,
        "verified": finding.verified,
        "evidence": finding.evidence,
    }


def diagnostic_fields(entry: Any) -> dict[str, Any]:
    """A diagnostic as a dict, whether the dialect returned a dataclass or one.

    FOUR OF THE FIVE DIALECTS DISAGREE HERE TOO. AQL, KQL and YARA-L return a
    `Diagnostic` dataclass; Wazuh and SPL return a plain dict. Reading
    `entry.get("code")` therefore raised AttributeError on three dialects and
    worked on two, and the first author request against a QRadar rule died on it.
    One normaliser, here, so the web layer sees one shape.
    """
    if isinstance(entry, dict):
        return dict(entry)
    return {
        "code": getattr(entry, "code", "DIAGNOSTIC"),
        "severity": getattr(entry, "severity", "note"),
        "message": getattr(entry, "message", str(entry)),
    }


def dialect_choices() -> list[dict[str, str]]:
    """What the UI offers. Derived from DIALECTS, never a second list."""
    return [{"key": key, "label": spec["label"]}
            for key, spec in DIALECTS.items()]


def lower_for(dialect: str, text: str, rule_id: str = "rule",
              **options: Any):
    spec = DIALECTS.get(dialect)
    if spec is None:
        raise Refusal("DIALECT_UNKNOWN",
                      f"{dialect!r} is not a dialect this tool handles. "
                      f"Known: {', '.join(sorted(DIALECTS))}.", "ruleforge")
    return spec["lower_text"](text, rule_id, **options)


def render_for(dialect: str, ir) -> str:
    spec = DIALECTS.get(dialect)
    if spec is None:
        raise Refusal("DIALECT_UNKNOWN", f"{dialect!r} is unknown", "ruleforge")
    return spec["render"](ir)


# ---------------------------------------------------------------------------
# author
# ---------------------------------------------------------------------------


def author(dialect: str, text: str, rule_id: str = "rule",
           **options: Any) -> Outcome:
    """Paste a rule, get it back understood, editable and re-rendered."""
    try:
        ir, diagnostics = lower_for(dialect, text, rule_id, **options)
    except Refusal as refusal:
        # `getattr` because a Refusal is not guaranteed to carry every field. A
        # refusal with no `stage` used to raise AttributeError INSIDE the except
        # block, which replaced a clear "your rule could not be read" with a
        # traceback -- the least informative possible outcome for the user.
        return Outcome(ok=False, refusal={
            "code": refusal.code,
            "message": refusal.message,
            "stage": getattr(refusal, "stage", "") or "",
        })

    findings: list[Finding] = []
    diagnostics = [diagnostic_fields(d) for d in diagnostics]
    for entry in diagnostics:
        findings.append(Finding(
            code=entry.get("code", "DIAGNOSTIC"),
            severity=entry.get("severity", "note"),
            message=entry.get("message", ""),
            verified=True,
            evidence="the rule as written",
        ))

    try:
        rendered = render_for(dialect, ir)
    except Refusal as refusal:
        findings.append(Finding(
            code=refusal.code, severity="caution",
            message=f"understood, but not written back: {refusal.message}",
            verified=True, evidence="the lowered graph"))
        rendered = ""

    return Outcome(ok=True, findings=findings, rendered=rendered,
                   graph=describe(ir), diagnostics=diagnostics)


# ---------------------------------------------------------------------------
# understand
# ---------------------------------------------------------------------------


def understand(ir) -> Outcome:
    """Explain the graph, its cost, and every refusal baked into it."""
    findings: list[Finding] = []
    graph = describe(ir)

    for node in ir.nodes:
        kind = type(node).__name__
        node_findings = _explain_node(node, kind)
        findings.extend(node_findings)

    return Outcome(ok=True, findings=findings, graph=graph)


def _explain_node(node: Any, kind: str) -> list[Finding]:
    out: list[Finding] = []
    if kind == "Filter":
        out.append(Finding(
            "FILTER_SELECTS", "note",
            f"`{node.id}` keeps a row only if its condition is decided true. A "
            f"row it cannot decide is DROPPED, not matched -- and counted, so you "
            f"can see how many.", verified=True, evidence="the node's condition"))
    if kind == "Package":
        subject = "the parent rule" if node.count_subject == "parent" \
            else "the child rule"
        out.append(Finding(
            "CORRELATION_COUNTS", "caution",
            f"`{node.id}` fires when {subject} occurs {node.frequency} times "
            f"within {int(node.timeframe.seconds)}s, grouped on "
            f"{', '.join(f.full for f in node.same_fields)}. The count is over a "
            f"sliding window, and the parent is itself a complete rule that fires "
            f"on its own.", verified=True, evidence="the Package node"))
    if kind == "Join":
        out.append(Finding(
            "JOIN_PREFIXES", "note",
            f"`{node.id}` merges two streams. Columns are stored as "
            f"`{node.left_prefix}name` and `{node.right_prefix}name` so one side "
            f"cannot silently overwrite the other."
            + (f" It renamed {len(node.column_map)} columns."
               if node.column_map else ""),
            verified=True, evidence="the Join node"))
    return out


def describe(ir) -> dict[str, Any]:
    """The graph, for display. Field names verbatim -- never normalised."""
    return {
        "rule_id": ir.rule_id,
        "title": ir.title,
        "metadata": dict(ir.metadata),
        "output": ir.output,
        "nodes": [_describe_node(n) for n in ir.nodes],
    }


def _describe_node(node: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"id": node.id, "kind": type(node).__name__}
    for attribute in ("input", "left", "right", "how", "limit", "frequency",
                      "same_fields", "time_field", "count_subject", "column_map"):
        if hasattr(node, attribute):
            value = getattr(node, attribute)
            if attribute in ("same_fields", "column_map"):
                value = [list(v) if isinstance(v, tuple) else v for v in value]
            elif attribute == "timeframe" and value is not None:
                value = int(value.seconds)
            out[attribute] = value
    if hasattr(node, "measures"):
        out["measures"] = [{"name": m.name, "function": m.function,
                            "field": m.field.full if m.field else None}
                           for m in node.measures]
    if hasattr(node, "keys"):
        out["keys"] = [k.full for k in node.keys]
    if hasattr(node, "condition"):
        out["condition"] = repr(node.condition)
    if hasattr(node, "frame"):
        out["frame"] = {"kind": node.frame.kind,
                        "size": int(node.frame.size.seconds)
                        if node.frame.size else None,
                        "time_field": node.frame.time_ref.field_name
                        if node.frame.time_ref else None}
    return out


# ---------------------------------------------------------------------------
# tune
# ---------------------------------------------------------------------------


def tune(ir, events: list[dict[str, Any]] | None = None) -> Outcome:
    """Structural review always. Behavioural review ONLY with events.

    WITHOUT EVENTS THIS SAYS SO. It does not estimate a match rate, a volume, or
    a false-positive expectation from reading the text. A number invented from a
    static read is a number an analyst will quote in a ticket.
    """
    findings: list[Finding] = []
    result: dict[str, Any] | None = None

    if events:
        findings.extend(_behavioural(ir, events))
        result = _verdict_summary(evaluate(ir, events))
    else:
        findings.append(Finding(
            "TUNE_NO_EVENTS", "caution",
            "Only the STRUCTURE of this rule has been reviewed. Nothing here "
            "knows whether it matches the right number of events, because no "
            "events were supplied. Paste a sample -- even twenty rows -- to get "
            "the behavioural half.", verified=True,
            evidence="no events supplied"))

    findings.extend(_structural(ir))
    return Outcome(ok=True, findings=findings, graph=describe(ir), result=result)


def _structural(ir) -> list[Finding]:
    """Findings readable from the rule text alone. Always available."""
    findings: list[Finding] = []
    kinds = [type(n).__name__ for n in ir.nodes]

    if "Join" in kinds:
        findings.append(Finding(
            "TUNE_JOIN_CARDINALITY", "caution",
            "This rule joins two streams. A join is the usual reason a rule "
            "matches far more rows than expected, because one side can match "
            "many rows of the other. Check the row count before and after the "
            "join.", verified=True, evidence="a Join node is present"))

    if kinds.count("Aggregate") > 1:
        findings.append(Finding(
            "TUNE_REPEATED_AGGREGATION", "caution",
            f"This rule aggregates {kinds.count('Aggregate')} times. Each one "
            f"reduces the row count, and a group-by on a high-cardinality field "
            f"can produce more groups than you expect.", verified=True,
            evidence=f"{kinds.count('Aggregate')} Aggregate nodes"))

    for node in ir.nodes:
        if type(node).__name__ == "Aggregate" and not node.keys:
            findings.append(Finding(
                "TUNE_AGGREGATE_WITHOUT_GROUPING", "problem",
                f"`{node.id}` aggregates with no `by`, so it collapses every row "
                f"into ONE row. If the intent was per-host or per-user counts, "
                f"the grouping is missing -- and the rule will report a single "
                f"total that matches nothing you can act on.", verified=True,
                evidence="an Aggregate node with no keys"))
        if type(node).__name__ == "Pattern" and not node.time_field:
            findings.append(Finding(
                "TUNE_PATTERN_NO_TIME", "problem",
                f"`{node.id}` orders events by no declared time field, so the "
                f"sequence has no defined order.", verified=True,
                evidence="a Pattern node with no time_field"))

    return findings


def _behavioural(ir, events: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    verdict = evaluate(ir, events)
    total = len(events)

    for caveat in verdict.caveats:
        findings.append(Finding(
            caveat.code,
            "problem" if caveat.count else "note",
            caveat.detail + (f" ({caveat.count} rows)" if caveat.count else ""),
            verified=True, evidence=f"evaluated against {total} supplied events"))

    if verdict.verdict.value == "not_evaluated":
        findings.append(Finding(
            "TUNE_ALL_UNDECIDABLE", "problem",
            "Nothing could be decided. Usually the events are missing the fields "
            "the rule tests, so check the field names in the events against the "
            "rule.", verified=True, evidence=f"{total} events, 0 decided"))
    elif verdict.verdict.value == "matched":
        findings.append(Finding(
            "TUNE_MATCHED", "note",
            f"The rule matched {len(verdict.rows)} of {total} events. That is "
            f"this SAMPLE, not your production volume -- the sample is whatever "
            f"you pasted, and a sample chosen to show the rule working is not a "
            f"random draw.", verified=True,
            evidence=f"{total} events, {len(verdict.rows)} matched"))
    else:
        findings.append(Finding(
            "TUNE_NO_MATCH", "caution",
            f"The rule matched NONE of the {total} events. Either the rule does "
            f"not fire on this data, or the events do not contain the fields it "
            f"tests. Those are very different problems and the sample alone "
            f"cannot tell them apart.", verified=True,
            evidence=f"{total} events, 0 matched"))

    return findings


def _verdict_summary(result) -> dict[str, Any]:
    return {
        "verdict": result.verdict.value,
        "reason": result.reason.code if result.reason else None,
        "reason_detail": result.reason.detail if result.reason else "",
        "rows": len(result.rows),
        "caveats": [{"code": c.code, "detail": c.detail, "count": c.count}
                    for c in result.caveats],
        "trace": [{"node": t.node_id, "in": t.rows_in, "out": t.rows_out}
                  for t in result.trace],
    }


# ---------------------------------------------------------------------------
# debug
# ---------------------------------------------------------------------------


def debug_rule_to_logs(dialect: str, text: str, rule_id: str = "rule",
                       **options: Any) -> Outcome:
    """The search that returns the events the rule WOULD fire on.

    THIS IS NOT A VERIFICATION. Running it against your SIEM is how you verify;
    this tool has no connection to one and does not pretend otherwise. What it
    gives you is the query, and the honest note that the query and the rule are
    not the same thing -- a rule can be right and the query wrong.
    """
    outcome = author(dialect, text, rule_id, **options)
    if not outcome.ok:
        return outcome

    findings = list(outcome.findings)
    findings.append(Finding(
        "DEBUG_QUERY_NOT_VERIFIED", "caution",
        "This is the query to run against YOUR SIEM. Nothing here has run it: "
        "RuleForge has no connection to your data. If the query and the rule "
        "disagree, the rule decides -- the query is a probe, not the control.",
        verified=True, evidence="no SIEM connection exists"))

    if dialect == "wazuh":
        findings.append(Finding(
            "DEBUG_WAZUH_NOT_A_QUERY", "problem",
            "A Wazuh rule is not a query. It is XML evaluated by the agent "
            "against decoded events, and its meaning depends on the whole "
            "`if_sid` chain and on fields only the agent produces. There is no "
            "search you can paste into Kibana that reproduces it. Read the "
            "rule's conditions and search for the events they describe.",
            verified=True, evidence="Wazuh has no search syntax"))

    return Outcome(ok=True, findings=findings, rendered=outcome.rendered,
                   graph=outcome.graph, diagnostics=outcome.diagnostics)


def debug_logs_to_rule(dialect: str, events: list[dict[str, Any]],
                       fields: list[str] | None = None) -> Outcome:
    """Induce a CANDIDATE rule from events. It is a candidate, and says so.

    A SAMPLE CANNOT ESTABLISH INTENT. Ten rows of failed logons and ten rows of
    successful ones are the same shape; the difference is what you were watching
    for. So this reports the FIELD VALUES that separate the rows from each other
    and states plainly that it does not know which separation you meant.
    """
    findings: list[Finding] = []
    if not events:
        return Outcome(ok=False, findings=[Finding(
            "DEBUG_NO_EVENTS", "problem",
            "No events supplied, so there is nothing to induce a rule from.",
            verified=True, evidence="empty input")])

    keys = fields or sorted({k for row in events for k in row})
    summary = []
    for key in keys:
        values = [row.get(key) for row in events]
        present = [v for v in values if v not in (None, "")]
        distinct = sorted({str(v) for v in present})
        summary.append({
            "field": key,
            "present": len(present),
            "absent": len(values) - len(present),
            "distinct": len(distinct),
            "values": distinct[:12],
            "constant": len(distinct) == 1 and len(values) > 0,
        })

    # A field that is the same on every row cannot be what the sample is
    # "about", and saying so is more useful than listing it as a candidate.
    for entry in summary:
        if entry["constant"] and entry["distinct"] == 1:
            findings.append(Finding(
                "DEBUG_CONSTANT_FIELD", "note",
                f"`{entry['field']}` is {entry['values'][0]!r} on every event, so "
                f"it does not distinguish them. It may still belong in the rule "
                f"as context.", verified=True, evidence="all supplied events"))

    varied = [e for e in summary if e["distinct"] > 1]
    for entry in varied:
        findings.append(Finding(
            "DEBUG_VARYING_FIELD", "note",
            f"`{entry['field']}` takes {entry['distinct']} distinct values: "
            f"{', '.join(entry['values'][:5])}"
            f"{' ...' if entry['distinct'] > 5 else ''}. A rule could select on "
            f"any subset of these.", verified=True,
            evidence="all supplied events"))

    findings.append(Finding(
        "DEBUG_CANDIDATE_ONLY", "problem",
        "This is a CANDIDATE, not a rule. A sample cannot tell you WHICH of "
        "these differences you were looking for -- only which ones exist. "
        "Choosing among them is your judgement, and a tool that picked for you "
        "would be guessing at your intent.", verified=True,
        evidence="no intent available to this tool"))

    return Outcome(ok=True, findings=findings, result={"fields": summary})


def load_events(raw: str) -> list[dict[str, Any]]:
    """Parse pasted events. JSON array, or one JSON object per line.

    A PARSE ERROR NAMES THE LINE. "invalid JSON" tells the analyst nothing about
    which of four hundred pasted lines is wrong.
    """
    text = (raw or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        rows: list[dict[str, Any]] = []
        for number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                raise Refusal(
                    "EVENTS_BAD_LINE",
                    f"line {number} is not valid JSON: {exc.msg}. Pasting one "
                    f"JSON object per line works, as does a single JSON array.",
                    "ruleforge") from exc
            if not isinstance(parsed, dict):
                raise Refusal("EVENTS_NOT_AN_OBJECT",
                              f"line {number} is a {type(parsed).__name__}, not "
                              f"an object. Each line must be one event.",
                              "ruleforge")
            rows.append(parsed)
        return rows

    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        for index, row in enumerate(data):
            if not isinstance(row, dict):
                raise Refusal("EVENTS_NOT_AN_OBJECT",
                              f"entry {index} is a {type(row).__name__}, not an "
                              f"object", "ruleforge")
        return data
    raise Refusal("EVENTS_NOT_EVENTS",
                  f"expected a JSON array or object, got {type(data).__name__}",
                  "ruleforge")
