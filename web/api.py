"""The local HTTP API.

This is the seam between the engine and the browser. Everything the GUI can do
goes through here, and nothing here knows a vendor's syntax -- it asks the
dialect registry by key, exactly as the engine's layering requires.

Built on `http.server` rather than Flask or FastAPI, because the package has
zero third-party dependencies and that is a deliberate property: a detection
engineer can run this inside a locked-down SOC where `pip install` is not
available. `ThreadingHTTPServer` is more than enough for one analyst on
localhost, and the alternative would mean the tool cannot be used where it is
most needed.

Bound to 127.0.0.1 by default. This serves an endpoint that parses untrusted
rule text and evaluates rules against untrusted samples; it is a local
workbench, not a service, and binding it to a routable interface would make it
one. Doing that takes an explicit `--host`.

Every failure is a REFUSAL with a code and a reason, returned as JSON with
status 400. That is the same contract the engine uses internally, which is why
`Refusal.as_dict()` and `Diagnostic.as_dict()` already existed before anything
served them. Unexpected exceptions return a generic 500 and are logged to
stderr -- a traceback in a response body tells an attacker about the host and
tells the analyst nothing they can act on.
"""

from __future__ import annotations

import json
import mimetypes
import sys
import traceback
from decimal import Decimal
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Final
from urllib.parse import parse_qs, unquote, urlparse

from engine import dialects, synthesize
from engine.codec import rule_from_dict, rule_to_dict
from engine.evaluate import Budget, Caveat, EvaluationResult, Trace
from engine.ir import Rule, render_expr
from engine.pipeline import evaluate
from engine.store import ORIGINS, RuleStore
from engine.validate import validate
from engine.values import ABSENT, UNDECIDED, Capability, Duration, Refusal, Seq

__all__ = ["Api", "RuleForgeHandler", "build_server", "serve", "MAX_BODY_BYTES"]

#: Request body ceiling. Log samples are genuinely large -- a few thousand
#: events pasted in is normal -- but an unbounded read is a way to exhaust
#: memory with one request.
MAX_BODY_BYTES: Final = 16 * 1024 * 1024

#: Evaluation sample ceiling. Past this the browser cannot render the result
#: and the analyst is better served by a narrower sample.
MAX_EVENTS: Final = 20_000

#: Refusal codes that are about the request's SIZE rather than its content.
#:
#: They get HTTP 413 so a client can tell "too big" from "malformed" without
#: parsing the message, and the body is drained before answering -- see
#: `_refuse`.
_TOO_LARGE_CODES: Final[frozenset[str]] = frozenset({
    "REQUEST_TOO_LARGE",
    "REQUEST_TOO_MANY_EVENTS",
})

#: How much of an over-sized body to read before answering it.
#:
#: Set to the accept ceiling itself. A 2 MB cap was not enough: a 17 MB paste
#: still had 15 MB left to write when the server answered, so the connection
#: reset and the client saw nothing -- the same failure the drain exists to
#: prevent, moved further along.
#:
#: Reading this much to refuse it is not a new exposure, because a request
#: that stayed just inside the limit would have been read and parsed anyway.
#: A body far beyond it is still cut off, and a client sending one is not
#: owed a courteous explanation.
_DRAIN_LIMIT: Final = MAX_BODY_BYTES

_WEB_ROOT: Final = Path(__file__).resolve().parent
_STATIC_ROOT: Final = _WEB_ROOT / "static"
_TEMPLATE_ROOT: Final = _WEB_ROOT / "templates"


# ---------------------------------------------------------------------------
# Display encoding
# ---------------------------------------------------------------------------
#
# NOT the codec. `codec.py` is lossless and round-trip-exact, for rules that
# have to come back identical. This is one-way, for things the browser only
# displays: evaluation rows, traces, caveats.
#
# The special values still get tags, because the whole point of this engine is
# that ABSENT, null and UNDECIDED are three different answers. Rendering all
# three as an empty cell would throw away the distinction the evaluator works
# hardest to preserve.


def _display(value: Any) -> Any:
    if value is ABSENT:
        return {"$": "absent"}
    if value is UNDECIDED:
        return {"$": "undecided"}
    if value is None:
        return None
    if isinstance(value, Capability):
        return value.value
    if isinstance(value, bool):
        return value
    if isinstance(value, Decimal):
        # A string, not a float. A count of 5 arrives as "5", which the browser
        # renders identically and which cannot quietly become 4.999999.
        return str(value)
    if isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, Duration):
        return {"$": "duration", "seconds": str(value.seconds)}
    if isinstance(value, Seq):
        return {
            "$": "seq",
            "distinct": value.distinct,
            "items": [_display(i) for i in value.items],
        }
    if isinstance(value, (list, tuple)):
        return [_display(i) for i in value]
    if isinstance(value, dict):
        return {str(k): _display(v) for k, v in value.items()}
    return str(value)


def _caveat_dict(caveat: Caveat) -> dict[str, Any]:
    return {
        "code": caveat.code,
        "message": caveat.message,
        "severity": caveat.severity,
        "where": caveat.where,
        "capability": caveat.capability.value if caveat.capability else None,
    }


def _trace_dict(trace: Trace) -> dict[str, Any]:
    return {
        "stage": trace.stage,
        "kind": trace.kind,
        "rows_in": trace.rows_in,
        "rows_out": trace.rows_out,
        "dropped": trace.dropped,
        "undecided": trace.undecided,
        "detail": trace.detail,
    }


def _result_dict(result: EvaluationResult) -> dict[str, Any]:
    return {
        "verdict": result.verdict,
        "matched": result.matched,
        "undecided": result.undecided,
        "rows": [_display(row.values) for row in result.rows],
        "trace": [_trace_dict(t) for t in result.trace],
        "caveats": [_caveat_dict(c) for c in result.caveats],
        "refusal": (
            {
                "code": result.refusal.code,
                "message": result.refusal.message,
                "where": result.refusal.where,
            }
            if result.refusal is not None
            else None
        ),
    }


def _span(duration: Any) -> str:
    """A Duration as the span an analyst would write.

    `str(Duration)` is a debugging repr, and `Duration(300s)` leaking into the
    outline pane reads as a bug rather than as five minutes.
    """
    seconds = int(duration.seconds)
    for suffix, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size and seconds % size == 0:
            return f"{seconds // size}{suffix}"
    return f"{seconds}s"


def _outline(rule: Rule) -> dict[str, Any]:
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
            body["maxspan"] = _span(maxspan) if maxspan is not None else ""
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


# ---------------------------------------------------------------------------
# The API
# ---------------------------------------------------------------------------


class Api:
    """The request handlers, with no HTTP in them.

    Separated from the handler class so every endpoint is callable from a test
    without opening a socket. `tests/test_api.py` drives this directly.
    """

    def __init__(self, store: RuleStore | None = None) -> None:
        self.store = store if store is not None else RuleStore()

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _require(body: dict[str, Any], key: str) -> Any:
        if key not in body:
            raise Refusal(
                "REQUEST_FIELD_MISSING",
                f"this request needs `{key}`.",
                "api",
            )
        return body[key]

    @staticmethod
    def _text(body: dict[str, Any], key: str) -> str:
        value = Api._require(body, key)
        if not isinstance(value, str):
            raise Refusal(
                "REQUEST_FIELD_TYPE",
                f"`{key}` must be text, not {type(value).__name__}.",
                "api",
            )
        return value

    @staticmethod
    def _rule(body: dict[str, Any]) -> Rule:
        payload = Api._require(body, "rule")
        if not isinstance(payload, dict):
            raise Refusal(
                "REQUEST_FIELD_TYPE",
                "`rule` must be an encoded rule object.",
                "api",
            )
        return rule_from_dict(payload)

    # -- dialects ---------------------------------------------------------

    def dialects(self) -> dict[str, Any]:
        """Every dialect, ready or planned.

        Planned ones are included on purpose: a greyed-out entry with a reason
        is navigable, and a missing entry looks like a bug.
        """
        return {"dialects": dialects.catalogue()}

    # -- pillar 2: paste a rule, read it, tune it -------------------------

    def lower(self, body: dict[str, Any]) -> dict[str, Any]:
        """Native rule text to the IR, plus what could not be represented.

        The import half of paste-and-tune. The analyst gets back a structured
        rule the builder can edit, an outline that says what the rule means,
        and the diagnostics explaining anything that did not survive.
        """
        key = self._text(body, "dialect")
        text = self._text(body, "text")
        rule_id = body.get("rule_id") or "rule"
        if not isinstance(rule_id, str):
            raise Refusal("REQUEST_FIELD_TYPE", "`rule_id` must be text.", "api")
        if not text.strip():
            raise Refusal(
                "REQUEST_EMPTY",
                "there is no rule text to read. Paste a rule first.",
                "api",
            )
        rule, diagnostics = dialects.lower(key, text, rule_id)
        return {
            "rule": rule_to_dict(rule),
            "outline": _outline(rule),
            "diagnostics": [d.as_dict() for d in diagnostics],
        }

    def render(self, body: dict[str, Any]) -> dict[str, Any]:
        """The IR back out as native text in any ready dialect.

        The same call serves authoring (pillar 1) and cross-SIEM translation:
        a rule lowered from one dialect can be rendered into another, and the
        refusals are where the two vendors genuinely disagree.

        `diagnostics` carries what the text does not say -- chiefly a source
        selector that could not cross dialects. It is returned on the same
        footing as `/lower`'s so the GUI cannot show translated text while
        omitting the reason it is broader than the original.
        """
        key = self._text(body, "dialect")
        rule = self._rule(body)
        text, diagnostics = dialects.render(key, rule)
        return {
            "dialect": key,
            "text": text,
            "diagnostics": [d.as_dict() for d in diagnostics],
        }

    def validate(self, body: dict[str, Any]) -> dict[str, Any]:
        """Lint a rule, including the deploy-path ReDoS screen."""
        rule = self._rule(body)
        validate(rule)
        return {"ok": True, "outline": _outline(rule)}

    def outline(self, body: dict[str, Any]) -> dict[str, Any]:
        return {"outline": _outline(self._rule(body))}

    # -- the tuning loop --------------------------------------------------

    def evaluate(self, body: dict[str, Any]) -> dict[str, Any]:
        """Run a rule against a sample and say why it did or did not match.

        This is the debugging half of tuning. The result carries a per-stage
        row ledger and per-predicate reasons, and a three-way verdict: a rule
        that could not be decided reports `not_evaluated` rather than claiming
        `no_match`, because a confident no on evidence the engine never had is
        the one answer a detection engineer must never be given.
        """
        rule = self._rule(body)
        events = self._events(body)
        if len(events) > MAX_EVENTS:
            raise Refusal(
                "REQUEST_TOO_MANY_EVENTS",
                f"{len(events):,} events is more than this workbench evaluates "
                f"in one pass (the ceiling is {MAX_EVENTS:,}). Narrow the "
                f"sample -- a rule that needs every event to be understood is "
                f"not being debugged, it is being hoped about.",
                "api",
            )
        result = evaluate(rule, events, budget=Budget())
        return _result_dict(result)

    # -- evidence: datasets and replay runs -------------------------------

    def datasets(self, params: dict[str, list[str]]) -> dict[str, Any]:
        def one(name: str, default: str = "") -> str:
            values = params.get(name) or []
            return values[0] if values else default

        try:
            limit = int(one("limit", "50"))
            offset = int(one("offset", "0"))
        except ValueError as exc:
            raise Refusal(
                "REQUEST_FIELD_TYPE", "`limit` and `offset` must be numbers.", "api"
            ) from exc
        found = self.store.datasets(
            limit=limit,
            offset=offset,
            query=one("q"),
            format=one("format"),
        )
        return {
            "datasets": [dataset.as_dict() for dataset in found],
            "total": self.store.dataset_count(),
        }

    def dataset(self, dataset_id: int) -> dict[str, Any]:
        dataset = self.store.dataset(dataset_id)
        body = dataset.as_dict(include_events=True)
        body["events"] = [_display(event) for event in dataset.events()]
        return body

    def dataset_save(self, body: dict[str, Any]) -> dict[str, Any]:
        name = self._text(body, "name")
        text = self._text(body, "text")
        raw_format = body.get("format", "jsonl")
        if not isinstance(raw_format, str):
            raise Refusal("REQUEST_FIELD_TYPE", "`format` must be text.", "api")
        events = list(synthesize.parse_events(text, raw_format.strip().lower()))
        if len(events) > MAX_EVENTS:
            raise Refusal(
                "REQUEST_TOO_MANY_EVENTS",
                f"{len(events):,} events is more than this workbench stores in "
                f"one dataset (the ceiling is {MAX_EVENTS:,}). Narrow the sample.",
                "api",
            )
        labels = body.get("labels", [])
        if isinstance(labels, str):
            labels = [labels]
        if not isinstance(labels, list) or not all(
            isinstance(label, str) for label in labels
        ):
            raise Refusal(
                "REQUEST_FIELD_TYPE", "`labels` must be a list of text values.", "api"
            )
        table = body.get("table", "events")
        if not isinstance(table, str):
            raise Refusal("REQUEST_FIELD_TYPE", "`table` must be text.", "api")
        description = body.get("description", "")
        if not isinstance(description, str):
            raise Refusal(
                "REQUEST_FIELD_TYPE", "`description` must be text.", "api"
            )
        source_type = body.get("source_type", "imported")
        if not isinstance(source_type, str):
            raise Refusal(
                "REQUEST_FIELD_TYPE", "`source_type` must be text.", "api"
            )
        dataset = self.store.save_dataset(
            name=name,
            raw_text=text,
            format=raw_format,
            events=events,
            table_name=table,
            description=description,
            source_type=source_type,
            labels=tuple(labels),
        )
        body = dataset.as_dict(include_events=True)
        body["events"] = [_display(event) for event in dataset.events()]
        return body

    def test_runs(self, params: dict[str, list[str]]) -> dict[str, Any]:
        def one(name: str, default: str = "") -> str:
            values = params.get(name) or []
            return values[0] if values else default

        try:
            limit = int(one("limit", "50"))
            offset = int(one("offset", "0"))
            dataset_id = one("dataset_id")
            parsed_dataset_id = int(dataset_id) if dataset_id else None
        except ValueError as exc:
            raise Refusal(
                "REQUEST_FIELD_TYPE",
                "`limit`, `offset`, and `dataset_id` must be numbers.",
                "api",
            ) from exc
        found = self.store.test_runs(
            limit=limit,
            offset=offset,
            rule_hash=one("rule_hash"),
            dataset_id=parsed_dataset_id,
        )
        return {
            "test_runs": [run.as_dict() for run in found],
            "total": self.store.test_run_count(),
        }

    def test_run(self, run_id: int) -> dict[str, Any]:
        run = self.store.test_run(run_id)
        body = run.as_dict(include_result=True)
        body["dataset"] = self.store.dataset(run.dataset_id).as_dict()
        return body

    def test_run_save(self, body: dict[str, Any]) -> dict[str, Any]:
        rule = self._rule(body)
        raw_dataset_id = self._require(body, "dataset_id")
        if isinstance(raw_dataset_id, bool) or not isinstance(raw_dataset_id, int):
            raise Refusal(
                "REQUEST_FIELD_TYPE", "`dataset_id` must be a number.", "api"
            )
        dataset = self.store.dataset(raw_dataset_id)
        result = evaluate(rule, dataset.events(), budget=Budget())
        result_body = _result_dict(result)
        expected = body.get("expected_verdict", "")
        if not isinstance(expected, str):
            raise Refusal(
                "REQUEST_FIELD_TYPE", "`expected_verdict` must be text.", "api"
            )
        purpose = body.get("purpose", "manual")
        note = body.get("note", "")
        if not isinstance(purpose, str) or not isinstance(note, str):
            raise Refusal(
                "REQUEST_FIELD_TYPE", "`purpose` and `note` must be text.", "api"
            )
        entry_id = body.get("rule_entry_id")
        if entry_id is not None and (
            isinstance(entry_id, bool) or not isinstance(entry_id, int)
        ):
            raise Refusal(
                "REQUEST_FIELD_TYPE", "`rule_entry_id` must be a number.", "api"
            )
        run = self.store.save_test_run(
            rule=rule,
            result=result_body,
            dataset_id=dataset.id,
            expected_verdict=expected,
            purpose=purpose,
            note=note,
            rule_entry_id=entry_id,
        )
        body = run.as_dict(include_result=True)
        body["dataset"] = dataset.as_dict()
        return body

    def _events(self, body: dict[str, Any]) -> list[Any]:
        """The sample, either already parsed or as raw text to parse here.

        `text` + `format` exists so the BROWSER never parses log samples. It
        used to: `app.js` carried its own `parseLogs` and `coerce`, which
        disagreed with `synthesize.parse_events` -- JavaScript left `1.5` a
        string and `-` a string where Python produced `Decimal("1.5")` and
        `None`. The same pasted line therefore meant different things in the
        Run tab and the From Log tab, and only one of the two parsers was
        reachable by a test.

        It also means the Run tab reads `kv` and `syslog`, which the
        browser-side parser never supported.
        """
        if "text" in body and "events" not in body:
            text = self._text(body, "text")
            fmt = body.get("format") or "jsonl"
            if not isinstance(fmt, str):
                raise Refusal(
                    "REQUEST_FIELD_TYPE", "`format` must be text.", "api"
                )
            return list(synthesize.parse_events(text, fmt.strip().lower()))

        events = body.get("events", [])
        if not isinstance(events, list):
            raise Refusal(
                "REQUEST_FIELD_TYPE",
                "`events` must be a list of event objects, or send `text` and "
                "`format` and let the server parse the sample.",
                "api",
            )
        return events

    # -- pillar 4: history ------------------------------------------------

    def history(self, params: dict[str, list[str]]) -> dict[str, Any]:
        def one(name: str, default: str = "") -> str:
            values = params.get(name) or []
            return values[0] if values else default

        try:
            limit = int(one("limit", "50"))
            offset = int(one("offset", "0"))
        except ValueError as exc:
            raise Refusal(
                "REQUEST_FIELD_TYPE", "`limit` and `offset` must be numbers.", "api"
            ) from exc

        entries = self.store.history(
            limit=limit,
            offset=offset,
            dialect=one("dialect"),
            origin=one("origin"),
            query=one("q"),
        )
        return {
            "entries": [e.as_dict() for e in entries],
            "total": self.store.count(),
        }

    def history_entry(self, entry_id: int) -> dict[str, Any]:
        entry = self.store.entry(entry_id)
        rule = self.store.rule(entry_id)
        body = entry.as_dict(include_rule=True)
        body["outline"] = _outline(rule)
        return body

    def history_lineage(self, entry_id: int) -> dict[str, Any]:
        return {
            "lineage": [e.as_dict() for e in self.store.lineage(entry_id)]
        }

    def synthesize(self, body: dict[str, Any]) -> dict[str, Any]:
        """Log samples to a proposed rule, with the reasoning behind it.

        The third pillar. This lived entirely in the browser, which made it
        the one part of the tool the test suite could not reach -- and the
        decision it makes, which fields become the detection, is the decision
        that determines whether the result is a rule or a rule that matches
        everything.

        `fields` is returned alongside `rule` deliberately: a generated rule
        without the analysis that produced it is a rule the analyst has to
        reverse-engineer before they can trust it.
        """
        text = self._text(body, "text")
        fmt = (body.get("format") or "jsonl")
        if not isinstance(fmt, str):
            raise Refusal("REQUEST_FIELD_TYPE", "`format` must be text.", "api")

        options = self._synthesis_options(body)
        events = synthesize.parse_events(text, fmt.strip().lower())
        if len(events) > MAX_EVENTS:
            raise Refusal(
                "REQUEST_TOO_MANY_EVENTS",
                f"{len(events)} samples is beyond the {MAX_EVENTS} this "
                f"endpoint accepts. Field stability is settled long before "
                f"that many, so the extra samples only slow the answer down.",
                "api",
            )
        rule, reports, diagnostics = synthesize.propose(events, options)
        return {
            "rule": rule_to_dict(rule),
            "outline": _outline(rule),
            "fields": [r.as_dict() for r in reports],
            "samples": len(events),
            "diagnostics": [d.as_dict() for d in diagnostics],
        }

    def _synthesis_options(self, body: dict[str, Any]) -> synthesize.Options:
        """The request's options, with every type checked.

        A bad type is refused rather than coerced. A `frequency` of `"five"`
        silently becoming the default would hand back a threshold the analyst
        did not ask for and has no reason to doubt.
        """
        raw = body.get("options")
        if raw is None:
            raw = {}
        # Checked for being a MAPPING, not for truthiness. `options: []` is
        # falsy, so an `or {}` default silently accepted a list and ran with
        # every default -- handing back a rule built from settings the caller
        # never chose.
        if not isinstance(raw, dict):
            raise Refusal(
                "REQUEST_FIELD_TYPE", "`options` must be an object.", "api"
            )

        def flag(name: str, default: bool) -> bool:
            value = raw.get(name, default)
            if not isinstance(value, bool):
                raise Refusal(
                    "REQUEST_FIELD_TYPE",
                    f"`options.{name}` must be true or false.",
                    "api",
                )
            return value

        def whole(name: str, default: int) -> int:
            value = raw.get(name, default)
            if isinstance(value, bool) or not isinstance(value, int):
                raise Refusal(
                    "REQUEST_FIELD_TYPE",
                    f"`options.{name}` must be a whole number.",
                    "api",
                )
            return value

        table = raw.get("table", "events")
        if not isinstance(table, str):
            raise Refusal(
                "REQUEST_FIELD_TYPE", "`options.table` must be text.", "api"
            )

        group_by = raw.get("group_by", [])
        if isinstance(group_by, str):
            group_by = [group_by]
        if not isinstance(group_by, list) or not all(
            isinstance(g, str) for g in group_by
        ):
            raise Refusal(
                "REQUEST_FIELD_TYPE",
                "`options.group_by` must be a list of field names.",
                "api",
            )

        return synthesize.Options(
            table=table.strip() or "events",
            skip_volatile=flag("skip_volatile", True),
            skip_timestamps=flag("skip_timestamps", True),
            threshold=flag("threshold", False),
            group_by=tuple(g for g in group_by if g.strip()),
            frequency=whole("frequency", 5),
            window_seconds=whole("window_seconds", 300),
        )

    def history_save(self, body: dict[str, Any]) -> dict[str, Any]:
        rule = self._rule(body)
        origin = body.get("origin", "authored")
        if not isinstance(origin, str) or origin not in ORIGINS:
            raise Refusal(
                "STORE_ORIGIN_UNKNOWN",
                f"`{origin}` is not how a rule can come to exist. Use one of: "
                f"{', '.join(sorted(ORIGINS))}.",
                "api",
            )
        parent_id = body.get("parent_id")
        if parent_id is not None and not isinstance(parent_id, int):
            raise Refusal(
                "REQUEST_FIELD_TYPE", "`parent_id` must be a number.", "api"
            )
        entry = self.store.save(
            rule,
            origin=origin,
            source_text=str(body.get("source_text") or ""),
            note=str(body.get("note") or ""),
            parent_id=parent_id,
            title=body.get("title") if isinstance(body.get("title"), str) else None,
        )
        return entry.as_dict()

    def history_forget(self, entry_id: int) -> dict[str, Any]:
        self.store.forget(entry_id)
        return {"ok": True}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class RuleForgeHandler(BaseHTTPRequestHandler):
    """Routing and transport. No engine logic lives here."""

    server_version = "RuleForge"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    #: Seconds a single connection may sit idle mid-request.
    #:
    #: `BaseHTTPRequestHandler` applies no timeout unless this is set, and
    #: with HTTP/1.1 keep-alive plus a thread per connection that is a wedge:
    #: a client that declares `Content-Length: 16000000` and then sends ten
    #: bytes leaves `rfile.read` blocking forever, holding its thread. A
    #: handful of those -- a crashed script, a stuck browser tab, or anything
    #: deliberate -- takes the workbench down, and `serve()` already warns
    #: that this endpoint should not face a network.
    #:
    #: Generous enough that a slow 16 MB paste over a loopback socket is not
    #: cut off mid-upload.
    timeout = 30

    api: Api  # set by build_server

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        # One line per request, on stderr, without the default's noise.
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # This tool renders rule text and log samples that came from
        # elsewhere. A restrictive CSP and nosniff are the cheap half of not
        # turning a pasted rule into script execution.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _refuse(self, refusal: Refusal, status: int = HTTPStatus.BAD_REQUEST) -> None:
        """Answer a refusal, making sure the client can actually read it.

        A size refusal is raised BEFORE the body is read, so the handler used
        to respond and close while the client was still writing -- which on
        Windows resets the connection and the client sees nothing at all. A
        16 MB paste into the From Log box therefore reported "network error"
        rather than "your sample is too large", which is the one message that
        would have told the analyst what to do.

        So the socket is drained first, up to a bound. Unbounded draining
        would mean reading all of a body this very function is refusing to
        read; reading none of it means the explanation never arrives.
        """
        if refusal.code in _TOO_LARGE_CODES:
            status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            self._drain()
        self._send(status, {
            "error": {
                "code": refusal.code,
                "message": refusal.message,
                "where": refusal.where,
            }
        })

    def _drain(self) -> None:
        """Read and discard the request body, up to `_DRAIN_LIMIT`.

        Best effort on purpose: if the peer has already gone away there is
        nothing to drain and nothing to report, and raising here would replace
        a useful 413 with an unhandled error.
        """
        try:
            remaining = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return
        remaining = min(remaining, _DRAIN_LIMIT)
        while remaining > 0:
            try:
                chunk = self.rfile.read(min(remaining, 65536))
            except OSError:
                return
            if not chunk:
                return
            remaining -= len(chunk)

    def handle(self) -> None:
        """Serve the connection, treating a dropped one as ordinary.

        A client that goes away mid-request is normal: a browser tab closes, a
        script is interrupted, a read times out. `socketserver` prints a full
        traceback for each one, and once a connection has timed out the
        keep-alive loop raises again on the next `readline` -- so a single
        stuck client produced two tracebacks on stderr. That noise buries the
        `traceback.print_exc()` in `_dispatch`, which is the one that means
        something is actually wrong with the workbench.
        """
        try:
            super().handle()
        except (TimeoutError, OSError):
            self.close_connection = True

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError as exc:
            raise Refusal("REQUEST_BAD_LENGTH", "Content-Length is not a number.",
                          "api") from exc
        if length < 0:
            raise Refusal("REQUEST_BAD_LENGTH", "Content-Length is negative.", "api")
        if length > MAX_BODY_BYTES:
            raise Refusal(
                "REQUEST_TOO_LARGE",
                f"this request is {length:,} bytes and the ceiling is "
                f"{MAX_BODY_BYTES:,}.",
                "api",
            )
        if length == 0:
            return {}
        try:
            raw = self.rfile.read(length)
        except (TimeoutError, OSError) as exc:
            # The declared length never arrived. Refused by name rather than
            # falling through to a JSON error about truncated input, which
            # would send the analyst looking for a syntax problem in a body
            # that was simply never finished.
            #
            # The connection is closed rather than kept alive: a socket that
            # has already timed out raises again on the next read, which is
            # how one stuck client produced a second traceback.
            self.close_connection = True
            raise Refusal(
                "REQUEST_INCOMPLETE",
                f"the body stopped arriving before the {length:,} bytes its "
                f"Content-Length promised. Nothing has been interpreted.",
                "api",
            ) from exc
        if len(raw) < length:
            raise Refusal(
                "REQUEST_INCOMPLETE",
                f"the body is {len(raw):,} bytes but Content-Length said "
                f"{length:,}. A short body would parse as truncated JSON and "
                f"report a syntax error that is not there.",
                "api",
            )
        try:
            # parse_float=Decimal so a threshold or a numeric field in a pasted
            # log sample does not arrive as a float. The engine is Decimal
            # throughout and this is the one place floats could sneak in.
            data = json.loads(raw.decode("utf-8"), parse_float=Decimal)
        except UnicodeDecodeError as exc:
            raise Refusal("REQUEST_NOT_UTF8", "the body is not UTF-8.", "api") from exc
        except json.JSONDecodeError as exc:
            raise Refusal(
                "REQUEST_NOT_JSON",
                f"the body is not JSON: {exc.msg} at line {exc.lineno} "
                f"column {exc.colno}.",
                "api",
            ) from exc
        if not isinstance(data, dict):
            raise Refusal(
                "REQUEST_NOT_OBJECT",
                f"the body must be a JSON object, not a "
                f"{type(data).__name__}.",
                "api",
            )
        return data

    # -- static -----------------------------------------------------------

    def _serve_file(self, path: Path, fallback_type: str = "text/plain") -> None:
        try:
            data = path.read_bytes()
        except OSError:
            self._send(HTTPStatus.NOT_FOUND, {"error": {
                "code": "NOT_FOUND",
                "message": f"{path.name} is not part of this build.",
                "where": "api",
            }})
            return
        guessed, _ = mimetypes.guess_type(path.name)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{guessed or fallback_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _serve_static(self, relative: str) -> None:
        # Resolve and then confirm containment. Checking for ".." in the raw
        # string misses encoded traversal and symlinks; comparing resolved
        # paths does not.
        target = (_STATIC_ROOT / unquote(relative)).resolve()
        try:
            target.relative_to(_STATIC_ROOT.resolve())
        except ValueError:
            self._refuse(
                Refusal(
                    "PATH_OUTSIDE_STATIC",
                    f"`{relative}` resolves outside the static directory.",
                    "api",
                ),
                HTTPStatus.FORBIDDEN,
            )
            return
        if not target.is_file():
            self._send(HTTPStatus.NOT_FOUND, {"error": {
                "code": "NOT_FOUND", "message": f"{relative} not found.",
                "where": "api",
            }})
            return
        self._serve_file(target)

    # -- routing ----------------------------------------------------------

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)

        try:
            if method == "GET":
                if route in ("/", "/index.html"):
                    self._serve_file(_TEMPLATE_ROOT / "index.html", "text/html")
                    return
                if route.startswith("/static/"):
                    self._serve_static(route[len("/static/"):])
                    return
                if route == "/api/dialects":
                    self._send(HTTPStatus.OK, self.api.dialects())
                    return
                if route == "/api/health":
                    self._send(HTTPStatus.OK, {"ok": True})
                    return
                if route == "/api/history":
                    self._send(HTTPStatus.OK, self.api.history(params))
                    return
                if route == "/api/datasets":
                    self._send(HTTPStatus.OK, self.api.datasets(params))
                    return
                dataset_id = _entry_id(route, "/api/datasets/")
                if dataset_id is not None:
                    self._send(HTTPStatus.OK, self.api.dataset(dataset_id))
                    return
                if route == "/api/test-runs":
                    self._send(HTTPStatus.OK, self.api.test_runs(params))
                    return
                run_id = _entry_id(route, "/api/test-runs/")
                if run_id is not None:
                    self._send(HTTPStatus.OK, self.api.test_run(run_id))
                    return
                entry_id = _entry_id(route, "/api/history/", "/lineage")
                if entry_id is not None:
                    self._send(HTTPStatus.OK, self.api.history_lineage(entry_id))
                    return
                entry_id = _entry_id(route, "/api/history/")
                if entry_id is not None:
                    self._send(HTTPStatus.OK, self.api.history_entry(entry_id))
                    return

            elif method == "POST":
                handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
                    "/api/lower": self.api.lower,
                    "/api/render": self.api.render,
                    "/api/validate": self.api.validate,
                    "/api/outline": self.api.outline,
                    "/api/evaluate": self.api.evaluate,
                    "/api/synthesize": self.api.synthesize,
                    "/api/history": self.api.history_save,
                    "/api/datasets": self.api.dataset_save,
                    "/api/test-runs": self.api.test_run_save,
                }
                handler = handlers.get(route)
                if handler is not None:
                    self._send(HTTPStatus.OK, handler(self._body()))
                    return

            elif method == "DELETE":
                entry_id = _entry_id(route, "/api/history/")
                if entry_id is not None:
                    self._send(HTTPStatus.OK, self.api.history_forget(entry_id))
                    return

            self._send(HTTPStatus.NOT_FOUND, {"error": {
                "code": "ROUTE_UNKNOWN",
                "message": f"{method} {route} is not an endpoint of this API.",
                "where": "api",
            }})

        except Refusal as refusal:
            self._refuse(refusal)
        except Exception:  # pragma: no cover - the backstop
            # A traceback in the body tells an attacker about the host and the
            # analyst nothing they can act on. It goes to stderr instead.
            traceback.print_exc()
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": {
                "code": "INTERNAL",
                "message": "something failed inside the workbench. The detail is "
                           "on the server's stderr.",
                "where": "api",
            }})

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")


def _entry_id(route: str, prefix: str, suffix: str = "") -> int | None:
    """The integer id in `/api/history/12` or `/api/history/12/lineage`."""
    if not route.startswith(prefix):
        return None
    rest = route[len(prefix):]
    if suffix:
        if not rest.endswith(suffix):
            return None
        rest = rest[: -len(suffix)]
    if not rest.isdigit():
        return None
    return int(rest)


def build_server(
    host: str = "127.0.0.1", port: int = 8765, store: RuleStore | None = None
) -> ThreadingHTTPServer:
    api = Api(store)

    class BoundHandler(RuleForgeHandler):
        pass

    BoundHandler.api = api
    server = ThreadingHTTPServer((host, port), BoundHandler)
    server.daemon_threads = True
    return server


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = build_server(host, port)
    where = f"http://{host}:{port}/"
    sys.stderr.write(f"RuleForge listening on {where}\n")
    if host not in ("127.0.0.1", "localhost", "::1"):
        sys.stderr.write(
            "WARNING: bound to a non-local interface. This endpoint parses "
            "untrusted rule text and evaluates rules against untrusted "
            "samples; it is a workbench, not a service.\n"
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nstopping\n")
    finally:
        server.server_close()
