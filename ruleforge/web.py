"""RuleForge web app.

Flask, because the project already depends on it -- not because it is the best
choice for a greenfield tool. Nothing here imports the parent application: this
package stays standalone, and a test enforces it.

WHAT THIS IS NOT

  * No authentication. It binds to localhost and is a single-analyst tool. If you
    expose it, you have exposed an unauthenticated rule editor to the network,
    which is a decision for you and not for this app to make silently.
  * No database. History is an append-only JSON file, and there is no update or
    delete path through any route.
  * No SIEM connection. Nothing here talks to your data. Every route says so.

THE REFUSAL IS RENDERED, NOT SWALLOWED

When a dialect cannot represent something, the named refusal is shown in full.
That is the product working, not failing: a tool that quietly dropped the part it
did not understand would hand back a rule that looks fine and matches a different
set of events.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, render_template, request

from . import history, jobs
from .engine.values import Refusal

#: History lives beside the package, not in a temp directory, so it survives a
#: restart. It is a FILE the analyst can read, back up and delete themselves.
HISTORY_PATH = Path(os.environ.get(
    "RULEFORGE_HISTORY",
    Path(__file__).resolve().parent / "data" / "history.json"))


def create_app() -> Flask:
    app = Flask(__name__)

    # NO DEBUG. The Werkzeug debugger is an interactive console that executes
    # arbitrary code in the process. It is a development tool, and this process
    # holds pasted rules and file paths.
    app.config["DEBUG"] = False
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

    @app.get("/")
    def home() -> str:
        return render_template(
            "home.html",
            dialects=jobs.dialect_choices(),
            targets=jobs.TARGETS,
        )

    @app.get("/workshop")
    def workshop() -> str:
        return render_template(
            "workshop.html",
            dialects=jobs.dialect_choices(),
            tab=request.args.get("tab", "author"),
        )

    @app.get("/history")
    def history_page() -> str:
        try:
            entries = history.recent(HISTORY_PATH, limit=100)
            problem = None
        except history.Refused as exc:
            # A DAMAGED HISTORY IS SHOWN AS A PROBLEM, not as an empty list. An
            # empty list would read as "you have no history", which is a
            # different and more comforting lie.
            entries, problem = [], str(exc)
        return render_template("history.html", entries=entries, problem=problem)

    @app.post("/api/<job>")
    def run_job(job: str) -> Any:
        # AN UNKNOWN JOB IS A 404, CHECKED FIRST. The payload validation below
        # runs before dispatch, so an unknown route used to be reported as
        # "no JSON body was sent" -- which is not what was wrong with it.
        if job not in ("author", "understand", "tune", "debug_rule_to_logs",
                       "debug_logs_to_rule"):
            abort(404)

        # THE PAYLOAD IS UNTRUSTED IN ITS SHAPE, NOT JUST ITS CONTENT. Twelve
        # unhandled 500s came from typing alone: a JSON list body has no `.get`,
        # `rule_id: 7` has no `.strip`, `dialect: []` is unhashable, `fields: 5`
        # is not iterable, `fields: {}` is unhashable, and a 100k-deep array
        # raises RecursionError in the JSON parser. None of those is the
        # analyst's fault, and all of them produced a bare Werkzeug 500 with no
        # code for the UI to show.
        try:
            payload = request.get_json(silent=True)
        except RecursionError:
            return _bad_request("PAYLOAD_TOO_DEEP",
                                "the pasted JSON is nested too deeply to read")
        if payload is None:
            return _bad_request("PAYLOAD_MISSING",
                                "no JSON body was sent")
        if not isinstance(payload, dict):
            return _bad_request("PAYLOAD_NOT_AN_OBJECT",
                                f"the body is a {type(payload).__name__}, not a "
                                f"JSON object")

        dialect = payload.get("dialect", "")
        text = payload.get("rule", "") or ""
        if not isinstance(dialect, str) or not isinstance(text, str):
            return _bad_request("PAYLOAD_FIELD_WRONG_TYPE",
                                "`dialect` and `rule` must be strings")

        raw_id = payload.get("rule_id") or "rule"
        if not isinstance(raw_id, str):
            return _bad_request("PAYLOAD_FIELD_WRONG_TYPE",
                                f"`rule_id` is a {type(raw_id).__name__}, not a "
                                f"string")
        rule_id = raw_id.strip() or "rule"

        raw_fields = payload.get("fields")
        fields = None
        if raw_fields is not None:
            if not isinstance(raw_fields, list) or not all(
                    isinstance(f, str) for f in raw_fields):
                return _bad_request("PAYLOAD_FIELD_WRONG_TYPE",
                                    "`fields` must be a list of field-name "
                                    "strings")
            # IT WAS VALIDATED AND THEN THROTTEN AWAY. `fields` was read, type
            # checked, and then `None` was passed to the job regardless, so the
            # induced-rule summary always reported EVERY field in the sample --
            # asking for one field got all of them, and the answer silently
            # ignored the question.
            fields = list(raw_fields)

        # `events` IS THE ONE PAYLOAD KEY THAT WAS NOT TYPE-CHECKED. A list, an
        # int or a dict reached `load_events` and hit `.strip()` on a non-string,
        # which the catch-all reported as "a bug in RuleForge, not a problem with
        # your rule" -- the blame inverted, and once per request in the log.
        raw_events = payload.get("events", "")
        if isinstance(raw_events, (list, dict, int, float, bool)):
            return _bad_request("PAYLOAD_FIELD_WRONG_TYPE",
                                "`events` must be a JSON string -- either an "
                                "array or one object per line")
        events_text = raw_events if isinstance(raw_events, str) else ""

        try:
            if job == "author":
                outcome = jobs.author(dialect, text, rule_id)
            elif job == "understand":
                ir = jobs._lower_validated(dialect, text, rule_id)
                outcome = jobs.understand(ir)
            elif job == "tune":
                ir = jobs._lower_validated(dialect, text, rule_id)
                events = jobs.load_events(events_text)
                outcome = jobs.tune(ir, events)
            elif job == "debug_rule_to_logs":
                outcome = jobs.debug_rule_to_logs(dialect, text, rule_id)
            elif job == "debug_logs_to_rule":
                events = jobs.load_events(events_text)
                outcome = jobs.debug_logs_to_rule(dialect, events, fields)
        except Refusal as refusal:
            return jsonify({
                "ok": False,
                "refusal": {"code": refusal.code, "message": refusal.message},
                "findings": [],
            }), 200
        except RecursionError:
            return _bad_request("INPUT_TOO_DEEP",
                                "the pasted events are nested too deeply to "
                                "read")
        except history.Refused as exc:
            return jsonify({"ok": False, "refusal": {
                "code": "HISTORY_REFUSED", "message": str(exc)},
                "findings": []}), 200
        except Exception as exc:  # noqa: BLE001
            # The LAST RESORT, and it names itself as a bug rather than blaming
            # the analyst's input. `DEBUG` is off, so a bare 500 would carry no
            # traceback and no clue at all.
            app.logger.exception("ruleforge: unhandled error in job %s", job)
            return _bad_request(
                "RULEFORGE_INTERNAL_ERROR",
                f"RuleForge hit an unexpected error handling this request "
                f"({type(exc).__name__}). That is a bug in RuleForge, not a "
                f"problem with your rule. The detail is in the terminal "
                f"running it.")

        saved = None
        dropped = 0
        # A ROUTE IS NOT A HISTORY KIND. `debug_rule_to_logs` and
        # `debug_logs_to_rule` are two routes under the one `debug` job, and
        # passing the route name straight to `history.append` meant neither could
        # ever be saved. The mapping is explicit and lives here, next to the
        # routes, so the two vocabularies cannot drift apart again.
        history_kind = {"debug_rule_to_logs": "debug",
                        "debug_logs_to_rule": "debug"}.get(job, job)

        if payload.get("save") and outcome.ok:
            if history_kind not in history.JOBS:
                return jsonify({"ok": False, "refusal": {
                    "code": "HISTORY_UNKNOWN_JOB",
                    "message": f"{job!r} has no history kind. This is a wiring "
                               f"bug in the app, not something you did.",
                }, "findings": []}), 200
            try:
                result = history.append(
                    HISTORY_PATH, kind=history_kind, dialect=dialect,
                    rule_id=rule_id,
                    title=outcome.graph.get("title") or rule_id,
                    summary=_one_line(outcome), payload={
                        "rule": text,
                        "rendered": outcome.rendered,
                        "findings": [f.code for f in outcome.findings],
                    })
                saved, dropped = result.entry, result.dropped
            except history.Refused as exc:
                outcome.findings.append(jobs.Finding(
                    "HISTORY_NOT_SAVED", "caution", str(exc)))

        body = outcome.to_dict()
        body["saved"] = saved is not None
        body["dropped"] = dropped
        return jsonify(body), 200

    return app


def _bad_request(code: str, message: str) -> Any:
    """A refusal for a malformed request. 200, because a refusal is an answer.

    Every job route answers 200 even when it refuses, and this does too: the UI
    reads `refusal` and shows the message, so a 4xx would just be a different
    flavour of the same blank panel.
    """
    return jsonify({"ok": False, "refusal": {"code": code, "message": message},
                    "findings": []}), 200


def _one_line(outcome: jobs.Outcome) -> str:
    """A one-line summary for the history list. Never invents a measurement."""
    problems = sum(1 for f in outcome.findings if f.severity == "problem")
    cautions = sum(1 for f in outcome.findings if f.severity == "caution")
    if outcome.refusal:
        return f"refused: {outcome.refusal['code']}"
    parts = [f"{len(outcome.graph.get('nodes', []))} nodes"]
    if problems:
        parts.append(f"{problems} problem(s)")
    if cautions:
        parts.append(f"{cautions} caution(s)")
    if not problems and not cautions:
        parts.append("nothing flagged")
    return ", ".join(parts)


app = None


def main() -> None:  # pragma: no cover - manual entry point
    global app
    app = create_app()
    # 127.0.0.1 ONLY. See the module docstring: there is no authentication, so
    # binding to every interface would expose an unauthenticated rule editor.
    app.run(host="127.0.0.1", port=5001, debug=False)


if __name__ == "__main__":  # pragma: no cover
    main()
