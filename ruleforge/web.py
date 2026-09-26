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
        payload = request.get_json(silent=True) or {}
        dialect = payload.get("dialect", "")
        text = payload.get("rule", "") or ""
        rule_id = (payload.get("rule_id") or "rule").strip() or "rule"

        try:
            if job == "author":
                outcome = jobs.author(dialect, text, rule_id)
            elif job == "understand":
                ir, _ = jobs.lower_for(dialect, text, rule_id)
                outcome = jobs.understand(ir)
            elif job == "tune":
                ir, _ = jobs.lower_for(dialect, text, rule_id)
                events = jobs.load_events(payload.get("events", ""))
                outcome = jobs.tune(ir, events)
            elif job == "debug_rule_to_logs":
                outcome = jobs.debug_rule_to_logs(dialect, text, rule_id)
            elif job == "debug_logs_to_rule":
                events = jobs.load_events(payload.get("events", ""))
                outcome = jobs.debug_logs_to_rule(dialect, events,
                                                  payload.get("fields"))
            else:
                abort(404)
        except Refusal as refusal:
            return jsonify({
                "ok": False,
                "refusal": {"code": refusal.code, "message": refusal.message},
                "findings": [],
            }), 200
        except history.Refused as exc:
            return jsonify({"ok": False, "refusal": {
                "code": "HISTORY_REFUSED", "message": str(exc)},
                "findings": []}), 200

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
