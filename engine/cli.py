"""`python run.py` -- the workbench, and the same engine headless.

A module entry point rather than a console script, because there is no install
step: the package runs from a checkout, which is the point of having no
dependencies.

Subcommands exist because the backend was only reachable through the browser.
A detection engineer cannot put a browser in CI, and "convert this directory
of Sigma rules and tell me which ones will not translate" is the question this
tool is for. Every subcommand writes refusals to stderr and uses the exit code
so a shell can act on the answer:

    0  the work succeeded
    1  a rule was refused, or a conversion lost something
    2  the arguments were wrong
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import dialects, synthesize
from .codec import rule_to_dict
from .pipeline import evaluate as run_rule
from .validate import validate
from .outline import outline
from .values import Refusal

# NOTE: `web.api.serve` is imported INSIDE `_cmd_serve`, not here.
# `engine/` must not import `web/` -- that is the layering rule this
# project states, and a module-level import broke it for every CLI
# invocation, including the ones that never start a server.


def _read(path: str) -> str:
    """Rule text from a file, or from stdin when the path is `-`.

    `-` is supported so the subcommands compose in a pipeline, which is the
    only reason a CLI is better than the GUI for this work.
    """
    if path == "-":
        return sys.stdin.read()
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise Refusal(
            "CLI_UNREADABLE",
            f"could not read `{path}`: {exc.strerror or exc}.",
            "cli",
        ) from None


def _report(refusal: Refusal) -> int:
    """A refusal on stderr, so stdout stays machine-readable."""
    sys.stderr.write(f"{refusal.code}: {refusal.message}\n")
    if refusal.where:
        sys.stderr.write(f"  (in {refusal.where})\n")
    return 1


def _notes(notes: list[Any], label: str) -> int:
    """Diagnostics on stderr. Returns 1 when any of them is a problem.

    A conversion that reports `SELECTOR_NOT_TRANSFERABLE` has produced text
    that is broader than the rule it came from. In a shell that has to be a
    non-zero exit, or a pipeline will deploy it.
    """
    worst = 0
    for note in notes:
        sys.stderr.write(f"{label} {note.severity}: {note.code}: "
                         f"{note.message}\n")
        if note.severity == "problem":
            worst = 1
    return worst


def _cmd_convert(args: argparse.Namespace) -> int:
    text = _read(args.path)
    rule, lowered = dialects.lower(args.source, text, )
    status = _notes(lowered, "read")
    out, notes = dialects.render(args.target, rule)
    status = max(status, _notes(notes, "write"))
    sys.stdout.write(out if out.endswith("\n") else out + "\n")
    return status


def _cmd_check(args: argparse.Namespace) -> int:
    text = _read(args.path)
    rule, lowered = dialects.lower(args.source, text)
    validate(rule)
    status = _notes(lowered, "read")
    stages = " -> ".join(type(n).__name__ for n in rule.pipeline)
    sys.stdout.write(f"ok  {args.source}  {stages}\n")
    return status


def _cmd_explain(args: argparse.Namespace) -> int:
    text = _read(args.path)
    rule, lowered = dialects.lower(args.source, text)
    # A `problem` diagnostic means the rule did not survive the read
    # intact. Reporting it on stderr and still exiting 0 told a CI job
    # the rule was fine while the text on stderr said otherwise.
    status = _notes(lowered, "read")
    if args.json:
        sys.stdout.write(json.dumps(rule_to_dict(rule), indent=2) + "\n")
        return status

    described = outline(rule)
    sys.stdout.write(f"{described['annotations']['title'] or rule.rule_id}\n")
    for stage in described["pipeline"]:
        line = f"  {stage['kind']:12} {stage['id']}"
        for key in ("condition", "predicate"):
            if stage.get(key):
                line += f"\n    {stage[key]}"
        for step in stage.get("steps", ()):
            line += f"\n    {step['position']}. {step['condition']}"
        sys.stdout.write(line + "\n")
    return status


def _cmd_test(args: argparse.Namespace) -> int:
    # The lowering diagnostics are REPORTED, not dropped. A rule that read
    # in with a `problem` -- a selector that could not be carried, a clause
    # that was approximated -- is not the rule that was written, and a
    # verdict about it is a verdict about something else.
    rule, lowered = dialects.lower(args.source, _read(args.path))
    status = _notes(lowered, "read")
    events = synthesize.parse_events(_read(args.events), args.format)
    result = run_rule(rule, events)
    sys.stdout.write(f"{result.verdict}  {len(result.rows)} row(s) of "
                     f"{len(events)} event(s)\n")
    for caveat in result.caveats:
        sys.stderr.write(f"caveat: {caveat.code}: {caveat.message}\n")
    if result.refusal is not None:
        return _report(result.refusal)
    # A non-match is a legitimate answer, not a failure. Only an UNDECIDED
    # result is an error for a shell: it means the question was not answered.
    if result.verdict not in ("matched", "no_match"):
        return 1
    return status


def _cmd_propose(args: argparse.Namespace) -> int:
    events = synthesize.parse_events(_read(args.path), args.format)
    options = synthesize.Options(
        table=args.table,
        skip_volatile=not args.keep_volatile,
        skip_timestamps=not args.keep_timestamps,
    )
    rule, reports, notes = synthesize.propose(events, options)
    for report in reports:
        mark = "pin " if report.include else "skip"
        reasons = "; ".join(report.reasons)
        sys.stderr.write(
            f"{mark} {report.name} = {report.sample!r}"
            + (f"  ({reasons})" if reasons else "") + "\n"
        )
    status = _notes(notes, "propose")
    # The RENDER diagnostics were discarded, so a proposed rule written
    # out with a selector that could not cross dialects came back with a
    # clean exit and text broader than the analysis behind it.
    out, rendered = dialects.render(args.target, rule)
    status = max(status, _notes(rendered, "write"))
    sys.stdout.write(out if out.endswith("\n") else out + "\n")
    return status


def _cmd_dialects(_args: argparse.Namespace) -> int:
    rows = dialects.catalogue()
    width = max(len(r["key"]) for r in rows)
    for row in rows:
        flags = []
        if row["can_parse"]:
            flags.append("read")
        if row["can_render"]:
            flags.append("write")
        if row["carries_annotations"]:
            flags.append("metadata")
        sys.stdout.write(
            f"{row['key']:<{width}}  {row['language']:<12} "
            f"{row['status']:<8} {','.join(flags)}\n"
        )
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    # Imported here so `engine/` never imports `web/` at module scope.
    from web.api import serve

    serve(args.host, args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python run.py",
        description="A local detection-rule workbench: author, tune and debug "
                    "SIEM rules across dialects.",
    )
    subs = parser.add_subparsers(dest="command")

    # `serve` is also the default, so `python run.py` still opens the
    # workbench and no existing invocation changes meaning.
    web = subs.add_parser("serve", help="start the browser workbench")
    web.add_argument(
        "--host", default="127.0.0.1",
        help="interface to bind. Defaults to 127.0.0.1. This endpoint parses "
             "untrusted rule text and evaluates rules against untrusted log "
             "samples, so binding it anywhere routable is an explicit choice.",
    )
    web.add_argument("--port", type=int, default=8765,
                     help="port (default 8765)")
    web.set_defaults(handler=_cmd_serve)

    convert = subs.add_parser(
        "convert", help="read a rule in one dialect and write it in another")
    convert.add_argument("source", help="dialect to read")
    convert.add_argument("target", help="dialect to write")
    convert.add_argument("path", help="rule file, or - for stdin")
    convert.set_defaults(handler=_cmd_convert)

    check = subs.add_parser(
        "check", help="parse and validate a rule, reporting what it loses")
    check.add_argument("source", help="dialect to read")
    check.add_argument("path", help="rule file, or - for stdin")
    check.set_defaults(handler=_cmd_check)

    explain = subs.add_parser(
        "explain", help="say in prose what a rule actually matches")
    explain.add_argument("source", help="dialect to read")
    explain.add_argument("path", help="rule file, or - for stdin")
    explain.add_argument("--json", action="store_true",
                         help="emit the rule's IR instead of prose")
    explain.set_defaults(handler=_cmd_explain)

    test = subs.add_parser(
        "test", help="run a rule against a sample and report the verdict")
    test.add_argument("source", help="dialect to read")
    test.add_argument("path", help="rule file, or - for stdin")
    test.add_argument("events", help="sample file, or - for stdin")
    test.add_argument("--format", default="jsonl",
                      choices=sorted(synthesize.FORMATS))
    test.set_defaults(handler=_cmd_test)

    propose = subs.add_parser(
        "propose", help="derive a candidate rule from log samples")
    propose.add_argument("path", help="sample file, or - for stdin")
    propose.add_argument("--target", default="sigma",
                         help="dialect to write (default sigma)")
    propose.add_argument("--format", default="jsonl",
                         choices=sorted(synthesize.FORMATS))
    propose.add_argument("--table", default="events")
    propose.add_argument("--keep-volatile", action="store_true",
                         help="pin fields that differ between samples")
    propose.add_argument("--keep-timestamps", action="store_true",
                         help="pin fields that look per-event")
    propose.set_defaults(handler=_cmd_propose)

    listing = subs.add_parser("dialects", help="list the dialects")
    listing.set_defaults(handler=_cmd_dialects)

    args = parser.parse_args(argv)
    if args.command is None:
        # No subcommand: serve, as this entry point always did.
        return _cmd_serve(parser.parse_args(["serve"]))

    if args.command == "serve" and not 1 <= args.port <= 65535:
        parser.error(f"{args.port} is not a port")

    try:
        return args.handler(args)
    except Refusal as refusal:
        # A refusal is the tool working. It goes to stderr with its code, and
        # the exit status is 1 so a shell can branch on it -- NOT a traceback,
        # which would read as the tool breaking.
        return _report(refusal)
    except BrokenPipeError:
        # `| head` closes the pipe. Normal, not an error.
        return 0


if __name__ == "__main__":
    sys.exit(main())
