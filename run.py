"""RuleForge -- one entry point for the whole tool.

The pipeline every dialect plugs into:

    parse    native text  -> parsed structure
    lower    parsed       -> Rule          (the model in ir.py)
    render   Rule         -> native text

Nothing above the engine is allowed to know a vendor's syntax, and nothing
in the engine is allowed to know a vendor exists. That is what makes eight
dialects possible without eight tools, and it is enforced by a test rather
than by good intentions.

    python run.py                  open the browser workbench
    python run.py verify           the test suite, then the corpus sweep
    python run.py corpus --full    every corpus rule, with its message
    python run.py check sigma rule.yml

This file is the only entry point. Every other tool in the suite starts with
`python run.py`, and a tool that starts differently is a tool nobody remembers
how to start. It also gives the two things that were only reachable by
remembering a long command: the whole test suite, and the corpus sweep that
the suite does not run.

WHAT IT DELIBERATELY DOES NOT DO

* IT DOES NOT BIND 0.0.0.0 BY DEFAULT. This endpoint parses untrusted rule
  text and evaluates rules against untrusted samples, so it is loopback only
  and says so out loud if you override that.
* IT DOES NOT PRINT A DIFFERENT PORT THAN THE ONE IT SERVES. If the preferred
  port is busy it names the one it actually bound.
* IT DOES NOT NEED ANYTHING INSTALLED. `verify` runs unittest, not pytest,
  because a check that needs a dependency cannot run in the locked-down SOC
  this tool is built for. pytest works too; it is just not the floor.
"""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    # `python run.py` is meant to work from any working directory, and the
    # package it imports sits beside this file rather than on sys.path.
    sys.path.insert(0, str(ROOT))

from web.api import build_server  # noqa: E402

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
PORT_ATTEMPTS = 20

HELP = """\
RuleForge -- a detection rule workbench for enterprise SIEM rules.

    python run.py                  start the browser workbench (default)
    python run.py serve --port N   start it on a specific port
    python run.py verify           run the test suite, then the corpus sweep
    python run.py corpus [args]    sweep every dialect's corpus rules

Every other command is the engine CLI, unchanged:

    python run.py dialects
    python run.py check     sigma    rule.yml
    python run.py explain   sigma    rule.yml
    python run.py convert   sigma sentinel rule.yml
    python run.py test      sigma    rule.yml events.jsonl
    python run.py propose   samples.jsonl --target sigma

Exit codes: 0 the work succeeded, 1 a rule was refused or a conversion lost
something, 2 the arguments were wrong.
"""


def _port_is_free(host: str, port: int) -> bool:
    """True when nothing is already LISTENING on host:port.

    A connect probe rather than a bind, because a failed bind can mean
    permission or a stale socket as well as "in use", and only one of those
    is worth moving to the next port for.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.4)
        return probe.connect_ex((host, port)) != 0


def _find_port(host: str, preferred: int) -> int:
    for offset in range(PORT_ATTEMPTS):
        candidate = preferred + offset
        if candidate > 65535:
            break
        if _port_is_free(host, candidate):
            return candidate
    raise SystemExit(
        f"Could not find a free port.\n"
        f"  Tried {preferred} to {preferred + PORT_ATTEMPTS - 1} on {host}.\n"
        f"  Something else may have them, or this account may not have\n"
        f"  permission to bind. Try:  python run.py serve --port 8080"
    )


def _serve(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python run.py serve",
        description="Start the RuleForge browser workbench.",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port to try first (default {DEFAULT_PORT})")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"bind address (default {DEFAULT_HOST})")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open a browser")
    args = parser.parse_args(argv)

    if not 1 <= args.port <= 65535:
        parser.error(f"{args.port} is not a port")

    port = _find_port(args.host, args.port)
    try:
        server = build_server(args.host, port)
    except OSError as exc:
        print(
            f"\nCould not start on port {port}: {exc}\n"
            f"  Another program may have taken it between the check and the\n"
            f"  start. Try again, or pass --port to choose one.\n",
            file=sys.stderr,
        )
        return 1

    bound = server.server_address[1]
    url = f"http://{args.host}:{bound}/"

    # One write, flushed. Piped or redirected stdout is block-buffered, and a
    # banner that arrives only when the process exits is a banner that tells
    # nobody where the workbench went.
    lines = [
        "",
        "  RuleForge -- Detection Rule Workbench",
        f"  {url}",
    ]
    if bound != args.port:
        lines.append(f"  (port {args.port} was busy, so this is on {bound})")
    lines += [
        "",
        "  Eight dialects, one rule model, standard library only.",
        "  Ctrl+C to stop.",
        "",
    ]
    print("\n".join(lines), flush=True)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"  WARNING: bound to {args.host}, which is not loopback. This\n"
            f"  endpoint parses untrusted rule text and evaluates rules\n"
            f"  against untrusted samples; it is a workbench, not a service.\n",
            file=sys.stderr,
        )

    if not args.no_browser:
        threading.Thread(
            target=lambda: (time.sleep(0.6), webbrowser.open(url)),
            daemon=True,
        ).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        server.server_close()
    return 0


def _run(command: list[str], label: str) -> int:
    """One check, with its own banner so a failure names what failed."""
    print(f"\n== {label} " + "=" * max(0, 58 - len(label)))
    code = subprocess.run(command, cwd=ROOT).returncode
    print(f"== {label}: {'ok' if code == 0 else 'FAILED'}")
    return code


def _verify(_argv: list[str]) -> int:
    """Everything this repository can prove about itself, in one command.

    The suite first because it is fast and localised, then the corpus sweep
    because it is the only check that walks all 400-odd real-shaped rules
    through all eight dialects. A green suite alone has been misleading here
    before: it was fully green while a renderer dropped thresholds.
    """
    status = _run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
        "test suite",
    )
    status = max(status, _run(
        [sys.executable, str(ROOT / "corpus" / "run_corpus.py")],
        "corpus sweep",
    ))
    print()
    print("  All checks passed." if status == 0
          else "  Something failed. See the banner above.")
    return status


def _corpus(argv: list[str]) -> int:
    return subprocess.run(
        [sys.executable, str(ROOT / "corpus" / "run_corpus.py"), *argv],
        cwd=ROOT,
    ).returncode


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] in ("-h", "--help", "help"):
        print(HELP)
        return 0

    if not argv or argv[0] == "serve":
        return _serve(argv[1:])
    if argv[0] == "verify":
        return _verify(argv[1:])
    if argv[0] == "corpus":
        return _corpus(argv[1:])

    # Anything else is the package's own CLI, handed over untouched so there
    # is one parser to learn rather than two that disagree.
    from engine.cli import main as engine_cli

    return engine_cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())
