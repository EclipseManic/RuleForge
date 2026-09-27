#!/usr/bin/env python3
"""Start RuleForge and open it in a browser.

    python run.py

That is the whole interface. No arguments, no environment, no Flask knowledge
required. The audience is an analyst who wants to paste a rule and see what it
means -- not someone who wants to run a web framework.

WHY THIS FILE SITS BESIDE THE CODE AND NOT IN A PACKAGE

RuleForge is flat: `run.py`, `web.py`, `jobs.py`, `history.py`, `engine/` and
`dialects/` are all siblings in one directory. Python puts the folder containing
a running script on `sys.path`, so that folder is already importable and this
launcher has no path to arrange. It works from a double-click, from any working
directory, and from a fresh checkout, because it resolves everything from
`__file__` rather than from where it was invoked.

WHAT IT DELIBERATELY DOES NOT DO

* IT DOES NOT BIND 0.0.0.0. This process has no authentication, it holds pasted
  rules and log samples, and its History file records them. Binding every
  interface would put all of that on the network. It binds the loopback
  interface, which is reachable only from this machine. If you need it on
  another host, that is a decision with a security review attached to it, not a
  default.
* IT DOES NOT ENABLE THE DEBUGGER. `web.py` sets `DEBUG = False` and this does
  not override it. The Werkzeug debugger is an interactive console that executes
  arbitrary code in this process.
* IT DOES NOT PRINT A DIFFERENT PORT THAN THE ONE IT SERVES. If the default port
  is busy it picks the next free one and tells you which, because a launcher that
  silently moved would send you to a dead address.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import webbrowser
from pathlib import Path

#: `run.py` SITS BESIDE THE CODE IT LAUNCHES, AND THERE IS NO PACKAGE.
#:
#: It has been in three places. It started at a repository root shared with an
#: older tool, so a file called `run.py` next to two projects did not say which
#: one it started. It then moved INSIDE the `ruleforge/` package, which fixed the
#: ambiguity and created a different problem: Python puts the folder containing a
#: running script on `sys.path`, so that folder became the package itself and
#: `import ruleforge` could not resolve until the PARENT was added by hand. That
#: workaround needed a documented exemption in the test suite, and
#: `test_nothing_widens_the_import_path` had to be weakened to allow it.
#:
#: The package is now flattened, so all three problems are gone at once. Python
#: already puts THIS directory on the path, and this directory is the whole tool.
#: There is no parent to add, no import name to resolve, and no exemption left to
#: justify. `HERE` is the root, and it is all the path logic there is.
HERE = Path(__file__).resolve().parent

#: 127.0.0.1, spelled out, because "the loopback interface" and "every
#: interface" are the same word to most people and not the same thing at all.
LOOPBACK = "127.0.0.1"
DEFAULT_PORT = 5001
#: How many ports to try before giving up. A range this size means a stale
#: process on 5001 does not stop the tool from starting.
PORT_ATTEMPTS = 20


class StartupProblem(Exception):
    """Something the user needs to fix, phrased so they can act on it."""


def _check_layout() -> None:
    """Refuse to start if the code this launcher needs is not next to it.

    The check used to be "is there an `__init__.py`?", because that file is what
    made a directory a package. There is no package now, so that would have
    refused a perfectly good checkout. What actually has to be true is that
    `web.py` is a sibling -- so that is what is asked, and it is asked before
    anything is imported, so the failure is a sentence on the console rather than
    a ModuleNotFoundError traceback.
    """
    missing = [name for name in ("web.py", "jobs.py", "engine")
               if not (HERE / name).exists()]
    if missing:
        raise StartupProblem(
            f"RuleForge is incomplete.\n"
            f"  Missing next to this file: {', '.join(missing)}\n"
            f"  This file is at: {HERE}\n"
            f"  Keep run.py, web.py, jobs.py, history.py and engine/ together.")


def _port_is_free(host: str, port: int) -> bool:
    """True when nothing is already LISTENING on `host:port`.

    ASK BY CONNECTING, NOT BY BINDING. The first version tried to bind a probe
    socket, on the reasoning that a bind would fail on a busy port. It does not
    hold on Windows: without `SO_EXCLUSIVEADDRUSE` the bind SUCCEEDS against a
    port another process is already serving, so a second `run.py` cheerfully
    announced port 5099 while the first instance held it. Two servers on one
    address means the browser reaches whichever won the race, which is the exact
    failure the check existed to prevent -- and my own comment in the first
    version described that risk while the code permitted it.

    Connecting cannot lie in the same way. If a connect succeeds, something is
    accepting there. If it is refused, nothing is. A refused connection is the
    normal, expected result on a free port and is not an error.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.35)
        return probe.connect_ex((host, port)) != 0


def _find_port(host: str, preferred: int) -> int:
    for offset in range(PORT_ATTEMPTS):
        candidate = preferred + offset
        if candidate > 65535:
            break
        if _port_is_free(host, candidate):
            return candidate
    raise StartupProblem(
        f"Could not find a free port.\n"
        f"  Tried {preferred} to {preferred + PORT_ATTEMPTS - 1} on {host}.\n"
        f"  Something else is using that whole range, or you do not have\n"
        f"  permission to bind. Try:  python run.py --port 8080")


def _prepare_data_dir() -> None:
    """Create the History folder before the first request can need it.

    Doing this here means the failure is a line on the console at startup, with a
    path the user can act on, rather than a 500 on the History tab minutes later.
    """
    import web

    parent = web.HISTORY_PATH.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StartupProblem(
            f"Could not create the folder RuleForge saves its history in.\n"
            f"  Path: {parent}\n"
            f"  Error: {exc}\n"
            f"  Set RULEFORGE_HISTORY to a writable file to choose another "
            f"location.") from exc


def _browse_when_ready(url: str, delay: float = 0.6) -> None:
    """Open the browser once the server is accepting connections.

    On a timer rather than immediately, because a browser opened before the
    socket is listening shows a connection error, and the user's first
    impression of this tool would be a failure that is not one.
    """
    def open_it() -> None:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001 - a browser is a convenience
            # A machine with no browser, or a locked-down one, is a normal
            # situation. The URL is already printed, so this is not an error.
            pass

    threading.Timer(delay, open_it).start()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Start RuleForge locally and open it in your browser.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Nothing here is required. `python run.py` is enough.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port to try first (default {DEFAULT_PORT}); "
                             f"the next free one is used if it is taken")
    parser.add_argument("--host", default=LOOPBACK,
                        help=f"interface to bind (default {LOOPBACK}, this "
                             f"machine only). Changing this exposes pasted "
                             f"rules and history to your network, because "
                             f"RuleForge has no login.")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open a browser; just print the URL")
    parser.add_argument("--debug", action="store_true",
                        help="allow in-process reloading while editing. This "
                             "enables an interactive console that executes code "
                             "in this process, so it is off unless you ask.")
    args = parser.parse_args(argv)

    _check_layout()
    # NO `sys.path` INSERT, AND ITS ABSENCE IS THE POINT. Python puts the folder
    # containing a running script on the path, so `HERE` is already there and
    # already is the whole tool. The insert this replaces existed only to make
    # `import ruleforge` resolve from inside the package; with the package gone
    # it would add a parent directory that contains nothing but this repository's
    # siblings -- widening the import path for no benefit. `run.py` is therefore
    # no longer on the `sys.path` exemption list in the test suite, because it no
    # longer touches `sys.path` at all.

    try:
        import web
    except ImportError as exc:
        raise StartupProblem(
            f"RuleForge could not be imported: {exc}\n"
            f"  Python {sys.version.split()[0]}, running from {Path.cwd()}\n"
            f"  If you just cloned this, install Flask with:\n"
            f"      pip install -r {HERE / 'requirements.txt'}") from exc

    port = _find_port(args.host, args.port)
    _prepare_data_dir()

    app = web.create_app()
    url = f"http://{args.host}:{port}/"
    workshop = f"http://{args.host}:{port}/workshop"

    width = 68
    print("=" * width)
    print("  RuleForge")
    print("=" * width)
    print(f"  Home     {url}")
    print(f"  Workshop {workshop}")
    print()
    print(f"  History  {web.HISTORY_PATH}")
    print(f"  Bound to {args.host} only -- not reachable from other machines.")
    print()
    print("  Paste a rule into the Workshop. Nothing is sent anywhere.")
    if port != args.port:
        print(f"  (port {args.port} was busy, so this is on {port})")
    print()
    print("  Press Ctrl+C to stop.")
    print("=" * width)

    if not args.no_browser:
        _browse_when_ready(url)

    try:
        # threaded=True, because a page that is waiting on a long job must not
        # block the browser's other requests -- including the browser's own
        # cancel. use_reloader is off unless asked, since a reloader re-executes
        # this process and would print the banner twice.
        app.run(host=args.host, port=port, debug=args.debug,
                threaded=True, use_reloader=args.debug)
    except KeyboardInterrupt:
        print("\n  Stopped. Your history is saved.")
    except OSError as exc:
        raise StartupProblem(
            f"Could not start the server: {exc}\n"
            f"  Another program may have taken port {port} between the check "
            f"and the start. Try again, or pass --port to choose one.") from exc
    return 0


if __name__ == "__main__":
    # A traceback is the wrong output for this audience. A StartupProblem is a
    # sentence the user can act on; anything else is still shown, because
    # swallowing an unknown error is how a real bug stays invisible.
    try:
        sys.exit(main())
    except StartupProblem as problem:
        print(f"\n  RuleForge cannot start.\n\n{problem}\n", file=sys.stderr)
        sys.exit(1)
    except Exception:  # noqa: BLE001 - last resort, still shows the traceback
        print("\n  RuleForge hit an unexpected error. The full details are "
              "below.\n", file=sys.stderr)
        raise
