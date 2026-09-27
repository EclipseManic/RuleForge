"""Puts the repository root on `sys.path` so the flat top-level modules resolve.

Six test files each did `sys.path.insert(0, <repo root>)`. That put a whole
other project's modules on the import path for the entire suite -- which is
precisely how a tool that is supposed to be standalone stops being standalone,
with no import statement ever changing. A reviewer flagged it; a test now
enforces it.

Doing it here, once, means:
  * a single place to see what the suite puts on the path,
  * the root is added only if it is not already importable, so running the
    suite from the repository root adds nothing at all,
  * each test file reads as ordinary Python with no import-time side effects.

THE DEPTH CHANGED WHEN THE PACKAGE WAS FLATTENED, and this line is the whole
reason it is easy to get wrong. The file used to live at `ruleforge/tests/`, so
the root was three `parent` hops up. It now lives at `tests/`, so the root is
TWO. Leaving it at three would have put `Combined Project` -- the folder holding
every one of the user's other tools -- on the import path for the whole suite,
which is the exact leak this file exists to prevent, and it would have done it
silently.
"""
from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

try:  # already importable -- running from the repo root, the normal case
    import engine  # noqa: F401
except ModuleNotFoundError:  # running this file directly
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
