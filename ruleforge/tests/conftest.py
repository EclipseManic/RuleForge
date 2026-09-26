"""Makes `import ruleforge` work without any test file touching `sys.path`.

Six test files each did `sys.path.insert(0, <repo root>)`. That put the PARENT
PROJECT's modules on the import path for the entire suite -- which is precisely
how a tool that is supposed to be standalone stops being standalone, with no
import statement ever changing. A reviewer flagged it; a test now enforces it.

Doing it here, once, means:
  * a single place to see what the suite puts on the path,
  * the repo root is added only if `ruleforge` is not already importable, so
    running the suite from the repo root adds nothing at all,
  * each test file reads as ordinary Python with no import-time side effects.
"""
from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

try:  # already importable -- running from the repo root, the normal case
    import ruleforge  # noqa: F401
except ModuleNotFoundError:  # running this file directly
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
