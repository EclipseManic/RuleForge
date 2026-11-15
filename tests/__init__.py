"""RuleForge's test suite.

This file exists so `python -m unittest discover` recurses into this directory.
Without it unittest silently finds zero tests here and reports success, which
is the worst possible failure mode for a test suite: green because nothing ran.

It also holds `planned_dialect`, which several test modules need. All eight
dialects now ship, so there is no longer a real `planned` entry to point the
planned-dialect refusal tests at -- and those refusals are still live code
paths that a ninth dialect will land on. Rather than delete the tests (leaving
the paths untested) or pin them to a dialect that might ship (making them
assert the opposite of their name, which already happened twice here with
`sigma` and then `wazuh`), they run against a synthetic entry.
"""

from __future__ import annotations

import contextlib
from typing import Iterator

__all__ = ["planned_dialect", "PLANNED_KEY"]

#: The synthetic key. Deliberately not a real vendor name, so a future dialect
#: cannot collide with it and quietly make these tests pass for the wrong
#: reason.
PLANNED_KEY = "_notyet"


@contextlib.contextmanager
def planned_dialect(
    key: str = PLANNED_KEY,
    label: str = "Not Yet",
    note: str = "Planned. A synthetic entry used by the registry tests.",
) -> Iterator[str]:
    """Register a `planned` dialect for the duration of the block.

    Restored in a `finally`, and the module cache is left untouched because a
    planned entry has no module to import. A mutation that escaped would fail
    later in an unrelated test and only for some execution orders, which is
    the worst failure mode a suite can have.
    """
    from engine.dialects import REGISTRY, Dialect

    if key in REGISTRY:  # pragma: no cover - guards a careless rename
        raise AssertionError(
            f"`{key}` is a real dialect now, so it cannot stand in for a "
            f"planned one. Pick a key no vendor will ever use."
        )
    REGISTRY[key] = Dialect(
        key=key,
        label=label,
        language="None",
        module=None,
        parse_attr=f"parse_{key}",
        lower_attr=f"lower_{key}",
        render_attr=f"render_{key}",
        note=note,
    )
    try:
        yield key
    finally:
        REGISTRY.pop(key, None)
