"""Run a rule evaluation under a hard wall-clock limit.

Python's `re` module cannot be interrupted: it holds the interpreter lock for
the whole match, so no signal, thread timer or `Budget` can stop a pattern that
backtracks catastrophically. One such pattern in a pasted rule froze the entire
workbench -- even `/api/health` stopped answering -- and `run.py test` hung with
no way out.

The screen in `evaluate.py` catches the classic shapes, but a screen is a
heuristic and regex engines have more ways to be slow than any list of shapes.
The only guarantee is to run the match somewhere it can be KILLED. So when a
rule contains a pattern, evaluation runs in a worker process that is terminated
after `seconds`, and the caller gets a named refusal instead of a hang.

Rules with no pattern skip the worker: they are bounded by `Budget` and the
process start would only add latency.
"""

from __future__ import annotations

import multiprocessing
from typing import Any

from .pipeline import evaluate
from .values import Refusal

#: Generous for a legitimate sample, short enough that a wedged request is
#: reported while the analyst is still looking at the screen.
DEFAULT_SECONDS = 20.0

_PATTERN_MARKERS = ("Regex(", "regex", "match", "like", "extract", "replace")


def needs_isolation(rule: Any) -> bool:
    """True when evaluating `rule` could run an unbounded pattern match."""
    text = repr(rule).lower()
    return any(marker.lower() in text for marker in _PATTERN_MARKERS)


def _worker(connection: Any, rule: Any, events: Any, budget: Any) -> None:
    try:
        connection.send(("ok", evaluate(rule, events, budget=budget)))
    except Refusal as refusal:
        connection.send(("refusal", refusal))
    except BaseException as error:  # noqa: BLE001 - reported to the parent
        connection.send(("error", f"{type(error).__name__}: {error}"))
    finally:
        connection.close()


def evaluate_with_timeout(
    rule: Any,
    events: Any,
    *,
    budget: Any = None,
    seconds: float = DEFAULT_SECONDS,
) -> Any:
    """`evaluate`, killed and refused if it runs longer than `seconds`."""
    if not needs_isolation(rule):
        return evaluate(rule, events, budget=budget)

    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_worker, args=(child, rule, events, budget), daemon=True
    )
    process.start()
    child.close()
    try:
        if not parent.poll(seconds):
            raise Refusal(
                "EVALUATION_TIMEOUT",
                f"evaluating this rule took longer than {seconds:.0f} seconds "
                f"and was stopped. A pattern in it is almost certainly "
                f"backtracking catastrophically on a long field (nested or "
                f"overlapping quantifiers such as `(a+)+`, `(a|aa)*`, "
                f"`(.*,){{10}}`, or several `.*` in a row). Anchor it, make "
                f"each repetition unambiguous, or test it on a shorter sample.",
                "evaluate",
            )
        kind, payload = parent.recv()
    except EOFError as error:
        raise Refusal(
            "EVALUATION_WORKER_DIED",
            "the evaluation worker exited without an answer (out of memory?).",
            "evaluate",
        ) from error
    finally:
        if process.is_alive():
            process.terminate()
        process.join(timeout=2)
        parent.close()
    if kind == "ok":
        return payload
    if kind == "refusal":
        raise payload
    raise RuntimeError(payload)
