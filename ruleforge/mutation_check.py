"""Mutation check: do these tests actually fail when the engine is broken?

A green suite proves nothing unless removing a correct behaviour turns it red.
Five mutations, each removing one guarantee the design depends on:

  M1  NOT UNDECIDED returns True       -> every undecidable row becomes a match
  M2  ABSENT is treated as orderable    -> a missing field becomes "below threshold"
  M3  sliding falls back to tumbling    -> wrong counts, right shape
  M4  undecided rows silently dropped   -> "no match" claimed without evidence
  M5  regex dialect guard removed       -> a refused dialect gets evaluated anyway
"""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

MUTATIONS = [
    ("M1  NOT UNDECIDED returns True", "engine/values.py",
     "    if isinstance(value, Undecided):\n        return UNDECIDED\n    return not value",
     "    if isinstance(value, Undecided):\n        return True\n    return not value"),

    ("M2  ABSENT treated as orderable", "engine/values.py",
     "    if left is ABSENT or right is ABSENT:\n"
     "        return ComparisonResult(UNDECIDED, left, right,\n"
     "                                \"a field was absent, so it cannot be ordered\")",
     "    if left is ABSENT:\n        left = 0\n"
     "    if right is ABSENT:\n        right = 0"),

    ("M3  sliding falls back to tumbling", "engine/nodes.py",
     "    if frame.kind == \"sliding\":\n        assert frame.step is not None",
     "    if frame.kind == \"sliding\":\n        return _windows(\n"
     "            Frame(kind=\"tumbling\", size=frame.size,\n"
     "                   time_ref=frame.time_ref), times, rows)\n"
     "        assert frame.step is not None"),

    ("M4  undecided rows silently dropped", "engine/nodes.py",
     "    if undecided:\n        ctx.add(Caveat(",
     "    if False:\n        ctx.add(Caveat("),

    ("M5  regex dialect guard removed", "engine/regex.py",
     "    if dialect not in EXECUTABLE_DIALECTS:",
     "    if False:"),

    # --- mutations for the defects an independent review found in code that
    # --- already had 66 green tests. The original five all targeted densely
    # --- tested code; these target the paths the suite never constructed at all.
    ("M6  Pattern stage 0 not tested", "engine/nodes.py",
     "            if not _stage_matches(node.stages[0], start_row, ctx):\n"
     "                continue",
     "            if False:\n                continue"),

    ("M7  Pattern window not enforced", "engine/nodes.py",
     "                    if candidate_time is not None and candidate_time > window_end:",
     "                    if False:"),

    ("M8  Pattern until ignores the window", "engine/nodes.py",
     "            if node.until is not None and _window_satisfies(",
     "            if False and node.until is not None and _window_satisfies("),

    ("M9  BoolOp treats non-bool as True", "engine/evaluate.py",
     "    for operand, value in zip(expr.operands, values):\n"
     "        if not isinstance(value, (bool, Undecided)):",
     "    for operand, value in zip(expr.operands, values):\n"
     "        if False:"),

    ("M10 presence checks the value not the expr", "engine/evaluate.py",
     "        if not isinstance(expr.left, FieldExpr):\n"
     "            ctx.note_uncertain(\n"
     "                _describe_operand(expr.left),\n"
     "                \"a presence test needs a field, not a computed value\")\n"
     "            return UNDECIDED\n"
     "        return presence(_lookup(row, expr.left.ref), expr.op).value",
     "        left = eval_expr(expr.left, row, ctx, scope)\n"
     "        right = eval_expr(expr.right, row, ctx, scope)\n"
     "        if not isinstance(left, FieldExpr):\n            return UNDECIDED\n"
     "        return presence(left, expr.op).value"),

    ("M11 dedupe collapses absent keys", "engine/nodes.py",
     "            if any(part[0] == \"absent\" for part in identity):",
     "            if False:"),

    ("M12 BRE made executable again", "engine/regex.py",
     "EXECUTABLE_DIALECTS: Final = frozenset({\"posix_extended\"})",
     "EXECUTABLE_DIALECTS: Final = frozenset({\"posix_extended\", \"posix_basic\"})"),

    ("M13 lookaround no longer refused", "engine/regex.py",
     "        if char == \"(\" and pattern[index:index + 2] == \"(?\":\n"
     "            return _REFUSED_WITH_REASON[\"(?\"]",
     "        if False:\n            return _REFUSED_WITH_REASON[\"(?\"]"),

    ("M14 undecidability stops blocking NO_MATCH", "engine/run.py",
     "    blocking = [c for c in ctx.caveats if c.code not in ADVISORY_CAVEATS]",
     "    blocking = []"),

    ("M15 internal faults escape as tracebacks", "engine/run.py",
     "    except (TypeError, ValueError, ArithmeticError, AttributeError,\n"
     "            RecursionError, IndexError, KeyError) as exc:",
     "    except ():\n        raise\n    except (ZeroDivisionError,) as exc:"),
]


def run_tests() -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider",
         "--tb=no", "-x"],
        cwd=ROOT, capture_output=True, text=True, timeout=600)
    tail = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    return proc.returncode, (tail[-1] if tail else "")


def main() -> int:
    print(f"baseline: {run_tests()}")
    failures = 0
    for label, relative, original, replacement in MUTATIONS:
        path = ROOT / relative
        backup = path.read_text(encoding="utf-8")
        try:
            if original not in backup:
                print(f"  {label:38s} SKIPPED (pattern not found - cannot verify)")
                failures += 1
                continue
            path.write_text(backup.replace(original, replacement, 1),
                            encoding="utf-8")
            code, summary = run_tests()
            verdict = "RED (good)" if code != 0 else "GREEN (BAD - test is vacuous)"
            if code == 0:
                failures += 1
            print(f"  {label:38s} {verdict:28s} {summary}")
        finally:
            path.write_text(backup, encoding="utf-8")

    print(f"\nrestored: {run_tests()}")
    print("all mutations caught" if failures == 0
          else f"{failures} mutation(s) NOT caught")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
