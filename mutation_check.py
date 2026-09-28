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
# Only when run AS A SCRIPT (`python mutation_check.py`). When imported
# -- including by the test suite, which must never put a neighbouring project's
# tree on the path -- the tool's own modules are already importable and this does
# nothing. The unconditional version put that tree on sys.path for the session.
if __name__ == "__main__" and str(ROOT) not in sys.path:
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
     "                        if window_end is not None and candidate_time is not None \\\n"
     "                                and candidate_time > window_end:",
     "                        if False:"),

    ("M8  Pattern until ignores the window", "engine/nodes.py",
     "            if node.until is not None:",
     "            if False and node.until is not None:"),

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

    # THE SHIPPED CQL ORDERING BUG, AS A PERMANENT MUTATION. `| table a,b |
    # sort(x)` used to be emitted as `| sort(x) | table a,b`, because the
    # query held one slot per pipe kind and the lowerer emitted a fixed order.
    # The parse and the node chain looked right and the suite stayed green,
    # so this is the exact case that only a mutation can pin.
    ("M16 CQL pipes emitted in a fixed order, not the written one",
     "dialects/cql_ir.py",
     "    for index, stage in enumerate(query.stages):",
     "    for index, stage in enumerate(sorted(\n"
     "            query.stages, key=lambda s: 1 if isinstance(s, CqlTable) else 0)):"),

    # THE FLAG THREE RENDERERS BELIEVED AND THE EVALUATOR IGNORED.
    # `Derive.projects` says "replace the row, do not extend it". spl_render,
    # kql_render, and wazuh_render all read it; `eval_derive` did not, so
    # `| fields a,b`, KQL `| project a`, and CQL `| table a,b` all rendered as
    # projections and executed as pass-throughs, carrying every other column
    # into the output. The round trip looked perfect at every step, which is
    # precisely why only an execution test could have found it.
    ("M17 projection ignored at evaluation, so nothing is dropped",
     "engine/nodes.py",
     "    projected = [target for target, _ in node.assignments] if node.projects \\\n        else None",
     "    projected = None"),

    # THE OTHER HALF OF M17, and the one that catches an over-correction:
    # making EVERY Derive project would pass a table-only suite and break
    # `rename`, `eval`, `:=`, and KQL `extend` -- all of which ADD columns.
    ("M18 projection applied unconditionally, so extend drops columns too",
     "engine/nodes.py",
     "    projected = [target for target, _ in node.assignments] if node.projects \\\n        else None",
     "    projected = [target for target, _ in node.assignments]"),

    # THE DEFAULT FRAME IS A SILENTLY-WRONG ANSWER, NOT A LOUD ONE. `| count()`
    # with the default `tumbling` frame would emit ONE ROW PER WINDOW, so a rule
    # asking "how many" would return several numbers -- and it renders as
    # `| count()` either way, so no text test could see it. `per_event` is the
    # whole-input frame, the same one SPL's spanless `stats` uses.
    ("M19 CQL count uses the default tumbling frame, not the whole input",
     "dialects/cql_ir.py",
     '                                   frame=Frame(kind="per_event")))',
     "                                   ))"),

    # THE SILENT EMPTY ROW. `| count() | table a` projected a column the
    # aggregate could not produce, and the rule returned a row with ZERO columns
    # -- the count it had just computed, destroyed, with no caveat. To an
    # analyst that is indistinguishable from "no events matched". The check is
    # decidable at lower time because an Aggregate's output columns ARE its
    # measure names.
    ("M20 projection after an aggregate is not checked against it",
     "dialects/cql_ir.py",
     "            if present is not None:",
     "            if False:"),

    # RENAME, WHICH DROPS ITS SOURCE. `rename user as account` makes `user` STOP
    # EXISTING -- Splunk and CQL both, and this engine's own `ir.py` documents
    # it. It used to COPY the value and leave the source, so the rule rendered
    # as a rename and executed as an `eval`: byte-identical text, different
    # rowset, invisible to every text-level test. `projects` cannot express it,
    # because rename keeps every column EXCEPT the one it consumed.
    ("M21 rename copies its source column instead of dropping it",
     "engine/nodes.py",
     "        for name in node.drops:\n            values.pop(name, None)",
     "        for name in node.drops:\n            pass"),

    # AND THE OTHER DIRECTION: dropping when nothing asked for it. This is the
    # over-correction M21 invites -- a fix that treated every `Derive` as a
    # rename would pass a rename-only suite and silently delete columns from
    # every `:=`, every KQL `extend`, and every SPL `eval` in the tool.
    ("M22 drop applied whether or not the stage asked for one",
     "engine/nodes.py",
     "        for name in node.drops:\n            values.pop(name, None)",
     "        for name in node.assignments and () or ():\n"
     "            values.pop(name, None)"),

    # `keys` RECORDED BUT NOT GROUPED -- the same bug shape as Derive.projects
    # and rename, and the reason this test executes the rule rather than
    # comparing text. `| groupBy([a])` would render perfectly and return one
    # row per EVENT, each carrying the first row's key, instead of one row per
    # distinct key.
    ("M23 groupBy emits keys but never groups on them",
     "dialects/cql_ir.py",
     "                keys=tuple(FieldRef(_field_name(key)) for key in stage.keys)))",
     "                keys=()))"),

    # `runs` RECORDED BUT NOT ENFORCED -- the fourth instance of this repo's
    # worst bug shape, and the one most likely to ship, because a
    # `with runs=2` rule renders and round-trips perfectly while matching a
    # single occurrence. The mutation is the literal bug: the repeat loop runs
    # once regardless of the count.
    ("M24 runs is set by the lowerer but the evaluator runs it once anyway",
     "engine/nodes.py",
     "            for _repeat in range(node.runs):",
     "            for _repeat in range(1):"),

    # MED-4. The `until` veto used to `return False` on the first row past the
    # window end -- an early exit that is only valid when the group's rows are
    # in TIME order. An unordered pattern's rows are in ARRIVAL order, so the
    # scan stopped early and MISSED a veto that was inside the window, letting a
    # rule reading "and no logout in that window" fire anyway. `continue` is the
    # entire fix, and the test is why it can be verified: an unordered
    # window-scope `until` is now refused by the node, so this mutation needs a
    # hand-built node to be observable at all.
    ("M25 until veto early-exits on the first out-of-window row",
     "engine/nodes.py",
     "        if window_end is not None and moment > window_end:\n"
     "            # `continue`, NOT `return False`. This single keyword is the whole\n"
     "            # bug: the group's order is not the timeline's order unless the\n"
     "            # pattern is ordered, so an out-of-window row says nothing about the\n"
     "            # rows after it.\n"
     "            continue",
     "        if window_end is not None and moment > window_end:\n"
     "            return False"),

    # A DROPPED `!` IS THE WORST FAILURE IN THIS TOOL. A `!` sits OUTSIDE a
    # step's brackets, so a parser reading only inside them loses it silently
    # -- and that does not weaken the rule, it INVERTS it: "this happened and
    # that did not" becomes "this happened", matching strictly more than the
    # analyst wrote, with no error and no caveat. The mutation makes every
    # negative stage a required one.
    ("M26 a negative stage is required to occur instead of excluded",
     "engine/nodes.py",
     "                    if stage_index in node.negative_stages:",
     "                    if False and stage_index in node.negative_stages:"),

    # THE CAVEAT NAMED THE INTERNAL SENTINEL INSTEAD OF THE FIELD. A reader
    # cannot go and look for a field called `_absent`, so the one message whose
    # job is to point at the missing column pointed at nothing -- and it was a
    # false statement about the analyst's data, produced by the module whose
    # purpose is to avoid exactly that.
    ("M27 the absent-field caveat names the sentinel, not the field",
     "engine/evaluate.py",
     "        ctx.note_uncertain(_describe_operand(expr.left), result.reason)",
     "        ctx.note_uncertain(_describe_operand(left), result.reason)"),

    # THE DEDENT, AS A MUTATION. `e7e70b3` added the repeat loop and
    # re-indented the two inserted lines, but left the per-stage walk at its old
    # indent, so it became a SIBLING of the stage loop instead of its body. The
    # loop body kept only the negative check and the two `found = False`
    # stores, and the walk ran once per repeat on whatever `stage` the loop left
    # bound -- the LAST one. Every stage in between was never evaluated, so a
    # three-stage sequence matched on its first and last stages alone.
    #
    # It shipped green because every executing sequence test used two stages,
    # where the two layouts behave identically.
    ("M28 the per-stage walk sits outside the stage loop",
     "engine/nodes.py",
     "                    if stage_index in node.negative_stages:",
     "                    if False and stage_index in node.negative_stages:"),
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
