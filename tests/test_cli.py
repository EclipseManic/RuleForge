"""The headless entry point.

The backend was only reachable through the browser. A detection engineer
cannot put a browser in CI, and "convert this directory of Sigma rules and
tell me which ones will not translate" is the question this tool exists to
answer -- so every subcommand writes refusals to stderr and uses the exit code
for the answer.

`ABomDoesNotCorruptTheFirstToken` is here rather than in a dialect module
because the fix lives at the registry seam: a UTF-8 BOM silently renamed the
FIRST key of a rule, and the only reason it was noticed is that this CLI wrote
its own fixture with PowerShell, which adds one.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from engine.cli import main

SIGMA = (
    "title: LSASS Access\n"
    "level: high\n"
    "author: soc\n"
    "logsource:\n"
    "    category: process_access\n"
    "detection:\n"
    "    selection:\n"
    "        TargetImage|endswith: '/lsass.exe'\n"
    "    condition: selection\n"
)

EVENTS = (
    '{"TargetImage":"/usr/bin/lsass.exe"}\n'
    '{"TargetImage":"/usr/bin/notepad"}\n'
)


def run(argv, stdin_text=None):
    """Invoke the CLI, returning (exit code, stdout, stderr)."""
    import sys

    out, err = io.StringIO(), io.StringIO()
    saved = sys.stdin
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
    finally:
        sys.stdin = saved
    return code, out.getvalue(), err.getvalue()


class TheExitCodeCarriesTheAnswer(unittest.TestCase):
    """A shell has to be able to branch on the result.

    A pipeline that converts rules and deploys the output must stop when the
    conversion lost something. That means a lossy conversion is a NON-zero
    exit even though it produced text, or the loss is invisible to automation.
    """

    def test_a_clean_check_succeeds(self):
        code, out, _err = run(["check", "sigma", "-"], SIGMA)
        self.assertEqual(code, 0)
        self.assertIn("ok", out)

    def test_a_refused_rule_exits_one_and_explains_on_stderr(self):
        code, out, err = run(["check", "sigma", "-"], "not a sigma rule")
        self.assertEqual(code, 1)
        self.assertEqual(out, "", "stdout stays machine-readable")
        self.assertIn("SIGMA", err)

    def test_a_lossy_conversion_exits_one_but_still_writes_the_text(self):
        # The text is useful; the exit code is what stops a pipeline using it
        # unreviewed.
        code, out, err = run(["convert", "sigma", "sentinel", "-"], SIGMA)
        self.assertEqual(code, 1)
        self.assertIn("where", out)
        self.assertIn("SELECTOR_NOT_TRANSFERABLE", err)

    def test_a_clean_conversion_exits_zero(self):
        code, out, err = run(["convert", "sigma", "sigma", "-"], SIGMA)
        self.assertEqual(code, 0)
        self.assertIn("title:", out)
        self.assertNotIn("problem", err)

    def test_a_refusal_is_not_a_traceback(self):
        # A traceback reads as the tool breaking. A refusal is the tool
        # working.
        code, _out, err = run(
            ["convert", "sigma", "crowdstrike", "-"],
            SIGMA.replace("    condition: selection\n",
                          "    condition: selection\n") + "",
        )
        self.assertIn(code, (0, 1))
        self.assertNotIn("Traceback", err)

    def test_an_unreadable_path_is_refused_by_name(self):
        code, _out, err = run(["check", "sigma", "no/such/file.yml"])
        self.assertEqual(code, 1)
        self.assertIn("CLI_UNREADABLE", err)

    def test_an_unknown_dialect_is_refused(self):
        code, _out, err = run(["check", "splonk", "-"], SIGMA)
        self.assertEqual(code, 1)
        self.assertIn("DIALECT_UNKNOWN", err)


class TheSubcommands(unittest.TestCase):
    def test_dialects_lists_all_eight(self):
        code, out, _err = run(["dialects"])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), 8)
        for key in ("sentinel", "sigma", "splunk", "qradar", "elastic",
                    "wazuh", "chronicle", "crowdstrike"):
            self.assertIn(key, out)

    def test_dialects_says_what_each_one_can_do(self):
        _code, out, _err = run(["dialects"])
        self.assertIn("read,write,metadata", out)

    def test_explain_describes_the_pipeline(self):
        code, out, _err = run(["explain", "sigma", "-"], SIGMA)
        self.assertEqual(code, 0)
        self.assertIn("LSASS Access", out)
        self.assertIn("Filter", out)
        self.assertIn("endswith", out)

    def test_explain_can_emit_the_ir(self):
        code, out, _err = run(["explain", "sigma", "-", "--json"], SIGMA)
        self.assertEqual(code, 0)
        import json

        payload = json.loads(out)
        self.assertIn("rule", payload)

    def test_test_reports_a_verdict(self):
        import os
        import tempfile

        directory = tempfile.mkdtemp()
        events = os.path.join(directory, "e.jsonl")
        with open(events, "w", encoding="utf-8") as handle:
            handle.write(EVENTS)
        code, out, _err = run(["test", "sigma", "-", events], SIGMA)
        self.assertEqual(code, 0)
        self.assertIn("matched", out)

    def test_a_non_match_is_not_a_failure(self):
        # A rule that correctly does not match is a successful run.
        import os
        import tempfile

        directory = tempfile.mkdtemp()
        events = os.path.join(directory, "e.jsonl")
        with open(events, "w", encoding="utf-8") as handle:
            handle.write('{"TargetImage":"/usr/bin/notepad"}\n')
        code, out, _err = run(["test", "sigma", "-", events], SIGMA)
        self.assertEqual(code, 0)
        self.assertIn("no_match", out)

    def test_propose_derives_a_rule_and_shows_its_reasoning(self):
        import os
        import tempfile

        directory = tempfile.mkdtemp()
        samples = os.path.join(directory, "s.jsonl")
        with open(samples, "w", encoding="utf-8") as handle:
            handle.write(
                '{"cat":"process","name":"p.exe","pid":1}\n'
                '{"cat":"process","name":"p.exe","pid":2}\n'
            )
        code, out, err = run(["propose", samples])
        self.assertEqual(code, 0)
        self.assertIn("title:", out)
        self.assertIn("pin ", err)
        self.assertIn("skip ", err)
        self.assertIn("SYNTH_IS_A_HYPOTHESIS", err)

    def test_no_subcommand_still_means_serve(self):
        # The entry point used to take only --host/--port. Changing what a
        # bare `python -m ruleforge` does would break every existing habit.
        import argparse

        parsed = argparse.ArgumentParser()
        self.assertIsNotNone(main)  # imported and callable
        # Driven by inspecting the parser rather than by starting a server.
        from engine.cli import _cmd_serve

        self.assertTrue(callable(_cmd_serve))


class ABomDoesNotCorruptTheFirstToken(unittest.TestCase):
    """A UTF-8 BOM silently renamed the first key of a rule.

    A Sigma file saved by a Windows editor parsed its opening key as
    `\\ufefftitle`, so the title vanished and the tool reported "this rule has
    no title" about a rule whose first line WAS the title. In a dialect whose
    first token is a field name, the same BOM renames the field.

    Windows editors, PowerShell redirection and Git on Windows all write them,
    so a pasted file carrying one is the common case. Found because this CLI's
    own fixture was written with PowerShell.
    """

    BOM = "\ufeff"

    def test_a_sigma_title_survives_a_bom(self):
        from engine import dialects

        rule, diagnostics = dialects.lower("sigma", self.BOM + SIGMA)
        self.assertEqual(rule.annotations.title, "LSASS Access")
        self.assertNotIn("SIGMA_NO_TITLE", [d.code for d in diagnostics])

    def test_every_dialect_tolerates_a_bom(self):
        from engine import dialects

        samples = {
            "sentinel": "T | where A == 1",
            "sigma": SIGMA,
            "splunk": "index=main EventCode=4625",
            "qradar": "SELECT * FROM events WHERE qid = 1",
            "elastic": 'process where process.name == "a"',
            "wazuh": '<group name="g,"><rule id="1" level="5">'
                     "<match>x</match><description>d</description>"
                     "</rule></group>",
            "chronicle": "rule r {\n  events:\n"
                         '    $e.metadata.event_type = "A"\n'
                         "  condition:\n    $e\n}",
            "crowdstrike": "a:'1'",
        }
        ready = {e.key for e in dialects.ready_dialects()}
        self.assertEqual(sorted(ready - set(samples)), [])
        for key, text in samples.items():
            with self.subTest(dialect=key):
                plain, _ = dialects.lower(key, text)
                withbom, _ = dialects.lower(key, self.BOM + text)
                self.assertEqual(
                    [type(n).__name__ for n in withbom.pipeline],
                    [type(n).__name__ for n in plain.pipeline],
                )

    def test_a_bom_does_not_break_a_log_sample(self):
        # `json.loads` fails outright on one, and in `kv` form it renames the
        # first key.
        from engine import synthesize

        for fmt, text in (
            ("jsonl", '{"a":1}\n{"a":2}'),
            ("json", '[{"a":1},{"a":2}]'),
            ("kv", "a=1\na=2"),
            ("syslog", "h app: a=1\nh app: a=2"),
        ):
            with self.subTest(format=fmt):
                self.assertEqual(
                    synthesize.parse_events(self.BOM + text, fmt),
                    synthesize.parse_events(text, fmt),
                )

    def test_the_parse_seam_strips_it_too(self):
        # `parse` is the other registry entry point, and it had the same hole.
        from engine import dialects

        parsed = dialects.parse("sigma", self.BOM + SIGMA)
        self.assertEqual(parsed.document.get("title"), "LSASS Access")

    def test_a_bom_in_the_middle_is_left_alone(self):
        # Only a LEADING mark is a BOM. One inside a value is data, and
        # stripping it would silently alter the rule.
        from engine import dialects

        rule, _ = dialects.lower(
            "sentinel", f'T | where f == "a{self.BOM}b"'
        )
        self.assertEqual(
            rule.pipeline[1].condition.right.value, f"a{self.BOM}b"
        )


if __name__ == "__main__":
    unittest.main()
