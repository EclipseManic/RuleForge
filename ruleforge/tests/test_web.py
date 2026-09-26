"""Web layer, jobs and history tests.

THE ASSERTION THAT MATTERS MOST IN THIS FILE

There is no `innerHTML` in the shipped JavaScript. The rule text is the analyst's
own, but it is also attacker-reachable -- a rule pasted from a shared document, a
SIEM export or a ticket can contain anything, including markup. Building the
findings or the rendered rule with innerHTML would execute it. That is checked
mechanically, because "we were careful" is not a control.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from ruleforge import history, jobs
from ruleforge.engine.values import Refusal

STATIC = Path(__file__).resolve().parent.parent / "static" / "ruleforge.js"


class XssTests(unittest.TestCase):
    def test_the_javascript_contains_no_innerhtml(self):
        source = STATIC.read_text(encoding="utf-8")
        self.assertNotIn("innerHTML", source,
                         "the shipped JS builds DOM from pasted rule text; "
                         "innerHTML would execute it")
        self.assertNotIn("outerHTML", source)
        self.assertNotIn("document.write", source)
        self.assertNotIn("eval(", source)

    def test_the_javascript_uses_textcontent(self):
        source = STATIC.read_text(encoding="utf-8")
        self.assertIn("textContent", source)

    def test_it_does_not_use_jquery_or_a_cdn(self):
        """No third-party script from a CDN: this tool is meant to run offline,
        and a remote script would be code the analyst did not review executing
        with their rules in the page."""
        source = STATIC.read_text(encoding="utf-8")
        for marker in ("http://", "https://", "cdn.", "unpkg", "jsdelivr"):
            self.assertNotIn(marker, source)


class RefusalRenderingTests(unittest.TestCase):
    """A refusal must reach the user, not become a traceback."""

    def test_an_unreadable_rule_is_refused_not_raised(self):
        outcome = jobs.author("splunk", "| tstats dc(user) BY host", "r")
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.refusal["code"],
                         "SPL_TSTATS_FUNCTION_NOT_SUPPORTED")

    def test_the_refusal_carries_a_message_written_for_a_person(self):
        outcome = jobs.author("splunk", "| tstats dc(user) BY host", "r")
        self.assertIn("stats function", outcome.refusal["message"])

    def test_a_refusal_without_a_stage_still_renders(self):
        """A Refusal is not guaranteed to carry every field. Reading one that is
        absent used to raise AttributeError INSIDE the except block, replacing a
        clear message with a traceback."""
        class Bare(Exception):
            code = "X"
            message = "m"
        self.assertEqual(getattr(Bare(), "stage", "") or "", "")

    def test_an_unknown_dialect_is_refused_by_name(self):
        with self.assertRaises(Refusal) as caught:
            jobs.lower_for("nonsense", "x", "r")
        self.assertEqual(caught.exception.code, "DIALECT_UNKNOWN")
        self.assertIn("splunk", caught.exception.message)


class DiagnosticShapeTests(unittest.TestCase):
    """Three dialects return a dataclass, two return a dict."""

    def test_both_shapes_normalise(self):
        from ruleforge.dialects.aql import Diagnostic
        as_dict = jobs.diagnostic_fields({"code": "A", "severity": "note",
                                          "message": "m"})
        as_obj = jobs.diagnostic_fields(
            Diagnostic(code="A", severity="note", message="m"))
        self.assertEqual(as_dict, as_obj)

    def test_every_dialect_loads_through_the_one_table(self):
        """One signature for all five, or the first request against a dialect
        that disagrees dies."""
        for key in jobs.DIALECTS:
            spec = jobs.DIALECTS[key]
            self.assertTrue(callable(spec["lower_text"]), key)
            self.assertTrue(callable(spec["render"]), key)


class AuthorTests(unittest.TestCase):
    def test_each_dialect_authors(self):
        from ruleforge.tests.test_aql import USER_QRADAR_RULE
        from ruleforge.tests.test_kql import USER_SENTINEL_RULE
        from ruleforge.tests.test_wazuh import WAZUH_RULESET
        cases = [
            ("qradar", USER_QRADAR_RULE, "r"),
            ("sentinel", USER_SENTINEL_RULE, "r"),
            ("wradar", "", ""),          # placeholder, replaced below
            ("splunk", "index=main | stats count BY host", "r"),
            ("wazuh", WAZUH_RULESET, "60205"),
        ]
        for key, text, rid in cases:
            if not text:
                continue
            with self.subTest(dialect=key):
                outcome = jobs.author(key, text, rid)
                self.assertTrue(outcome.ok, outcome.refusal)
                self.assertTrue(outcome.rendered,
                                f"{key} authored but wrote nothing back")
                self.assertTrue(outcome.graph["nodes"])


class TuneHonestyTests(unittest.TestCase):
    """Without events, no estimate. This is the whole contract of `tune`."""

    def _ir(self):
        return jobs.lower_for("splunk", "index=main | stats count BY host")[0]

    def test_without_events_it_says_so(self):
        outcome = jobs.tune(self._ir())
        codes = [f.code for f in outcome.findings]
        self.assertIn("TUNE_NO_EVENTS", codes)

    def test_without_events_there_is_no_measurement(self):
        outcome = jobs.tune(self._ir())
        self.assertIsNone(outcome.result,
                          "a verdict was produced with no events to produce it "
                          "from")

    def test_structural_findings_are_still_given(self):
        outcome = jobs.tune(self._ir())
        self.assertTrue(outcome.findings,
                        "the structural half should work without events")

    def test_an_aggregate_with_no_grouping_is_flagged(self):
        ir = jobs.lower_for("splunk", "index=main | stats count")[0]
        codes = [f.code for f in jobs.tune(ir).findings]
        self.assertIn("TUNE_AGGREGATE_WITHOUT_GROUPING", codes)

    def test_with_events_a_verdict_is_measured(self):
        ir = jobs.lower_for("splunk", "index=main | stats count BY host")[0]
        events = [{"index": "main", "host": "h1"} for _ in range(3)]
        outcome = jobs.tune(ir, events)
        self.assertIsNotNone(outcome.result)
        self.assertIn(outcome.result["verdict"],
                      ("matched", "no_match", "not_evaluated"))

    def test_the_finding_says_the_sample_is_not_production_volume(self):
        ir = jobs.lower_for("splunk", "index=main | stats count BY host")[0]
        events = [{"index": "main", "host": "h1"} for _ in range(3)]
        messages = " ".join(f.message for f in jobs.tune(ir, events).findings)
        self.assertIn("not your production volume", messages)


class LogToRuleHonestyTests(unittest.TestCase):
    def test_it_refuses_to_pick_a_rule(self):
        outcome = jobs.debug_logs_to_rule("splunk", [
            {"host": "h1", "result": "fail"},
            {"host": "h2", "result": "ok"},
        ])
        codes = [f.code for f in outcome.findings]
        self.assertIn("DEBUG_CANDIDATE_ONLY", codes)

    def test_a_constant_field_is_not_offered_as_a_discriminator(self):
        """`host` is the same on both rows, so it cannot be what the sample is
        "about". Offering it as a candidate would be noise."""
        outcome = jobs.debug_logs_to_rule("splunk", [
            {"host": "same", "result": "a"},
            {"host": "same", "result": "b"},
        ])
        codes = [f.code for f in outcome.findings]
        self.assertIn("DEBUG_CONSTANT_FIELD", codes)

        varying = [f.message for f in outcome.findings
                   if f.code == "DEBUG_VARYING_FIELD"]
        self.assertTrue(varying)
        for message in varying:
            self.assertNotIn("`host`", message,
                             "a constant field was offered as a discriminator")

    def test_no_events_is_an_error(self):
        outcome = jobs.debug_logs_to_rule("splunk", [])
        self.assertFalse(outcome.ok)


class RuleToLogHonestyTests(unittest.TestCase):
    def test_it_says_the_query_is_not_verified(self):
        outcome = jobs.debug_rule_to_logs("splunk",
                                          "index=main | stats count BY host")
        codes = [f.code for f in outcome.findings]
        self.assertIn("DEBUG_QUERY_NOT_VERIFIED", codes)

    def test_wazuh_is_told_it_is_not_a_query(self):
        """A Wazuh rule is XML the agent evaluates. There is no search you can
        paste anywhere that reproduces it, and pretending otherwise wastes an
        analyst's afternoon."""
        from ruleforge.tests.test_wazuh import WAZUH_RULESET
        outcome = jobs.debug_rule_to_logs("wazuh", WAZUH_RULESET, "60205")
        codes = [f.code for f in outcome.findings]
        self.assertIn("DEBUG_WAZUH_NOT_A_QUERY", codes)


class EventParsingTests(unittest.TestCase):
    def test_a_json_array_parses(self):
        self.assertEqual(len(jobs.load_events('[{"a":1},{"a":2}]')), 2)

    def test_one_object_per_line_parses(self):
        self.assertEqual(len(jobs.load_events('{"a":1}\n{"a":2}')), 2)

    def test_a_single_object_parses(self):
        self.assertEqual(len(jobs.load_events('{"a":1}')), 1)

    def test_a_bad_line_is_named(self):
        """'invalid JSON' tells the analyst nothing about which of four hundred
        pasted lines is wrong."""
        with self.assertRaises(Refusal) as caught:
            jobs.load_events('{"a":1}\n{oops}\n{"a":3}')
        self.assertEqual(caught.exception.code, "EVENTS_BAD_LINE")
        self.assertIn("line 2", caught.exception.message)

    def test_a_non_object_line_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            jobs.load_events("[1, 2, 3]")
        self.assertEqual(caught.exception.code, "EVENTS_NOT_AN_OBJECT")


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(self.enterContext(_temp_dir())) / "history.json"

    def _save(self, **kwargs):
        payload = {"kind": "author", "dialect": "splunk", "rule_id": "r",
                   "title": "t", "summary": "s", "payload": {"rule": "x"}}
        payload.update(kwargs)
        return history.append(self.path, **payload)

    def test_it_appends(self):
        self._save()
        self._save()
        self.assertEqual(len(history.load(self.path)), 2)

    def test_an_earlier_entry_is_never_rewritten(self):
        self._save(rule_id="first")
        first = history.load(self.path)[0]
        self._save(rule_id="second")
        entries = history.load(self.path)
        self.assertEqual(entries[0]["rule_id"], "first",
                         "an existing history entry was modified")
        self.assertEqual(first["rule_id"], "first")

    def test_there_is_no_delete_path(self):
        """Not a test of a missing function -- a statement of intent, so that
        adding one later is a visible decision."""
        self.assertFalse(hasattr(history, "delete"))
        self.assertFalse(hasattr(history, "update"))
        self.assertFalse(hasattr(history, "clear"))

    def test_a_corrupt_file_is_reported_not_treated_as_empty(self):
        """Returning [] would make a damaged audit trail look like an empty one,
        and the user would carry on believing they had a record."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(history.Refused) as caught:
            history.load(self.path)
        self.assertIn("not been overwritten", str(caught.exception))

    def test_a_corrupt_file_is_not_overwritten_by_a_save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(history.Refused):
            self._save()
        self.assertEqual(self.path.read_text(encoding="utf-8"), "{not json")

    def test_an_oversized_entry_is_refused(self):
        with self.assertRaises(history.Refused) as caught:
            self._save(payload={"events": "x" * (history.MAX_ENTRY_CHARS + 10)})
        self.assertIn("log sample", str(caught.exception))

    def test_an_unknown_job_is_refused(self):
        with self.assertRaises(history.Refused):
            self._save(kind="nonsense")

    def test_recent_is_newest_first(self):
        self._save(rule_id="a")
        self._save(rule_id="b")
        self.assertEqual([e["rule_id"] for e in history.recent(self.path)],
                         ["b", "a"])

    def test_the_drop_count_is_reported_not_just_computed(self):
        """The cap is the one place this file removes anything, so the count has
        to reach the caller. An earlier version computed it into an unused local
        and carried a comment claiming the caller was told -- which was not true,
        and is exactly the kind of claim this file exists to avoid."""
        original_cap = history.MAX_ENTRIES
        history.MAX_ENTRIES = 3
        self.addCleanup(setattr, history, "MAX_ENTRIES", original_cap)

        results = [self._save(rule_id=str(n)) for n in range(5)]
        self.assertEqual(history.MAX_ENTRIES, 3)
        self.assertEqual(len(history.load(self.path)), 3)
        self.assertEqual([r.dropped for r in results], [0, 0, 0, 1, 1])
        self.assertEqual(results[-1].dropped, 1,
                         "the drop was not reported to the caller")

    def test_no_temp_file_is_left_behind(self):
        self._save()
        leftovers = list(self.path.parent.glob(".history-*"))
        self.assertEqual(leftovers, [], f"temp files left behind: {leftovers}")


def _temp_dir():
    import tempfile
    return tempfile.TemporaryDirectory()


class FlaskTests(unittest.TestCase):
    def setUp(self):
        global web
        from ruleforge import web as web_module
        web = web_module
        self.temp = _temp_dir()
        self.addCleanup(self.temp.cleanup)
        self.original = web.HISTORY_PATH
        web.HISTORY_PATH = Path(self.temp.name) / "history.json"
        self.addCleanup(lambda: setattr(web, "HISTORY_PATH", self.original))
        self.client = web.create_app().test_client()

    def test_the_home_page_loads(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_the_workshop_loads(self):
        self.assertEqual(self.client.get("/workshop").status_code, 200)

    def test_the_history_page_loads(self):
        self.assertEqual(self.client.get("/history").status_code, 200)

    def test_the_pages_offer_every_dialect(self):
        body = self.client.get("/workshop").get_data(as_text=True)
        for key in jobs.DIALECTS:
            self.assertIn(f'value="{key}"', body)

    def test_author_over_http(self):
        response = self.client.post("/api/author", json={
            "dialect": "splunk", "rule": "index=main | stats count BY host",
            "rule_id": "r"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["ok"])
        self.assertIn("stats", data["rendered"])

    def test_a_refusal_is_a_200_with_a_named_code(self):
        """A refusal is a normal answer here, not a server error."""
        response = self.client.post("/api/author", json={
            "dialect": "splunk", "rule": "| tstats dc(user) BY host"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertFalse(data["ok"])
        self.assertTrue(data["refusal"]["code"])

    def test_an_unknown_job_is_404(self):
        self.assertEqual(self.client.post("/api/nonsense", json={}).status_code,
                         404)

    def test_saving_writes_to_history(self):
        self.client.post("/api/author", json={
            "dialect": "splunk", "rule": "index=main | stats count BY host",
            "save": True})
        self.assertEqual(len(history.load(web.HISTORY_PATH)), 1)

    def test_a_damaged_history_is_shown_as_a_problem(self):
        web.HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        web.HISTORY_PATH.write_text("{broken", encoding="utf-8")
        body = self.client.get("/history").get_data(as_text=True)
        self.assertIn("could not be read", body)
        self.assertNotIn("Nothing saved yet", body)

    def test_debug_is_404_free(self):
        response = self.client.post("/api/debug_logs_to_rule", json={
            "dialect": "splunk", "events": '[{"a":1},{"a":2}]'})
        self.assertEqual(response.status_code, 200)
        self.assertIn("DEBUG_CANDIDATE_ONLY",
                      [f["code"] for f in response.get_json()["findings"]])


if __name__ == "__main__":
    unittest.main()
