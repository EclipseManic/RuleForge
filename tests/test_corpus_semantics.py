"""Representative positive/negative checks for the external dialect corpus.

The corpus runner proves that a rule parses and round-trips.  These checks add
the other half of that guarantee: a small, deliberately chosen sample must
produce the verdict the rule's predicates describe.  They stay focused on
locally evaluable constructs; vendor-only regex engines and appliance lookups
are covered by their explicit ``not_evaluated`` tests in the dialect suites.
"""

from __future__ import annotations

import unittest

from engine import dialects
from engine.pipeline import Verdict, evaluate


class CorpusSemantics(unittest.TestCase):
    def assert_rule_matches_only(self, dialect: str, text: str,
                                 positive: list[dict],
                                 negative: list[dict]) -> None:
        rule, _ = dialects.lower(dialect, text)
        hit = evaluate(rule, positive)
        miss = evaluate(rule, negative)
        self.assertEqual(hit.verdict, Verdict.MATCHED,
                         f"{dialect} positive caveats: {hit.caveats}")
        self.assertEqual(miss.verdict, Verdict.NO_MATCH,
                         f"{dialect} negative caveats: {miss.caveats}")

    def test_sentinel_event_predicate(self):
        self.assert_rule_matches_only(
            "sentinel",
            "SecurityEvent | where EventID == 4625",
            [{"EventID": 4625, "TimeGenerated": 1}],
            [{"EventID": 4624, "TimeGenerated": 1}],
        )

    def test_sigma_selection(self):
        self.assert_rule_matches_only(
            "sigma",
            "title: Failed Logon\n"
            "logsource:\n  product: windows\n  service: security\n"
            "detection:\n  selection:\n    EventID: 4625\n"
            "  condition: selection\n",
            [{"EventID": 4625}],
            [{"EventID": 4624}],
        )

    def test_splunk_field_predicate(self):
        self.assert_rule_matches_only(
            "splunk",
            "index=wineventlog EventCode=4625",
            [{"EventCode": 4625}],
            [{"EventCode": 4624}],
        )

    def test_qradar_where_predicate(self):
        self.assert_rule_matches_only(
            "qradar",
            "SELECT * FROM events WHERE qid = 28250080 "
            "AND username = 'admin'",
            [{"qid": 28250080, "username": "admin", "starttime": 1}],
            [{"qid": 28250080, "username": "bob", "starttime": 1}],
        )

    def test_elastic_sequence_preserves_order(self):
        rule, _ = dialects.lower(
            "elastic",
            'sequence by host.id with maxspan=5m\n'
            '  [process where process.name == "procdump.exe"]\n'
            '  [process where process.name : "*lsass*"]',
        )
        forward = [
            {"@timestamp": 1, "event": {"category": "process"},
             "process": {"name": "procdump.exe"}, "host": {"id": "H1"}},
            {"@timestamp": 2, "event": {"category": "process"},
             "process": {"name": "lsass.exe"}, "host": {"id": "H1"}},
        ]
        reverse = [
            {"@timestamp": 1, "event": {"category": "process"},
             "process": {"name": "lsass.exe"}, "host": {"id": "H1"}},
            {"@timestamp": 2, "event": {"category": "process"},
             "process": {"name": "procdump.exe"}, "host": {"id": "H1"}},
        ]
        self.assertEqual(evaluate(rule, forward).verdict, Verdict.MATCHED)
        self.assertEqual(evaluate(rule, reverse).verdict, Verdict.NO_MATCH)

    def test_wazuh_field_predicates(self):
        self.assert_rule_matches_only(
            "wazuh",
            '<group name="windows,"><rule id="100" level="10">'
            '<field name="win.eventdata.targetImage">lsass.exe</field>'
            '<field name="win.eventdata.grantedAccess">0x1010</field>'
            '<description>LSASS access</description></rule></group>',
            [{"win": {"eventdata": {"targetImage": "lsass.exe",
                                      "grantedAccess": "0x1010"}}}],
            [{"win": {"eventdata": {"targetImage": "notepad.exe",
                                      "grantedAccess": "0x1010"}}}],
        )

    def test_chronicle_regex_predicate(self):
        self.assert_rule_matches_only(
            "chronicle",
            'rule x {\n events:\n'
            '  $e.metadata.event_type = "PROCESS_ACCESS"\n'
            '  $e.target.process.file.full_path = /\\\\lsass\\.exe$/ nocase\n'
            ' condition:\n  $e\n}',
            [{"metadata": {"event_type": "PROCESS_ACCESS"},
              "target": {"process": {"file": {
                  "full_path": r"C:\\LSASS.EXE"}}}}],
            [{"metadata": {"event_type": "PROCESS_ACCESS"},
              "target": {"process": {"file": {
                  "full_path": r"C:\\notepad.exe"}}}}],
        )

    def test_crowdstrike_list_predicate(self):
        self.assert_rule_matches_only(
            "crowdstrike",
            "event_simpleName:'ProcessRollup2'+"
            "FileName:['a.exe','b.exe']",
            [{"event_simpleName": "ProcessRollup2", "FileName": "b.exe"}],
            [{"event_simpleName": "ProcessRollup2", "FileName": "c.exe"}],
        )


if __name__ == "__main__":
    unittest.main()
