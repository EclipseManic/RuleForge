import unittest

from rule_engine import RuleValidationError, analyze_rule, detect_siem, generate_rules, generate_workbench
from detection_model import DetectionDocument


def example(**overrides):
    payload = {
        "title": "Encoded PowerShell",
        "description": "Detect encoded PowerShell execution.",
        "severity": "high",
        "technique": "encoded_powershell",
        "field": "process.command_line",
        "operator": "contains",
        "value": "-enc",
        "threshold": 1,
        "timeframe": "5m",
        "group_by": "host.name",
        "data_source": "logs-*",
        "siems": ["splunk", "sentinel", "elastic"],
    }
    payload.update(overrides)
    return payload


class GeneratorTests(unittest.TestCase):
    def test_analyzes_simple_pasted_rule(self):
        result = analyze_rule('index=auth | search user="alice" | stats count by host', "splunk")
        self.assertEqual(result["mode"], "simple")
        self.assertEqual(result["payload_defaults"]["field"], "user")
        self.assertEqual(result["payload_defaults"]["operator"], "equals")

    def test_analyzes_multiline_siem_rule(self):
        rule = """index=windows
| search process_name=\"powershell.exe\"
| search process_command_line=\"*-enc*\"
| stats count by host
| where count >= 5"""
        result = analyze_rule(rule, "splunk")
        self.assertEqual(result["mode"], "advanced")
        self.assertGreaterEqual(len(result["conditions"]), 2)

    def test_auto_detects_rule_dialect(self):
            self.assertEqual(detect_siem('DeviceProcessEvents | where FileName =~ "powershell.exe"')["siem"], "sentinel")
            self.assertEqual(analyze_rule('<group name="local,"><rule id="100001"></rule></group>', "auto")["siem"], "wazuh")
            self.assertEqual(detect_siem("title: Suspicious PowerShell\nlogsource:\n  product: windows\ndetection:\n  selection:\n    Image: powershell.exe\n  condition: selection")["siem"], "sigma")

    def test_sigma_import_preserves_metadata_and_detection(self):
                rule = """title: Suspicious PowerShell
id: 12345678-bef0-4204-a928-ef5e620d6fcc
status: test
author: Detection Engineering
logsource:
    product: windows
detection:
    selection:
        Image|endswith: powershell.exe
    filter:
        User: trusted-admin
    condition: selection and not filter
falsepositives:
    - Administrative scripts
level: high
"""
                result = analyze_rule(rule, "sigma")
                self.assertEqual(result["native_metadata"]["status"], "test")
                self.assertEqual(result["native_metadata"]["level"], "high")
                self.assertIn("detection", result["native_sections"])
                self.assertEqual(result["conditions"][0]["field"], "Image")

    def test_sigma_is_available_as_a_generation_target(self):
        rules = generate_rules(example(siems=["sigma"], technique="custom"))
        self.assertIn("detection:", rules[0]["rule"])

    def test_yara_metadata_is_not_treated_as_detection_logic(self):
        rule = """rule test {
  meta:
    author = "Detection Engineering"
    severity = "HIGH"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
  condition:
    $e
}"""
        result = analyze_rule(rule, "google_secops")
        self.assertEqual([condition["field"] for condition in result["conditions"]], ["metadata.event_type"])

    def test_analyzer_extracts_scope_and_grouping(self):
        result = analyze_rule("index=windows | stats count by host | where count >= 5", "splunk")
        self.assertEqual(result["payload_defaults"]["data_source"], "windows")
        self.assertEqual(result["payload_defaults"]["group_by"], "host")
        self.assertTrue(result["payload_defaults"]["use_threshold"])

    def test_import_model_preserves_eql_sequence(self):
        result = analyze_rule('sequence by host.name with maxspan=5m\n [process where process.name == "winword.exe"]\n [network where destination.port == "443"]', "elastic")
        self.assertEqual(result["sequences"][0]["join_by"], "host.name")
        self.assertEqual(len(result["sequences"][0]["stages"]), 2)
        self.assertFalse(result["equivalent_recompile"])

    def test_import_model_preserves_wazuh_correlation(self):
        result = analyze_rule('<group><rule id="100210" frequency="5" timeframe="300"><if_matched_sid>5710</if_matched_sid><same_srcip /></rule></group>', "wazuh")
        self.assertEqual(result["native_metadata"]["parent_rules"], ["5710"])
        self.assertIn("same_srcip", result["native_metadata"]["same_fields"])
        self.assertEqual(result["threshold"], 5)
        self.assertEqual(result["conditions"], [])

    def test_qradar_import_preserves_aggregation_and_time(self):
        result = analyze_rule("SELECT sourceip, SUM(magnitude) AS magsum FROM events GROUP BY sourceip LAST 15 MINUTES", "qradar")
        self.assertEqual(result["aggregations"][0]["function"].upper(), "SUM")
        self.assertEqual(result["timeframe"], "15m")
        self.assertFalse(result["equivalent_recompile"])

    def test_import_model_preserves_sentinel_join(self):
        result = analyze_rule("let p = DeviceProcessEvents; p | join kind=inner network on DeviceId", "sentinel")
        self.assertEqual(result["joins"][0]["on"], "DeviceId")
        self.assertIn("join", result["native_sections"]["let_bindings"])

    def test_import_model_preserves_sentinel_streams_and_time_constraints(self):
        result = analyze_rule("""let suspicious = DeviceProcessEvents
| project DeviceId;
let network = DeviceNetworkEvents
| project DeviceId;
suspicious | join kind=inner network on DeviceId
| where NetworkTime between (ProcessTime .. ProcessTime + 10m)""", "sentinel")
        self.assertEqual(result["event_streams"][0]["source"], "DeviceProcessEvents")
        self.assertEqual(result["event_streams"][1]["source"], "DeviceNetworkEvents")
        self.assertTrue(result["time_constraints"])

    def test_import_model_preserves_splunk_lookup(self):
        result = analyze_rule("index=windows | lookup privileged_accounts user OUTPUT is_privileged", "splunk")
        self.assertEqual(result["lookups"][0]["name"], "privileged_accounts")

    def test_import_model_preserves_yara_sections(self):
        rule = '''rule x {
  meta:
    author = "a"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
  outcome:
    $risk_score = 75
  condition:
    $e
}'''
        result = analyze_rule(rule, "google_secops")
        self.assertIn("meta", result["native_sections"])
        self.assertIn("outcome", result["native_sections"])

    def test_yara_event_relationship_is_classified_as_cross_event_logic(self):
        result = analyze_rule("""rule x {
  events:
    $process.principal.hostname = $network.principal.hostname
}""", "google_secops")
        self.assertIn("cross-event join", result["unsupported_features"])

    def test_unchanged_import_preserves_original_source_artifact(self):
        source = "let suspicious = DeviceProcessEvents\n| where FileName =~ \"powershell.exe\"\n| summarize count()"
        payload = example(technique="custom", siems=["sentinel"], conditions=[{"field": "FileName", "operator": "equals", "value": "powershell.exe"}], field="FileName", operator="equals", value="powershell.exe", source_rule=source, source_siem="sentinel", preserve_source_rule=True)
        result = generate_workbench(payload)
        self.assertEqual(result["rules"][0]["rule"], source)
        self.assertEqual(result["rules"][0]["fidelity"], "exact")

    def test_compile_contract_distinguishes_preservation_from_draft(self):
        analysis = analyze_rule("sequence by host.name with maxspan=5m [process where x=\"a\"] [network where y=\"b\"]", "elastic")
        document = DetectionDocument.from_analysis(analysis)
        self.assertEqual(document.compile_decision(preserve_source=True, target_siem="elastic")["mode"], "preserve_source")
        self.assertEqual(document.compile_decision(preserve_source=False, target_siem="elastic")["mode"], "blocked_unsafe_edit")

    def test_workbench_returns_partial_compile_contract_for_imported_edit(self):
        analysis = analyze_rule("let x = DeviceProcessEvents | where FileName == \"cmd.exe\"; let y = DeviceNetworkEvents; x | join kind=inner y on DeviceId", "sentinel")
        payload = example(technique="custom", siems=["sentinel"], conditions=[{"field": "FileName", "operator": "equals", "value": "cmd.exe"}], source_rule=analysis["raw_rule"], source_siem="sentinel", source_analysis=analysis, preserve_source_rule=False)
        result = generate_workbench(payload)
        self.assertFalse(result["compile_contract"]["source"]["equivalent"])
        self.assertEqual(result["compile_contract"]["source"]["mode"], "blocked_unsafe_edit")
        self.assertFalse(result["compile_allowed"])

    def test_complex_import_cannot_use_flattened_editor(self):
        analysis = analyze_rule("sequence by host.name with maxspan=5m [process where x=\"a\"] [network where y=\"b\"]", "elastic")
        payload = example(technique="custom", siems=["elastic"], conditions=analysis["conditions"], source_rule=analysis["raw_rule"], source_siem="elastic", source_analysis=analysis, preserve_source_rule=False)
        result = generate_workbench(payload)
        self.assertFalse(result["compile_allowed"])

    def test_rejects_only_null_bytes_in_pasted_rule(self):
        with self.assertRaises(RuleValidationError):
            analyze_rule("process.name=\"powershell.exe\"\x00", "sentinel")

    def test_flags_advanced_pasted_rule_for_manual_review(self):
        result = analyze_rule('process.name == "powershell.exe" and process.command_line contains "-enc"', "sentinel")
        self.assertEqual(result["mode"], "advanced")
        self.assertEqual(len(result["conditions"]), 2)

    def test_analyzes_sentinel_has_any_and_flags_join(self):
        rule = """let p = DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand");
p | join kind=inner DeviceNetworkEvents on DeviceId"""
        result = analyze_rule(rule, "sentinel")
        self.assertEqual(result["mode"], "advanced")
        self.assertIn("cross-event join", result["unsupported_features"])
        self.assertGreaterEqual(len(result["conditions"]), 2)

    def test_flags_sequence_and_lookup_features(self):
        result = analyze_rule("sequence by host.name with maxspan=5m [process where x=\"a\"] [network where y=\"b\"] | lookup threat_feed", "elastic")
        self.assertEqual(result["mode"], "advanced")
        self.assertIn("ordered sequence", result["unsupported_features"])
        self.assertIn("lookup or enrichment", result["unsupported_features"])

    def test_compound_payload_can_omit_legacy_single_condition_fields(self):
        payload = example(conditions=[
            {"field": "process.name", "operator": "equals", "value": "powershell.exe"},
            {"field": "process.command_line", "operator": "contains", "value": "-enc"},
        ])
        payload.pop("field")
        payload.pop("operator")
        payload.pop("value")
        self.assertEqual(len(generate_rules(payload)), 3)

    def test_generates_every_requested_siem(self):
        rules = generate_rules(example())
        self.assertEqual([rule["siem"] for rule in rules], ["splunk", "sentinel", "elastic"])
        self.assertIn("index=logs-*", rules[0]["rule"])
        self.assertIn("TimeGenerated", rules[1]["rule"])
        self.assertIn("process where", rules[2]["rule"])

    def test_threshold_is_rendered(self):
        rules = generate_rules(example(threshold=5, siems=["sentinel"]))
        self.assertIn("EventCount >= 5", rules[0]["rule"])

    def test_threshold_can_be_disabled_for_single_event_rules(self):
        rules = generate_rules(example(use_threshold=False, threshold="", siems=["sentinel", "splunk", "wazuh"]))
        self.assertNotIn("EventCount >=", rules[0]["rule"])
        self.assertNotIn("stats count by", rules[1]["rule"])
        self.assertNotIn("frequency=", rules[2]["rule"])

    def test_compound_conditions_and_exclusions_are_rendered(self):
        rules = generate_rules(example(
            siems=["sentinel"],
            technique="custom",
            conditions=[
                {"field": "process.name", "operator": "equals", "value": "powershell.exe"},
                {"field": "process.command_line", "operator": "contains", "value": "-enc"},
            ],
            condition_logic="all",
            exclude_conditions=[{"field": "user.name", "operator": "equals", "value": "trusted-admin"}],
        ))
        # Verified ASIM ProcessEvent column names, not legacy SecurityEvent names.
        self.assertIn("(TargetProcessName == \"powershell.exe\" and TargetProcessCommandLine contains \"-enc\")", rules[0]["rule"])
        self.assertIn("not (TargetUsername == \"trusted-admin\")", rules[0]["rule"])

    def test_empty_exclusions_are_allowed(self):
        rules = generate_rules(example(conditions=[{"field": "host.name", "operator": "equals", "value": "sensor-1"}], exclude_conditions=[]))
        self.assertEqual(len(rules), 3)

    def test_rejects_more_than_twenty_conditions(self):
        with self.assertRaises(RuleValidationError):
            generate_rules(example(conditions=[{"field": "host.name", "operator": "equals", "value": "host"}] * 21))

    def test_google_threshold_uses_a_declared_group_variable(self):
        rule = generate_rules(example(threshold=5, siems=["google_secops"]))[0]["rule"]
        self.assertIn("$e.principal.hostname = $group", rule)
        self.assertIn("$group over 5m", rule)

    def test_generates_wazuh_custom_rule(self):
        rule = generate_rules(example(threshold=5, siems=["wazuh"]))[0]["rule"]
        self.assertIn('<rule id="100100" level="10" frequency="5" timeframe="300">', rule)
        self.assertIn("<same_field>agent.name</same_field>", rule)
        self.assertIn("<id>T1059.001</id>", rule)

    def test_known_fields_are_translated_per_siem(self):
        rule = generate_rules(example(siems=["sentinel"]))[0]
        # ASIM ProcessEvent naming (learn.microsoft.com/azure/sentinel/normalization-schema-process-event)
        self.assertIn("TargetProcessCommandLine", rule["rule"])
        self.assertEqual(rule["field_mapping"]["native_field"], "TargetProcessCommandLine")

    def test_rejects_out_of_range_wazuh_id(self):
        with self.assertRaises(RuleValidationError):
            generate_rules(example(siems=["wazuh"], wazuh_rule_id=99999))

    def test_rejects_invalid_field(self):
        with self.assertRaises(RuleValidationError):
            generate_rules(example(field="process.name | delete", siems=["splunk"]))

    def test_rejects_empty_siem_selection(self):
        with self.assertRaises(RuleValidationError):
            generate_rules(example(siems=[]))


if __name__ == "__main__":
    unittest.main()
