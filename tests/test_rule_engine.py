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

    def test_wazuh_refuses_out_of_range_counts_per_target(self):
        """Wazuh frequency is 2-9999 and timeframe is capped at 99999 SECONDS.

        The generic parser accepted a threshold of 10000 and a 999d window, so a request
        could return HTTP 200 carrying attribute values Wazuh rejects. It must refuse, and
        it must refuse THIS target: rejecting the whole request would cost the analyst
        every other selected target because of one Wazuh setting.
        """
        from rule_engine import _wazuh_attribute_problems
        self.assertEqual(_wazuh_attribute_problems(1, "5m"), [],
                         msg="threshold 1 emits no frequency, so it is always valid")
        self.assertEqual(_wazuh_attribute_problems(9999, "5m"), [])
        self.assertTrue(_wazuh_attribute_problems(10000, "5m"),
                        msg="frequency 10000 exceeds the documented 9999 maximum")
        self.assertTrue(_wazuh_attribute_problems(5, "999d"),
                        msg="999d is 86,313,600s, far past the 99999s cap")
        self.assertEqual(_wazuh_attribute_problems(5, "1d"), [])

        # Per-target refusal: the other targets still compile.
        rules = generate_rules(example(threshold=10000, use_threshold=True,
                                      siems=["splunk", "wazuh", "sentinel"]))
        by_siem = {r["siem"]: r for r in rules}
        self.assertTrue(by_siem["wazuh"].get("refused"),
                        msg="Wazuh must refuse an out-of-range frequency")
        self.assertEqual(by_siem["wazuh"]["rule"], "",
                         msg="a refused target must not emit a rule body")
        self.assertIn("9999", by_siem["wazuh"]["refusal_reason"])
        for other in ("splunk", "sentinel"):
            self.assertFalse(by_siem[other].get("refused"),
                             msg=f"{other} must be unaffected by the Wazuh refusal")
            self.assertTrue(by_siem[other]["rule"].strip(),
                            msg=f"{other} must still produce a rule")

    def test_wazuh_timeframe_attribute_keeps_exact_seconds(self):
        """Wazuh's timeframe counts SECONDS, so a 30s window must stay 30.

        The renderer went through a minutes helper, which can only express whole minutes
        and rounds up: 30s became 60 and 61s became 120. The UI advertises 30s, so this
        silently changed the count window the analyst asked for. QRadar's `LAST n MINUTES`
        genuinely needs whole minutes and keeps the rounding helper.
        """
        from rule_engine import _timeframe_seconds
        self.assertEqual(_timeframe_seconds("30s"), 30)
        self.assertEqual(_timeframe_seconds("61s"), 61)
        self.assertEqual(_timeframe_seconds("5m"), 300)
        self.assertEqual(_timeframe_seconds("2h"), 7200)
        self.assertEqual(_timeframe_seconds("1d"), 86400)
        for window, expected in (("30s", 30), ("61s", 61), ("5m", 300), ("1h", 3600)):
            rule = generate_rules(example(threshold=5, use_threshold=True, timeframe=window,
                                          siems=["wazuh"]))[0]
            self.assertIn(f'timeframe="{expected}"', rule["rule"],
                          msg=f"window {window} must reach Wazuh unaltered")
        self.assertIn("LAST 1 MINUTES",
                      generate_rules(example(threshold=5, use_threshold=True, timeframe="30s",
                                             siems=["qradar"]))[0]["rule"],
                      msg="QRadar can only say whole minutes, so 30s rounds up to 1")

    def test_wazuh_is_not_refused_for_a_window_it_never_emits(self):
        """No count means no frequency and no timeframe attribute at all.

        The bound was checked unconditionally, so a 999d window with thresholding turned
        off refused Wazuh for a value the generated rule never contained - costing the
        analyst the target for a limit their output does not hit.
        """
        from rule_engine import _wazuh_attribute_problems
        self.assertEqual(_wazuh_attribute_problems(None, "999d"), [],
                         msg="no threshold means neither attribute is emitted")
        self.assertEqual(_wazuh_attribute_problems(1, "999d"), [],
                         msg="threshold 1 emits no frequency, so no timeframe either")
        rules = generate_rules(example(threshold=1, use_threshold=False, timeframe="999d",
                                      siems=["wazuh", "splunk"]))
        by_siem = {r["siem"]: r for r in rules}
        self.assertFalse(by_siem["wazuh"].get("refused"),
                         msg="an unemitted attribute must not refuse the target")
        self.assertNotIn("timeframe=", by_siem["wazuh"]["rule"])
        # The cap still applies once a count is on, which is the only time it can bite.
        self.assertTrue(_wazuh_attribute_problems(5, "999d"))

    def test_an_advanced_wazuh_request_is_refused_per_target_not_raised(self):
        """A correlation request reaches render_wazuh through compile_model, not RENDERERS.

        The per-target refusal only wrapped the flat path, so an out-of-range count on a
        sequence request escaped as an unhandled exception and cost the analyst every other
        selected target too.
        """
        from compiler.pipeline import compile_request
        from rule_engine import parse_request
        request = parse_request(example(
            threshold=10000, use_threshold=True, siems=["sentinel", "wazuh"],
            correlation={"aggregations": [{"function": "dc", "field": "destination.ip", "alias": "d"}]}))
        out = compile_request(request, "wazuh")
        self.assertTrue(out.get("refused"))
        self.assertEqual(out["rule"], "", msg="a refused advanced target emits no rule body")
        self.assertIn("9999", out["refusal_reason"])
        self.assertEqual(out["refusal_kind"], "target_constraint")
        other = compile_request(request, "sentinel")
        self.assertFalse(other.get("refused"))
        self.assertTrue(other["rule"].strip())

    def test_a_refusal_is_not_reported_as_a_strict_mode_refusal(self):
        """Two different things refuse a target and the UI must not conflate them.

        Strict mode refuses lossy conversions and is switched off in the form. A vendor
        range violation cannot be switched off, so telling the analyst to disable strict
        mode for it sends them to fix the wrong control.
        """
        rules = generate_rules(example(threshold=10000, use_threshold=True,
                                      siems=["wazuh", "elastic"], strict=True))
        by_siem = {r["siem"]: r for r in rules}
        self.assertEqual(by_siem["wazuh"]["refusal_kind"], "target_constraint")
        strict = generate_rules(example(threshold=5, use_threshold=True, siems=["splunk"],
                                       strict=True,
                                       correlation={"sequences": [{"join_by": "host.name", "maxspan": "5m",
                                                                  "stages": [{"event": "a", "condition": ""},
                                                                             {"event": "b", "condition": ""}]}]}))
        refused = [r for r in strict if r.get("refused")]
        self.assertTrue(refused, msg="strict mode must still refuse a lossy target")
        self.assertEqual(refused[0]["refusal_kind"], "strict_fidelity")

    def test_source_preservation_does_not_revive_a_refused_target(self):
        """Preservation overwrote `rule` on an item still marked refused/validation failed.

        A consumer reading that bundle got a non-empty Wazuh rule from a target that had
        just been refused, with fidelity upgraded to exact. The refusal is the truth.
        """
        payload = example(threshold=10000, use_threshold=True, siems=["wazuh", "splunk"],
                          source_rule="<rule id=\"100100\" frequency=\"10000\"/>",
                          source_siem="wazuh", preserve_source_rule=True)
        result = generate_workbench(payload)
        by_siem = {r["siem"]: r for r in result["rules"]}
        wazuh = by_siem["wazuh"]
        self.assertTrue(wazuh.get("refused"))
        self.assertEqual(wazuh["rule"], "",
                         msg="a refused target must not be handed a rule body")
        self.assertEqual(wazuh["validation"], "failed")
        self.assertNotEqual(wazuh.get("fidelity"), "exact",
                            msg="a refused target cannot be an exact preservation")
        self.assertIn("not", wazuh["review_note"])
        self.assertTrue(by_siem["splunk"]["rule"].strip())

    def test_preservation_contract_reports_reality_not_intent(self):
        """The bundle-level contract described the REQUEST, not what the bundle contains.

        With a real imported source, preservation that was skipped because the target
        refused still produced `mode: preserve_source, equivalent: true` and
        `compile_allowed: true` - a false passing contract next to a target that emitted
        nothing. The contract, the gate and the allowed flag now all read from whether
        preservation actually happened.
        """
        analysis = analyze_rule('<group><rule id="100210" frequency="5" timeframe="60"><same_srcip /></rule></group>', "wazuh")
        payload = example(threshold=10000, use_threshold=True, siems=["wazuh"],
                          technique="custom",
                          conditions=[{"field": "CommandLine", "operator": "contains", "value": "-enc"}],
                          source_rule=analysis["raw_rule"], source_siem="wazuh",
                          source_analysis=analysis, preserve_source_rule=True)
        result = generate_workbench(payload)
        self.assertEqual(result["compile_contract"]["source"]["mode"], "preserve_source_not_applied")
        self.assertFalse(result["compile_contract"]["source"]["equivalent"])
        self.assertFalse(result["compile_allowed"],
                         msg="nothing in this bundle is the source artifact")
        skipped = [g for g in result["quality_gates"] if g["title"] == "Source preservation skipped"]
        self.assertEqual(len(skipped), 1, msg="skipping preservation must say so once")
        self.assertIn("wazuh", skipped[0]["detail"])
        self.assertEqual(result["rules"][0]["rule"], "")

    def test_a_preserved_source_is_the_only_artifact_reported(self):
        """Only `rule` was replaced with the source, so `query`, checks and validation
        still described the generated draft it had just been overwritten with. A consumer
        could read a source rule next to a passing verdict on different text."""
        source_text = '<group><rule id="100210" frequency="5" timeframe="60"><same_srcip /></rule></group>'
        analysis = analyze_rule(source_text, "wazuh")
        payload = example(threshold=5, use_threshold=True, siems=["wazuh"], technique="custom",
                          conditions=[{"field": "CommandLine", "operator": "contains", "value": "-enc"}],
                          source_rule=source_text, source_siem="wazuh",
                          source_analysis=analysis, preserve_source_rule=True)
        rule = generate_workbench(payload)["rules"][0]
        self.assertEqual(rule["rule"], source_text)
        self.assertEqual(rule["query"], source_text,
                         msg="query must not keep describing the overwritten draft")
        self.assertEqual(rule["validation"], "unverified",
                         msg="this tool did not validate text it passed through")
        self.assertTrue(any("did not re-validate" in c for c in rule["checks"]))
        self.assertEqual(rule["warnings"], [])

    def test_wazuh_import_round_trips_seconds_exactly(self):
        """Wazuh stores its timeframe in seconds; importing one rounded it to whole minutes.

        61s came back as 1m and 90s as 2m, so recompiling an imported rule silently changed
        its count window. A valid 99999s also had to survive the window grammar, which only
        accepted three digits.
        """
        from rule_engine import _duration_from_seconds
        self.assertEqual(_duration_from_seconds(30), "30s")
        self.assertEqual(_duration_from_seconds(61), "61s")
        self.assertEqual(_duration_from_seconds(90), "90s")
        self.assertEqual(_duration_from_seconds(300), "5m")
        self.assertEqual(_duration_from_seconds(3600), "1h")
        self.assertEqual(_duration_from_seconds(99999), "99999s")
        for seconds, expected in ((30, "30s"), (61, "61s"), (90, "90s"), (600, "10m"), (99999, "99999s")):
            raw = f'<group><rule id="100210" frequency="5" timeframe="{seconds}"><same_srcip /></rule></group>'
            analysis = analyze_rule(raw, "wazuh")
            self.assertEqual(analysis["timeframe"], expected,
                             msg=f"importing timeframe={seconds} must not change it")
            out = generate_rules(example(threshold=5, use_threshold=True, siems=["wazuh"],
                                        timeframe=analysis["timeframe"]))[0]
            self.assertIn(f'timeframe="{seconds}"', out["rule"],
                          msg=f"{expected} must reach Wazuh as {seconds} seconds")

    def test_elastic_threshold_window_keeps_exact_seconds(self):
        """Elastic's threshold_window is a seconds duration derived from a minutes helper,
        so a 30s request became 60s - the same silent widening as the Wazuh bug."""
        from compiler.sigma_compiler import _window_seconds
        self.assertEqual(_window_seconds("30s"), 30)
        self.assertEqual(_window_seconds("61s"), 61)
        self.assertEqual(_window_seconds("5m"), 300)
        self.assertEqual(_window_seconds("2h"), 7200)
        rendered = generate_rules(example(threshold=5, use_threshold=True, timeframe="30s",
                                          siems=["elastic"],
                                          correlation={"aggregations": [{"function": "dc", "field": "destination.ip", "alias": "d"}]}))[0]["rule"]
        self.assertIn('threshold_window: "30s"', rendered)

    def test_generated_header_does_not_claim_a_schedule(self):
        """`Schedule: every 5m` was wrong: nothing schedules these rules.

        The value is a query lookback (and a count window when thresholding). Calling it
        a schedule is what made a single-event rule look like it waited before firing.
        """
        rule = generate_rules(example(use_threshold=False, siems=["splunk"]))[0]["rule"]
        self.assertNotIn("Schedule:", rule, msg="there is no scheduler in this tool")
        self.assertIn("Window:", rule)
        self.assertIn("not a schedule", rule)

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
