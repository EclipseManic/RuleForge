import json
import unittest

from models.correlation import CorrelationModel, LogicNode, Predicate, flat_conditions_to_logic
from parsers.sigma_parser import parse_sigma
from compiler.validators import sigma_check, target_check
from compiler.sigma_compiler import UNSUPPORTED_MAP, compile_model
from explainer import explain
from evaluator.match_tester import test_events as match_test_events
from diff_tool import diff_models
from app import create_app


SIGMA_SAMPLE = """title: Suspicious PowerShell With Administrative Context
status: test
author: Detection Engineering
description: Detects encoded PowerShell outside an approved account context.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - "\\\\powershell.exe"
      - "\\\\pwsh.exe"
    CommandLine|contains:
      - "-enc"
  filter:
    User:
      - "trusted-admin"
  condition: selection and not filter
falsepositives:
  - Approved automation
level: high
"""


class AnalystWorkbenchTests(unittest.TestCase):
    def test_sigma_parser_preserves_modifiers_lists_condition(self):
        model, meta = parse_sigma(SIGMA_SAMPLE)
        self.assertEqual(meta["title"], "Suspicious PowerShell With Administrative Context")
        self.assertIn("detection", model.native_sections)
        # endswith modifier + list preserved as in_list predicate
        self.assertIsNotNone(model.logic)
        self.assertEqual(len(model.exclusions), 1)
        self.assertEqual(model.fidelity, "safe_normalized")

    def test_sigma_check_flags_missing_sections(self):
        self.assertTrue(sigma_check("title: x\ndetection:\n  selection:\n    a: b\n  condition: selection\n"))
        self.assertIn("Missing 'logsource'", sigma_check("title: x\ndetection:\n  selection:\n    a: b\n  condition: selection\n")[0])

    def test_compiler_renders_modifiers_and_lists_per_dialect(self):
        model, _ = parse_sigma(SIGMA_SAMPLE)
        spl, fidelity, _ = compile_model(model, "splunk")
        self.assertIn("powershell.exe", spl)
        self.assertIn(fidelity, ("safe_normalized", "exact", "partial"))
        kql, _, _ = compile_model(model, "sentinel")
        self.assertIn("in (", kql)  # endswith + list -> KQL in-list (correct)
        self.assertIn("contains", kql)
        # single endswith (no list) renders as endswith per dialect
        single = CorrelationModel(logic=Predicate(field="Image", operator="ends_with", value="powershell.exe"))
        single_kql, _, _ = compile_model(single, "sentinel")
        self.assertIn("endswith", single_kql)
        # target sanity passes
        self.assertEqual(target_check("splunk", spl), [])
        self.assertEqual(target_check("sentinel", kql), [])

    def test_explainer_flags_sequences_joins(self):
        result = {"conditions": [{"field": "a", "operator": "equals", "value": "b"}],
                  "sequences": [{"join_by": "host.name", "maxspan": "5m", "stages": [{"event": "process", "condition": "x"}]}],
                  "joins": [], "aggregations": [], "lookups": [{"name": "t", "arguments": ""}],
                  "event_streams": [], "time_constraints": [], "threshold": 5, "timeframe": "10m",
                  "group_by": "host.name", "native_sections": {"sequence": "…"}, "native_metadata": {},
                  "unsupported_features": [], "siem": "elastic", "raw_rule": "sequence by host.name",
                  "conditions_raw": []}
        from app import _analysis_to_model
        model = _analysis_to_model(result)
        out = explain(model, dialect="elastic")
        self.assertIn("ordered sequence", out["lossy_flags"])
        self.assertIn("lookup or enrichment", out["lossy_flags"])
        self.assertEqual(out["fidelity"], "partial")

    def test_match_tester_clause_reasons_and_exclusion(self):
        model = CorrelationModel(
            logic=LogicNode(op="and", children=(
                Predicate(field="process.name", operator="equals", value="powershell.exe"),
                Predicate(field="process.command_line", operator="contains", value="-enc"),)),
            exclusions=[Predicate(field="user.name", operator="equals", value="trusted-admin")],
            threshold=1)
        events = [
            {"process.name": "powershell.exe", "process.command_line": "powershell -enc abc", "user.name": "alice"},
            {"process.name": "powershell.exe", "process.command_line": "powershell -enc abc", "user.name": "trusted-admin"},
            {"process.name": "cmd.exe", "process.command_line": "dir", "user.name": "alice"},
        ]
        out = match_test_events(model, events)
        self.assertEqual(out["matched"], 1)
        self.assertTrue(out["per_event"][0]["matched"])
        self.assertTrue(out["per_event"][1]["suppressed_by_exclusion"])
        self.assertFalse(out["per_event"][2]["matched"])

    def test_diff_detects_clause_and_setting_changes(self):
        before = {"logic": {"field": "a", "operator": "equals", "value": "1"}, "threshold": 1, "window": "5m", "group_by": ["h"], "fidelity": "safe_normalized"}
        after = {"logic": {"op": "and", "children": [{"field": "a", "operator": "equals", "value": "1"}, {"field": "b", "operator": "contains", "value": "x"}]},
                 "threshold": 5, "window": "5m", "group_by": ["h"], "fidelity": "partial"}
        diff = diff_models(before, after)
        self.assertEqual(len(diff["added"]), 1)
        self.assertTrue(any(c["setting"] == "threshold" for c in diff["setting_changes"]))

    def test_unsupported_map_covers_rf13_rf16(self):
        for key in ("RF-13", "RF-14", "RF-15", "RF-16"):
            self.assertIn(key, UNSUPPORTED_MAP)

    def test_bad_sigma_returns_400_not_500(self):
        app = create_app()
        client = app.test_client()
        base = {"title": "t", "description": "d", "severity": "high", "technique": "custom",
                "threshold": 1, "timeframe": "5m", "group_by": "host.name", "data_source": "*",
                "siems": ["splunk"], "conditions": [{"field": "a", "operator": "equals", "value": "b"}]}
        for route, extra in (("/api/compile", {}), ("/api/explain", {}),
                             ("/api/test_match", {"events": [{"a": "b"}]})):
            rv = client.post(route, json={**base, "sigma": "title: [unclosed", **extra})
            self.assertEqual(rv.status_code, 400, route)

    def test_non_dict_events_rejected(self):
        app = create_app()
        client = app.test_client()
        base = {"title": "t", "description": "d", "severity": "high", "technique": "custom",
                "threshold": 1, "timeframe": "5m", "group_by": "host.name", "data_source": "*",
                "siems": ["splunk"], "conditions": [{"field": "a", "operator": "equals", "value": "b"}]}
        for bad in ([1, 2], [None], ["x"], [{"a": "b"}, 3]):
            rv = client.post("/api/test_match", json={**base, "events": bad})
            self.assertEqual(rv.status_code, 400)

    def test_preserve_mismatch_warns(self):
        from rule_engine import generate_workbench
        out = generate_workbench({"title": "t", "description": "d", "severity": "high", "technique": "custom",
                                  "threshold": 1, "timeframe": "5m", "group_by": "host.name", "data_source": "*",
                                  "siems": ["splunk"],
                                  "conditions": [{"field": "a", "operator": "equals", "value": "b"}],
                                  "source_rule": "DeviceProcessEvents | where x == 1",
                                  "source_siem": "sentinel", "preserve_source_rule": True})
        self.assertTrue(any(g["title"] == "Source preservation skipped" for g in out["quality_gates"]))

    def test_zero_timeframe_rejected(self):
        from rule_engine import RuleValidationError, generate_rules
        with self.assertRaises(RuleValidationError):
            generate_rules({"title": "t", "description": "d", "severity": "high", "technique": "custom",
                            "threshold": 1, "timeframe": "0m", "group_by": "host.name", "data_source": "*",
                            "siems": ["splunk"],
                            "conditions": [{"field": "a", "operator": "equals", "value": "b"}]})

    def test_inventory_flags_known_issues(self):
        from compiler.spec_checks import check_technique_ids, validate_sigma_inventory
        findings = validate_sigma_inventory("title: x\ndetection:\n  selection:\n    a: b\n  condition: selection\n")
        ids = {f["id"] for f in findings}
        self.assertIn("missing_logsource", ids)
        self.assertIn("identifier_existence", ids)
        self.assertIn("title_length", ids)
        bad = check_technique_ids(["T1110", "nope"])
        self.assertTrue(any(f["id"] == "technique_guidance" for f in bad))
        self.assertTrue(any(f["id"] == "technique_format" for f in bad))

    def test_modifiers_parse_and_match(self):
        from parsers.sigma_parser import parse_sigma
        from evaluator.match_tester import test_events
        model, _ = parse_sigma("title: Long Enough Title Here\ndescription: d\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|windash|contains: '-enc'\n    SourceIp|cidr: '10.0.0.0/8'\n  condition: selection\nlevel: high\n")
        out = test_events(model, [{"CommandLine": "powershell /enc abc", "SourceIp": "10.1.2.3"}])
        self.assertEqual(out["matched"], 1)
        out = test_events(model, [{"CommandLine": "powershell abc", "SourceIp": "192.168.1.1"}])
        self.assertEqual(out["matched"], 0)

    def test_sigma_emit_preserves_modifiers_and_metadata(self):
        import yaml
        from rule_engine import generate_rules
        rules = generate_rules({"title": "PowerShell Encoded Execution Test", "description": "d",
                                "severity": "high", "technique": "encoded_powershell",
                                "threshold": 1, "timeframe": "5m", "group_by": "host.name",
                                "data_source": "logs-*", "siems": ["sigma"],
                                "conditions": [{"field": "CommandLine", "operator": "contains", "value": "-enc"}],
                                "exclude_conditions": [{"field": "User", "operator": "equals", "value": "admin"}]})
        doc = yaml.safe_load(rules[0]["rule"])
        self.assertIn("CommandLine|contains", doc["detection"]["selection"])
        self.assertIn("filter", doc["detection"])
        self.assertIn("attack.t1059.001", doc["tags"])

    def test_parser_gaps_closed(self):
        from rule_engine import analyze_rule
        kql = analyze_rule("let a = T | summarize C=count(), M=min(x) by h", "sentinel")
        self.assertTrue(any(a["alias"] == "C" for a in kql["aggregations"]))
        qradar = analyze_rule("SELECT a FROM events WHERE b ILIKE '%x%' AND XFORCE_IP_CONFIDENCE('Spam', a) > 3 LAST 5 MINUTES", "qradar")
        self.assertTrue(any(l["name"] == "XFORCE_IP_CONFIDENCE" for l in qradar["lookups"]))
        eql = analyze_rule("sequence by h with maxspan=5m [a where x == 1] ![b where y == 2]", "elastic")
        self.assertTrue(eql["sequences"][0]["stages"][1]["negated"])
        yara = analyze_rule("rule x {\n events:\n $a.target.user.userid = $user\n $b.target.user.userid = $user\n condition:\n $a and $b\n}", "google_secops")
        self.assertTrue(any(j["on"] == "$user" for j in yara["joins"]))
        wazuh = analyze_rule('<group><rule id="100210"><field name="f" negate="yes" type="pcre2">x</field></rule></group>', "wazuh")
        self.assertEqual(len(wazuh["exclusions"]), 1)

    def test_lineage_versions_increase(self):
        import tempfile
        from pathlib import Path
        from storage import RuleStore
        with tempfile.TemporaryDirectory() as directory:
            store = RuleStore(Path(directory) / "r.db")
            first = store.record_history("generated", "T", "s", "sum", {}, {})
            second = store.record_history("generated", "T", "s", "sum", {}, {})
            self.assertEqual(first["version"], 1)
            self.assertEqual(second["version"], 2)
            self.assertEqual(second["parent_id"], first["id"])

    def test_target_warnings_fire(self):
        from compiler.validators import target_warnings
        self.assertTrue(target_warnings("splunk", "index=* | search a=1"))
        self.assertTrue(target_warnings("qradar", "SELECT a FROM events WHERE b=1"))
        self.assertEqual(target_warnings("splunk", "index=win | search a=1"), [])

    def test_temporal_partitions_and_scoring(self):
        from models.correlation import CorrelationModel, Predicate
        from evaluator.match_tester import test_events
        model = CorrelationModel(logic=Predicate(field="a", operator="equals", value="b"),
                                 threshold=2, window="5m", group_by=["h"])
        events = [{"a": "b", "h": "ws1", "timestamp": 1000, "_expected": True},
                  {"a": "b", "h": "ws1", "timestamp": 1100, "_expected": True},
                  {"a": "b", "h": "ws2", "timestamp": 1200, "_expected": False}]
        out = test_events(model, events)
        self.assertTrue(out["would_fire"])
        self.assertEqual(out["partitions"], {"ws1": 2, "ws2": 1})
        self.assertEqual(out["scoring"]["tp"], 2)
        self.assertEqual(out["scoring"]["fp"], 1)
        late = test_events(model, [{**e, "timestamp": i * 10000} for i, e in enumerate(events)])
        self.assertFalse(late["window_ok"])

    def test_verdict_diff_and_evasion(self):
        app = create_app()
        client = app.test_client()
        before = {"logic": {"field": "a", "operator": "equals", "value": "powershell.exe"},
                  "threshold": 1, "window": "5m", "group_by": ["h"], "fidelity": "x"}
        after = {"logic": {"field": "a", "operator": "equals", "value": "notpresent"},
                 "threshold": 1, "window": "5m", "group_by": ["h"], "fidelity": "x"}
        events = [{"a": "powershell.exe"}]
        rv = client.post("/api/diff", json={"before": before, "after": after, "events": events})
        body = rv.get_json()
        self.assertTrue(body["verdict_changed"])
        self.assertEqual(body["verdict_before"], "would-fire")
        base = {"title": "t", "description": "d", "severity": "high", "technique": "custom",
                "threshold": 1, "timeframe": "5m", "group_by": "host.name", "data_source": "*",
                "siems": ["splunk"], "conditions": [{"field": "process.name", "operator": "equals", "value": "powershell.exe"}]}
        rv = client.post("/api/evade", json={**base, "event": {"process.name": "powershell.exe"}})
        body = rv.get_json()
        self.assertTrue(body["base_matched"])
        self.assertGreaterEqual(body["evasions"], 1)
        from rule_engine import RuleValidationError, generate_rules
        with self.assertRaises(RuleValidationError):
            generate_rules({"title": "t", "description": "d", "severity": "high", "technique": "custom",
                            "threshold": 1, "timeframe": "0m", "group_by": "host.name", "data_source": "*",
                            "siems": ["splunk"],
                            "conditions": [{"field": "a", "operator": "equals", "value": "b"}]})

    def test_section_view_splits_yara_sigma_kql(self):
        from section_view import section_blocks
        yara = section_blocks("rule x {\n  meta:\n    author = \"a\"\n  events:\n    $e.a = \"b\"\n  match:\n    $h over 10m\n  outcome:\n    $risk_score = 90\n  condition:\n    $e\n}", "google_secops")
        self.assertEqual([b["title"] for b in yara if b["title"] != "rule header"],
                         ["meta", "events", "match", "outcome", "condition"])
        kql = section_blocks("let a = T\n| where x == 1", "sentinel")
        self.assertEqual([b["title"] for b in kql], ["event streams (let)", "query"])
        sig = section_blocks("title: t\nlogsource:\n  product: windows\ndetection:\n  selection:\n    a: b\n  condition: selection\nlevel: high\n", "sigma")
        self.assertIn("detection", [b["title"] for b in sig])

    def test_falcon_cql_regex_lookup_groupby_parsed(self):
        from rule_engine import analyze_rule
        result = analyze_rule("#repo=windows\nImageFileName=/powershell\\.exe/i\nCommandLine=/-(enc)/i\n"
                              '| lookup(["privileged_accounts.csv"], field=UserName, key=UserName)\n'
                              "| groupBy([ComputerName], function=[count(as=process_count)])", "falcon")
        self.assertGreaterEqual(len(result["conditions"]), 2)
        self.assertEqual(result["lookups"][0]["name"], "privileged_accounts.csv")
        self.assertEqual(result["aggregations"][0]["alias"], "process_count")
        self.assertIn("repo", result["native_sections"])

    def test_api_endpoints(self):
        app = create_app()
        client = app.test_client()
        self.assertEqual(client.get("/api/rf-families").status_code, 200)
        rv = client.post("/api/validate", json={"sigma": SIGMA_SAMPLE})
        self.assertTrue(rv.get_json()["valid"])
        rv = client.post("/api/compile", json={"title": "t", "description": "d", "severity": "high",
            "technique": "custom", "threshold": 1, "timeframe": "5m", "group_by": "host.name",
            "data_source": "*", "siems": ["splunk", "sentinel"],
            "conditions": [{"field": "process.name", "operator": "endswith", "value": "powershell.exe"}]})
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(rv.get_json()["outputs"]), 2)
        rv = client.post("/api/test_match", json={"threshold": 1, "timeframe": "5m", "group_by": "host.name",
            "technique": "custom", "title": "t", "description": "d", "severity": "high", "data_source": "*",
            "siems": ["splunk"], "conditions": [{"field": "process.name", "operator": "equals", "value": "powershell.exe"}],
            "events": [{"process.name": "powershell.exe"}]})
        self.assertEqual(rv.get_json()["verdict"], "would-fire")
        rv = client.post("/api/diff", json={"before": {"logic": None, "threshold": 1}, "after": {"logic": None, "threshold": 5}})
        self.assertTrue(any(c["setting"] == "threshold" for c in rv.get_json()["setting_changes"]))
        # analyze now attaches explainer + model without breaking legacy keys
        rv = client.post("/api/analyze", json={"rule": 'index=auth | search user="alice"', "siem": "splunk"})
        body = rv.get_json()
        self.assertIn("conditions", body)
        self.assertIn("explanation", body)
        self.assertIn("correlation_model", body)


class AuditFixTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()
        self.base = {"title": "t", "description": "d", "severity": "high", "technique": "custom",
                     "threshold": 1, "timeframe": "5m", "group_by": "host.name", "data_source": "*",
                     "siems": ["splunk"], "conditions": [{"field": "a", "operator": "equals", "value": "b"}]}

    def test_non_dict_bodies_rejected(self):
        self.assertEqual(self.client.post("/api/validate", data='"hi"', content_type="application/json").status_code, 400)
        self.assertEqual(self.client.post("/api/explain", json=[1]).status_code, 400)
        self.assertEqual(self.client.post("/api/diff", json=[1]).status_code, 400)
        self.assertEqual(self.client.post("/api/test_match", json=[1]).status_code, 400)
        self.assertEqual(self.client.post("/api/evade", json="x").status_code, 400)

    def test_unhashable_inputs_rejected(self):
        self.assertEqual(self.client.post("/api/generate", json={**self.base, "conditions": ["oops"]}).status_code, 400)
        self.assertEqual(self.client.post("/api/generate", json={**self.base, "siems": [[]]}).status_code, 400)
        rv = self.client.post("/api/generate", json={**self.base, "source_rule": "x", "preserve_source_rule": True, "source_siem": []})
        self.assertEqual(rv.status_code, 200)
        self.assertTrue(any(g["title"] == "Source preservation skipped" for g in rv.get_json()["quality_gates"]))

    def test_uppercase_not_no_recursion(self):
        rv = self.client.post("/api/compile", json={**self.base, "sigma": "title: Long Enough Title Here\nlogsource:\n  product: windows\ndetection:\n  selection:\n    a: b\n  filter:\n    c: d\n  condition: selection AND NOT filter\n"})
        self.assertEqual(rv.status_code, 200)

    def test_diff_children_null_rejected(self):
        rv = self.client.post("/api/diff", json={"before": {"logic": {"op": "and", "children": None}}, "after": {}})
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.get_json()["added"], [])

    def test_wazuh_native_preserved(self):
        from rule_engine import analyze_rule
        result = analyze_rule('<group><rule id="100210" frequency="5" timeframe="60"><same_srcip /></rule></group>', "wazuh")
        self.assertEqual(result["threshold"], 5)
        self.assertEqual(result["timeframe"], "1m")
        self.assertEqual(result["group_by"], "source.ip")

    def test_no_prose_spills(self):
        from rule_engine import analyze_rule
        splunk = analyze_rule('index=a EventCode=1 | search note="count 1000 events total" | stats count by h', "splunk")
        self.assertEqual(splunk["threshold"], 1)
        simple = analyze_rule('index=a | search b="word or phrase"', "splunk")
        self.assertNotIn("boolean branching", simple["unsupported_features"])
        self.assertEqual(simple["mode"], "simple")

    def test_roundtrip_spellings_accepted(self):
        from rule_engine import generate_rules
        rules = generate_rules({**self.base, "conditions": [{"field": "a", "operator": "startswith", "value": "b"}]})
        self.assertIn("b", rules[0]["rule"])

    def test_severity_strict_and_value_zero(self):
        from rule_engine import RuleValidationError, generate_rules
        with self.assertRaises(RuleValidationError):
            generate_rules({**self.base, "severity": "nope"})
        rules = generate_rules({**self.base, "conditions": [{"field": "e", "operator": "equals", "value": 0}]})
        self.assertIn("0", rules[0]["rule"])

    def test_yara_title_prefixed(self):
        from rule_engine import generate_rules
        rules = generate_rules({**self.base, "title": "123 test", "siems": ["google_secops"]})
        self.assertTrue(rules[0]["rule"].startswith("rule rule_123_test")
                        or rules[0]["rule"].startswith("rule _123_test"))

    def test_sane_defaults(self):
        from rule_engine import generate_rules
        rules = generate_rules({**self.base, "siems": ["elastic", "sentinel"]})
        by_siem = {r["siem"]: r["rule"] for r in rules}
        self.assertNotIn("any where", by_siem["elastic"])
        self.assertFalse(by_siem["sentinel"].splitlines()[1].startswith("*"))

    def test_wazuh_renders_all_clauses(self):
        from rule_engine import generate_rules
        rules = generate_rules({**self.base, "siems": ["wazuh"], "wazuh_rule_id": 100100,
                                "conditions": [{"field": "a", "operator": "equals", "value": "x"},
                                               {"field": "b", "operator": "equals", "value": "y"}],
                                "condition_logic": "any",
                                "exclude_conditions": [{"field": "c", "operator": "equals", "value": "z"}]})
        rule = rules[0]["rule"]
        self.assertIn('name="b"', rule)
        self.assertIn('negate="yes"', rule)
        self.assertIn("split OR branches", rule)

    def test_sigma_dup_filters_kept(self):
        import yaml
        from rule_engine import generate_rules
        rules = generate_rules({**self.base, "siems": ["sigma"],
                                "exclude_conditions": [{"field": "u", "operator": "equals", "value": "a1"},
                                                       {"field": "u", "operator": "equals", "value": "b1"}]})
        doc = yaml.safe_load(rules[0]["rule"])
        self.assertIn("filter", doc["detection"])
        self.assertIn("filter_1", doc["detection"])
        self.assertEqual(doc["detection"]["filter"], {"u": "a1"})
        self.assertEqual(doc["detection"]["filter_1"], {"u": "b1"})
        self.assertIn("filter_1", doc["detection"])

    def test_gate_names_unmapped_field(self):
        from rule_engine import generate_workbench
        out = generate_workbench({**self.base, "siems": ["sentinel"],
                                  "conditions": [{"field": "user.name", "operator": "equals", "value": "x"},
                                                 {"field": "custom_thing", "operator": "equals", "value": "y"}]})
        details = " ".join(g["detail"] for g in out["quality_gates"])
        self.assertIn("custom_thing", details)
        self.assertNotIn("user.name", details.split("custom_thing")[0][-80:])

    def test_falcon_cql_natives(self):
        from compiler.sigma_compiler import compile_model
        from models.correlation import CorrelationModel, Predicate
        query, _, _ = compile_model(CorrelationModel(logic=Predicate("f", "in_list", ["a", "b"])), "falcon")
        self.assertIn("in(f, values=", query)
        query, _, _ = compile_model(CorrelationModel(logic=Predicate("ip", "cidr", "10.0.0.0/8")), "falcon")
        self.assertIn('cidr(ip, subnet="10.0.0.0/8")', query)
        query, _, _ = compile_model(CorrelationModel(logic=Predicate("f", "exists", "true")), "falcon")
        self.assertIn("f = *", query)

    def test_wrappers_use_model_fields(self):
        from compiler.sigma_compiler import compile_model
        from models.correlation import CorrelationModel, Predicate
        model = CorrelationModel(logic=Predicate("a", "equals", "b"), threshold=5, window="1h",
                                 group_by=["h"], source="logs-*")
        query, _, _ = compile_model(model, "qradar")
        self.assertIn("LAST 60 MINUTES", query)
        query, _, _ = compile_model(model, "sentinel")
        self.assertIn("logs-*", query.splitlines()[0])
        query, _, _ = compile_model(model, "falcon")
        self.assertIn("#repo=logs-*", query)
        query, _, _ = compile_model(model, "splunk")
        self.assertIn("earliest=-1h", query)

    def test_sigma_logicnode_emit_valid(self):
        import yaml
        from compiler.sigma_compiler import compile_model
        from models.correlation import CorrelationModel, LogicNode, Predicate
        model = CorrelationModel(logic=LogicNode("and", (Predicate("a", "equals", "x"), Predicate("b", "equals", "y"))))
        query, _, _ = compile_model(model, "sigma")
        doc = yaml.safe_load(query)
        condition = doc["detection"]["condition"]
        self.assertIn("selection_0", condition)
        self.assertIn("selection_1", condition)

    def test_validators_hardened(self):
        from compiler.validators import sigma_check, target_check
        self.assertEqual(sigma_check(None), ["Sigma YAML is empty."])
        self.assertEqual(target_check("wazuh", '<rule id="100100" level="5"><description>x</description></rule>'), [])
        self.assertEqual(target_check("splunk", 'index=a | search b="foo(bar"'), [])

    def test_analyze_contract_keys_present(self):
        rv = self.client.post("/api/analyze", json={"rule": 'index=auth | search user="alice"', "siem": "splunk"})
        body = rv.get_json()
        for key in ("conditions", "explanation", "correlation_model", "sections_parsed", "section_blocks"):
            self.assertIn(key, body)

    def test_tester_hardening(self):
        from evaluator.match_tester import test_events
        from models.correlation import CorrelationModel, Predicate
        self.assertTrue(test_events(CorrelationModel(logic=Predicate("x", "exists", "false")), [{}])["per_event"][0]["matched"])
        out = test_events(CorrelationModel(logic=Predicate("a", "equals", ["x", "y"])), [{"a": "y"}])
        self.assertTrue(out["per_event"][0]["matched"])
        out = test_events(CorrelationModel(logic=Predicate("a", "equals", "b"), threshold=2, window="5m", group_by=["h"]),
                          [{"a": "b", "h": "w1", "timestamp": 1000, "_expected": True},
                           {"a": "b", "h": "w1", "timestamp": 1100, "_expected": 1},
                           {"a": "b", "h": "w2", "timestamp": 1200, "_expected": "benign"}])
        self.assertTrue(out["would_fire"])
        self.assertEqual(out["scoring"]["tp"], 2)
        self.assertEqual(out["scoring"]["fp"], 1)
        self.assertEqual(out["partitions"], {"w1": 2, "w2": 1})

    def test_threshold_and_window_guards(self):
        from evaluator.match_tester import test_events
        from models.correlation import CorrelationModel, Predicate
        with self.assertRaises(ValueError):
            test_events(CorrelationModel(logic=Predicate("a", "equals", "b"), threshold=-1), [{"a": "z"}])
        rv = self.client.post("/api/test_match", json={**self.base, "threshold": "abc", "events": [{"a": "b"}]})
        self.assertEqual(rv.status_code, 400)
        rv = self.client.post("/api/test_match", json={**self.base, "window": "soon", "events": [{"a": "b"}]})
        self.assertEqual(rv.status_code, 400)
        rv = self.client.post("/api/test_match", json={**self.base, "window": "1h", "events": [{"a": "b"}]})
        self.assertEqual(rv.status_code, 200)

    def test_diff_strict_and_verdict_enum(self):
        rv = self.client.post("/api/diff", json={"before": {}, "after": {}, "events": [{"a": "b"}, 1]})
        self.assertEqual(rv.status_code, 400)
        before = {"logic": {"field": "a", "operator": "equals", "value": "x"}, "threshold": 5,
                  "window": "5m", "group_by": ["h"]}
        events = [{"a": "x", "h": "w", "timestamp": 1000}, {"a": "x", "h": "w", "timestamp": 1100}]
        rv = self.client.post("/api/diff", json={"before": before, "after": before, "events": events})
        body = rv.get_json()
        self.assertIn(body["verdict_before"], {"would-fire", "no-match", "suppressed"})
        self.assertFalse(body["verdict_changed"])

    def test_evasion_reports(self):
        from evaluator.evasion import evasion_report
        from models.correlation import CorrelationModel, Predicate
        report = evasion_report(CorrelationModel(logic=Predicate("process.name", "equals", "powershell.exe")),
                                {"process.name": "powershell.exe"})
        self.assertTrue(report["base_matched"])
        self.assertGreater(report["variants_tested"], 1)
        dull = evasion_report(CorrelationModel(logic=Predicate("a", "equals", "b")), {"a": "zzz"})
        self.assertIn("does not match", dull["verdict"])

    def test_storage_quarantine_and_lineage(self):
        import sqlite3
        import tempfile
        from pathlib import Path
        from storage import RuleStore
        with tempfile.TemporaryDirectory() as directory:
            store = RuleStore(Path(directory) / "r.db")
            first = store.record_history("generated", "T", "s", "sum", {"a": 1}, {"b": 2})
            second = store.record_history("generated", "T", "s", "sum", {"a": 1}, {"b": 2})
            self.assertEqual((first["version"], second["version"], second["parent_id"]), (1, 2, first["id"]))
            connection = sqlite3.connect(Path(directory) / "r.db")
            connection.execute("INSERT INTO rule_history (id, kind, title, siem, summary, payload_json, details_json, created_at) VALUES ('HX','k','t','s','sum','{oops','{}','now')")
            connection.commit()
            connection.close()
            history = store.list_history()
            self.assertTrue(all(h["id"] != "HX" for h in history))
            self.assertTrue(any(h["id"] == first["id"] for h in history))



    def test_honesty_wazuh_preserves_predicates(self):
        model = CorrelationModel(
            logic=LogicNode(op="and", children=(
                Predicate(field="process.name", operator="equals", value="a.exe"),
                Predicate(field="user.name", operator="equals", value="bob"),
                Predicate(field="host.name", operator="contains", value="ws"),)),
            exclusions=[Predicate(field="user.name", operator="equals", value="admin")])
        query, fidelity, notes = compile_model(model, "wazuh")
        self.assertEqual(query.count("<field name="), 4)
        self.assertIn('negate="yes"', query)
        self.assertEqual(fidelity, "safe_normalized")
        self.assertEqual(notes, [])

    def test_honesty_wazuh_or_split_guidance(self):
        model = CorrelationModel(logic=LogicNode(op="or", children=(
            Predicate(field="a", operator="equals", value="1"),
            Predicate(field="b", operator="equals", value="2"))))
        query, fidelity, notes = compile_model(model, "wazuh")
        self.assertEqual(fidelity, "partial")
        self.assertTrue(any("if_group" in n for n in notes))
        self.assertEqual(query.count("<field name="), 2)

    def test_honesty_multievent_projection_labeled(self):
        from models.correlation import Sequence, SequenceStage
        model = CorrelationModel(
            logic=Predicate(field="process.name", operator="equals", value="a.exe"),
            sequences=[Sequence(join_by="host.name", maxspan="5m",
                                stages=(SequenceStage(event="logon", condition="x"),
                                        SequenceStage(event="exec", condition="y")))])
        query, fidelity, notes = compile_model(model, "splunk")
        self.assertEqual(fidelity, "partial")
        self.assertTrue(any("project" in n for n in notes))
        self.assertIn("a.exe", query)

    def test_honesty_banner_data_present(self):
        rv = self.client.post("/api/generate", json={**self.base, "siems": ["wazuh", "splunk"]})
        self.assertEqual(rv.status_code, 200)
        for rule in rv.get_json()["rules"]:
            for key in ("capability_notes", "checks", "warnings", "fidelity"):
                self.assertIn(key, rule)


    def test_honesty_regex_single_boolean_hit_flagged(self):
        rv = self.client.post("/api/analyze", json={"rule": 'index=auth src="10.0.0.1" OR fail*', "siem": "splunk"})
        body = rv.get_json()
        self.assertEqual(body["fidelity"], "partial")
        self.assertIn("boolean branching", body["unsupported_features"])
        self.assertTrue(any("regex-extracted" in u for u in body["unsupported_features"]))

    def test_honesty_simple_regex_stays_exact(self):
        rv = self.client.post("/api/analyze", json={"rule": 'index=auth | search user="alice"', "siem": "splunk"})
        body = rv.get_json()
        self.assertEqual(body["fidelity"], "exact")
        self.assertEqual(body["faithfulness"]["badge"], "faithful")

    def test_honesty_roundtrip_native_and_lossy(self):
        eql = 'sequence by host.name with maxspan=5m [process where process.name == "a.exe"] [process where process.name == "b.exe"]'
        body = self.client.post("/api/analyze", json={"rule": eql, "siem": "elastic"}).get_json()
        self.assertEqual(body["faithfulness"]["badge"], "faithful")
        neg = 'sequence by host.name with maxspan=5m [process where process.name == "a.exe"] ![process where process.name == "b.exe"]'
        negated = self.client.post("/api/analyze", json={"rule": neg, "siem": "elastic"}).get_json()
        self.assertEqual(negated["faithfulness"]["badge"], "faithful")

    def test_research_eql_negation_and_yaral_span(self):
        from compiler.sigma_compiler import _yaral_span, compile_model
        from models.correlation import CorrelationModel, Predicate, Sequence, SequenceStage
        seq = Sequence(join_by="h", maxspan="5m", stages=(SequenceStage("a", "", False),
                                                          SequenceStage("b", "", True)))
        model = CorrelationModel(logic=Predicate("x", "equals", "1"), threshold=1, window="5m", sequences=[seq])
        query, fidelity, _ = compile_model(model, "elastic")
        self.assertIn("![b where", query)
        self.assertEqual(fidelity, "safe_normalized")
        self.assertEqual(_yaral_span("30s"), "1m")
        self.assertEqual(_yaral_span("5m"), "5m")
        self.assertEqual(_yaral_span("5d"), "48h")
        self.assertEqual(_yaral_span("bogus"), "5m")
        yara, _, _ = compile_model(model, "google_secops")
        self.assertIn("$e1.user.name = $group", yara)
        self.assertIn("over 5m", yara)


    def _seq_payload(self, stages=({"event": "logon", "condition": ""}, {"event": "exec", "condition": ""})):
        return {**self.base, "siems": ["splunk", "elastic"],
                "correlation": {"sequences": [{"join_by": "host.name", "maxspan": "10m",
                                               "stages": list(stages)}]}}

    def test_honesty_authored_sequence_compiles(self):
        rv = self.client.post("/api/generate", json=self._seq_payload())
        self.assertEqual(rv.status_code, 200)
        by_siem = {r["siem"]: r for r in rv.get_json()["rules"]}
        self.assertIn("sequence", by_siem["splunk"]["capability"])
        self.assertEqual(by_siem["splunk"]["fidelity"], "partial")
        self.assertTrue(any("sequence" in n for n in by_siem["splunk"]["capability_notes"]))
        self.assertIn("sequence by host.name", by_siem["elastic"]["rule"])
        self.assertEqual(by_siem["elastic"]["fidelity"], "safe_normalized")

    def test_honesty_authored_absence_flagged(self):
        from compiler.pipeline import involved_families
        from rule_engine import parse_request
        payload = self._seq_payload(stages=({"event": "logon", "condition": ""},
                                            {"event": "exec", "condition": "", "negated": True}))
        request = parse_request(payload)
        self.assertIn("sequence", involved_families(request))
        self.assertIn("absence", involved_families(request))

    def test_honesty_authored_join_aggregation(self):
        from compiler.pipeline import involved_families
        from rule_engine import parse_request
        payload = {**self.base, "siems": ["sentinel"],
                   "correlation": {"joins": [{"kind": "inner", "left": "a", "right": "b", "on": "host.name"}],
                                   "aggregations": [{"function": "count", "field": "*", "alias": "c"}]}}
        request = parse_request(payload)
        self.assertIn("join", involved_families(request))
        self.assertIn("aggregation", involved_families(request))
        rv = self.client.post("/api/generate", json=payload)
        self.assertEqual(rv.status_code, 200)

    def test_honesty_bad_correlation_rejected(self):
        rv = self.client.post("/api/generate", json=self._seq_payload(stages=({"event": "only"},)))
        self.assertEqual(rv.status_code, 400)

    def test_honesty_compile_carries_model(self):
        rv = self.client.post("/api/compile", json={**self._seq_payload(), "title": "seq"})
        self.assertEqual(rv.status_code, 200)
        body = rv.get_json()
        self.assertEqual(len(body["model"]["sequences"]), 1)
        self.assertEqual(len(body["model"]["sequences"][0]["stages"]), 2)
        for output in body["outputs"]:
            self.assertIn("section_blocks", output)


    def test_taxonomy_loads_with_legacy_intact(self):
        from rule_engine import FIELD_MAPPINGS, _load_catalog
        self.assertEqual(FIELD_MAPPINGS["splunk"]["process.name"], "process_name")
        self.assertEqual(FIELD_MAPPINGS["falcon"]["process.name"], "ImageFileName")
        self.assertTrue(all(k == v for k, v in FIELD_MAPPINGS["elastic"].items()))
        self.assertGreaterEqual(len(FIELD_MAPPINGS["sigma"]), 30)
        self.assertIn("file.hash.sha256", FIELD_MAPPINGS["sigma"])
        self.assertEqual(_load_catalog("nope.json"), {})

    def test_taxonomy_unmapped_still_flagged(self):
        payload = {**self.base, "siems": ["splunk"], "field": "weird.custom",
                   "conditions": [{"field": "weird.custom", "operator": "equals", "value": "x"}]}
        rv = self.client.post("/api/generate", json=payload)
        self.assertEqual(rv.status_code, 200)
        mapping = rv.get_json()["rules"][0]["field_mapping"]
        self.assertIn("weird.custom", mapping["unmapped_fields"])

    def test_techniques_endpoint_and_generate(self):
        catalog = self.client.get("/api/techniques").get_json()
        ids = [t["id"] for t in catalog["techniques"]]
        self.assertIn("valid_accounts", ids)
        self.assertIn("failed_logins", ids)
        self.assertIn("file.hash.sha256", catalog["fields"])
        entry = next(t for t in catalog["techniques"] if t["id"] == "valid_accounts")
        self.assertIn("T1078", entry["mitre"])
        rv = self.client.post("/api/generate", json={**self.base, "siems": ["splunk"], "technique": "valid_accounts"})
        self.assertEqual(rv.status_code, 200)
        self.assertIn("T1078", rv.get_json()["rules"][0]["rule"])

    def test_technique_guidance_extended(self):
        from compiler.spec_checks import check_technique_ids
        findings = check_technique_ids(["T1078"])
        self.assertTrue(any(f["id"] == "technique_guidance" and "T1078" in f["message"] for f in findings))

    def test_index_renders_catalogs(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn('value="valid_accounts"', html)
        self.assertIn('value="file.hash.sha256"', html)
        self.assertIn('id="technique-data"', html)


    def test_ingest_ndjson_with_bad_lines(self):
        body = self.client.post("/api/ingest", json={
            "content": '{"process.name": "a.exe", "user.name": "x"}\nnot json\n{"process": {"name": "b.exe"}}',
            "format": "ndjson"}).get_json()
        self.assertEqual(body["count"], 2)
        self.assertIn("process.name", body["fields"])
        self.assertTrue(body["warnings"])
        self.assertEqual(body["format"], "ndjson")

    def test_ingest_csv_label_and_caps(self):
        csv_text = "process.name,user.name,label\npowershell.exe,alice,malicious\nexplorer.exe,bob,benign"
        body = self.client.post("/api/ingest", json={"content": csv_text, "format": "csv"}).get_json()
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["events"][0]["_expected"], "malicious")
        self.assertIn("process.name", body["fields"])
        rv = self.client.post("/api/ingest", json={"content": "nothing like data", "format": "auto"})
        self.assertEqual(rv.status_code, 400)
        rv = self.client.post("/api/ingest", json={"content": "x", "format": "yaml"})
        self.assertEqual(rv.status_code, 400)
        big = "\n".join(['{"a": 1}'] * 5001)
        rv = self.client.post("/api/ingest", json={"content": big, "format": "ndjson"})
        self.assertEqual(rv.status_code, 400)

    def test_validation_levels(self):
        from compiler.validators import validation_level
        self.assertEqual(validation_level("sigma", []), "grammar-checked")
        self.assertEqual(validation_level("wazuh", []), "grammar-checked")
        # SPL/KQL/AQL/EQL/CQL/YARA-L now go through real structural parsers, so an
        # empty problem list means the grammar shape parsed - not a keyword probe.
        self.assertEqual(validation_level("splunk", []), "structure-parsed")
        self.assertEqual(validation_level("sentinel", []), "structure-parsed")
        self.assertEqual(validation_level("elastic", []), "structure-parsed")
        self.assertEqual(validation_level("splunk", ["problem"]), "failed")
        # A dialect with no structural parser must not claim one.
        self.assertEqual(validation_level("wazuh_unknown", []), "sanity-checked")
        rv = self.client.post("/api/generate", json={**self.base, "siems": ["splunk", "wazuh"]}).get_json()
        by_siem = {r["siem"]: r for r in rv["rules"]}
        self.assertEqual(by_siem["splunk"]["validation"], "structure-parsed")
        self.assertEqual(by_siem["wazuh"]["validation"], "grammar-checked")


    def test_reaudit_agg_threshold_roundtrip(self):
        from models.correlation import Aggregation, CorrelationModel, Predicate, model_from_dict
        model = CorrelationModel(logic=Predicate("a", "equals", "1"),
                                 aggregations=[Aggregation(function="count", field="a", alias="c", threshold=5)])
        self.assertEqual(model_from_dict(model.to_dict()).aggregations[0].threshold, 5)

    def test_reaudit_tester_does_not_mutate_model(self):
        from evaluator.match_tester import test_events
        from models.correlation import CorrelationModel, Predicate
        model = CorrelationModel(logic=Predicate("a", "equals", "1"), threshold=1, window="5m", group_by="h")
        test_events(model, [{"a": "1", "h": "w"}])
        self.assertEqual(model.group_by, "h")

    def test_reaudit_numeric_guards(self):
        rv = self.client.post("/api/generate", json={**self.base, "threshold": 2.5})
        self.assertEqual(rv.status_code, 400)
        rv = self.client.post("/api/generate", json={**self.base, "siems": ["wazuh"], "wazuh_rule_id": True})
        self.assertEqual(rv.status_code, 400)

    def test_reaudit_canonical_drops_labeled(self):
        from models.correlation import CorrelationModel, Predicate, Sequence, SequenceStage
        seq = Sequence(join_by="h", maxspan="5m", stages=(SequenceStage("a", "", False),
                                                          SequenceStage("b", "", False)))
        model = CorrelationModel(logic=Predicate("a", "equals", "1"), threshold=1, window="5m", sequences=[seq])
        _, wazuh_fidelity, wazuh_notes = compile_model(model, "wazuh")
        self.assertEqual(wazuh_fidelity, "partial")
        self.assertTrue(any("sequences" in n for n in wazuh_notes))
        _, sigma_fidelity, sigma_notes = compile_model(model, "sigma")
        self.assertEqual(sigma_fidelity, "partial")
        self.assertTrue(any("sequences" in n for n in sigma_notes))

    def test_reaudit_stage_event_token(self):
        rv = self.client.post("/api/generate", json={**self.base, "siems": ["elastic"],
            "correlation": {"sequences": [{"join_by": "h", "maxspan": "5m",
                                           "stages": [{"event": "my event"}, {"event": "b"}]}]}})
        self.assertEqual(rv.status_code, 400)


    def test_strict_mode_refuses_lossy_targets(self):
        payload = {**self.base, "siems": ["splunk", "elastic"], "strict": True,
                   "correlation": {"sequences": [{"join_by": "h", "maxspan": "5m",
                                                  "stages": [{"event": "a", "condition": ""},
                                                             {"event": "b", "condition": ""}]}]}}
        rules = {r["siem"]: r for r in self.client.post("/api/generate", json=payload).get_json()["rules"]}
        self.assertTrue(rules["splunk"]["refused"])
        self.assertEqual(rules["splunk"]["rule"], "")
        self.assertEqual(rules["splunk"]["validation"], "failed")
        self.assertIn("sequence", rules["splunk"]["refusal_reason"])
        self.assertFalse(rules["elastic"].get("refused", False))
        self.assertIn("sequence by", rules["elastic"]["rule"])

    def test_strict_mode_allows_faithful_targets(self):
        rv = self.client.post("/api/generate", json={**self.base, "siems": ["splunk"], "strict": True})
        rule = rv.get_json()["rules"][0]
        self.assertFalse(rule.get("refused", False))
        self.assertTrue(rule["rule"])
        rv = self.client.post("/api/generate", json={**self.base, "siems": ["splunk"], "strict": "on"})
        self.assertFalse(rv.get_json()["rules"][0].get("refused", False))


    def test_fixture_replay_loop(self):
        good = [{"a": "b", "_expected": True}, {"a": "z", "_expected": False}]
        bad = [{"a": "z", "_expected": True}]
        ids = [self.client.post("/api/fixtures", json={"title": t, "events": e}).get_json()["id"]
               for t, e in (("good", good), ("bad", bad))]
        try:
            listed = self.client.get("/api/fixtures").get_json()["fixtures"]
            # Scope to this test's own fixtures. The store is persistent and shared with
            # the running app, so asserting the whole listing held nothing else made this
            # test fail whenever an analyst saved a fixture through the UI.
            mine = [f for f in listed if f["id"] in ids]
            self.assertEqual({f["title"] for f in mine}, {"good", "bad"})
            self.assertNotIn("events", mine[0])  # list view must not dump raw events
            out = self.client.post("/api/fixtures/replay", json={**self.base, "fixture_ids": ids}).get_json()
            self.assertEqual(out["total"], 2)
            self.assertEqual(out["passed_count"], 1)
            failed = next(r for r in out["results"] if r["title"] == "bad")
            self.assertFalse(failed["passed"])
            self.assertTrue(failed["mismatches"])
        finally:
            for fixture_id in ids:
                self.client.delete(f"/api/fixtures/{fixture_id}")
        # Cleanup is asserted per id. The store legitimately holds the analyst's own
        # fixtures, so it must never be asserted empty.
        remaining = {f["id"] for f in self.client.get("/api/fixtures").get_json()["fixtures"]}
        self.assertFalse(remaining & set(ids), msg="this test's own fixtures were not cleaned up")

    def test_fixture_validation(self):
        self.assertEqual(self.client.post("/api/fixtures", json={"title": "", "events": [{"a": 1}]}).status_code, 400)
        self.assertEqual(self.client.post("/api/fixtures", json={"title": "t", "events": [{"a": 1}]}).status_code, 400)
        self.assertEqual(self.client.post("/api/fixtures", json={"title": "t", "events": [1]}).status_code, 400)
        self.assertEqual(self.client.post("/api/fixtures/replay", json={**self.base, "events": []}).status_code, 400)
        self.assertEqual(self.client.post("/api/fixtures/replay", json={**self.base, "fixture_ids": "x"}).status_code, 400)


    def test_sigma_only_compile_works(self):
        rv = self.client.post("/api/compile", json={"siems": ["splunk", "sigma"], "sigma": SIGMA_SAMPLE})
        self.assertEqual(rv.status_code, 200)
        body = rv.get_json()
        self.assertEqual(len(body["outputs"]), 2)
        self.assertGreaterEqual(body["model"]["predicate_count"], 2)
        for output in body["outputs"]:
            self.assertTrue(output["rule"])

    def test_pysigma_status_is_honest(self):
        from compiler.sigma_compiler import compile_sigma_with_pysigma, pysigma_status
        status = pysigma_status()
        self.assertIn("installed", status)
        self.assertIn("backends_ready", status)
        if not status["installed"]:
            self.assertEqual(status["backends_ready"], [])
        self.assertIsNone(compile_sigma_with_pysigma("title: t", "splunk"))

    def test_coverage_is_measured(self):
        cov = self.client.get("/api/coverage").get_json()
        self.assertGreater(cov["total"], 0)
        self.assertEqual(len(cov["families"]), 5)
        for siem, counts in cov["summary"].items():
            self.assertEqual(sum(counts.values()), cov["total"], siem)
        for row in cov["families"]:
            for siem, cell in row["targets"].items():
                self.assertIn(cell["fidelity"], {"exact", "safe_normalized", "partial", "unsupported"})


    def test_pysigma_backends_produce_native_queries(self):
        from compiler.sigma_compiler import compile_sigma_with_pysigma, pysigma_status
        status = pysigma_status()
        if not status["installed"]:
            self.skipTest("pySigma not installed")
        outputs = {s: compile_sigma_with_pysigma(SIGMA_SAMPLE, s) for s in ("splunk", "sentinel", "elastic", "qradar", "falcon")}
        for siem, result in outputs.items():
            if result is None:
                continue
            query, notes = result
            self.assertTrue(query.strip(), siem)
            self.assertTrue(any("pySigma" in n for n in notes), siem)
        self.assertIsNone(compile_sigma_with_pysigma(SIGMA_SAMPLE, "sigma"))  # no backend by design

    def test_pysigma_path_labeled_authoritative(self):
        from compiler.sigma_compiler import pysigma_status
        if not pysigma_status()["installed"]:
            self.skipTest("pySigma not installed")
        body = self.client.post("/api/compile", json={"siems": ["splunk"], "sigma": SIGMA_SAMPLE}).get_json()
        out = body["outputs"][0]
        self.assertEqual(out["fidelity"], "exact")
        self.assertEqual(out["validation"], "grammar-checked")
        self.assertTrue(any("pySigma" in n for n in out["notes"]))

    def test_pysigma_scope_notes_are_honest(self):
        from compiler.sigma_compiler import compile_sigma_with_pysigma
        result = compile_sigma_with_pysigma(SIGMA_SAMPLE, "splunk")
        if result is None:
            self.skipTest("splunk backend not installed")
        query, notes = result
        self.assertRegex(query, r"index=\*")
        self.assertTrue(any("index" in n.lower() for n in notes))


    def test_native_constructs_rendered_per_dialect(self):
        from compiler.sigma_compiler import compile_model
        from models.correlation import Aggregation, CorrelationModel, Join, Lookup, Predicate
        base = dict(logic=Predicate("process.name", "equals", "a.exe"), threshold=1, window="5m", group_by=["host.name"])
        join = CorrelationModel(**base, joins=[Join(kind="inner", left="a", right="alerts", on="host.name")])
        self.assertIn("| join", compile_model(join, "splunk")[0])
        self.assertIn("| join kind=inner", compile_model(join, "sentinel")[0])
        self.assertIn("IN (SELECT", compile_model(join, "qradar")[0])
        self.assertIn("| join([", compile_model(join, "falcon")[0])
        agg = CorrelationModel(**base, aggregations=[Aggregation(function="dc", field="user.name", alias="uniq")])
        self.assertIn("| stats dc(user.name) as uniq by host.name", compile_model(agg, "splunk")[0])
        self.assertIn("| summarize uniq = dc(user.name)", compile_model(agg, "sentinel")[0])
        lookup = CorrelationModel(**base, lookups=[Lookup(name="watchlist")])
        self.assertIn("| inputlookup watchlist", compile_model(lookup, "splunk")[0])
        self.assertIn("| lookup('watchlist')", compile_model(lookup, "falcon")[0])

    def test_native_constructs_are_never_exact(self):
        from compiler.sigma_compiler import compile_model
        from models.correlation import Aggregation, CorrelationModel, Predicate
        model = CorrelationModel(logic=Predicate("process.name", "equals", "a.exe"), threshold=1, window="5m",
                                 group_by=["host.name"], aggregations=[Aggregation(function="count")])
        for siem in ("splunk", "sentinel", "qradar", "falcon"):
            _, fidelity, notes = compile_model(model, siem)
            self.assertEqual(fidelity, "partial", siem)
            self.assertTrue(any("Verify" in n for n in notes), siem)

    def test_unimplementable_families_reported(self):
        from compiler.sigma_compiler import compile_model
        from models.correlation import CorrelationModel, Lookup, Predicate
        model = CorrelationModel(logic=Predicate("a", "equals", "1"), threshold=1, window="5m",
                                 group_by=["h"], lookups=[Lookup(name="wl")])
        query, fidelity, notes = compile_model(model, "elastic")
        self.assertEqual(fidelity, "partial")
        self.assertTrue(any("no native" in n.lower() or "No native" in n for n in notes))
        self.assertIn("EQL has no lookup primitive", query)


    def test_attack_catalog_is_real_and_separate(self):
        body = self.client.get("/api/attack").get_json()
        self.assertGreater(body["total"], 500)
        ids = {t["id"] for t in body["techniques"]}
        self.assertIn("T1059", ids)
        self.assertIn("T1059.001", ids)
        self.assertNotIn("T9999", ids)
        self.assertTrue(any(t["buildable"] for t in body["techniques"]))
        self.assertTrue(any(not t["buildable"] for t in body["techniques"]))
        entry = next(t for t in body["techniques"] if t["id"] == "T1059.001")
        self.assertTrue(entry["name"])
        self.assertTrue(entry["tactics"])

    def test_ecs_field_autocomplete_scale(self):
        from rule_engine import ECS_FIELDS
        self.assertGreater(len(ECS_FIELDS), 2000)
        for field in ("process.name", "process.parent.name", "dns.question.name",
                      "file.hash.sha256", "threat.technique.id", "dns.answers.name"):
            self.assertIn(field, ECS_FIELDS)
        body = self.client.get("/api/techniques").get_json()
        self.assertGreaterEqual(body["mapped_field_count"], 50)
        self.assertLess(body["mapped_field_count"], body["field_count"])
        self.assertGreater(body["field_count"], 2000)
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn('id="attack-search"', html)

    def test_unmapped_ecs_field_passes_through_flagged(self):
        rv = self.client.post("/api/generate", json={**self.base, "field": "threat.technique.id",
            "conditions": [{"field": "threat.technique.id", "operator": "equals", "value": "T1059"}]})
        rule = rv.get_json()["rules"][0]
        self.assertIn("threat.technique.id", rule["field_mapping"]["unmapped_fields"])
        self.assertIn("threat.technique.id", rule["rule"])


    def test_analysis_boolean_structure_is_quote_aware(self):
        from rule_engine import _boolean_structure, analyze_rule
        quoted = _boolean_structure('where msg = "error and abort"')
        self.assertEqual(quoted["operator_count"], 0)
        real = _boolean_structure('where a="1" and (b="2" or c="3")')
        self.assertEqual(real["operator_count"], 2)
        self.assertEqual(real["group_depth"], 1)
        self.assertEqual(_boolean_structure('where (a="1" and (b="2" or c="3"))')["group_depth"], 2)
        clean = analyze_rule('index=a | search user="error and abort"', "splunk")
        self.assertEqual(clean["fidelity"], "exact")
        self.assertNotIn("boolean branching", clean["unsupported_features"])
        nested = analyze_rule('index=a | search (u="x" or (u="y" and h="z"))', "splunk")
        self.assertIn("boolean branching", nested["unsupported_features"])
        self.assertTrue(any("nested grouping" in f for f in nested["unsupported_features"]))

    def test_sigma_pysigma_path_discloses_unverified_field_names(self):
        """The Sigma path must not look verified when it was not checked.

        pySigma emits Sigma field names (Image, CommandLine) verbatim. The built-in path
        emits mapped vendor columns and shows a mapping chip. This path previously carried
        no field_mapping at all, so the same logical rule looked checked on one entry path
        and unchecked on the other, and the analyst was told nothing.
        """
        from app import _sigma_native_fields
        from compiler.sigma_compiler import pysigma_status
        self.assertEqual(_sigma_native_fields('index=* CommandLine="*-enc*"'), ["CommandLine"])
        self.assertEqual(_sigma_native_fields('| Image=/powershell/i'), ["Image"])
        # A dotted ECS path is a field even under an EQL event-category head.
        self.assertEqual(_sigma_native_fields('process where process.name == "x"'),
                         ["process.name"])
        # Quoted values are values, not fields.
        self.assertEqual(_sigma_native_fields('#repo=*\n| TargetFilename="a.exe"'),
                         ["TargetFilename"])
        # Boilerplate must not become a field list, or the disclosure is noise.
        self.assertEqual(_sigma_native_fields("index=logs-* | stats count by user"), [])

        if not pysigma_status()["installed"]:
            self.skipTest("pySigma not installed")
        body = self.client.post("/api/compile", json={
            "title": "t", "siems": ["splunk"],
            "sigma": "title: t\nlogsource:\n  product: windows\n  category: process_creation\n"
                     "detection:\n  selection:\n    CommandLine|contains: -enc\n"
                     "  condition: selection\n"}).get_json()
        out = body["outputs"][0]
        self.assertIn("field_mapping", out, msg="Sigma output must carry a field_mapping")
        self.assertEqual(out["field_mapping"]["mapping_confidence"], "unverified")
        self.assertTrue(
            any("not columns verified" in n for n in out["notes"]),
            msg="the unverified-field caveat must be stated, not implied")

    def test_pysigma_boundary_is_documented(self):
        status = self.client.get("/api/siems").get_json()["pysigma"]
        self.assertIn("no_backend", status)
        self.assertIn("no_backend_reason", status)
        for target in ("sigma", "wazuh", "google_secops"):
            self.assertIn(target, status["no_backend"])
        self.assertIn("live", self.client.get("/api/siems").get_json()["verification_note"])

    def test_coverage_is_cached_but_correct(self):
        import time
        client = self.client
        first = client.get("/api/coverage").get_json()
        start = time.time()
        second = client.get("/api/coverage").get_json()
        elapsed = time.time() - start
        self.assertEqual(first["summary"], second["summary"])
        self.assertLess(elapsed, 0.5)


    def test_mapping_provenance_is_exposed(self):
        body = self.client.get("/api/techniques").get_json()
        prov = body["provenance"]
        self.assertIn("targets", prov)
        self.assertTrue(prov["provenance_policy"])
        for target in ("splunk", "sentinel", "google_secops", "qradar", "wazuh"):
            entry = prov["targets"][target]
            self.assertTrue(entry["source_url"].startswith("https://"))
            self.assertTrue(entry["schema"])
            self.assertTrue(entry["version"])
            self.assertIn(entry["confidence"], ("documented", "inferred"))
        # Targets without a fixed published schema must be labelled inferred, not documented.
        self.assertEqual(prov["targets"]["wazuh"]["confidence"], "inferred")
        self.assertEqual(prov["targets"]["qradar"]["confidence"], "inferred")
        self.assertEqual(prov["targets"]["splunk"]["confidence"], "documented")

    def test_override_round_trip_applies_to_compile(self):
        import shutil
        import tempfile
        from pathlib import Path
        from mapping_overrides import OverrideError, clear_override, load_overrides, write_override

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            saved = write_override(root, "splunk", "threat.technique.id", "attack_technique_id",
                                   reason="our CIM alias", author="tester")
            self.assertEqual(saved["native_field"], "attack_technique_id")
            self.assertEqual(load_overrides(root)["splunk"]["threat.technique.id"], "attack_technique_id")
            self.assertEqual(load_overrides(root)["splunk"]["threat.technique.id"], "attack_technique_id")
            notes = json.loads((root / "data" / "mappings" / "overrides.json").read_text(encoding="utf-8"))
            self.assertEqual(notes["notes"]["splunk:threat.technique.id"]["reason"], "our CIM alias")
            self.assertEqual(notes["notes"]["splunk:threat.technique.id"]["author"], "tester")

    def test_override_validation_rejects_bad_input(self):
        from mapping_overrides import OverrideError, write_override
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for bad_target, bad_field, bad_value in (
                ("nosuchsiem", "a.b", "x"),
                ("splunk", "not a field", "x"),
                ("splunk", "a.b", ""),
                ("splunk", "a.b", "bad\nvalue"),
            ):
                with self.assertRaises(OverrideError, msg=str((bad_target, bad_field, bad_value))):
                    write_override(root, bad_target, bad_field, bad_value)
            self.assertFalse((root / "data" / "mappings" / "overrides.json").exists())

    def test_override_api_rejects_bad_payload(self):
        rv = self.client.post("/api/mappings/overrides", json={"target": "nosuchsiem",
                                                               "canonical_field": "a.b", "native_field": "x"})
        self.assertEqual(rv.status_code, 400)
        self.assertIn("error", rv.get_json())
        self.assertEqual(self.client.get("/api/mappings/overrides").get_json()["count"], 0)

    def test_override_endpoint_round_trip(self):
        rv = self.client.post("/api/mappings/overrides", json={
            "target": "falcon", "canonical_field": "threat.technique.id", "native_field": "TechniqueId",
            "reason": "pinned for our log source", "author": "tester"})
        self.assertEqual(rv.status_code, 200)
        try:
            self.assertEqual(rv.get_json()["saved"]["native_field"], "TechniqueId")
            listed = self.client.get("/api/mappings/overrides").get_json()
            self.assertEqual(listed["overrides"]["falcon"]["threat.technique.id"], "TechniqueId")
            self.assertEqual(listed["notes"]["falcon:threat.technique.id"]["author"], "tester")
            # The override must actually reach the compiler, not just the store.
            body = self.client.post("/api/generate", json={
                **self.base, "siems": ["falcon"],
                "conditions": [{"field": "threat.technique.id", "operator": "equals", "value": "T1059"}]}).get_json()
            self.assertIn("TechniqueId", body["rules"][0]["rule"])
            self.assertNotIn("unmapped_fields", str(body["rules"][0]["field_mapping"]["unmapped_fields"]))
        finally:
            self.client.delete("/api/mappings/overrides", json={
                "target": "falcon", "canonical_field": "threat.technique.id"})
        self.assertNotIn("falcon", self.client.get("/api/mappings/overrides").get_json()["overrides"])

    def test_elastic_threshold_renders_native_rule(self):
        from compiler.sigma_compiler import compile_model
        model = CorrelationModel(
            logic=Predicate(field="process.name", operator="equals", value="powershell.exe"),
            threshold=5, window="5m", group_by=["user.name"], source="logs-*")
        query, fidelity, notes = compile_model(model, "elastic")
        self.assertIn('type: "threshold"', query)
        self.assertIn("group_by:", query)
        self.assertTrue("process.name" in query or "ProcessName" in query)
        self.assertIn(fidelity, ("safe_normalized", "exact", "partial"))
        # A threshold rule is not EQL, so the EQL parser must not be applied to it.
        self.assertEqual(target_check("elastic", query), [])
        # The one honest caveat: threshold buckets are clock-aligned, so a burst that
        # straddles a boundary can split. The rule must say so rather than claim exactness.
        self.assertTrue(any("clock-aligned" in n and "straddl" in n for n in notes),
                        msg=f"threshold rule must disclose its clock-aligned window semantics: {notes}")
        self.assertNotEqual(fidelity, "exact")

    def test_dialect_parsers_run_on_generated_output(self):
        """Every generated rule for a structured dialect must pass its own parser."""
        for siem in ("splunk", "sentinel", "elastic", "qradar", "falcon", "google_secops", "sigma"):
            body = self.client.post("/api/generate", json={**self.base, "siems": [siem]}).get_json()
            rule = body["rules"][0]
            self.assertEqual(rule["checks"], [], msg=f"{siem}: {rule['checks']}")
            self.assertEqual(rule["validation"], "grammar-checked" if siem in ("sigma", "wazuh") else "structure-parsed",
                             msg=siem)

    def test_analyze_reports_structure_evidence(self):
        body = self.client.post("/api/analyze", json={
            "rule": 'index=auth\n| search user="alice"', "siem": "splunk"}).get_json()
        self.assertIn("structure", body)
        self.assertTrue(body["structure"]["structured"])
        self.assertEqual(body["structure_problems"], [])
        bad = self.client.post("/api/analyze", json={
            "rule": 'index=auth\n| where (a="1"', "siem": "splunk"}).get_json()
        self.assertTrue(bad["structure_problems"])
        self.assertIn("structural parse", " ".join(bad["unsupported_features"]))

    def test_every_metadata_line_is_commented(self):
        """Rendered rule headers must not leak uncommented text into the query."""
        from compiler.validators import target_check as check
        for siem, marker in (("splunk", "#"), ("sentinel", "//"), ("qradar", "--"), ("falcon", "//")):
            body = self.client.post("/api/generate", json={**self.base, "siems": [siem]}).get_json()
            rule = body["rules"][0]["rule"]
            for line in rule.splitlines()[:5]:
                if line.strip().startswith(("Name:", "Severity:", "MITRE", "Schedule:")):
                    self.fail(f"{siem} leaked uncommented header line: {line!r}")
            self.assertEqual(check(siem, rule), [], msg=siem)


    def test_asim_mappings_use_the_published_schema(self):
        """ASIM is role-prefixed. These are the names in Microsoft's published schema;
        the legacy SecurityEvent/DeviceProcessEvents names do not exist in ASIM tables,
        so a regression to them would silently produce rules that match nothing."""
        from rule_engine import FIELD_MAPPINGS
        as_im = FIELD_MAPPINGS["sentinel"]
        expected = {
            "process.name": "TargetProcessName",
            "process.command_line": "TargetProcessCommandLine",
            "process.pid": "TargetProcessId",
            "process.parent.name": "ParentProcessName",
            "user.name": "TargetUsername",
            "host.name": "DvcHostname",
            "source.ip": "SrcIpAddr",
            "destination.ip": "DstIpAddr",
            "dns.question.name": "DnsQuery",
            "file.path": "TargetFilePath",
        }
        for canonical, native in expected.items():
            self.assertEqual(as_im.get(canonical), native, msg=canonical)
        legacy = {"ProcessName", "ProcessCommandLine", "UserName", "Computer",
                  "SourceIp", "DestinationIp", "FolderPath", "InitiatingProcessFileName"}
        for canonical, native in FIELD_MAPPINGS["sentinel"].items():
            self.assertNotIn(native, legacy,
                             msg=f"{canonical} regressed to legacy {native}, absent from ASIM")

    def test_udm_mappings_use_noun_blocks(self):
        from rule_engine import FIELD_MAPPINGS
        udm = FIELD_MAPPINGS["google_secops"]
        for canonical, native in udm.items():
            self.assertRegex(native, r"^(metadata|principal|target|src|network|security_result|observer|about|intermediary)\.",
                             msg=f"{canonical} -> {native} is not a UDM noun block")
        self.assertEqual(udm["process.command_line"], "target.process.command_line")
        self.assertEqual(udm["user.name"], "principal.user.userid")

    def test_documented_targets_expanded_others_unchanged(self):
        """Documented-schema targets gained verified coverage; the two targets with no
        published schema must stay 'inferred' rather than being bulk-filled with guesses."""
        from rule_engine import FIELD_MAPPINGS, mapping_provenance
        prov = mapping_provenance()["targets"]
        self.assertGreaterEqual(len(FIELD_MAPPINGS["sentinel"]), 50)
        self.assertGreaterEqual(len(FIELD_MAPPINGS["google_secops"]), 45)
        self.assertGreaterEqual(len(FIELD_MAPPINGS["splunk"]), 40)
        self.assertEqual(prov["wazuh"]["confidence"], "inferred")
        self.assertEqual(prov["qradar"]["confidence"], "inferred")
        self.assertEqual(prov["sentinel"]["confidence"], "documented")
        self.assertIn("normalization", prov["sentinel"]["source_url"])


    def test_generation_is_deterministic(self):
        """Same request -> byte-identical rules. Only generated_at may vary; a rule that
        changes between identical calls is not reproducible or auditable."""
        payload = {**self.base, "siems": ["splunk", "sentinel", "elastic", "qradar",
                                          "google_secops", "falcon", "wazuh", "sigma"]}
        runs = [self.client.post("/api/generate", json=payload).get_json() for _ in range(5)]
        signatures = {json.dumps({k: v for k, v in run.items() if k != "generated_at"}, sort_keys=True)
                      for run in runs}
        self.assertEqual(len(signatures), 1, msg="generate() is not deterministic")
        self.assertEqual(len({json.dumps(r["rules"], sort_keys=True) for r in runs}), 1)


if __name__ == "__main__":
    unittest.main()
