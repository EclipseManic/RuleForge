"""Tests for the detection engineer's actual workflows.

The product is a drafting tool for a human analyst, not an autonomous generator. These
tests therefore pin the workflow an analyst performs - paste a real event from their
console, paste an existing rule, draft once for every target - rather than coverage
percentages. A regression here costs the analyst real time.

Deliberately NOT tested as defects: unmapped-field warnings, partial fidelity labels and
verify-before-enabling notes. Under a human-in-the-loop standard those are the correct
behaviour: a flagged field is a five-second lookup for someone who can read a log, while
a silently wrong field is a detection that never fires.
"""
import unittest

from rule_engine import analyze_rule, generate_rules

RAW_EVENTS = {
    "splunk": '2026-09-24 09:14:22 HOST EventCode=1 Image="C:\\Windows\\System32\\rundll32.exe" '
              'CommandLine="rundll32.exe javascript:x" User="CONTOSO\\jdoe"',
    "sentinel": 'EventCode=1 Image="powershell.exe" CommandLine="powershell -enc SQBFAFgA" '
                'User="CORP\\asmith" Computer="FIN-WS-22"',
    "elastic": '{"@timestamp":"2026-09-24T10:02:11Z","event":{"code":1},'
               '"process":{"name":"certutil.exe","command_line":"certutil -urlcache"},'
               '"user":{"name":"svc_backup"},"host":{"name":"DC-07"}}',
    "qradar": '2026-09-24 11:00:00 WIN_DEFEND PROTECTION_HISTORY 1 10.0.0.5 '
              '[User: admin] [CommandLine: "Add-MpPreference"]',
    "google_secops": 'metadata.event_type="USER_LOGIN" principal.user.userid="alice" '
                     'principal.ip="10.0.0.9"',
    "falcon": '#repo="falcon"\n| ImageFileName="mimikatz.exe"',
    "wazuh": '<event><field name="win.eventdata.image">psexec.exe</field></event>',
    "sigma": 'title: t\nlogsource:\n  product: windows\ndetection:\n'
             '  selection:\n    Image: cmd.exe\n  condition: selection',
}

EXISTING_RULES = {
    "splunk": 'index=main earliest=-5m\n| search Image="rundll32.exe" CommandLine="*javascript:*"\n| stats count by User',
    "sentinel": 'SecurityEvent\n| where Image == "powershell.exe" and CommandLine contains "-enc"',
    "elastic": 'process where process.name == "certutil.exe" and process.command_line : "*-urlcache*"',
    "qradar": "SELECT username FROM events WHERE processName ILIKE '%powershell%' LAST 5 MINUTES",
    "google_secops": 'rule r {\n  meta:\n    author: "me"\n  events:\n'
                     '    $e.target.process.file.full_path = "net.exe"\n  condition:\n    $e\n}',
    "falcon": '#repo="falcon"\n| ImageFileName="mimikatz.exe"\n| groupBy([ComputerName], function=count())',
    "wazuh": '<rule id="100100" level="10" frequency="5" timeframe="300"><description>d</description>'
             '<match><field name="win.eventdata.image">psexec.exe</field></match></rule>',
    "sigma": 'title: Test\nid: 1\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image: cmd.exe\n'
             '  filter:\n    User: SYSTEM\n  condition: sel and not filter\nlevel: high',
}


class RawEventImportTests(unittest.TestCase):
    """Pasting one event from the analyst's console must produce a starting draft."""

    def test_every_target_extracts_conditions_from_a_real_event(self):
        for target, raw in RAW_EVENTS.items():
            result = analyze_rule(raw, target)
            self.assertTrue(result["conditions"],
                            msg=f"{target}: pasted a real event but got no conditions")

    def test_elastic_json_flattens_to_dotted_paths(self):
        result = analyze_rule(RAW_EVENTS["elastic"], "elastic")
        fields = {c["field"]: c["value"] for c in result["conditions"]}
        self.assertEqual(fields["process.name"], "certutil.exe")
        self.assertEqual(fields["user.name"], "svc_backup")
        self.assertEqual(fields["host.name"], "DC-07")
        self.assertEqual(fields["event.code"], "1")

    def test_elastic_json_multi_valued_fields_use_the_real_field_name(self):
        """A multi-valued ECS field is addressed by its own name. `event.type.0` is not a
        field in any index, so a rule built on it would deploy and never match."""
        raw = '{"event":{"type":["start","exec"]},"process":{"trusted":false,"pid":42}}'
        conds = analyze_rule(raw, "elastic")["conditions"]
        by_field = {c["field"]: c for c in conds}
        self.assertIn("event.type", by_field)
        self.assertEqual(by_field["event.type"]["operator"], "in_list")
        self.assertEqual(by_field["event.type"]["value"], ["start", "exec"])
        self.assertEqual(by_field["process.pid"]["value"], "42")
        # No invented positional paths, and booleans are predicates not match values.
        self.assertNotIn("event.type.0", by_field)
        self.assertNotIn("process.trusted", by_field)
        for condition in conds:
            self.assertNotRegex(condition["field"], r"\.\d+$",
                                msg=f"invented array-index field: {condition['field']}")

    def test_qradar_event_extracts_bracketed_pairs(self):
        fields = {c["field"]: c["value"] for c in analyze_rule(RAW_EVENTS["qradar"], "qradar")["conditions"]}
        self.assertEqual(fields["User"], "admin")
        self.assertEqual(fields["CommandLine"], "Add-MpPreference")

    def test_wazuh_event_extracts_field_nodes(self):
        fields = {c["field"]: c["value"] for c in analyze_rule(RAW_EVENTS["wazuh"], "wazuh")["conditions"]}
        self.assertEqual(fields["win.eventdata.image"], "psexec.exe")

    def test_malformed_json_does_not_crash(self):
        for raw in ('{"broken": ', '{"a": 1,,}', '[1,2', "{'single': 'quotes'}"):
            result = analyze_rule(raw, "elastic")
            self.assertIsInstance(result.get("conditions"), list, msg=raw)

    def test_pathological_yaml_does_not_crash(self):
        """PyYAML recurses on unterminated flow sequences. A bad paste must be a clean
        validation error, never a RecursionError escaping into a 500."""
        from rule_engine import RuleValidationError
        for raw in ("[K: " * 500, "[[" * 400, "{" * 400):
            with self.assertRaises(RuleValidationError, msg=raw[:20]):
                analyze_rule(raw, "sigma")

    def test_pathological_yaml_is_rejected_by_every_entry_point(self):
        from compiler.validators import sigma_check, target_check
        from parsers.sigma_parser import parse_sigma
        from section_view import section_blocks
        raw = "[K: " * 500
        with self.assertRaises(ValueError):
            parse_sigma(raw)
        self.assertTrue(any("YAML" in m for m in sigma_check(raw)))
        self.assertTrue(any("YAML" in p for p in target_check("sigma", raw)))
        self.assertIsInstance(section_blocks(raw, "sigma"), list)


class ExistingRuleImportTests(unittest.TestCase):

    def test_every_target_extracts_conditions_from_an_existing_rule(self):
        for target, raw in EXISTING_RULES.items():
            result = analyze_rule(raw, target)
            self.assertTrue(result["conditions"], msg=f"{target}: valid rule yielded no conditions")

    def test_no_crash_on_wazuh_event_without_rule_element(self):
        """A bare <event> has no <rule>, so the group-by default must be used rather
        than leaving the variable unbound and raising at return time."""
        result = analyze_rule('<event><field name="win.eventdata.image">psexec.exe</field></event>', "wazuh")
        self.assertEqual(result["group_by"], "user.name")
        self.assertTrue(result["conditions"])

    def test_no_crash_on_wazuh_xml_without_match(self):
        result = analyze_rule('<group><rule id="100100" level="5" /></group>', "wazuh")
        self.assertIn("group_by", result)
        self.assertEqual(result["threshold"], 1)

    def test_wazuh_rule_threshold_and_timeframe_are_read(self):
        result = analyze_rule(EXISTING_RULES["wazuh"], "wazuh")
        self.assertEqual(result["threshold"], 5)
        self.assertEqual(result["timeframe"], "5m")

    def test_repo_scope_is_not_offered_as_a_condition(self):
        """#repo selects the log source; treating it as match logic would have the
        analyst draft a rule on their own repository name."""
        result = analyze_rule(EXISTING_RULES["falcon"], "falcon")
        self.assertNotIn("repo", [c["field"] for c in result["conditions"]])
        self.assertEqual(result["native_sections"].get("repo"), '"falcon"')


class PastedValueSafetyTests(unittest.TestCase):
    """Values come from untrusted pasted logs and end up inside query string literals.

    A value must never be able to terminate its own literal and inject query syntax.
    """

    def _rules_for(self, value):
        return generate_rules({
            "title": "t", "description": "d", "severity": "low", "technique": "custom",
            "field": "process.name", "operator": "equals", "value": value,
            "conditions": [{"field": "process.name", "operator": "equals", "value": value}],
            "condition_logic": "all", "exclude_conditions": [], "threshold": 1, "timeframe": "5m",
            "group_by": "user.name", "data_source": "*",
            "siems": ["qradar", "splunk", "sentinel", "elastic"]})

    def test_double_quote_in_value_cannot_terminate_a_splunk_literal(self):
        import re
        rule = next(r for r in self._rules_for('evil" | stats count by User #') if r["siem"] == "splunk")["rule"]
        search_line = [l for l in rule.splitlines() if "| search" in l][0]
        self.assertIn('\\"', search_line)
        # Count only quotes that actually delimit a literal: an escaped \" does not close
        # one, so those must be excluded or the count is meaningless.
        unescaped = re.findall(r'(?<!\\)"', search_line)
        self.assertEqual(len(unescaped) % 2, 0, msg=f"unbalanced literal in {search_line!r}")
        # The injected pipe must stay inside the quoted literal, not become a real stage.
        self.assertEqual(len([l for l in rule.splitlines() if l.strip().startswith("|")]), 2,
                         msg="a pasted value created an extra pipeline stage")

    def test_double_quote_is_harmless_inside_an_aql_literal(self):
        """AQL literals are single-quoted, so an embedded double quote needs no escaping
        and must not be altered."""
        rule = next(r for r in self._rules_for('evil" | stats count by User #') if r["siem"] == "qradar")["rule"]
        where = [l for l in rule.splitlines() if l.startswith("WHERE")][0]
        self.assertIn("'evil\"", where)
        self.assertEqual(where.count("'") % 2, 0, msg="unbalanced single quotes in AQL")

    def test_single_quote_in_value_cannot_terminate_an_aql_literal(self):
        rule = self._rules_for("x' OR '1'='1")[0]["rule"]
        where = [l for l in rule.splitlines() if l.startswith("WHERE")][0]
        self.assertIn("\\'", where)
        # AQL cannot be made to evaluate an injected OR: the quote is escaped.
        self.assertEqual(where.count("'") % 2, 0, msg="unbalanced single quotes in AQL")

    def test_control_characters_are_rejected_not_rendered(self):
        from rule_engine import RuleValidationError
        with self.assertRaises(RuleValidationError):
            self._rules_for("line1\nline2")

    def test_json_event_containing_a_pipe_still_extracts(self):
        """A command line legitimately contains '|'. Sniffing by 'does this look like a
        query' previously suppressed extraction and returned nothing at all."""
        raw = '{"process":{"name":"cmd.exe","command_line":"cmd /c \\"dir | findstr foo\\""}}'
        fields = {c["field"]: c["value"] for c in analyze_rule(raw, "elastic")["conditions"]}
        self.assertEqual(fields["process.name"], "cmd.exe")
        self.assertEqual(fields["process.command_line"], 'cmd /c "dir | findstr foo"')

    def test_bracket_extraction_is_not_quadratic(self):
        """Unterminated bracket input must fail fast, not rescan from every position."""
        import time
        from rule_engine import _bracket_event_conditions
        timings = []
        for n in (1000, 4000):
            start = time.time()
            _bracket_event_conditions("[K: " * n)
            timings.append(time.time() - start)
        self.assertLess(timings[1], max(0.5, timings[0] * 6),
                        msg=f"bracket extraction looks quadratic: {timings}")

class DraftingWorkflowTests(unittest.TestCase):
    def _request(self):
        return {
            "title": "Suspicious certutil download", "description": "d", "severity": "high",
            "technique": "custom", "field": "process.name", "operator": "equals", "value": "certutil.exe",
            "conditions": [{"field": "process.name", "operator": "equals", "value": "certutil.exe"},
                           {"field": "process.command_line", "operator": "contains", "value": "-urlcache"}],
            "condition_logic": "all",
            "exclude_conditions": [{"field": "user.name", "operator": "equals", "value": "svc_backup"}],
            "threshold": 1, "timeframe": "5m", "group_by": "host.name",
            "data_source": "logs-endpoint.events.*",
            "siems": ["splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon", "sigma"],
        }

    def test_one_intent_yields_every_target_with_clean_output(self):
        for rule in generate_rules(self._request()):
            self.assertEqual(rule["checks"], [], msg=f"{rule['siem']}: {rule['checks']}")
            self.assertIn(rule["validation"], ("structure-parsed", "grammar-checked"))

    def test_exclusion_survives_into_every_target(self):
        for rule in generate_rules(self._request()):
            self.assertIn("svc_backup", rule["rule"], msg=f"{rule['siem']} dropped the exclusion")

    def test_draft_is_deterministic(self):
        first = [r["rule"] for r in generate_rules(self._request())]
        second = [r["rule"] for r in generate_rules(self._request())]
        self.assertEqual(first, second)


class IndependentReviewRegressionTests(unittest.TestCase):
    """Findings from an independent code review, pinned so they cannot return."""

    def test_wazuh_negated_field_becomes_an_exclusion(self):
        """Importing negate="yes" as a positive match inverts the rule silently - worse
        than a wrong field name, because the rule looks correct and does the opposite."""
        rule = ('<rule id="100100" level="5"><match>'
                '<field name="User">admin</field>'
                '<field name="CommandLine" negate="yes">-enc</field>'
                '</match></rule>')
        result = analyze_rule(rule, "wazuh")
        positive = {c["field"] for c in result["conditions"]}
        negative = {c["field"] for c in result["exclusions"]}
        self.assertIn("User", positive)
        self.assertIn("CommandLine", negative)
        self.assertNotIn("CommandLine", positive)
        # The exclusion must survive the round trip as a negation, not as a match.
        from app import _analysis_to_model
        from compiler.sigma_compiler import compile_model
        recompiled, _, _ = compile_model(_analysis_to_model(result), "wazuh")
        self.assertIn('negate="yes"', recompiled)

    def test_semantically_wrong_mappings_are_absent(self):
        """These three aliased a field to a DIFFERENT field, changing the predicate."""
        from rule_engine import FIELD_MAPPINGS
        for target, canonical in (("sentinel", "process.working_directory"),
                                  ("google_secops", "process.thread.id"),
                                  ("google_secops", "event.id")):
            self.assertNotIn(canonical, FIELD_MAPPINGS[target],
                             msg=f"{target}.{canonical} aliased to an unrelated field")

    def test_inferred_targets_are_labelled_not_presented_as_verified(self):
        from rule_engine import FIELD_MAPPINGS, INFERRED_TARGETS, generate_rules as gr
        for target in INFERRED_TARGETS:
            self.assertIn(target, FIELD_MAPPINGS)
        out = gr({
            "title": "t", "description": "d", "severity": "low", "technique": "custom",
            "field": "process.name", "operator": "equals", "value": "psexec.exe",
            "conditions": [{"field": "process.name", "operator": "equals", "value": "psexec.exe"}],
            "condition_logic": "all", "exclude_conditions": [], "threshold": 1, "timeframe": "5m",
            "group_by": "host.name", "data_source": "*", "siems": ["wazuh", "qradar", "splunk"]})
        by = {r["siem"]: r for r in out}
        for target in ("wazuh", "qradar"):
            self.assertEqual(by[target]["field_mapping"]["mapping_confidence"], "inferred")
            self.assertIn(target, by[target]["field_mapping"]["inferred_target"])
        self.assertEqual(by["splunk"]["field_mapping"]["mapping_confidence"], "documented")

    def test_elastic_threshold_does_not_claim_a_dropped_aggregation(self):
        from models.correlation import Aggregation, CorrelationModel, Predicate
        from compiler.sigma_compiler import compile_model
        model = CorrelationModel(
            logic=Predicate(field="process.name", operator="equals", value="certutil.exe"),
            threshold=5, window="5m", group_by=["host.name"],
            aggregations=[Aggregation(function="dc", field="destination.ip", alias="dest_hosts")])
        query, fidelity, notes = compile_model(model, "elastic")
        self.assertNotIn("Aggregation rendered", " ".join(notes),
                         msg="claimed an aggregation was rendered when it was dropped")
        self.assertIn("dc", " ".join(notes), msg="dropped aggregation must be named")
        self.assertNotIn("destination.ip", query)
        self.assertEqual(fidelity, "partial")

    def test_valid_aql_select_distinct_is_accepted(self):
        from compiler.dialects import parse_aql
        self.assertEqual(parse_aql("SELECT DISTINCT username FROM events "
                                   "WHERE sourceip = '1.2.3.4' LAST 5 MINUTES"), [])

    def test_unterminated_quote_is_reported(self):
        """Malformed input must not earn a structure-parsed claim. The check lives in
        structure_check/target_check, which is the path every consumer uses."""
        from compiler.dialects import structure_check
        from compiler.validators import target_check, validation_level
        for siem, query in (("splunk", 'index=x | search foo="oops'),
                            ("qradar", "SELECT a FROM events WHERE b = 'oops")):
            self.assertTrue(any("Unterminated" in p for p in structure_check(siem, query)), msg=siem)
            self.assertTrue(any("Unterminated" in p for p in target_check(siem, query)), msg=siem)
        self.assertEqual(validation_level("splunk", target_check("splunk", 'index=x | search foo="oops')), "failed")

    def test_apostrophe_inside_double_quotes_is_not_a_false_positive(self):
        from compiler.dialects import unterminated_literals
        self.assertEqual(unterminated_literals('user="alice\'s"'), [])

    def test_bracket_extraction_keeps_nested_brackets_and_spaces_in_labels(self):
        from rule_engine import _bracket_event_conditions
        out = _bracket_event_conditions('[CommandLine: "cmd /c echo [x]"] [User Name: admin]')
        fields = {c["field"]: c["value"] for c in out}
        self.assertEqual(fields["User Name"], "admin")
        self.assertIn("[x]", fields["CommandLine"])

    def test_override_native_field_cannot_contain_query_syntax(self):
        from mapping_overrides import OverrideError, validate_pair
        for bad in ('x" OR process.name contains "evil', "a b", "a,b", "a|b", "a=1"):
            with self.assertRaises(OverrideError, msg=bad):
                validate_pair("a.b", bad)
        self.assertEqual(validate_pair("a.b", "TargetProcessName"), ("a.b", "TargetProcessName"))
        self.assertEqual(validate_pair("a.b", "win.eventdata.image"), ("a.b", "win.eventdata.image"))


    def test_sentinel_never_pairs_asim_columns_with_the_legacy_table(self):
        """ASIM columns (TargetProcessName) do not exist in SecurityEvent, which carries
        Account/CommandLine/Image. Emitting that pairing produced a rule referencing
        columns its own table did not contain."""
        from rule_engine import ASIM_TABLE_PLACEHOLDER
        from compiler.pipeline import compile_request
        from rule_engine import parse_request
        request = parse_request({
            "title": "t", "description": "d", "severity": "low", "technique": "custom",
            "field": "process.name", "operator": "equals", "value": "powershell.exe",
            "threshold": 1, "timeframe": "5m", "group_by": "host.name", "data_source": "*",
            "siems": ["sentinel"],
            "conditions": [{"field": "process.name", "operator": "equals", "value": "powershell.exe"}],
            "condition_logic": "all"})
        rule = compile_request(request, "sentinel")
        self.assertIn(ASIM_TABLE_PLACEHOLDER, rule["rule"])
        self.assertIn("TargetProcessName", rule["rule"])
        # The legacy table name may only appear inside a comment explaining why not.
        executable = [l for l in rule["rule"].splitlines() if not l.strip().startswith("//")]
        self.assertFalse(any("SecurityEvent" in l for l in executable),
                         msg="legacy table name used as an executable table")
        self.assertTrue(any("placeholder" in w for w in rule["warnings"]), msg=rule["warnings"])

    def test_sentinel_uses_the_analysts_own_table_when_given(self):
        from rule_engine import ASIM_TABLE_PLACEHOLDER
        from compiler.pipeline import compile_request
        from rule_engine import parse_request
        request = parse_request({
            "title": "t", "description": "d", "severity": "low", "technique": "custom",
            "field": "process.name", "operator": "equals", "value": "powershell.exe",
            "threshold": 1, "timeframe": "5m", "group_by": "host.name",
            "data_source": "MyAsimProcessEvents", "siems": ["sentinel"],
            "conditions": [{"field": "process.name", "operator": "equals", "value": "powershell.exe"}],
            "condition_logic": "all"})
        rule = compile_request(request, "sentinel")
        self.assertNotIn(ASIM_TABLE_PLACEHOLDER, rule["rule"])
        self.assertIn("MyAsimProcessEvents", rule["rule"])
        self.assertIn("TargetProcessName", rule["rule"])

    def test_sentinel_placeholder_raises_a_visible_warning(self):
        from compiler.validators import target_warnings
        from rule_engine import ASIM_TABLE_PLACEHOLDER
        warnings = target_warnings("sentinel", f"{ASIM_TABLE_PLACEHOLDER}\n| where TimeGenerated >= ago(5m)\n"
                                               '| where TargetProcessName == "x"')
        self.assertTrue(any("placeholder" in w for w in warnings), msg=warnings)
        self.assertFalse(target_warnings("sentinel", "MyAsimTable\n| where TimeGenerated >= ago(5m)\n"
                                                   '| where TargetProcessName == "x"'))


    def test_bracket_extraction_is_not_quadratic(self):
        """Unterminated bracket input must fail fast, and colon-free input must not
        rescan the suffix from every unmatched bracket."""
        import time
        from rule_engine import _bracket_event_conditions
        timings = []
        for payload in ("[K: " * 1000, "[" * 1000, "[" * 4000):
            start = time.time()
            _bracket_event_conditions(payload)
            timings.append(time.time() - start)
        self.assertLess(timings[1], 0.5, msg=f"colon-free input too slow: {timings}")
        self.assertLess(timings[2], 1.0, msg=f"scaling is superlinear: {timings}")


class SecondReviewRegressionTests(unittest.TestCase):
    """Findings from the second independent review pass."""

    def test_advanced_correlation_emits_native_not_canonical_fields(self):
        """The advanced path built its model from the untranslated request, so the API
        reported native_field=TargetProcessName while the rule emitted process.name."""
        from compiler.pipeline import compile_request
        from rule_engine import parse_request
        request = parse_request({
            "title": "t", "description": "d", "severity": "high", "technique": "custom",
            "field": "process.name", "operator": "equals", "value": "psexec.exe",
            "threshold": 1, "timeframe": "5m", "group_by": "host.name", "data_source": "*",
            "siems": ["sentinel"],
            "conditions": [{"field": "process.name", "operator": "equals", "value": "psexec.exe"}],
            "condition_logic": "all",
            "correlation": {"aggregations": [{"function": "dc", "field": "destination.ip", "alias": "d"}]}})
        out = compile_request(request, "sentinel")
        self.assertIn("TargetProcessName", out["rule"])
        self.assertNotIn("process.name ==", out["rule"])
        self.assertIn(out["field_mapping"]["native_field"], out["rule"])

    def test_explicit_legacy_sentinel_table_is_refused(self):
        """Supplying SecurityEvent explicitly must not pair legacy columns with ASIM."""
        from app import create_app
        from rule_engine import ASIM_TABLE_PLACEHOLDER
        client = create_app().test_client()
        rule = client.post("/api/generate", json={
            "technique": "custom", "field": "process.name", "operator": "equals", "value": "x.exe",
            "threshold": 1, "timeframe": "5m", "group_by": "host.name",
            "data_source": "SecurityEvent", "title": "t", "description": "d", "severity": "low",
            "siems": ["sentinel"],
            "conditions": [{"field": "process.name", "operator": "equals", "value": "x.exe"}],
            "condition_logic": "all"}).get_json()["rules"][0]
        executable = [l for l in rule["rule"].splitlines() if not l.strip().startswith("//")]
        self.assertFalse(any(l.strip().startswith("SecurityEvent") for l in executable))
        self.assertIn(ASIM_TABLE_PLACEHOLDER, rule["rule"])
        self.assertTrue(any("legacy" in w.lower() for w in rule["warnings"]), msg=rule["warnings"])

    def test_qradar_value_does_not_become_a_field(self):
        """`[CommandLine: "cmd /c foo=bar"]` invented a phantom field `foo`."""
        result = analyze_rule('2026-09-24 11:00:00 EV 1 10.0.0.5 [CommandLine: "cmd /c foo=bar"]', "qradar")
        self.assertNotIn("foo", [c["field"] for c in result["conditions"]])
        self.assertIn("CommandLine", [c["field"] for c in result["conditions"]])

    def test_mixed_wazuh_layout_keeps_its_exclusion(self):
        result = analyze_rule(
            '<group><rule><field name="User">admin</field><match>'
            '<field name="CommandLine" negate="yes">-enc</field></match></rule></group>', "wazuh")
        self.assertIn("CommandLine", {c["field"] for c in result["exclusions"]})
        self.assertTrue(any("mixed Wazuh" in f for f in result["unsupported_features"]),
                        msg=result["unsupported_features"])

    def test_wazuh_negate_is_case_insensitive_and_not_double_counted(self):
        result = analyze_rule('<rule id="1" level="5"><match>'
                              '<field name="a" negate="YES">b</field></match></rule>', "wazuh")
        self.assertEqual({c["field"] for c in result["exclusions"]}, {"a"})
        self.assertEqual(result["conditions"], [])

    def test_quote_scanner_ignores_comments_regex_and_apostrophes(self):
        from compiler.dialects import unterminated_literals
        for text, why in (
            ('index=x | search user="O\'Brien"', "apostrophe in a value"),
            ('index=x | search a="1"\n// analyst\'s note', "apostrophe in a // comment"),
            ('index=x | search a="1"\n# analyst\'s note', "apostrophe in a # comment"),
            ('index=x | search a="1"\n/* don\'t worry */', "apostrophe in a block comment"),
            ("SELECT a FROM events WHERE name = 'O'Brien' LAST 5 MINUTES", "apostrophe in AQL"),
            ("rule r {\n  events:\n    $e.a = /foo'bar/\n  condition:\n    $e\n}", "regex literal"),
            ("title: Analyst's rule\ndetection: {}", "Sigma plain scalar"),
        ):
            self.assertEqual(unterminated_literals(text), [], msg=why)

    def test_quote_scanner_still_catches_malformed_queries(self):
        from compiler.dialects import unterminated_literals
        self.assertTrue(unterminated_literals('index=x | search foo="oops'))
        self.assertTrue(unterminated_literals("SELECT a FROM events WHERE b = 'oops"))

    def test_elastic_threshold_does_not_invent_an_index(self):
        from models.correlation import CorrelationModel, Predicate
        from compiler.sigma_compiler import ELASTIC_INDEX_PLACEHOLDER, compile_model
        model = CorrelationModel(logic=Predicate(field="process.name", operator="equals", value="x"),
                                 threshold=5, window="5m", group_by=["user.name"], source="*")
        query, _, _ = compile_model(model, "elastic")
        self.assertNotIn("logs-endpoint.events", query)
        self.assertIn(ELASTIC_INDEX_PLACEHOLDER, query)

    def test_persisted_overrides_are_revalidated_on_load(self):
        """A hand-edited overrides.json must not reintroduce injection."""
        import json
        import tempfile
        from pathlib import Path
        from mapping_overrides import load_overrides
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "data" / "mappings" / "overrides.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"mappings": {"splunk": {
                "good.field": "good_field",
                "evil.field": 'x" OR process.name contains "evil',
                "bad.name!": "ok_field"}}}), encoding="utf-8")
            loaded = load_overrides(root).get("splunk", {})
            self.assertEqual(loaded, {"good.field": "good_field"})

    def test_udm_working_directory_alias_is_absent(self):
        from rule_engine import FIELD_MAPPINGS
        self.assertNotIn("process.working_directory", FIELD_MAPPINGS["google_secops"])

    def test_aql_single_quoted_literals_extract_with_correct_polarity(self):
        positive = analyze_rule("SELECT a FROM events WHERE sourceip = '1.2.3.4' LAST 5 MINUTES", "qradar")
        self.assertEqual([(c["field"], c["value"]) for c in positive["conditions"]], [("sourceip", "1.2.3.4")])
        negated = analyze_rule("SELECT a FROM events WHERE a = 'x' AND NOT username = 'admin' "
                               "AND b != 'y' LAST 5 MINUTES", "qradar")
        self.assertEqual({c["field"] for c in negated["conditions"]}, {"a"})
        self.assertEqual({c["field"] for c in negated["exclusions"]}, {"username", "b"})

    def test_aql_exclusion_survives_the_round_trip(self):
        from app import _analysis_to_model
        from compiler.sigma_compiler import compile_model
        source = "SELECT a FROM events WHERE sourceip = '1.2.3.4' AND NOT username = 'admin' LAST 5 MINUTES"
        first = analyze_rule(source, "qradar")
        out, _, _ = compile_model(_analysis_to_model(first), "qradar")
        again = analyze_rule(out, "qradar")
        self.assertIn("username", {c["field"] for c in again["exclusions"]})


if __name__ == "__main__":
    unittest.main()
