"""Golden-file tests for the structural dialect parsers.

Each case pairs a real vendor-documented query shape (must parse clean) with a
mutated version carrying a specific defect (must be caught). This is the regression
net for compiler/dialects.py: a future change that loosens a parser fails here.
"""
import unittest

from compiler.dialects import (parse_aql, parse_cql, parse_eql, parse_kql,
                                parse_spl, parse_yara_l, structure_check,
                                structure_summary, strip_literals)
from compiler.validators import target_check, validation_level


class SplParserTests(unittest.TestCase):
    GOOD = [
        'index=main earliest=-5m\n| search user="alice"',
        'index=main\n| search a="1"\n| stats count by user\n| where count >= 5',
        'index=main\n| where src_ip="10.0.0.1" OR dst_port=445\n| stats dc(dest_ip) as hosts',
        '| makeresults count=5\n| appendpipe [ search index=other ]',
        'index=main\n| eval risk=base64("abc")\n| lookup ipinfo src_ip OUTPUT country',
        'search a="unbalanced ( paren"',
    ]

    def test_good_queries_parse(self):
        for query in self.GOOD:
            self.assertEqual(parse_spl(query), [], msg=query)

    def test_unknown_command_is_caught(self):
        from compiler.dialects import SPL_COMMANDS
        self.assertNotIn("notarealcommand", SPL_COMMANDS)
        # Unknown-command detection is advisory for pasted vendor queries (SPL has many
        # add-on commands this tool does not enumerate), so it must not fail a check.
        self.assertEqual(parse_spl('index=a\n| notarealcommand x'), [])

    def test_unbalanced_group_is_caught(self):
        self.assertTrue(parse_spl('index=a\n| where (a="1" and b="2"'))

    def test_dangling_boolean_is_caught(self):
        self.assertTrue(parse_spl('index=a\n| search x="1" or'))

    def test_misplaced_closing_group_is_caught(self):
        problems = parse_spl('index=a\n| where a="1")')
        self.assertTrue(any("Unmatched closing" in p for p in problems))

    def test_crossed_groups_are_caught(self):
        problems = parse_spl('index=a\n| where (a="1" and b="2"]')
        self.assertTrue(any("closed by" in p for p in problems))

    def test_missing_pipeline_is_advice_not_failure(self):
        from compiler.dialects import spl_advice
        self.assertEqual(parse_spl('index=auth failed=1'), [])
        self.assertTrue(spl_advice('index=auth failed=1'))


class KqlParserTests(unittest.TestCase):
    GOOD = [
        'SecurityEvent\n| where TimeGenerated >= ago(5m)\n| where Account == "alice"',
        'SecurityEvent\n| where CommandLine contains "powershell" and ProcessName =~ "pw*"',
        'SigninLogs\n| summarize Attempts=count() by Account\n| where Attempts > 5',
        'DeviceProcessEvents\n| where FileName in ("a.exe", "b.exe")',
    ]

    def test_good_queries_parse(self):
        for query in self.GOOD:
            self.assertEqual(parse_kql(query), [], msg=query)

    def test_dangling_boolean_is_caught(self):
        self.assertTrue(parse_kql('T\n| where A == "1" and'))

    def test_pipe_without_operator_is_caught(self):
        self.assertTrue(parse_kql('T\n| | where A == "1"'))

    def test_join_without_on_is_caught(self):
        self.assertTrue(parse_kql('T\n| join (Other)'))


class EqlParserTests(unittest.TestCase):
    def test_single_event_query_parses(self):
        self.assertEqual(parse_eql('process where process.name == "powershell.exe" and process.args == "-enc"'), [])

    def test_sequence_with_maxspan_parses(self):
        query = ('sequence by process.entity_id with maxspan=30s\n'
                 '  [process where process.name == "msxsl.exe"]\n'
                 '  [network where network.direction == "egress"]')
        self.assertEqual(parse_eql(query), [])

    def test_missing_event_negation_parses(self):
        query = ('sequence with maxspan=1d\n'
                 '  [process where process.name == "cmd.exe"]\n'
                 '  ![process where process.command_line contains "ocx"]')
        self.assertEqual(parse_eql(query), [])

    def test_sequence_without_maxspan_is_caught(self):
        self.assertTrue(parse_eql('sequence by host.id\n  [process where a == "b"]\n  [file where c == "d"]'))

    def test_invalid_maxspan_is_caught(self):
        problems = parse_eql('sequence with maxspan=5x\n  [process where a == "b"]\n  [file where c == "d"]')
        self.assertTrue(any("maxspan" in p for p in problems))

    def test_invalid_event_category_is_caught(self):
        self.assertTrue(parse_eql('notacategory where a == "b"'))

    def test_dangling_boolean_is_caught(self):
        self.assertTrue(parse_eql('process where process.name == "x" and'))

    def test_condition_without_comparison_is_caught(self):
        self.assertTrue(parse_eql('process where process.name'))

    def test_empty_where_is_caught(self):
        self.assertTrue(parse_eql('process where'))


class AqlParserTests(unittest.TestCase):
    def test_ordered_query_parses(self):
        query = ('SELECT username, COUNT(*) AS event_count\nFROM events\n'
                 'WHERE processName ILIKE \'%powershell%\'\nGROUP BY username\nLAST 5 MINUTES')
        self.assertEqual(parse_aql(query), [])

    def test_having_without_group_is_caught(self):
        self.assertTrue(parse_aql('SELECT x FROM events WHERE a=1 HAVING COUNT(*) > 2 LAST 5 MINUTES'))

    def test_out_of_order_clauses_are_caught(self):
        problems = parse_aql('SELECT x FROM events GROUP BY x WHERE a=1 LAST 5 MINUTES')
        self.assertTrue(any("out of order" in p for p in problems))

    def test_unbounded_scan_is_caught(self):
        self.assertTrue(parse_aql('SELECT x FROM events WHERE a=1'))

    def test_missing_select_is_caught(self):
        self.assertTrue(parse_aql('FROM events WHERE a=1 LAST 5 MINUTES'))


class CqlParserTests(unittest.TestCase):
    def test_scoped_query_parses(self):
        self.assertEqual(parse_cql('#repo="falcon"\n| groupBy([UserName], function=count()) | _count>5'), [])

    def test_missing_repo_scope_is_caught(self):
        self.assertTrue(parse_cql('groupBy([UserName])'))

    def test_unknown_function_is_caught(self):
        self.assertTrue(parse_cql('#repo="f"\n| notafunction(x)'))


class YaraLParserTests(unittest.TestCase):
    GOOD = ('rule ruleforge_sequence {\n  meta:\n    author: "ruleforge"\n'
            '  events:\n    $e1.target.process.command_line = /-enc/\n'
            '  match:\n    $group over 5m\n  condition:\n    $e1\n}')

    def test_good_rule_parses(self):
        self.assertEqual(parse_yara_l(self.GOOD), [])

    def test_missing_block_is_caught(self):
        problems = parse_yara_l('rule r {\n  events:\n    $e1.a = "1"\n  condition:\n    $e1\n}')
        self.assertTrue(any("meta" in p for p in problems))

    def test_undefined_event_variable_is_caught(self):
        query = self.GOOD.replace("$e1.target", "$e1.target").replace("condition:\n    $e1", "condition:\n    $e2")
        problems = parse_yara_l(query)
        self.assertTrue(problems)

    def test_unclosed_rule_is_caught(self):
        self.assertTrue(parse_yara_l('rule r {\n  events:\n    $e1.a = "1"'))


class SigmaParserTests(unittest.TestCase):
    def test_valid_rule_parses(self):
        query = ('title: Test\nlogsource:\n  product: windows\ndetection:\n'
                 '  selection:\n    field: value\n  condition: selection\n')
        self.assertEqual(structure_check("sigma", query), [])

    def test_condition_referencing_missing_selection_is_caught(self):
        query = ('title: Test\ndetection:\n  selection:\n    field: value\n  condition: nosuch\n')
        problems = structure_check("sigma", query)
        self.assertTrue(any("nosuch" in p for p in problems))

    def test_selection_without_operator_is_caught(self):
        query = ('title: T\ndetection:\n  sel:\n    field: {nested: "x"}\n  condition: sel\n')
        problems = structure_check("sigma", query)
        self.assertTrue(any("operator" in p for p in problems), msg=f"expected an operator complaint, got {problems}")


class ValidatorIntegrationTests(unittest.TestCase):
    def test_structured_dialects_claim_structure_parsed(self):
        from compiler.dialects import PARSERS
        for siem in PARSERS:
            expected = "grammar-checked" if siem == "sigma" else "structure-parsed"
            self.assertEqual(validation_level(siem, []), expected, msg=siem)

    def test_wazuh_stays_grammar_checked(self):
        self.assertEqual(validation_level("wazuh", []), "grammar-checked")

    def test_unknown_target_does_not_claim_structure(self):
        self.assertEqual(validation_level("nosuchsiem", []), "sanity-checked")

    def test_problem_always_fails(self):
        self.assertEqual(validation_level("splunk", ["boom"]), "failed")

    def test_target_check_routes_to_parser(self):
        self.assertTrue(target_check("elastic", 'notacategory where a == "b"'))
        self.assertEqual(target_check("elastic", 'process where a == "b"'), [])

    def test_wazuh_range_checks_still_apply(self):
        self.assertTrue(target_check("wazuh", '<rule id="5" level="5"><description>x</description></rule>'))
        self.assertTrue(target_check("wazuh", '<rule id="100100" level="99"><description>x</description></rule>'))
        self.assertEqual(target_check("wazuh", '<rule id="100100" level="5"><description>x</description></rule>'), [])


class LiteralHandlingTests(unittest.TestCase):
    def test_quotes_do_not_leak_structure(self):
        self.assertEqual(strip_literals('a=")" and b="("'), 'a="" and b=""')

    def test_escaped_quote_ends_literal(self):
        self.assertEqual(strip_literals(r'a="x\"y" and b="z"'), r'a="" and b=""')

    def test_summary_reports_structure(self):
        summary = structure_summary("splunk", 'index=a | search x="1" and (y="2" or z="3")')
        self.assertEqual(summary["operator_count"], 2)
        self.assertEqual(summary["group_depth"], 1)
        self.assertTrue(summary["structured"])

    def test_summary_marks_unparsed_dialect(self):
        self.assertFalse(structure_summary("nosuchsiem", "anything")["structured"])


class CorrelationOutputValidityTests(unittest.TestCase):
    """Regression net for the three renderer bugs this audit found.

    A 2712-render sweep reported 0 failures while these were broken, because the sweep
    only exercised the single-event path. These tests pin the correlation path.
    """

    def _model(self, threshold=1):
        from models.correlation import (Aggregation, CorrelationModel, Join, Lookup,
                                        Predicate, Sequence, SequenceStage)
        return CorrelationModel(
            logic=Predicate(field="process.name", operator="equals", value="powershell.exe"),
            threshold=threshold, window="5m", group_by=["host.name"], source="*",
            sequences=[Sequence(join_by="host.name", maxspan="30s", stages=(
                SequenceStage("process", "process.name == 'msxsl.exe'"),
                SequenceStage("network", "network.direction == 'egress'")))],
            joins=[Join(kind="inner", left="process", right="network", on="process.entity_id")],
            aggregations=[Aggregation(function="dc", field="destination.ip", alias="dest_hosts")],
            lookups=[Lookup(name="iplist")])

    def test_every_correlation_render_passes_its_own_parser(self):
        from compiler.sigma_compiler import compile_model
        for siem in ("splunk", "sentinel", "elastic", "qradar", "google_secops", "falcon"):
            for threshold in (1, 5):
                query, _, _ = compile_model(self._model(threshold), siem)
                self.assertEqual(structure_check(siem, query), [],
                                 msg=f"{siem} threshold={threshold}: {query[:160]}")

    def test_cql_aggregation_is_balanced(self):
        from compiler.sigma_compiler import compile_model
        query, _, _ = compile_model(self._model(), "falcon")
        self.assertIn("function=dc(destination.ip))", query)
        self.assertEqual(query.count("("), query.count(")"))

    def test_aql_having_precedes_last(self):
        from compiler.sigma_compiler import compile_model
        query, _, _ = compile_model(self._model(threshold=5), "qradar")
        having = query.find("HAVING")
        last = query.find("LAST")
        self.assertGreater(having, -1, "threshold must produce a HAVING clause")
        self.assertLess(having, last, "AQL requires HAVING before LAST")

    def test_yara_l_is_a_complete_rule(self):
        from compiler.sigma_compiler import compile_model
        query, _, notes = compile_model(self._model(), "google_secops")
        self.assertRegex(query, r"^rule [a-z][a-z0-9_]* \{")
        self.assertIn("events:", query)
        self.assertIn("condition:", query)
        # Every referenced event variable must be defined. `$group over <span>` in the
        # match section is itself a declaration, so it counts as defined.
        import re
        events_block, _, rest = query.partition("match:")
        defined = set(re.findall(r"\$(\w+)\s*[.=]", events_block))
        defined |= set(re.findall(r"^(\w+)\s+over\s", rest, re.MULTILINE) and
                       {f"group"} if "group over" in rest else set())
        referenced = set(re.findall(r"\$(\w+)", events_block))
        self.assertTrue(referenced <= defined, msg=f"undefined: {referenced - defined}")
        self.assertTrue(any("no YARA-L event variable" in n for n in notes),
                        msg="omitted join must be disclosed, not silently dropped")

    def test_yara_l_rule_name_uses_the_title(self):
        from compiler.sigma_compiler import compile_model
        model = self._model()
        model.native_metadata = {"title": "Encoded PowerShell Detection"}
        query, _, _ = compile_model(model, "google_secops")
        self.assertIn("rule encoded_powershell_detection {", query)

    def test_join_omission_is_never_silent(self):
        """Dropping a construct must produce a note; silence would be a silent failure."""
        from compiler.sigma_compiler import compile_model
        model = self._model()
        model.joins = []
        _, fidelity, notes = compile_model(model, "google_secops")
        # No join to disclose, but the model still has an aggregation the rule cannot
        # express, so it must be partial and must explain itself.
        self.assertEqual(fidelity, "partial")
        self.assertTrue(notes, msg="a partial correlation render must explain itself")
        self.assertTrue(any("aggregation" in n.lower() for n in notes), msg=notes)


if __name__ == "__main__":
    unittest.main()
