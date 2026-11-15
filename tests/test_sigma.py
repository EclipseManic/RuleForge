"""Sigma: the proof that the IR is vendor-neutral rather than KQL-shaped.

Three groups of tests carry most of the weight.

`ListsAreOrMapsAreAnd` is first because getting that asymmetry backwards is the
single easiest way to break a Sigma converter, and it breaks it SILENTLY:
`EventID: [10, 11]` read as AND is unsatisfiable, so the rule never fires and
nothing reports an error.

`MetadataRoundTrips` exists because `kql.py` drops annotations entirely. Sigma is
mostly metadata, so a converter that loses it produces rules a SOC cannot
triage -- and this is the dialect where the defect would hurt most.

`TheYamlSubset` is about refusing rather than guessing. Every construct this
reader does not implement has to be named, because a reader that silently
mishandles an anchor hands back a rule that is not the rule on disk.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from engine.dialects.sigma import (
    DIALECT,
    LANGUAGE,
    MODIFIER_REFUSALS,
    lower_sigma,
    parse_sigma,
    read_yaml,
    render_sigma,
)
from engine.ir import (
    Aggregate,
    BoolOp,
    Call,
    Comparison,
    Correlation,
    Emit,
    Filter,
    Literal,
    Not,
    Read,
    Regex,
    render_expr,
)
from engine.values import Refusal

#: The reference rule, in the shape a real Sigma rule takes: full metadata, a
#: logsource, two selections, modifiers, a value list, and an exclusion.
USER_RULE = """
title: Credential Dumping via LSASS Access
id: 5b4a1b2c-0000-4aaa-bbbb-ccccdddd0001
status: experimental
description: |
    Detects a process opening LSASS with a dump-capable access mask.
    Backup agents do this legitimately, which is why the filter exists.
references:
    - https://attack.mitre.org/techniques/T1003/001/
author: Detection Desk
date: 2026/01/15
modified: 2026/02/02
tags:
    - attack.credential_access
    - attack.t1003.001
    - cve.2021-44228
logsource:
    product: windows
    service: sysmon
    category: process_access
detection:
    selection:
        EventID: 10
        TargetImage|endswith: lsass.exe
        GrantedAccess:
            - 1010
            - 1410
    filter:
        SourceImage|startswith: BackupAgent
    condition: selection and not filter
fields:
    - SourceImage
    - GrantedAccess
falsepositives:
    - Backup agents
    - Endpoint protection products
level: high
"""

MINIMAL = """
title: Minimal
logsource:
    category: process_creation
detection:
    selection:
        EventID: 4688
    condition: selection
"""


def lower(text=MINIMAL):
    rule, diagnostics = lower_sigma(text)
    return rule


def detection_of(rule):
    for node in rule.pipeline:
        if isinstance(node, Filter):
            return node.condition
    raise AssertionError("the rule has no filter stage")


class Parsing(unittest.TestCase):
    def setUp(self):
        self.parsed = parse_sigma(USER_RULE)

    def test_the_selections_are_separated_from_the_condition(self):
        self.assertEqual(sorted(self.parsed.selections), ["filter", "selection"])
        self.assertEqual(self.parsed.condition, "selection and not filter")

    def test_the_logsource_is_kept_whole(self):
        self.assertEqual(
            self.parsed.logsource,
            {"product": "windows", "service": "sysmon",
             "category": "process_access"},
        )

    def test_a_block_scalar_keeps_its_line_breaks(self):
        self.assertIn("\n", self.parsed.document["description"])
        self.assertIn("Backup agents", self.parsed.document["description"])

    def test_a_rule_with_no_detection_is_refused(self):
        # A rule with nothing to match is not an empty rule -- it is a rule that
        # matches everything or nothing depending on who reads it.
        with self.assertRaises(Refusal) as caught:
            parse_sigma("title: x\nlogsource:\n    category: y\n")
        self.assertEqual(caught.exception.code, "SIGMA_NO_DETECTION")

    def test_a_detection_with_no_condition_is_refused(self):
        # Sigma does not default it, and guessing between AND and OR would
        # produce two different detections from one rule.
        with self.assertRaises(Refusal) as caught:
            parse_sigma(
                "title: x\ndetection:\n    selection:\n        EventID: 1\n"
            )
        self.assertEqual(caught.exception.code, "SIGMA_NO_CONDITION")

    def test_a_condition_with_no_selection_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_sigma("title: x\ndetection:\n    condition: selection\n")
        self.assertEqual(caught.exception.code, "SIGMA_NO_SELECTION")

    def test_a_list_of_conditions_is_refused_rather_than_joined(self):
        # Sigma v1 allowed it and removed it because nobody agreed on how the
        # entries combined. Joining them with AND here would be inventing the
        # answer the spec deliberately dropped.
        with self.assertRaises(Refusal) as caught:
            parse_sigma(
                "title: x\ndetection:\n    selection:\n        EventID: 1\n"
                "    condition:\n        - selection\n        - not filter\n"
            )
        self.assertEqual(caught.exception.code, "SIGMA_CONDITION_MALFORMED")


class TheYamlSubset(unittest.TestCase):
    def test_nested_maps_and_block_lists(self):
        parsed = read_yaml(
            "a: 1\nb:\n    c: two\n    d:\n        - x\n        - y\n"
        )
        self.assertEqual(parsed, {"a": 1, "b": {"c": "two", "d": ["x", "y"]}})

    def test_a_list_may_sit_at_its_keys_own_column(self):
        # Legal YAML and common in real Sigma rules.
        self.assertEqual(
            read_yaml("refs:\n- one\n- two\n"), {"refs": ["one", "two"]}
        )

    def test_a_list_of_maps(self):
        parsed = read_yaml(
            "selection:\n    - EventID: 10\n      Image: a.exe\n    - EventID: 11\n"
        )
        self.assertEqual(
            parsed["selection"],
            [{"EventID": 10, "Image": "a.exe"}, {"EventID": 11}],
        )

    def test_comments_are_stripped_but_a_hash_in_a_value_is_not(self):
        parsed = read_yaml("a: one  # trailing\nb: '#notacomment'\nc: ab#cd\n")
        self.assertEqual(parsed, {"a": "one", "b": "#notacomment", "c": "ab#cd"})

    def test_a_colon_inside_a_value_is_not_a_key(self):
        # A URL and a Windows path both contain a colon, and reading either as a
        # key would silently discard the value.
        parsed = read_yaml("url: https://example.invalid/a\npath: C:\\Windows\n")
        self.assertEqual(parsed["url"], "https://example.invalid/a")
        self.assertEqual(parsed["path"], "C:\\Windows")

    def test_quoted_scalars(self):
        parsed = read_yaml("a: 'it''s'\nb: \"tab\\there\"\nc: ''\n")
        self.assertEqual(parsed["a"], "it's")
        self.assertEqual(parsed["b"], "tab\there")
        self.assertEqual(parsed["c"], "")

    def test_scalar_types(self):
        parsed = read_yaml(
            "i: 10\nf: 1.5\nt: true\nn: null\ntilde: ~\ns: text\n"
        )
        self.assertEqual(parsed["i"], 10)
        self.assertEqual(parsed["f"], 1.5)
        self.assertIs(parsed["t"], True)
        self.assertIsNone(parsed["n"])
        self.assertIsNone(parsed["tilde"])
        self.assertEqual(parsed["s"], "text")

    def test_a_hex_mask_stays_text(self):
        # GrantedAccess is held as text in the log, so coercing 0x1410 to 5136
        # would stop the comparison matching.
        self.assertEqual(read_yaml("GrantedAccess: 0x1410")["GrantedAccess"],
                         "0x1410")

    def test_an_inline_flow_list(self):
        self.assertEqual(read_yaml("a: [one, two]")["a"], ["one", "two"])

    def test_a_flow_mapping_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            read_yaml("a: {b: c}")
        self.assertEqual(caught.exception.code, "SIGMA_YAML_FLOW_MAP")

    def test_an_anchor_is_refused_rather_than_ignored(self):
        # Resolving it wrongly would change what the rule detects.
        with self.assertRaises(Refusal) as caught:
            read_yaml("a: &anchor value\nb: *anchor\n")
        self.assertEqual(caught.exception.code, "SIGMA_YAML_ANCHOR")

    def test_a_tab_indent_is_refused(self):
        # Two editors would disagree about what the rule says.
        with self.assertRaises(Refusal) as caught:
            read_yaml("a:\n\tb: 1\n")
        self.assertEqual(caught.exception.code, "SIGMA_YAML_TAB")

    def test_a_duplicate_key_is_refused(self):
        # One of the two would silently win, and which one is not something a
        # reader should decide.
        with self.assertRaises(Refusal) as caught:
            read_yaml("level: high\nlevel: low\n")
        self.assertEqual(caught.exception.code, "SIGMA_DUPLICATE_KEY")

    def test_an_empty_document_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            read_yaml("# only a comment\n")
        self.assertEqual(caught.exception.code, "SIGMA_EMPTY")

    def test_a_second_document_is_refused_rather_than_discarded(self):
        # Reading the first rule and silently dropping the rest would hide
        # detections, which is the worst way to fail.
        with self.assertRaises(Refusal) as caught:
            read_yaml("title: one\n---\ntitle: two\n")
        self.assertEqual(caught.exception.code, "SIGMA_YAML_TRAILING")


class ListsAreOrMapsAreAnd(unittest.TestCase):
    """The asymmetry that is easiest to get backwards, and silent when wrong."""

    def test_several_fields_in_one_selection_are_anded(self):
        condition = detection_of(lower(
            "title: t\ndetection:\n    selection:\n"
            "        EventID: 10\n        Image: a.exe\n"
            "    condition: selection\n"
        ))
        self.assertIsInstance(condition, BoolOp)
        self.assertEqual(condition.op, "and")
        self.assertEqual(len(condition.operands), 2)

    def test_a_value_list_for_one_field_is_ored(self):
        # Backwards this is "10 AND 11", which no event can satisfy -- a rule
        # that never fires and never complains.
        condition = detection_of(lower(
            "title: t\ndetection:\n    selection:\n        EventID:\n"
            "            - 10\n            - 11\n    condition: selection\n"
        ))
        self.assertIsInstance(condition, BoolOp)
        self.assertEqual(condition.op, "or")

    def test_the_all_modifier_turns_a_value_list_into_an_and(self):
        condition = detection_of(lower(
            "title: t\ndetection:\n    selection:\n        cmd|contains|all:\n"
            "            - lsass\n            - dump\n    condition: selection\n"
        ))
        self.assertEqual(condition.op, "and")
        self.assertEqual(
            {o.op for o in condition.operands}, {"contains"}
        )

    def test_a_list_of_maps_is_ored_across_the_maps(self):
        condition = detection_of(lower(
            "title: t\ndetection:\n    selection:\n"
            "        - EventID: 10\n          Image: a.exe\n"
            "        - EventID: 11\n"
            "    condition: selection\n"
        ))
        self.assertEqual(condition.op, "or")
        self.assertEqual(condition.operands[0].op, "and")

    def test_an_empty_value_list_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(
                "title: t\ndetection:\n    selection:\n        EventID: []\n"
                "    condition: selection\n"
            )
        self.assertEqual(caught.exception.code, "SIGMA_VALUE_LIST_EMPTY")

    def test_an_empty_selection_is_refused(self):
        # An empty selection matches everything, which is the defect this
        # codebase exists to refuse to produce.
        with self.assertRaises(Refusal) as caught:
            lower(
                "title: t\ndetection:\n    selection:\n    condition: selection\n"
            )
        self.assertIn(
            caught.exception.code,
            ("SIGMA_SELECTION_EMPTY", "SIGMA_SELECTION_MALFORMED"),
        )

    def test_a_keyword_list_is_refused_rather_than_invented(self):
        # A bare list means full-text search across the whole event, and there
        # is no field here to search.
        with self.assertRaises(Refusal) as caught:
            lower(
                "title: t\ndetection:\n    keywords:\n        - lsass\n"
                "        - dump\n    condition: keywords\n"
            )
        self.assertEqual(
            caught.exception.code, "SIGMA_KEYWORD_SEARCH_UNSUPPORTED"
        )


class Modifiers(unittest.TestCase):
    def predicate(self, entry, value="x"):
        return detection_of(lower(
            f"title: t\ndetection:\n    selection:\n        {entry}: {value}\n"
            f"    condition: selection\n"
        ))

    def test_each_comparison_modifier_maps_to_its_operator(self):
        expected = {
            "f": "==", "f|contains": "contains", "f|startswith": "startswith",
            "f|endswith": "endswith", "f|lt": "<", "f|lte": "<=",
            "f|gt": ">", "f|gte": ">=",
        }
        for entry, operator in expected.items():
            with self.subTest(entry=entry):
                self.assertEqual(self.predicate(entry).op, operator)

    def test_a_numeric_value_becomes_a_decimal_not_a_float(self):
        # The engine is Decimal end to end; a threshold that arrives as a float
        # is a different threshold.
        right = self.predicate("Count|gte", "10").right
        self.assertIsInstance(right.value, Decimal)
        self.assertEqual(right.value, Decimal(10))

    def test_the_re_modifier_becomes_a_regex_node(self):
        right = self.predicate("cmd|re", "lsass.*dump").right
        self.assertIsInstance(right, Regex)
        self.assertEqual(right.pattern, "lsass.*dump")
        self.assertFalse(right.nocase)

    def test_the_regex_dialect_allows_local_execution(self):
        # Modelling Sigma's regex as PCRE would be the pessimistic choice:
        # evaluate.py refuses every PCRE pattern locally, so every Sigma rule
        # would become untestable in this workbench.
        from engine.evaluate import compile_pattern

        right = self.predicate("cmd|re", "lsass").right
        self.assertEqual(right.dialect, "posix_extended")
        self.assertIsNotNone(compile_pattern(right.dialect, right.pattern))

    def test_the_i_flag_makes_a_regex_case_insensitive(self):
        self.assertTrue(self.predicate("cmd|re|i", "lsass").right.nocase)

    def test_the_cidr_modifier_uses_a_function_that_runs_locally(self):
        # cidr_contains is pure computation over two arguments, so a Sigma rule
        # using |cidr can actually be test-run against a sample here.
        from engine.ir import LOCAL_FUNCTIONS

        condition = self.predicate("src_ip|cidr", "10.0.0.0/8")
        self.assertIsInstance(condition.left, Call)
        self.assertEqual(condition.left.function, "cidr_contains")
        self.assertIn("cidr_contains", LOCAL_FUNCTIONS)
        # address first, network second -- backwards it answers a different
        # question and quietly returns the wrong boolean.
        self.assertEqual(condition.left.args[0].full, "src_ip")
        self.assertEqual(condition.left.args[1].value, "10.0.0.0/8")

    def test_a_cidr_rule_actually_evaluates(self):
        from engine.pipeline import evaluate

        rule = lower(
            "title: t\nlogsource:\n    category: firewall\n"
            "detection:\n    selection:\n        src_ip|cidr: 10.0.0.0/8\n"
            "    condition: selection\n"
        )
        self.assertEqual(
            evaluate(rule, [{"src_ip": "10.1.2.3"}]).verdict, "matched"
        )
        # NOT `no_match`: the logsource is an index-time selector that this
        # engine never applies locally, so it refuses to report a CONFIDENT
        # non-match. See the INDEX_TIME_FILTER caveat.
        outside = evaluate(rule, [{"src_ip": "192.168.1.1"}])
        self.assertFalse(outside.matched)
        self.assertIn(
            "INDEX_TIME_FILTER", [c.code for c in outside.caveats]
        )

    def test_a_transform_modifier_is_refused_by_name_with_a_reason(self):
        # Transforming a value is not comparing it, and there is no transform
        # stage. Lowering |base64offset as equality would produce a rule that
        # looks right and matches nothing.
        for modifier in sorted(MODIFIER_REFUSALS):
            with self.subTest(modifier=modifier):
                with self.assertRaises(Refusal) as caught:
                    self.predicate(f"cmd|{modifier}")
                self.assertEqual(
                    caught.exception.code, "SIGMA_MODIFIER_UNSUPPORTED"
                )
                self.assertIn(modifier, caught.exception.message)

    def test_an_unknown_modifier_is_refused_rather_than_ignored(self):
        # Ignoring a modifier widens the detection without saying so.
        with self.assertRaises(Refusal) as caught:
            self.predicate("cmd|frobnicate")
        self.assertEqual(caught.exception.code, "SIGMA_MODIFIER_UNKNOWN")

    def test_conflicting_modifiers_are_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.predicate("cmd|re|cidr", "10.0.0.0/8")
        self.assertEqual(caught.exception.code, "SIGMA_MODIFIER_CONFLICT")

    def test_a_nested_field_name_keeps_its_path(self):
        condition = self.predicate("win.eventdata.Image|endswith", "a.exe")
        self.assertEqual(condition.left.name, "win")
        self.assertEqual(condition.left.path, ("eventdata", "Image"))


class NullIsNotAbsent(unittest.TestCase):
    """Four distinct things, and Sigma can express one of them."""

    def test_field_null_asks_whether_the_field_is_null(self):
        # `== null` is the obvious lowering and the wrong one: the evaluator
        # treats every comparison against null as UNDECIDED, on the grounds that
        # null is a third thing rather than a value to compare -- so the test
        # would never answer. `is_null` returns a real boolean.
        condition = detection_of(lower(
            "title: t\ndetection:\n    selection:\n        User: null\n"
            "    condition: selection\n"
        ))
        self.assertIsInstance(condition, Call)
        self.assertEqual(condition.function, "is_null")
        self.assertEqual(condition.args[0].full, "User")

    def test_a_null_test_answers_rather_than_going_undecided(self):
        from engine.pipeline import evaluate

        rule = lower(
            "title: t\ndetection:\n    selection:\n        User: null\n"
            "    condition: selection\n"
        )
        self.assertEqual(evaluate(rule, [{"User": None}]).verdict, "matched")
        # A field that is PRESENT and not null is a real non-match.
        self.assertFalse(evaluate(rule, [{"User": "svc"}]).matched)

    def test_an_absent_field_is_not_reported_as_null(self):
        # Absent and null are two of the four states this engine keeps apart. A
        # converter that collapsed them would report a confident answer it has
        # no evidence for.
        from engine.pipeline import evaluate

        rule = lower(
            "title: t\ndetection:\n    selection:\n        User: null\n"
            "    condition: selection\n"
        )
        self.assertEqual(evaluate(rule, [{"Other": 1}]).verdict, "not_evaluated")

    def test_a_null_entry_round_trips(self):
        rule = lower(
            "title: t\ndetection:\n    selection:\n        User: null\n"
            "    condition: selection\n"
        )
        self.assertIn("User: null", render_sigma(rule))

    def test_an_empty_string_is_not_null(self):
        condition = detection_of(lower(
            "title: t\ndetection:\n    selection:\n        User: ''\n"
            "    condition: selection\n"
        ))
        self.assertEqual(condition.right.value, "")
        self.assertIsNotNone(condition.right.value)


class TheCondition(unittest.TestCase):
    def condition(self, text, extra=""):
        return detection_of(lower(
            "title: t\ndetection:\n"
            "    selection_a:\n        A: 1\n"
            "    selection_b:\n        B: 2\n"
            "    filter:\n        C: 3\n"
            f"{extra}"
            f"    condition: {text}\n"
        ))

    def test_and_or_precedence_matches_every_other_dialect(self):
        # A rule whose `a and b or c` groups differently here than in kql.py is
        # a rule that matches different events after conversion. The shared
        # precedence table is the only reason they agree.
        tree = self.condition("selection_a and selection_b or filter")
        self.assertEqual(tree.op, "or")
        self.assertEqual(tree.operands[0].op, "and")

    def test_parentheses_override_precedence(self):
        tree = self.condition("selection_a and (selection_b or filter)")
        self.assertEqual(tree.op, "and")
        self.assertEqual(tree.operands[1].op, "or")

    def test_not_negates_only_its_own_operand(self):
        tree = self.condition("selection_a and not filter")
        self.assertEqual(tree.op, "and")
        self.assertIsInstance(tree.operands[1], Not)

    def test_the_selections_are_substituted_not_left_as_field_references(self):
        # Left as a bare FieldRef, `selection` would be a truthy string and the
        # filter would match nearly every row. validate() refuses that, so this
        # also proves the substitution happened.
        tree = self.condition("selection_a")
        self.assertIsInstance(tree, Comparison)
        self.assertEqual(tree.left.full, "A")

    def test_one_of_them_becomes_an_or(self):
        tree = self.condition("1 of them")
        self.assertEqual(tree.op, "or")
        self.assertEqual(len(tree.operands), 3)

    def test_all_of_them_becomes_an_and(self):
        tree = self.condition("all of them")
        self.assertEqual(tree.op, "and")
        self.assertEqual(len(tree.operands), 3)

    def test_a_wildcard_selects_only_the_matching_names(self):
        tree = self.condition("1 of selection_*")
        self.assertEqual(tree.op, "or")
        self.assertEqual(len(tree.operands), 2)

    def test_one_of_combines_with_not(self):
        tree = self.condition("1 of selection_* and not filter")
        self.assertEqual(tree.op, "and")
        self.assertEqual(tree.operands[0].op, "or")
        self.assertIsInstance(tree.operands[1], Not)

    def test_an_n_of_m_count_is_refused_rather_than_approximated(self):
        # Sigma has no "exactly N", and reading `2 of them` as "at least 2" or
        # as "all" would each be a different detection.
        with self.assertRaises(Refusal) as caught:
            self.condition("2 of them")
        self.assertEqual(
            caught.exception.code, "SIGMA_CONDITION_COUNT_UNSUPPORTED"
        )

    def test_a_condition_naming_an_unknown_selection_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.condition("selection_a and absent_one")
        self.assertEqual(
            caught.exception.code, "SIGMA_CONDITION_UNKNOWN_SELECTION"
        )

    def test_a_wildcard_matching_nothing_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.condition("1 of nothing_*")
        self.assertEqual(
            caught.exception.code, "SIGMA_CONDITION_UNKNOWN_SELECTION"
        )

    def test_an_unreferenced_selection_is_reported_not_silently_kept(self):
        # Legitimate during development, but it reads as if it were doing
        # something, so the analyst is told.
        _, diagnostics = lower_sigma(
            "title: t\ndetection:\n    selection:\n        A: 1\n"
            "    unused:\n        B: 2\n    condition: selection\n"
        )
        self.assertEqual(
            [d.code for d in diagnostics], ["SIGMA_SELECTION_UNUSED"]
        )

    def test_a_selection_named_like_a_keyword_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(
                "title: t\ndetection:\n    not:\n        A: 1\n"
                "    condition: not\n"
            )
        self.assertEqual(
            caught.exception.code, "SIGMA_SELECTION_NAME_RESERVED"
        )


class TheLogSource(unittest.TestCase):
    def test_the_selector_is_kept_verbatim(self):
        # A log source is resolved by the backend's index mapping before any row
        # exists, so treating it as a row filter would let a local evaluation
        # claim a match it cannot produce.
        read = lower(USER_RULE).pipeline[0]
        self.assertIsInstance(read, Read)
        self.assertIn("product=windows", read.selector)
        self.assertIn("service=sysmon", read.selector)
        self.assertIn("category=process_access", read.selector)

    def test_the_most_specific_name_becomes_the_table(self):
        self.assertEqual(lower(USER_RULE).pipeline[0].table, "process_access")

    def test_a_rule_with_no_logsource_still_lowers(self):
        self.assertEqual(
            lower("title: t\ndetection:\n    selection:\n        A: 1\n"
                  "    condition: selection\n").pipeline[0].table,
            "events",
        )

    def test_the_logsource_is_never_turned_into_a_predicate(self):
        condition = detection_of(lower(USER_RULE))
        self.assertNotIn("product", render_expr(condition))
        self.assertNotIn("sysmon", render_expr(condition))


class MetadataRoundTrips(unittest.TestCase):
    """The defect `kql.py` has and this dialect must not copy."""

    def setUp(self):
        self.rule, self.diagnostics = lower_sigma(USER_RULE)
        self.annotations = self.rule.annotations

    def test_the_title_survives(self):
        self.assertEqual(
            self.annotations.title, "Credential Dumping via LSASS Access"
        )

    def test_the_level_becomes_the_severity(self):
        self.assertEqual(self.annotations.severity, "high")

    def test_the_description_keeps_its_shape(self):
        self.assertIn("dump-capable", self.annotations.description)
        self.assertIn("\n", self.annotations.description)

    def test_the_author_and_references_survive(self):
        self.assertEqual(self.annotations.author, "Detection Desk")
        self.assertEqual(len(self.annotations.references), 1)

    def test_the_false_positives_survive(self):
        self.assertEqual(len(self.annotations.false_positives), 2)

    def test_attack_tags_become_the_mitre_mapping(self):
        self.assertEqual(
            self.annotations.mitre_attack,
            (("credential-access", ("T1003.001",)),),
        )

    def test_the_sigma_id_becomes_the_rule_id(self):
        # Every reference to this rule uses that uuid, so losing it breaks them.
        self.assertEqual(
            self.rule.rule_id, "5b4a1b2c-0000-4aaa-bbbb-ccccdddd0001"
        )

    def test_an_explicit_rule_id_wins_over_the_sigma_id(self):
        rule, _ = lower_sigma(USER_RULE, "local-override")
        self.assertEqual(rule.rule_id, "local-override")

    def test_keys_annotations_cannot_hold_are_preserved(self):
        meta = self.rule.metadata
        self.assertEqual(meta["sigma.status"], "experimental")
        self.assertEqual(meta["sigma.date"], "2026/01/15")
        self.assertEqual(meta["sigma.modified"], "2026/02/02")
        self.assertIn("sysmon", meta["sigma.logsource"])
        self.assertIn("cve.2021-44228", meta["sigma.tags"])
        self.assertIn("SourceImage", meta["sigma.fields"])

    def test_a_non_attack_tag_is_not_lost(self):
        # Annotations has nowhere to put it, so dropping it would be the easy
        # choice and would lose an organisation's own taxonomy.
        self.assertIn("cve.2021-44228", self.rule.metadata["sigma.tags"])

    def test_an_unknown_top_level_key_is_carried_through(self):
        rule, _ = lower_sigma(
            "title: t\nour_ticket: SEC-4471\ndetection:\n"
            "    selection:\n        A: 1\n    condition: selection\n"
        )
        self.assertIn("SEC-4471", rule.metadata["sigma.extra"])

    def test_the_dialect_is_recorded_on_the_rule(self):
        self.assertEqual(self.rule.metadata["dialect"], DIALECT)
        self.assertEqual(self.rule.metadata["language"], LANGUAGE)

    def test_an_unknown_level_is_reported_not_silently_accepted(self):
        _, diagnostics = lower_sigma(
            "title: t\nlevel: catastrophic\ndetection:\n"
            "    selection:\n        A: 1\n    condition: selection\n"
        )
        self.assertIn("SIGMA_LEVEL_UNKNOWN", [d.code for d in diagnostics])

    def test_a_missing_title_is_reported(self):
        _, diagnostics = lower_sigma(
            "detection:\n    selection:\n        A: 1\n    condition: selection\n"
        )
        self.assertIn("SIGMA_NO_TITLE", [d.code for d in diagnostics])


class Rendering(unittest.TestCase):
    def setUp(self):
        self.rule, _ = lower_sigma(USER_RULE)
        self.text = render_sigma(self.rule)

    def test_the_metadata_is_written_back(self):
        for fragment in (
            "title: Credential Dumping via LSASS Access",
            "id: 5b4a1b2c-0000-4aaa-bbbb-ccccdddd0001",
            "status: experimental",
            "author: Detection Desk",
            "level: high",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.text)

    def test_the_attack_tags_are_written_back(self):
        self.assertIn("attack.credential_access", self.text)
        self.assertIn("attack.t1003.001", self.text)

    def test_a_non_attack_tag_survives_the_round_trip(self):
        self.assertIn("cve.2021-44228", self.text)

    def test_the_logsource_is_written_back(self):
        self.assertIn("product: windows", self.text)
        self.assertIn("service: sysmon", self.text)

    def test_selection_is_written_before_filter(self):
        # What it matches, then what it excludes -- the order a Sigma author
        # writes and reads.
        self.assertLess(
            self.text.index("selection:"), self.text.index("filter:")
        )

    def test_the_condition_names_both_selections(self):
        self.assertIn("condition: selection and not filter", self.text)

    def test_a_value_list_is_written_as_a_list(self):
        self.assertIn("GrantedAccess:", self.text)
        self.assertIn("- 1010", self.text)

    def test_modifiers_are_written_back(self):
        self.assertIn("TargetImage|endswith:", self.text)
        self.assertIn("SourceImage|startswith:", self.text)

    def test_the_rendered_rule_lowers_again_to_the_same_detection(self):
        again, _ = lower_sigma(self.text)
        self.assertEqual(
            render_expr(detection_of(again)),
            render_expr(detection_of(self.rule)),
        )

    def test_the_rendered_rule_keeps_its_metadata(self):
        again, _ = lower_sigma(self.text)
        self.assertEqual(again.annotations.title, self.rule.annotations.title)
        self.assertEqual(again.annotations.severity, self.rule.annotations.severity)
        self.assertEqual(
            again.annotations.mitre_attack, self.rule.annotations.mitre_attack
        )
        self.assertEqual(again.rule_id, self.rule.rule_id)

    def test_rendering_is_stable_across_two_round_trips(self):
        # An unstable renderer makes every save look like a change in history.
        again, _ = lower_sigma(self.text)
        self.assertEqual(render_sigma(again), self.text)

    def test_a_cidr_rule_round_trips(self):
        rule = lower(
            "title: t\nlogsource:\n    category: firewall\n"
            "detection:\n    selection:\n        src_ip|cidr: 10.0.0.0/8\n"
            "    condition: selection\n"
        )
        text = render_sigma(rule)
        self.assertIn("src_ip|cidr: 10.0.0.0/8", text)
        again, _ = lower_sigma(text)
        self.assertEqual(
            render_expr(detection_of(again)), render_expr(detection_of(rule))
        )

    def test_an_or_across_different_fields_is_a_list_of_maps(self):
        # Sigma's own syntax for an OR across fields is a LIST OF MAPS: list
        # items are ORed, keys inside one item are ANDed. This used to refuse
        # with SIGMA_RENDER_OR_ACROSS_FIELDS, on the grounds that splitting the
        # OR into several named selections was a decision about the rule -- but
        # that reasoning missed the list form, which needs no splitting and
        # which the parser here already reads. The standard "match the image or
        # its original filename" idiom could be imported and not written back.
        rule = lower(
            "title: t\ndetection:\n"
            "    a:\n        A: 1\n    b:\n        B: 2\n"
            "    condition: a or b\n"
        )
        text = render_sigma(rule)
        self.assertIn("- A: 1", text)
        self.assertIn("- B: 2", text)
        again, _ = lower_sigma(text)
        self.assertEqual(
            render_expr(detection_of(again)), render_expr(detection_of(rule))
        )

    def test_a_list_branch_does_not_share_a_selection_with_plain_keys(self):
        # A YAML sequence cannot coexist with `key: value` entries in one
        # mapping. Rendered into the same selection the body was both a list
        # and a map, which this module's own reader cannot parse at all.
        rule = lower(
            "title: t\ndetection:\n"
            "    a:\n        - A: 1\n        - B: 2\n"
            "    c:\n        C|contains: x\n"
            "    condition: a and c\n"
        )
        text = render_sigma(rule)
        again, _ = lower_sigma(text)
        self.assertEqual(
            render_expr(detection_of(again)), render_expr(detection_of(rule))
        )

    def test_two_contains_on_one_field_become_the_all_modifier(self):
        # Emitted as one key per value they were a duplicate YAML key. Most
        # readers keep only the last, so the rule silently stopped requiring
        # the first value -- a widened rule that still looks correct.
        rule = lower(
            "title: t\ndetection:\n"
            "    sel:\n        cmd|contains|all:\n            - ' -enc'\n"
            "            - 'JAB'\n"
            "    condition: sel\n"
        )
        text = render_sigma(rule)
        self.assertIn("cmd|contains|all:", text)
        self.assertEqual(text.count("cmd|contains"), 1)
        again, _ = lower_sigma(text)
        self.assertEqual(
            render_expr(detection_of(again)), render_expr(detection_of(rule))
        )

    def test_an_unrenderable_node_is_refused_rather_than_dropped(self):
        # A dropped clause produces a rule that reads correctly and matches more
        # events than it states. That defect is why every dispatch here ends in
        # a refusal.
        from engine.ir import Rule, Span

        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="source", table="t"),
                Filter(id="detection", condition=Span(
                    Literal(Decimal(5)), Literal(Decimal(1)), Literal(Decimal(9))
                )),
                Emit(id="out"),
            ),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_sigma(rule)
        self.assertTrue(caught.exception.code.startswith("SIGMA_RENDER_"))


class Correlations(unittest.TestCase):
    EVENT_COUNT = """
title: Brute force
logsource:
    product: windows
detection:
    selection:
        EventID: 4625
    condition: selection
correlation:
    type: event_count
    rules:
        - selection
    group-by:
        - TargetUserName
        - Computer
    timespan: 15m
    condition:
        gte: 10
"""

    def test_an_event_count_correlation_becomes_a_correlation_stage(self):
        rule = lower(self.EVENT_COUNT)
        stage = next(n for n in rule.pipeline if isinstance(n, Correlation))
        self.assertEqual(stage.frequency, 10)
        self.assertEqual(stage.timeframe.seconds, Decimal(900))

    def test_the_group_by_is_carried(self):
        # Getting this wrong turns a per-user threshold into a global one, which
        # is a completely different detection.
        rule = lower(self.EVENT_COUNT)
        stage = next(n for n in rule.pipeline if isinstance(n, Correlation))
        self.assertEqual(
            [key.full for key in stage.group_by],
            ["TargetUserName", "Computer"],
        )

    def test_a_correlation_with_no_group_by_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(self.EVENT_COUNT.replace(
                "    group-by:\n        - TargetUserName\n        - Computer\n", ""
            ))
        self.assertEqual(caught.exception.code, "SIGMA_CORRELATION_NO_GROUP")

    def test_a_correlation_with_no_timespan_is_refused(self):
        # A count with no window is not a threshold.
        with self.assertRaises(Refusal) as caught:
            lower(self.EVENT_COUNT.replace("    timespan: 15m\n", ""))
        self.assertEqual(caught.exception.code, "SIGMA_CORRELATION_TIMESPAN")

    def test_a_value_count_correlation_becomes_an_aggregate_plus_a_filter(self):
        rule = lower("""
title: Spray
logsource:
    product: windows
detection:
    selection:
        EventID: 4625
    condition: selection
correlation:
    type: value_count
    rules:
        - selection
    group-by:
        - Computer
    field: TargetUserName
    timespan: 1h
    condition:
        gte: 25
""")
        kinds = [type(n).__name__ for n in rule.pipeline]
        self.assertIn("Aggregate", kinds)
        aggregate = next(n for n in rule.pipeline if isinstance(n, Aggregate))
        self.assertTrue(aggregate.measures[0].distinct)
        self.assertEqual(aggregate.window.size.seconds, Decimal(3600))

    def test_a_value_count_with_no_field_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower("""
title: Spray
detection:
    selection:
        EventID: 4625
    condition: selection
correlation:
    type: value_count
    rules:
        - selection
    group-by:
        - Computer
    timespan: 1h
    condition:
        gte: 25
""")
        self.assertEqual(caught.exception.code, "SIGMA_CORRELATION_NO_FIELD")

    def test_a_temporal_correlation_is_refused_with_its_reason(self):
        # It fires when SEVERAL rules match in a window, and Correlation counts
        # ONE parent -- so expressing it would mean dropping rules.
        with self.assertRaises(Refusal) as caught:
            lower(self.EVENT_COUNT.replace(
                "type: event_count", "type: temporal"
            ))
        self.assertEqual(
            caught.exception.code, "SIGMA_CORRELATION_UNSUPPORTED"
        )
        self.assertIn("Correlation", caught.exception.message)

    def test_an_ordered_temporal_correlation_names_the_missing_ir_node(self):
        with self.assertRaises(Refusal) as caught:
            lower(self.EVENT_COUNT.replace(
                "type: event_count", "type: temporal_ordered"
            ))
        self.assertIn("ordering", caught.exception.message)

    def test_a_multi_rule_correlation_is_refused_rather_than_truncated(self):
        # Silently using the first rule would count the wrong events.
        with self.assertRaises(Refusal) as caught:
            lower(self.EVENT_COUNT.replace(
                "    rules:\n        - selection\n",
                "    rules:\n        - selection\n        - other\n",
            ))
        self.assertEqual(
            caught.exception.code, "SIGMA_CORRELATION_MULTI_RULE"
        )

    def test_a_correlation_round_trips(self):
        rule = lower(self.EVENT_COUNT)
        text = render_sigma(rule)
        self.assertIn("type: event_count", text)
        self.assertIn("timespan: 15m", text)
        self.assertIn("gte: 10", text)
        again = lower(text)
        stage = next(n for n in again.pipeline if isinstance(n, Correlation))
        self.assertEqual(stage.frequency, 10)
        self.assertEqual(stage.timeframe.seconds, Decimal(900))


class ItEvaluates(unittest.TestCase):
    """A Sigma rule, lowered and then actually run. The point of the IR."""

    def setUp(self):
        from engine.pipeline import evaluate
        self.evaluate = evaluate
        self.rule, _ = lower_sigma(USER_RULE)

    def event(self, **overrides):
        base = {
            "EventID": 10,
            "TargetImage": "C:/Windows/System32/lsass.exe",
            "GrantedAccess": "1410",
            "SourceImage": "C:/evil.exe",
        }
        base.update(overrides)
        return base

    def test_it_fires_on_a_matching_event(self):
        self.assertEqual(
            self.evaluate(self.rule, [self.event()]).verdict, "matched"
        )

    def test_the_filter_actually_excludes(self):
        # If `not filter` were dropped or inverted, this would MATCH -- which is
        # the inverted-detection failure mode. The verdict is `not_evaluated`
        # rather than `no_match` because every Sigma rule carries a logsource,
        # which is an index-time selector this engine never applies locally; so
        # it declines to call a non-match confident. What matters here is that
        # it did not match.
        result = self.evaluate(
            self.rule, [self.event(SourceImage="BackupAgent-run.exe")]
        )
        self.assertFalse(result.matched)

    def test_a_value_outside_the_list_does_not_fire(self):
        self.assertFalse(
            self.evaluate(self.rule, [self.event(GrantedAccess="0001")]).matched
        )

    def test_a_logsource_does_not_block_a_confident_non_match(self):
        # This used to assert `not_evaluated`, and the reason given was that it
        # surprises people -- not that the strict verdict was right.
        #
        # It was wrong, and expensively so. Every Sigma rule has a
        # `logsource`, so under the old policy NO Sigma rule could ever report
        # a non-match: "paste a rule and test it against events" could confirm
        # a hit and never confirm a miss, which is most of what that feature
        # is for.
        #
        # A logsource can only REMOVE events from what the engine saw, and for
        # a rule with no anti-join removing events cannot create a match. So
        # "no match against the sample you gave me" is the honest answer. The
        # caveat still reports that the selector was not applied, so the scope
        # limit stays visible.
        result = self.evaluate(self.rule, [self.event(GrantedAccess="0001")])
        self.assertEqual(result.verdict, "no_match")
        self.assertEqual(
            [c.code for c in result.caveats], ["INDEX_TIME_FILTER"]
        )

    def test_a_logsource_still_does_not_hide_a_real_uncertainty(self):
        # Relaxing the logsource caveat must not relax the others: a missing
        # field is still a genuine "cannot tell".
        event = self.event()
        del event["TargetImage"]
        result = self.evaluate(self.rule, [event])
        self.assertEqual(result.verdict, "not_evaluated")

    def test_a_missing_field_is_undecided_not_a_non_match(self):
        event = self.event()
        del event["TargetImage"]
        result = self.evaluate(self.rule, [event])
        self.assertEqual(result.verdict, "not_evaluated")
        self.assertIn(
            "TargetImage", " ".join(c.message for c in result.caveats)
        )


if __name__ == "__main__":
    unittest.main()
