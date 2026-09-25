"""Phase 0 gate: the acceptance corpus is frozen, complete, and honest.

Phase 0 of docs/ruleforge-redesign-plan.md. This is not a test of the new engine - the
engine does not exist yet. This test freezes WHAT the engine will be measured against, so
that later phases cannot quietly narrow the target or declare success on a subset.

The failure this prevents: a vertical slice shipping while some of the 70 cells were never
declared, or a "refused" cell that still produced a downloadable artifact. Both have
happened in this project before, in the form of a 3-stage Splunk pipeline graded `exact`
after being reduced to one predicate.
"""

import unittest

from tests.corpus.rule_corpus import RULES, TARGETS, cells, rule_ids
from tests.corpus.rule_matrix import (SUPPORT_VALUES, all_cells, declared_cell_count,
                                      expect, extra_cells, undeclared_cells)


class CorpusFreezeTests(unittest.TestCase):
    def test_corpus_holds_ten_real_rules(self):
        self.assertEqual(len(RULES), 10, "the corpus is the ten rules the maintainer supplied")
        for rule_id, rule in RULES.items():
            self.assertTrue(rule["source"].strip(), f"{rule_id} has no source text")
            self.assertTrue(rule["target"] in TARGETS, f"{rule_id} names an unknown target")
            self.assertTrue(rule["shape"], f"{rule_id} does not state its shape")
            self.assertTrue(rule["why"], f"{rule_id} does not record why it is in the corpus")
            self.assertTrue(rule["primitives"], f"{rule_id} does not state its primitive decomposition")

    def test_the_matrix_is_exactly_seventy_cells_with_none_undeclared(self):
        self.assertEqual(len(rule_ids()) * len(TARGETS), 70)
        self.assertEqual(declared_cell_count(), 70,
                         "a cell may not be silently omitted; declare it or remove the rule")
        self.assertEqual(undeclared_cells(), [])
        self.assertEqual(extra_cells(), [], "a declared cell names a rule or target that does not exist")

    def test_every_cell_is_native_equivalent_or_refused_and_nothing_else(self):
        for rule_id, target, (support, code, note) in all_cells():
            self.assertIn(support, SUPPORT_VALUES, f"({rule_id}, {target}) support={support!r}")
            self.assertTrue(note.strip(), f"({rule_id}, {target}) has no explanatory note")

    def test_a_refusal_always_names_the_missing_construct(self):
        """A refusal with no reason is a bug, not a feature.

        The entire value of refusing is telling the analyst what to build by hand. A refusal
        without a code is indistinguishable from the tool giving up, which is the failure
        mode this redesign exists to end.
        """
        refused = [(r, t, v) for r, t, v in all_cells() if v[0] == "refused"]
        self.assertTrue(refused, "a corpus with no refusals is not testing the refusal path")
        for rule_id, target, (support, code, note) in refused:
            self.assertTrue(code, f"({rule_id}, {target}) refuses without a refusal code")
            self.assertTrue(code.isupper(), f"({rule_id}, {target}) code {code!r} is not a code")
            self.assertRegex(code, r"^[A-Z][A-Z0-9_]+$",
                             f"({rule_id}, {target}) code {code!r} is not SCREAMING_SNAKE")

    def test_an_emitted_cell_never_claims_to_be_a_refusal_or_the_reverse(self):
        for rule_id, target, (support, code, _note) in all_cells():
            if support == "refused":
                self.assertTrue(code, f"({rule_id}, {target}) refused without a code")
            else:
                self.assertIsNone(code,
                                  f"({rule_id}, {target}) is {support} but carries a refusal code")

    def test_the_tier2_rules_record_the_semantics_an_engine_must_not_lose(self):
        """Each harder rule exists because an earlier draft got it wrong.

        Recording the specific semantic that must survive means a future renderer cannot
        satisfy the cell by producing something that merely looks like the rule.
        """
        for rule_id in ("t2_wazuh_rule_bundle", "t2_splunk_tstats_subquery",
                        "t2_sentinel_temporal_join", "t2_qradar_grouped_aql",
                        "t2_yaral_cross_event"):
            rule = RULES[rule_id]
            self.assertTrue(rule.get("critical_semantics") or rule.get("package_units"),
                            f"{rule_id} does not record the semantics that must survive")
        self.assertEqual(RULES["t2_wazuh_rule_bundle"]["package_units"], 2)
        self.assertEqual(RULES["t2_wazuh_rule_bundle"]["package_dependency"], "100211 -> 100210")
        self.assertIn("sysmon_event_10",
                      RULES["t2_wazuh_rule_bundle"]["unresolved_external_dependency"],
                      "the external dependency must stay named so it cannot be assumed away")

    def test_the_corpus_spans_every_primitive_the_kernel_defines(self):
        """If the corpus never exercises a primitive, a phase can pass without proving it.

        The generality gate (phase 9b) adds constructs outside the corpus; this only checks
        that the corpus is not so narrow that the kernel's core goes untested.
        """
        covered = {p for rule in RULES.values() for p in rule["primitives"]}
        for primitive in ("read", "filter", "frame", "aggregate", "join", "derive", "emit"):
            self.assertIn(primitive, covered, f"no corpus rule exercises {primitive!r}")

    def test_every_target_is_exercised_by_at_least_one_native_or_equivalent_cell(self):
        """A target that can only ever refuse has not been integrated, whatever the count."""
        for target in TARGETS:
            good = [r for r, t, v in all_cells()
                    if t == target and v[0] in {"native", "equivalent"}]
            self.assertTrue(good, f"{target} has no rule it can emit faithfully")

    def test_the_matrix_is_ordered_deterministically(self):
        """Stable ordering keeps diffs reviewable and makes a missing row obvious."""
        ids = rule_ids()
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(cells()), 70)


if __name__ == "__main__":
    unittest.main()
