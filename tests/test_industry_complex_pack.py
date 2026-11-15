"""The checked-in complex rule pack must have honest local verdicts.

The markdown file is not just documentation: it is the fixture a detection
engineer uses in the UI. This test keeps the rule/log pairs executable so a
parser or evaluator regression cannot turn a negative sample into a match or
silently turn every positive sample into ``not_evaluated``.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from engine import dialects
from engine.pipeline import Verdict, evaluate
from engine.synthesize import parse_events


PACK = Path(__file__).parents[1] / "examples" / "industry_complex_siem_rules.md"


RULE_DIALECTS = {
    "## 1.": "sentinel",
    "## 2.": "sigma",
    "## 3.": "splunk",
    "## 4.": "qradar",
    "## 5.": "elastic",
    "## 6.": "wazuh",
    "## 7.": "chronicle",
    "## 8.": "crowdstrike",
}


def _cases() -> list[tuple[str, str, str, str]]:
    text = PACK.read_text(encoding="utf-8")
    cases: list[tuple[str, str, str, str]] = []
    sections = re.split(r"(?=^## \d+\. )", text, flags=re.M)
    for section in sections:
        heading = section.splitlines()[0].strip() if section.strip() else ""
        dialect = next(
            (value for prefix, value in RULE_DIALECTS.items()
             if heading.startswith(prefix)),
            None,
        )
        if dialect is None:
            continue
        blocks = re.findall(r"```[^\n]+\n(.*?)\n```", section, flags=re.S)
        positive = re.search(
            r"### Positive fixture[^\n]*\n\n```jsonl\n(.*?)\n```",
            section,
            flags=re.S,
        )
        negative = re.search(
            r"### Negative fixture[^\n]*\n\n```jsonl\n(.*?)\n```",
            section,
            flags=re.S,
        )
        assert blocks and positive and negative, heading
        cases.append((dialect, blocks[0], positive.group(1), negative.group(1)))
    return cases


class ComplexRulePack(unittest.TestCase):
    """Unittest, not a bare pytest function.

    `python -m unittest discover` is the documented runner and it does not
    collect bare functions, so this check used to run under pytest only. The
    suite was green and the example pack was untested by the command the
    repository actually documents -- the failure mode `tests/__init__.py`
    warns about, where a suite passes because nothing ran.
    """

    def test_every_case_has_expected_local_verdicts(self) -> None:
        cases = _cases()
        self.assertEqual(len(cases), 8)
        for dialect, source, positive_text, negative_text in cases:
            rule, _ = dialects.lower(dialect, source)
            positive = evaluate(rule, parse_events(positive_text, "jsonl"))
            negative = evaluate(rule, parse_events(negative_text, "jsonl"))
            self.assertEqual(positive.verdict, Verdict.MATCHED,
                             f"{dialect} positive: {positive}")
            self.assertEqual(negative.verdict, Verdict.NO_MATCH,
                             f"{dialect} negative: {negative}")


if __name__ == "__main__":
    unittest.main()
