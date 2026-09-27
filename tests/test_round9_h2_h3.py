"""Round 9, H2 and H3: two commands whose names were parsed and then discarded.

`eventstats` and `tstats` are not `stats`. They were lowered as if they were,
and in both cases the result said ok=True while meaning something else.

H2 -- `eventstats` KEEPS EVERY ROW AND `stats` COLLAPSES THEM

    index=main | eventstats count BY host
      ->  index=main | stats count AS count by host    ok=True, findings=[]

In Splunk, `eventstats` computes the statistics and appends them as new columns
to EVERY input event. `stats` collapses to one row per group. The command name
was parsed and then thrown away, so the rule silently returned one row where
Splunk returns every event. The IR has no node for "append an aggregate to every
row" -- it would need a windowed join per group.

H3 -- THE MOST SPECIFIC REFUSAL NEVER GOT TO SPEAK

`| tstats count BY _time span=1h` was told:

    SPL_TIME_BUCKET_WITHOUT_SPAN
    "the rule groups by _time with no span=. Splunk requires a span..."

-- for a rule that HAS a span. The `tstats` refusal sat BELOW the `span=` and
`_time` checks, so a `tstats` grouped by time never reached
`TSTATS_NOT_EXECUTABLE_LOCALLY`. The message contradicted the input it was
given, on top of the comment above the span check claiming the most specific
refusal wins. Both now sit at the top, before any syntax check: `tstats` is
refused because it reads index-time fields no sample can reproduce, which is
true with or without a span.
"""

import unittest

import jobs
from dialects.spl_ir import SplParseError, lower


class EventstatsIsNotStats(unittest.TestCase):
    def test_it_is_refused_by_name(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | eventstats count BY host")
        self.assertEqual(caught.exception.code,
                         "SPL_EVENTSTATS_NOT_LOWERABLE")

    def test_it_is_refused_with_a_span_too(self):
        """The span must not change which refusal fires -- the command itself is
        the reason, with or without a window."""
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | eventstats count BY ts span=1h host")
        self.assertEqual(caught.exception.code,
                         "SPL_EVENTSTATS_NOT_LOWERABLE")

    def test_the_message_says_what_would_change(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | eventstats count BY host")
        self.assertIn("one row", caught.exception.message,
                      "the analyst must be told the result set would change, "
                      "not just that the command is unknown")

    def test_no_artifact_is_produced(self):
        outcome = jobs.author("splunk",
                              "index=main | eventstats count BY host", "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"],
                         "SPL_EVENTSTATS_NOT_LOWERABLE")

    def test_stats_without_eventstats_still_works(self):
        self.assertEqual(
            jobs.author("splunk", "index=main | stats count BY host",
                        "r1").rendered,
            "index=main | stats count AS count by host")


class TstatsGetsItsOwnRefusalFirst(unittest.TestCase):
    def test_tstats_by_time_with_a_span_gets_the_tstats_refusal(self):
        """THE BUG. The rule has a span, so telling it it has none is false --
        and the input never reached the refusal that actually applies."""
        with self.assertRaises(SplParseError) as caught:
            lower("| tstats count BY _time span=1h")
        self.assertEqual(caught.exception.code,
                         "TSTATS_NOT_EXECUTABLE_LOCALLY")

    def test_tstats_without_a_span_gets_the_tstats_refusal(self):
        with self.assertRaises(SplParseError) as caught:
            lower("| tstats count BY host")
        self.assertEqual(caught.exception.code,
                         "TSTATS_NOT_EXECUTABLE_LOCALLY")

    def test_tstats_with_from_gets_the_tstats_refusal(self):
        with self.assertRaises(SplParseError) as caught:
            lower("| tstats count AS n FROM datamodel=Authentication.Authentication"
                  " WHERE index=main BY host span=1h")
        self.assertEqual(caught.exception.code,
                         "TSTATS_NOT_EXECUTABLE_LOCALLY")

    def test_no_artifact_is_produced(self):
        outcome = jobs.author(
            "splunk", "index=main | tstats count BY _time span=1h", "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"],
                         "TSTATS_NOT_EXECUTABLE_LOCALLY")


if __name__ == "__main__":
    unittest.main()
