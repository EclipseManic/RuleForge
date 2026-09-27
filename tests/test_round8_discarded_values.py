"""Round 8, continued: three more values that were parsed and then discarded.

Same shape again. A token or a clause is read by the parser, carried nowhere, and
the rule that came back said `ok=True` with no finding while meaning something
different from what the analyst wrote:

    | sort -_time                     ->  | sort _time desc   (direction inverted)
    | sort 5 host                     ->  | sort +host        (count dropped)
    | stats count BY _time span=1h    ->  no span at all     (window dropped)
    | stats count FROM my_datamodel   ->  no datamodel       (dataset swapped)

The `span=` and `FROM` ones were refused rather than rendered, and in both cases
the reason is the same: the construct cannot be expressed in the IR, so rendering
it would have produced a plausible artifact that meant something else. The old
code chose the plausible artifact. This file pins the refusal, so it cannot go
back to being "helpful" again.
"""

import unittest

import jobs
from dialects.spl_ir import SplParseError, lower


class SortCountIsNotDiscarded(unittest.TestCase):
    """Splunk's syntax is `sort [<count>] [-|+]<field> [...]` and the count
    limits how many results come back. The digit branch walked past the token
    without reading it, so `sort 5 host` returned every row instead of five --
    a WIDER result set, which is the direction that hides alerts."""

    def test_a_sort_count_becomes_a_limit(self):
        self.assertEqual(
            jobs.author("splunk", "index=main | stats count BY host | sort 5 host",
                        "r1").rendered,
            "index=main | stats count AS count by host | sort +host | head 5")

    def test_sort_zero_still_means_no_limit(self):
        """Splunk documents 0 as 'no limit'. A cap of 0 would render `head 0` and
        return nothing, which is the opposite of what was asked."""
        self.assertEqual(
            jobs.author("splunk", "index=main | sort 0 host", "r1").rendered,
            "index=main | sort +host")

    def test_a_count_and_a_limit_compose(self):
        self.assertEqual(
            jobs.author("splunk", "index=main | sort 5 -_time", "r1").rendered,
            "index=main | sort -_time | head 5")

    def test_head_still_owns_its_own_count(self):
        """A second `limit = None` declaration was added while fixing the sort
        count, and it sat BELOW the one `head` uses -- silently resetting
        `head`'s limit to None. `| head 5` rendered as a bare `sort` with no
        `head` at all, and two tests caught it."""
        for source, expected in (
            ("index=main | head 5", "index=main | head 5"),
            ("index=main | sort 5 -_time", "index=main | sort -_time | head 5"),
            ("index=main | sort 2 host | head 3",
             "index=main | sort +host | head 2 | head 3"),
        ):
            with self.subTest(source=source):
                self.assertEqual(jobs.author("splunk", source, "r1").rendered,
                                 expected)

    def test_a_sort_count_of_zero_is_not_a_head_zero(self):
        """The blunt invariant, so `head 0` can never be rendered again."""
        self.assertNotIn("head 0",
                         jobs.author("splunk", "index=main | sort 0 host",
                                     "r1").rendered)


class SpanOnStatsIsNotValidSpl(unittest.TestCase):
    """`span=` is a `timechart` argument. `stats` does not take one, so the input
    was never valid SPL.

    It used to lower, synthesise a `__bucket__` key, and emit an INFO finding
    saying the window was "real rather than ignored" -- and then render without
    the window, keeping a bogus `count AS __bucket__` column, returning ok=True:

        in : index=main EventCode=4625 | stats count by _time span=1h host
        out: index=main | search EventCode="4625"
             | stats count AS count, count AS __bucket__ by _time, host

    One row per host instead of one per host per hour, and a diagnostic asserting
    the opposite of what shipped. The false claim was the more serious half.
    """

    def test_it_is_refused_by_name(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | stats count BY _time span=1h")
        self.assertEqual(caught.exception.code, "SPL_STATS_SPAN_NOT_VALID")

    def test_the_message_names_timechart(self):
        """The analyst needs to know which command DOES bucket time."""
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | stats count BY _time span=30m")
        self.assertIn("timechart", caught.exception.message)

    def test_tstats_still_gets_its_own_more_specific_refusal(self):
        """The documented `tstats` example carries `span=1h`, and letting the span
        check fire first replaced the real reason -- that tstats reads index-time
        fields no sample reproduces -- with a message about syntax. The most
        specific true refusal wins."""
        with self.assertRaises(SplParseError) as caught:
            lower("| tstats count AS n FROM datamodel=Authentication.Authentication"
                  " WHERE index=main BY host span=1h")
        self.assertEqual(caught.exception.code,
                         "TSTATS_NOT_EXECUTABLE_LOCALLY")

    def test_no_artifact_is_produced_for_a_span(self):
        """A refusal must mean no artifact, not a plausible one."""
        outcome = jobs.author(
            "splunk", "index=main EventCode=4625 | stats count by _time span=1h host",
            "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"], "SPL_STATS_SPAN_NOT_VALID")

    def test_the_false_synthesis_diagnostic_is_gone_entirely(self):
        """`__bucket__` must never reach an artifact again."""
        for source in ("index=main | stats count BY _time span=1h",
                       "index=main | stats count BY host span=1h"):
            with self.subTest(source=source):
                with self.assertRaises(SplParseError):
                    lower(source)
        self.assertNotIn("__bucket__",
                         jobs.author("splunk", "index=main | stats count BY host",
                                     "r1").rendered)


class StatsFromIsRefusedLikeTstats(unittest.TestCase):
    """A data model is a saved query, not a table, so RuleForge cannot evaluate
    it against the events it was handed. That is why `tstats` is refused -- and
    `from_clause` was referenced ONLY inside the tstats error message, so the
    construct was understood well enough to explain in one command and not in the
    other.

        | stats count FROM my_datamodel  ->  | stats count AS count   ok=True

    The rule silently ran against a different dataset than the analyst wrote.
    """

    def test_it_is_refused_by_name(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | stats count FROM my_datamodel")
        self.assertEqual(caught.exception.code, "SPL_STATS_FROM_NOT_LOWERABLE")

    def test_the_message_says_it_would_change_the_dataset(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | stats count FROM my_datamodel")
        self.assertIn("different", caught.exception.message.lower())

    def test_stats_without_a_from_still_works(self):
        """The refusal must be about the data model, not about `stats`."""
        self.assertEqual(
            jobs.author("splunk", "index=main | stats count BY host", "r1").rendered,
            "index=main | stats count AS count by host")


if __name__ == "__main__":
    unittest.main()
