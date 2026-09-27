"""Round 9, M2: three values that were parsed and then dropped.

Same shape as everything else this session. A token is read by the parser,
carried nowhere, and the rule comes back ok=True meaning something else -- or
in one case a dataclass field is declared, documented, and never filled, so a
reader believes a value flows through it.

`prestats=t` ON PLAIN `stats`

    index=main | stats prestats=t count BY host
      ->  index=main | stats count AS count by host    ok=True, findings=[]

The parser reads `prestats=t` into `SplStats.prestats` and the lowerer never
looks at the field, so the artifact is byte-identical to the rule without it.
In Splunk `prestats` is meaningful only with `tstats`, where it passes partial
results between stages; on plain `stats` Splunk itself ignores it. But an
analyst who writes `prestats=t` on a `stats` almost certainly MEANT `tstats`,
and silently accepting it hides that mistake. Refused by name, naming the
command it belongs to.

A SIGNED SORT COUNT IS NEITHER A COUNT NOR A FIELD

    index=main | sort -5 host   ->  index=main | sort +host | head 5

The `-` was stripped as a direction sign BEFORE the digit test, so `-5` became
a count of 5 -- a number the analyst never wrote as a count. Splunk's syntax is
`sort [<count>] [-|+]<field>`: the count is never signed, and the sign belongs
to a FIELD. But a bare number is never a field name either. So `-5` is neither,
and it is refused rather than read as a count of 5.

`bare_search` WAS DECLARED, DOCUMENTED, AND NEVER FILLED

`SplCommand.bare_search` carried a docstring -- "The leading `search` of a bare
search line" -- and was never assigned anywhere in `spl.py`. Bare search heads
(`index=main foo=bar`) lower correctly through the head parsing without it. A
declared-but-never-populated field invites a reader to believe a value flows
through it, and a future writer to read a value that is always empty. Removed,
with a comment saying why, so nobody re-adds it thinking it is missing. If
bare-search handling ever needs its own slot, it should arrive with the code
that fills it.
"""

import unittest

import jobs
from dialects.spl_ir import SplParseError, lower


class PrestatsBelongsToTstats(unittest.TestCase):
    def test_it_is_refused_by_name(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | stats prestats=t count BY host")
        self.assertEqual(caught.exception.code, "SPL_PRESTATS_NOT_ON_STATS")

    def test_the_message_names_tstats(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | stats prestats=t count BY host")
        self.assertIn("tstats", caught.exception.message,
                      "the analyst almost certainly meant tstats, so the "
                      "message must say so")

    def test_stats_without_prestats_still_works(self):
        self.assertEqual(
            jobs.author("splunk", "index=main | stats count BY host",
                        "r1").rendered,
            "index=main | stats count AS count by host")

    def test_no_artifact_is_produced(self):
        outcome = jobs.author(
            "splunk", "index=main | stats prestats=t count BY host", "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"], "SPL_PRESTATS_NOT_ON_STATS")


class ASignedCountIsNeither(unittest.TestCase):
    def test_minus_five_is_refused(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | sort -5 host")
        self.assertEqual(caught.exception.code, "SPL_SORT_SIGNED_COUNT")

    def test_plus_five_is_refused(self):
        with self.assertRaises(SplParseError) as caught:
            lower("index=main | sort +5 host")
        self.assertEqual(caught.exception.code, "SPL_SORT_SIGNED_COUNT")

    def test_an_unsigned_count_still_works(self):
        self.assertEqual(
            jobs.author("splunk", "index=main | sort 5 host", "r1").rendered,
            "index=main | sort +host | head 5")

    def test_a_signed_field_still_works(self):
        """The sign belongs to a FIELD. `-_time` and `+host` must keep
        working -- only a signed bare number is refused."""
        self.assertEqual(
            jobs.author("splunk", "index=main | sort -_time", "r1").rendered,
            "index=main | sort -_time")
        self.assertEqual(
            jobs.author("splunk", "index=main | sort +host", "r1").rendered,
            "index=main | sort +host")

    def test_no_artifact_is_produced(self):
        outcome = jobs.author("splunk", "index=main | sort -5 host", "r1")
        self.assertFalse(outcome.rendered)
        self.assertEqual(outcome.refusal["code"], "SPL_SORT_SIGNED_COUNT")


class BareSearchNeedsNoSlot(unittest.TestCase):
    def test_a_bare_search_head_still_lowers(self):
        """The `bare_search` field was removed. Bare search heads must keep
        working through the head parsing, which is what actually handles them."""
        self.assertEqual(
            jobs.author("splunk", "index=main foo=bar", "r1").rendered,
            'index=main | search foo="bar"')
        self.assertEqual(
            jobs.author("splunk", "index=main foo=bar | stats count BY host",
                        "r1").rendered,
            'index=main | search foo="bar" | stats count AS count by host')

    def test_no_command_carries_a_bare_search_field(self):
        """Structural: if the field comes back, this fails."""
        import dataclasses

        from dialects.spl import SplCommand
        self.assertNotIn("bare_search",
                         {f.name for f in dataclasses.fields(SplCommand)},
                         "bare_search was removed because nothing ever filled "
                         "it; if it is back, it must arrive with the code that "
                         "fills it")


if __name__ == "__main__":
    unittest.main()
