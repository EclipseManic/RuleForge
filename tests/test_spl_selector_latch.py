"""The selector-hoist latch closed on the wrong condition.

`_split_selector` separates a head filter's search-time selectors (`index=`,
`sourcetype=`) from the rest, so selectors hoist to the head and everything
else stays a `| search`. The comment promises ONLY THE FIRST FILTER'S SELECTORS
CAN BE HOISTED, because the same shape later in the pipeline is a filter at that
point.

But the latch (`selector_emitted`) was set only WHEN SELECTORS WERE FOUND. So a
head filter with no selector term left it open, and a LATER filter's selectors
were hoisted:

    EventCode=4625 | search index=other
      ->  index=other | search EventCode="4625"

The `| search index=other` stage vanished from the pipeline and reappeared at
the head. For `index=` the result set is the same either way, but the comment
promised first-filter-only and the code did later-filter-too -- and an explicit
mid-pipeline `| where` being relocated is a surprise no analyst asked for.

The latch now means "the first filter has passed", and it closes after the
first filter whether or not that filter had selectors.
"""

import unittest

import jobs


class OnlyTheFirstFilterHoists(unittest.TestCase):
    def test_a_later_index_is_not_hoisted_to_the_head(self):
        """THE BUG. The first filter has no selector, so the latch used to stay
        open and `index=other` moved to the head."""
        self.assertEqual(
            jobs.author("splunk", "EventCode=4625 | search index=other",
                        "r1").rendered,
            '| search EventCode="4625" | search index="other"')

    def test_a_head_selector_still_hoists(self):
        """The latch must still do its job for the filter it was built for."""
        self.assertEqual(
            jobs.author("splunk", "index=main EventCode=4625", "r1").rendered,
            'index=main | search EventCode="4625"')

    def test_a_head_selector_plus_a_later_index_keeps_both_places(self):
        self.assertEqual(
            jobs.author("splunk",
                        "index=main EventCode=4625 | search index=other",
                        "r1").rendered,
            'index=main | search EventCode="4625" | search index="other"')

    def test_an_explicit_mid_pipeline_where_is_not_relocated(self):
        """`host` is a selector field. The `where` must stay where the analyst
        put it."""
        rendered = jobs.author(
            "splunk", 'index=main | where host="h" | search index=other',
            "r1").rendered
        self.assertEqual(rendered,
                         'index=main | search host="h" | search index="other"')
        self.assertLess(rendered.index('host="h"'),
                        rendered.index('index="other"'),
                        "the where-stage must come before the later search, in "
                        "pipeline order")


if __name__ == "__main__":
    unittest.main()
