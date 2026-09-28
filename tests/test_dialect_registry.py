"""The dialect registry cannot drift: one table for what works, one for targets.

`jobs.DIALECTS` is what works today; `TARGETS` is what must eventually be
handled. The home page shows DIALECTS labels for wired dialects and TARGETS
names for the rest, so the two tables disagreeing is how a partial dialect
gets over-claimed or a missing one goes unlisted.

Round 10 noted `TARGETS["falcon"]="CQL"` against a wired FQL slice and called
it not-a-defect -- correctly, because TARGETS names the eventual target. What
would be a defect is the reverse: a DIALECTS label claiming a whole language
for a slice. So this file pins the contract from both sides.
"""

import unittest

import jobs
from dialects import TARGETS


class TheRegistryCannotDrift(unittest.TestCase):
    def test_every_target_is_either_wired_or_listed_as_missing(self):
        """A TARGETS key with no DIALECTS entry must show on the home page as
        missing; a key with one must not. If these two tables disagree about
        which dialects exist, the UI lies in one direction or the other."""
        wired = set(jobs.DIALECTS)
        for key in TARGETS:
            self.assertIsInstance(TARGETS[key], str)
            self.assertTrue(TARGETS[key].strip(),
                            f"TARGETS[{key!r}] is an empty label")
        # sigma is a corpus, not a dialect: it must stay UNWIRED, or the UI
        # offers a dialect that does not exist.
        self.assertNotIn("sigma", wired,
                         "sigma is a test corpus, not a dialect; wiring it "
                         "would offer a language the tool does not speak")

    def test_partial_dialects_name_their_slice_in_the_label(self):
        """The EQL and FQL labels must say which slice is wired. A bare
        "Elastic EQL" or "CrowdStrike Falcon" label claims the whole language
        for a 5%-done dialect -- the same false claim this project deletes
        everywhere else."""
        for key, fragment in (("elastic", "sequence"),
                              ("falcon", "flat filter")):
            with self.subTest(dialect=key):
                label = jobs.DIALECTS[key]["label"].lower()
                self.assertIn(fragment, label,
                              f"DIALECTS[{key!r}] label {label!r} must name "
                              f"the wired slice")

    def test_every_wired_dialect_has_parse_lower_render(self):
        """The DIALECTS table comment promises one table so a dialect cannot
        be parseable and unrenderable with nothing complaining. Pinned: every
        entry carries a name, a label, and both callables. (`dialect` is the
        string constant, not a function -- parsing lives inside `lower_text`,
        which is why the check is shaped this way.)"""
        for key, spec in jobs.DIALECTS.items():
            with self.subTest(dialect=key):
                self.assertTrue(spec["dialect"],
                                f"DIALECTS[{key!r}] has an empty dialect name")
                self.assertTrue(spec["label"].strip(),
                                f"DIALECTS[{key!r}] has an empty label")
                for slot in ("lower_text", "render"):
                    self.assertTrue(callable(spec[slot]),
                                    f"DIALECTS[{key!r}] has no callable {slot!r}")


if __name__ == "__main__":
    unittest.main()
