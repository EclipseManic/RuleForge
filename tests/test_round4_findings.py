"""Round 4: the ReDoS control was itself a denial-of-service vector, and the
separator was never the thing being checked.

Round 3 shipped a ReDoS guard and described it as holding. Two independent
reviewers then found, between them, that it had four live bypasses and would
hang on 55 characters. Every finding here has the measured number next to it.
"""
import pathlib
import time
import unittest

from engine.redos import catastrophic_reason, _quantified_bodies
from engine.regex import compile_pattern, Refusal
from dialects import kql_render


def _elapsed_ms(fn):
    start = time.perf_counter()
    try:
        return (time.perf_counter() - start) * 1000, fn()
    except Refusal as exc:
        return (time.perf_counter() - start) * 1000, exc


class CatastrophicMustBeRefused(unittest.TestCase):
    """Each of these was ACCEPTED, with the measured cost in the name."""

    def test_twelve_characters_no_parentheses(self):
        # The round-3 control only looked INSIDE groups, so this walked through.
        self.assertIsNotNone(catastrophic_reason("a*a*a*a*a*a*a*a*$"))

    def test_character_set_overlap_is_not_a_string_prefix(self):
        # 19.73s at n=50. `[a-c][a-c]` and `[b-d][b-d]` are not string prefixes
        # of each other, but they share `b` and `c` at BOTH positions, so each
        # one has 2 ways to match and there are 2^(n/2) ways to divide the text.
        self.assertIsNotNone(
            catastrophic_reason("([a-c][a-c]|[b-d][b-d])+$"))

    def test_six_characters_with_a_shared_tail(self):
        # 6.07s at n=3000. Two quantifiers, so it sat exactly ON the limit of
        # two, and the limit was justified by a pattern whose safety came from a
        # separator the check could not see.
        self.assertIsNotNone(catastrophic_reason("a*a*b$"))
        self.assertIsNotNone(catastrophic_reason("a*a*b*c$"))

    def test_optional_groups_multiply_too(self):
        # 4.85s at n=32. `?` is exempt from the adjacency check on purpose --
        # it is tried once and cannot re-split anything -- so the count of `?`
        # is the only thing standing between this and the engine.
        self.assertIsNotNone(catastrophic_reason("a?" * 24 + "$"))
        self.assertIsNotNone(catastrophic_reason("[ab]?" * 24 + "$"))

    def test_open_ended_interval_is_a_quantifier(self):
        # `a{1,}` was being read as the literal text `{1,}` with nothing
        # quantified, so the group looked harmless.
        self.assertIsNotNone(catastrophic_reason("(a{1,})+$"))
        self.assertIsNotNone(catastrophic_reason("(a{2,})+$"))

    def test_classic_shapes_still_refused(self):
        for pattern in ("(a+)+$", "(a|aa)+$", "((a|aa))+$", "([a-z]+)*$",
                        "(a|a)*b", "(x+x+)+y", "(foo|foobar)+$", "(.*)*b",
                        "(a*)*(b*)*", "((a|ab)*)+$"):
            with self.subTest(pattern=pattern):
                self.assertIsNotNone(catastrophic_reason(pattern))


class GroupPrefixesMustNotHideTheBody(unittest.TestCase):
    """`(?:a|aa)+$` was ACCEPTED while `(a|aa)+$` was refused.

    Same language, different verdict, and the difference was a two-character
    group prefix. `_quantified_bodies` sliced each body as
    `pattern[start + 1:...]` where `start` was the index of `(`, so for EVERY
    prefixed group the slice began at the `?` and the real body was never looked
    at. For `(?:a|aa)+` the "body" was the single character `?` -- no
    alternation, therefore nothing to catch. It measured 0.6-1.0s at n=32.

    A named group was wrong for a second reason: the prefix scan stopped at the
    `<` of `(?P<` and landed ON the name, so the slice began inside the
    identifier.

    These are stated as a table because the point is that the VERDICT must not
    depend on the prefix. If someone reintroduces prefix-blind slicing, the
    first test in this class fails.
    """

    #: Prefixes that must make no difference to the verdict. All of these are
    #: real Python `re` constructs. `?a` and `:` are deliberately NOT here: `(?a`
    #: is not a group prefix in Python at all, and `(:a|aa)` is an ordinary group
    #: whose body genuinely starts with a colon, so neither says anything about
    #: prefix handling.
    PREFIXES = ("", "?:", "?P<w>", "?P<name>", "(?i:")

    def test_the_verdict_does_not_depend_on_the_group_prefix(self):
        for prefix in self.PREFIXES:
            pattern = f"({prefix}a|aa)+$"
            with self.subTest(pattern=pattern):
                reason = catastrophic_reason(pattern)
                self.assertIsNotNone(
                    reason,
                    f"{pattern} was accepted; the same alternation without a "
                    f"prefix is refused, so the prefix is hiding the body")
                # And refused for the RIGHT reason, not by some unrelated
                # control that happens to fire.
                self.assertIn("alternatives", reason)

    def test_the_extracted_body_is_the_body_not_the_prefix(self):
        """Asserted on the extractor, because the verdict alone does not say
        WHY it changed."""
        for prefix, expected in (("?:", "a|aa"), ("?P<w>", "a|aa"),
                                 ("?P<name>", "a|aa"), ("", "a|aa"),
                                 ("(?i:", "a|aa")):
            with self.subTest(prefix=prefix):
                bodies = _quantified_bodies(f"({prefix}a|aa)+")
                self.assertEqual([b for _, b, _ in bodies], [expected])

    def test_a_lookbehind_is_not_a_quantified_body(self):
        """`(?<=a|b)` has alternatives and is not quantified, so it must not be
        reported as a quantified body -- that would refuse ordinary patterns."""
        self.assertEqual(_quantified_bodies("(?<=a|b)foo"), [])
        self.assertIsNone(catastrophic_reason("(?<=abc)def"))

    def test_inline_flags_do_not_shift_the_body(self):
        """`(?i:...)` is a scoped flag group. The body after it is still the
        body."""
        self.assertEqual([b for _, b, _ in _quantified_bodies("(?i:ab|cd)+")],
                         ["ab|cd"])

    def test_a_comment_group_contains_no_pattern(self):
        """`(?#...)` is a comment. Its text is not a pattern, so a `|` inside it
        must not be read as an alternation."""
        self.assertEqual(_quantified_bodies("(?#a|aa)x+"), [])

    def test_ordinary_prefixed_groups_are_still_accepted(self):
        """The other direction. A guard that refuses every parenthesised group
        because prefixes are now parsed would be worse than the bypass.

        `(?:[a-z]+)+` and `(?:\\d{4})+` are deliberately NOT in this list. The
        first is a quantified group whose body is itself quantified -- the
        nested-quantifier case, catastrophic whatever the prefix. The second
        trips the quantifier-count control because a `+` and a `{4}` are two
        unbounded-ish quantifiers in one body. Neither says anything about
        whether prefixes are parsed, and listing them here would have been me
        asserting the guard should stay broken.
        """
        for pattern in ("(?:abc)+", "(?:foo|bar)+", "(?P<w>abc)+",
                        "(?:a-z)+", "(?i:abc)+"):
            with self.subTest(pattern=pattern):
                self.assertIsNone(catastrophic_reason(pattern),
                                  f"{pattern} is an ordinary pattern and must "
                                  f"not be refused")

    def test_a_nested_quantifier_is_refused_through_a_prefix_too(self):
        """The bypass could have been closed in the wrong direction -- by
        refusing everything prefixed. This pins that the prefixed nested case is
        still caught, so the fix was 'read the body', not 'distrust prefixes'."""
        for pattern in ("(?:[a-z]+)+", "(?:a+)+$", "(?P<w>a+)+$"):
            with self.subTest(pattern=pattern):
                self.assertIsNotNone(catastrophic_reason(pattern))


class OrdinaryPatternsMustCompile(unittest.TestCase):
    """A control that refuses real rules erodes the trust the refusals need.

    Round 3 refused an IPv4 regex, a timestamp, a date and an email, because it
    counted quantifiers globally and could not see the separator that made them
    safe.
    """

    def test_network_and_time_patterns(self):
        for pattern in (r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",  # IPv4
                        r"^[0-9]+:[0-9]+:[0-9]+$",           # timestamp
                        r"[0-9]+/[a-z]+/[0-9]+",              # date
                        r"\w+@\w+\.\w+",                      # email
                        r"[a-z]+@[a-z]+\.[a-z]+"):
            with self.subTest(pattern=pattern):
                self.assertIsNone(catastrophic_reason(pattern))

    def test_bounded_repeat_is_not_unbounded(self):
        # `{2,4}` consumes at most four characters. Treating it as open-ended
        # refused `[a-z]{2,4}\d*`.
        self.assertIsNone(catastrophic_reason("[a-z]{2,4}\\d*"))
        self.assertIsNone(catastrophic_reason("^a{2,4}b$"))
        self.assertIsNone(catastrophic_reason("^user-[0-9]{1,4}$"))

    def test_domain_with_a_mandatory_separator(self):
        # `([a-z]+\.)+[a-z]+` is an FQDN pattern. The dot inside the group
        # proves where each label ends, so there is nothing to re-split.
        self.assertIsNone(catastrophic_reason(r"([a-z]+\.)+[a-z]+"))

    def test_alternations_that_diverge(self):
        # GET and POST share a first letter but diverge at the second, so each
        # position has O(1) choices. Only a shared PREFIX is ambiguous.
        for pattern in (r"(a|b)+c", r"(GET|POST|PUT)+",
                        r"(admin|root|user)+$", r"(GET|HEAD|POST|PUT|DELETE)+",
                        r"^(GET|POST)+$", r"^(foo|bar)$", r"[0-9]+(\.[0-9]+)?"):
            with self.subTest(pattern=pattern):
                self.assertIsNone(catastrophic_reason(pattern))


class TheAnalysisItselfMustBeCheap(unittest.TestCase):
    """A guard that can be made to hang is worse than no guard.

    The recursion into nested group bodies was 2^depth, so the analysis -- not
    the pattern -- was the denial-of-service vector. Reachable from
    `POST /api/tune` with a single event.

    WHY THIS NO LONGER ASSERTS ONE WALL-CLOCK NUMBER PER DEPTH.

    It used to: one loop, one 250ms budget, every depth. That budget is a
    statement about the speed of the machine it was written on, and it was
    already failing here about one full-suite run in three at 270-300ms.
    Proven pre-existing rather than assumed: commit 114550e fails at the same
    rate in a clean worktree. A test that fails on a third of runs is a test
    people learn to ignore, and an ignored hang detector is worse than none.

    Worse, it spent its whole budget where there is nothing to detect. Measured
    on this machine, best-of-five:

        depth  22 (47 chars)     0.26 ms
        depth  40 (83 chars)     0.72 ms
        depth 200 (403 chars)   17.91 ms
        depth 900 (1803 chars) 149.31 ms
        depth 1800 (3603 chars) 154.47 ms   <- plateaus at the depth cap

    The defect was 15.28 SECONDS at depth 24 -- 47 characters. So the exponential
    shape is caught instantly by a budget on the SMALLEST depth, where the margin
    is about 58,000x. The large depths were consuming 60% of the budget each to
    confirm something that a plateau check confirms better.

    So the two properties worth asserting are separated:

      * a TIGHT budget at small depth, which is the regression detector for the
        exponential defect and has a margin wide enough to survive a slow
        machine, a loaded CI box, or a future CPython;
      * a generous budget at large depth, which is only a "does not hang"
        backstop, because a machine-independent number is not available;
      * a PLATEAU, which is the real property -- past the bound, doubling the
        depth must not double the work.

    AND THE PLATEAU IS NOT ENFORCED BY THE DEPTH CAP, THOUGH THE FIRST VERSION
    OF THIS COMMENT SAID IT WAS. Verified by mutation rather than assumed:

        _MAX_ANALYSIS_DEPTH 64 -> 4096    5 passed   (no effect)
        len(_seen) 512 -> 100000          2 FAILED, and the suite went 3s -> 45s

    So the curve is flattened by the DISTINCT-BODIES bound, because
    `((((a))))`-shaped nesting at depth 900 has 900 distinct bodies and trips
    `len(_seen) > 512` long before the depth cap at 64 is reached. The depth cap
    governs the other shape -- deeply nested groups whose bodies REPEAT, where
    `_seen` stays tiny -- which is what
    `test_the_depth_cap_bounds_repeated_bodies` covers.

    Both bounds matter and they are not interchangeable, which is exactly why
    each has its own test rather than one comment claiming they are the same
    mechanism.
    """

    #: Depth 24 is where the original defect cost 15.28s. Measured 0.29ms, so
    #: this budget has roughly a 50,000x margin -- wide enough that a loaded
    #: machine, a slower interpreter or a future CPython cannot make it a flake,
    #: while a return to anything exponential fails immediately.
    EXPONENTIAL_BUDGET_MS = 50.0

    #: Only a hang backstop. The measured cost at depth 900 is ~155ms, so this is
    #: ~13x headroom on an idle machine and it is not the regression detector.
    HANG_BACKSTOP_MS = 3000.0

    def _elapsed_ms(self, pattern, repeats=3):
        """Best of `repeats`, because a single sample on a shared machine is
        mostly scheduler noise and the minimum is the closest thing to the cost
        of the work itself."""
        best = None
        for _ in range(repeats):
            start = time.perf_counter()
            catastrophic_reason(pattern)
            elapsed = (time.perf_counter() - start) * 1000
            best = elapsed if best is None else min(best, elapsed)
        return best

    @staticmethod
    def _nested(depth):
        return "(" * depth + "a" + ")" * depth + "+$"

    def test_the_exponential_shape_is_caught_at_the_depth_it_broke(self):
        """THE regression detector. Depth 24 is where this cost 15.28 seconds,
        so the budget there is the one with a meaningful margin."""
        for depth in (22, 24, 26, 40):
            pattern = self._nested(depth)
            with self.subTest(depth=depth):
                elapsed = self._elapsed_ms(pattern)
                self.assertLess(
                    elapsed, self.EXPONENTIAL_BUDGET_MS,
                    f"the analysis took {elapsed:.0f}ms on {len(pattern)} "
                    f"characters; it was 15.28s at depth 24")

    def test_deep_nesting_does_not_hang(self):
        """A backstop, not the detector -- see the class docstring for why this
        is not the assertion carrying the regression."""
        for depth in (200, 900, 1800):
            pattern = self._nested(depth)
            with self.subTest(depth=depth):
                elapsed = self._elapsed_ms(pattern)
                self.assertLess(elapsed, self.HANG_BACKSTOP_MS,
                                f"the analysis took {elapsed:.0f}ms at depth "
                                f"{depth}")

    def test_the_cost_plateaus_past_the_distinct_bodies_bound(self):
        """THE REAL PROPERTY, and the machine-independent one.

        `len(_seen) > 512` in `redos.py` bounds how many distinct group bodies
        the descent will visit, so past that point doubling the depth must not
        double the work. Measured here: 149ms at depth 900 and 154ms at 1800 --
        flat. Raising the bound to 100000 makes this test fail and takes the
        suite from 3s to 45s, so it has teeth.

        A fixed millisecond budget could not do this. The same exponential
        regression passes on a fast machine and fails on a slow one, which is
        what made the original version of this test a coin flip.

        The allowance is 3x because the curve is not perfectly flat at the knee
        and the point is to catch a shape change, not to measure a constant.
        """
        at_bound = self._elapsed_ms(self._nested(900))
        past_bound = self._elapsed_ms(self._nested(1800))
        self.assertLess(
            past_bound, at_bound * 3.0,
            f"doubling the depth past the bound multiplied the cost by "
            f"{past_bound / max(at_bound, 1e-9):.1f}x ({at_bound:.0f}ms -> "
            f"{past_bound:.0f}ms), so the distinct-bodies bound is not holding "
            f"the descent")

    def test_the_depth_cap_bounds_repeated_bodies(self):
        """The OTHER bound, covering the shape the distinct-bodies bound cannot
        help with.

        `((((a))))` at depth 900 has ONE distinct body repeated, so `_seen` never
        grows and `len(_seen) > 512` never fires. `_MAX_ANALYSIS_DEPTH` is the
        only thing bounding that descent, which is why it needs its own coverage
        rather than being assumed by the plateau test above.
        """
        repeated = "(" * 900 + "a" + ")" * 900
        elapsed = self._elapsed_ms(repeated + "+$")
        self.assertLess(elapsed, self.HANG_BACKSTOP_MS)

    def test_raising_either_bound_would_show_up_somewhere(self):
        """Named, so the next reader does not have to re-derive which mechanism
        flattens which curve. The two bounds are not interchangeable:

          distinct bodies  `len(_seen) > 512`        this is what makes the
                                                      plateau test fail
          repeated bodies  `_MAX_ANALYSIS_DEPTH`     this is the only bound
                                                      that applies at all

        Both are real and both are load-bearing; this asserts they still exist,
        so deleting either one is a visible change rather than a silent
        performance regression found in production.
        """
        import engine.redos as redos
        self.assertTrue(hasattr(redos, "_MAX_ANALYSIS_DEPTH"))
        self.assertIsInstance(redos._MAX_ANALYSIS_DEPTH, int)
        source = pathlib.Path(redos.__file__).read_text(encoding="utf-8")
        self.assertIn("len(_seen) >", source,
                      "the distinct-bodies bound is gone; the plateau test "
                      "above no longer has a mechanism behind it")

    def test_deeply_nested_distinct_groups(self):
        # Memoisation cannot help when every body is different, so the depth cap
        # is the backstop rather than the fix.
        pattern = "".join(f"({'a' * i})" for i in range(1, 60)) + "+$"
        elapsed = self._elapsed_ms(pattern)
        self.assertLess(elapsed, self.HANG_BACKSTOP_MS)

    def test_wide_alternation_at_depth(self):
        pattern = "(" * 30 + "|" .join(["ab"] * 20) + ")" * 30 + "+$"
        elapsed = self._elapsed_ms(pattern)
        self.assertLess(elapsed, self.HANG_BACKSTOP_MS)


class DeepNestingIsARefusalNotACrash(unittest.TestCase):
    """`re.compile` used to run BEFORE the guard.

    `"(" * 900 + "a" + ")" * 900` raised a bare `RecursionError` out of
    `compile_pattern`. The catch-all then reported INPUT_TOO_DEEP -- "the pasted
    events are nested too deeply" -- which is the opposite of the truth: the
    cause was the rule's regex. A refusal that escapes as a non-Refusal is a
    crash, and one that misattributes blame is worse than the crash alone.
    """

    def test_no_non_refusal_exception_ever_escapes(self):
        """Whatever the reason, the answer must be a named Refusal.

        A reviewer measured a bare `RecursionError` out of this function. The
        dialect allowlist happens to catch deep nesting first today
        (REGEX_NOT_EXECUTABLE), so the crash is not currently reachable -- which
        is exactly why it needs a test. The `except RecursionError` in
        `compile_pattern` is defence in depth for any other dialect or path, and
        a defensive clause with no test is a clause that rots.
        """
        for depth in (60, 100, 200, 300, 500, 900, 1500):
            with self.subTest(depth=depth):
                try:
                    compile_pattern("posix_extended",
                                    "(" * depth + "a" + ")" * depth)
                except Refusal:
                    pass
                except Exception as exc:  # pragma: no cover - the defect
                    self.fail(
                        f"{type(exc).__name__} escaped at depth {depth}; every "
                        f"refusal must be a Refusal so the message can name the "
                        f"cause instead of blaming the wrong thing")

    def test_the_defensive_handler_is_reachable(self):
        """Prove the `except RecursionError` clause is live, not decorative."""
        import re as _re
        original = _re.compile
        try:
            def _boom(pattern, flags=0):
                raise RecursionError("simulated")
            _re.compile = _boom
            with self.assertRaises(Refusal) as caught:
                compile_pattern("posix_extended", "[a-z]+")
        finally:
            _re.compile = original
        self.assertEqual(caught.exception.code, "REGEX_NESTING_TOO_DEEP")

    def test_moderate_nesting_is_refused_not_crashed(self):
        for depth in (100, 300, 500):
            with self.subTest(depth=depth):
                try:
                    compile_pattern("posix_extended", "(" * depth + "a" + ")" * depth)
                except Refusal:
                    pass
                except RecursionError:  # pragma: no cover - the defect
                    self.fail(f"RecursionError escaped at depth {depth}")


class KqlBackslashEscaping(unittest.TestCase):
    """A SPL bug, fixed in SPL one commit earlier, missed in KQL.

    KQL regular strings treat `\\` as an escape. `render_literal` escaped `"` and
    not `\\`, so a trailing backslash escaped the CLOSING quote and the rest of
    the stage became live KQL. The deployed Sentinel rule returned zero rows
    with no error.
    """

    def test_trailing_backslash_closes_the_string(self):
        rendered = kql_render.render_literal("a\\")
        self.assertEqual(rendered, '"a\\\\"')

    def test_injection_through_a_backslash(self):
        # Backslash FIRST, then the quote. Escaping only the quote leaves the
        # backslash live, so it consumes the escape that protects the quote and
        # the literal closes early.
        rendered = kql_render.render_literal('a\\" | take 0 #')
        self.assertEqual(rendered, '"a\\\\\\" | take 0 #"')
        body = rendered[1:-1]
        self.assertEqual(
            sum(1 for index, char in enumerate(body)
                if char == '"' and (index == 0 or body[index - 1] != "\\")),
            0, f"an unescaped quote survived: {rendered!r}")

    def test_windows_path_with_a_trailing_backslash(self):
        rendered = kql_render.render_literal("C:\\logs\\win\\")
        self.assertEqual(rendered, '"C:\\\\logs\\\\win\\\\"')

    def test_quotes_still_escaped(self):
        self.assertEqual(kql_render.render_literal('a"b'), '"a\\"b"')


class NestingMustNotHideTheCheck(unittest.TestCase):
    """ONE EXTRA PAIR OF PARENTHESES MUST NOT CHANGE THE VERDICT.

    `((a+))+$` was ACCEPTED while `(a+)+$` was refused. Same language, and the
    only difference is a redundant group. Measured on the accepted one:
    0.0083s at n=18, 2.64s at n=26, 58.3s at n=30. `((a*))+$` reached 11s at
    n=26.

    The cause was an ASYMMETRY, and the asymmetry is the whole point. The
    alternation check descends into nested group bodies, so `((a|aa))+$` was
    always refused. The quantifier check treated a nested group as a single
    ATOM with no quantifier, so the `+` one level down was invisible. Nothing
    in the module said those two should differ.

    The test is stated as the PROPERTY rather than as a list of patterns,
    because the property is what has to hold: for any body X, if `(X)+$` is
    refused then `((X))+$` must be too. A table of hand-picked patterns would
    pass again the next time someone found a fourth spelling.
    """

    #: Bodies that are catastrophic once wrapped. Every one of these is refused
    #: in its plain `(X)+$` form -- asserted below, so the property cannot be
    #: satisfied by refusing everything.
    BODIES = ("a+", "a*", "a{1,}", "a|aa", "[a-z]+", "aa|a", "\\w+a")

    def test_the_plain_form_is_refused_for_every_body(self):
        """The premise of the property, asserted so it cannot rot."""
        for body in self.BODIES:
            with self.subTest(body=body):
                self.assertIsNotNone(
                    catastrophic_reason(f"({body})+$"),
                    f"({body})+$ is not being refused, so the wrapped form is "
                    f"not a bypass of anything")

    def test_wrapping_in_a_redundant_group_does_not_help(self):
        for body in self.BODIES:
            with self.subTest(body=body):
                self.assertIsNotNone(
                    catastrophic_reason(f"(({body}))+$"),
                    f"(({body}))+$ was ACCEPTED while ({body})+$ is refused")

    def test_several_layers_of_wrapping_do_not_help_either(self):
        for body in self.BODIES:
            with self.subTest(body=body):
                self.assertIsNotNone(catastrophic_reason(f"((({body})))+$"))

    def test_a_group_prefix_does_not_help(self):
        """`(?:` is the same wrapper spelled differently, and the prefix parsing
        has to reach the same verdict through it -- for every body in the table,
        including the alternation ones.

        This assertion was DELIBERATELY ABSENT from the first version of this
        class, with the gap written up in HANDOFF.md instead. `(?:(?:a|aa))+$`
        and `(?:(?:aa|a))+$` were accepted and genuinely exponential, and I chose
        not to write a test that passed by agreeing with a bug.

        The cause was a THIRD copy of the group-prefix rules. `_all_group_bodies`
        skipped a `?:`-style prefix inline and then appended from one character
        past the `(`, so it collected the body as `?:a|aa`. The alternation split
        produced the branches `?:a` and `aa`, which share no prefix, so the
        overlap check reported no ambiguity. The plain `((a|aa))` form worked
        because a plain group has no prefix to include -- which is exactly why
        the plain and singly-wrapped forms were refused while the `?:` form was
        not, and why nothing looked like an inconsistency.

        The fix is to call the same `_body_start_after_prefix` the other two
        callers use. That helper was extracted when the quantifier path was
        fixed; this call site was never migrated to it. The second source of
        truth arrived by OMISSION rather than by intent, which is the argument
        for the shared helper existing.
        """
        for body in self.BODIES:
            with self.subTest(body=body):
                self.assertIsNotNone(
                    catastrophic_reason(f"(?:(?:{body}))+$"),
                    f"(?:(?:{body}))+$ was accepted")


class EscapeClassesMustNotBeReadAsLiterals(unittest.TestCase):
    """`_first_set` returned `{atom[1]}` for EVERY escape.

    For a word escape that is the letter `w` -- the NAME of the class, treated
    as a literal character. So it and `a` were "proved" disjoint and the
    pattern below was accepted. Measured: 0.0022s at n=20, 0.18s at n=30,
    12.5s at n=38 -- about 8.7x per character added. The unwrapped equivalent
    `(aa|a)+$` is refused.

    The error is one of DIRECTION. Every consumer needs an UPPER bound on what
    an atom can match, because it uses the answer to prove two atoms cannot
    collide. One character is a LOWER bound, and a lower bound used as an upper
    bound proves the opposite of what is true.

    The module's own docstring named this exact invariant -- "None means
    UNKNOWN, and unknown is treated as overlapping with everything" -- and the
    code broke it. That is why these are tested as a group: the convention has
    to hold for every escape, not for the one somebody remembered.
    """

    def test_a_word_class_is_not_the_letter_w(self):
        self.assertIsNotNone(catastrophic_reason(r"(\w+a)+$"))

    def test_a_digit_class_is_not_the_letter_d(self):
        """Asserted on `_first_set` DIRECTLY, because guessing an end-to-end
        pattern for this one produced two wrong tests in a row.

        The first attempt used `(\\d+a)+$`. The second used `(\\d\\da|\\da)+$`.
        Both FAILED, and both times the screen was right and the test was wrong:
        a digit and `a` cannot collide, so neither pattern has anything to
        re-split, and I had asserted a falsehood rather than measuring. The
        defect class is identical to a false comment -- a claim outrunning the
        code -- and it is cheaper to catch by testing the thing that changed.

        What changed is one line: the escape branch returned `{atom[1]}`, so
        `\\d` became `{'d'}`. So that is what is asserted here. The end-to-end
        consequence is covered by `test_two_branches_that_collide_through_escapes`,
        which was measured before it was written.
        """
        import string

        from engine.redos import _first_set

        self.assertEqual(_first_set(r"\d"), frozenset(string.digits))
        self.assertNotEqual(_first_set(r"\d"), {"d"})
        # A word class must CONTAIN letters, which is the whole point: it is what
        # makes it collide with a literal `a` instead of being 'proved' disjoint.
        self.assertIn("a", _first_set(r"\w"))
        self.assertNotEqual(_first_set(r"\w"), {"w"})
        # Inside a character class the same one-line error existed.
        self.assertEqual(_first_set(r"[\d]"), frozenset(string.digits))

    def test_two_branches_that_collide_through_escapes(self):
        """`\\d` and `\\w` genuinely share every digit, so `\\d\\d` and `\\w\\d`
        are ambiguous at position two. Read as `{'d'}` versus `{'w'}` they looked
        disjoint."""
        self.assertIsNotNone(catastrophic_reason(r"(\d\d|\w\d)+$"))

    def test_an_escape_inside_a_character_class(self):
        """`[\\d]` used to contribute the letter `d` to the class, through a
        second copy of the same one-line error."""
        self.assertIsNotNone(catastrophic_reason(r"([\w]+a)+$"))

    def test_a_backreference_is_not_the_digit_after_the_slash(self):
        """`\\1` is unknowable without running the pattern, and this function
        must not run anything."""
        self.assertIsNone(catastrophic_reason(r"^(\w)\1(\w)\2$"),
                          "a pattern with backreferences should be judged on "
                          "its literal parts, not refused outright")

    def test_a_word_boundary_is_not_the_letter_b(self):
        """`\\b` matches the EMPTY string. Reporting it as `b` made a boundary
        assertion look like a literal."""
        self.assertIsNone(catastrophic_reason(r"\bword\b+\s"))

    def test_ordinary_patterns_that_use_escapes_are_still_accepted(self):
        """THE DIRECTION THAT MATTERS MOST. A ReDoS screen that refuses the
        standard shapes for an email, an IP, a date, a path or a word boundary
        is worse than no screen, because detection rules are full of them."""
        for pattern in (r"^\w+@\w+\.\w+$",
                        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
                        r"\d{4}-\d{2}-\d{2}",
                        r"[0-9]+(\.[0-9]+)?",
                        r"([a-z]+\.)+[a-z]+",
                        r"\bSYSTEM\b",
                        r"^lsass\.exe$",
                        r"\\lsass\.exe$",
                        r"(?i)\bcmd\.exe\b",
                        r"\s+ERROR\s+"):
            with self.subTest(pattern=pattern):
                self.assertIsNone(
                    catastrophic_reason(pattern),
                    f"{pattern} is an ordinary detection pattern and must not "
                    f"be refused")


if __name__ == "__main__":
    unittest.main()
