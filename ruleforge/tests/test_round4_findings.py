"""Round 4: the ReDoS control was itself a denial-of-service vector, and the
separator was never the thing being checked.

Round 3 shipped a ReDoS guard and described it as holding. Two independent
reviewers then found, between them, that it had four live bypasses and would
hang on 55 characters. Every finding here has the measured number next to it.
"""
import time
import unittest

from ruleforge.engine.redos import catastrophic_reason
from ruleforge.engine.regex import compile_pattern, Refusal
from ruleforge.dialects import kql_render


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
    """

    def _bounded(self, pattern, budget_ms=250.0):
        start = time.perf_counter()
        catastrophic_reason(pattern)
        return (time.perf_counter() - start) * 1000, budget_ms

    def test_deeply_nested_groups(self):
        for depth in (22, 24, 26, 40, 200, 900):
            pattern = "(" * depth + "a" + ")" * depth + "+$"
            with self.subTest(depth=depth):
                elapsed, budget = self._bounded(pattern)
                self.assertLess(
                    elapsed, budget,
                    f"the analysis took {elapsed:.0f}ms on {len(pattern)} "
                    f"characters; it was 15.28s at depth 24")

    def test_deeply_nested_distinct_groups(self):
        # Memoisation cannot help when every body is different, so the depth cap
        # is the backstop rather than the fix.
        pattern = "".join(f"({'a' * i})" for i in range(1, 60)) + "+$"
        elapsed, budget = self._bounded(pattern)
        self.assertLess(elapsed, budget)

    def test_wide_alternation_at_depth(self):
        pattern = "(" * 30 + "|" .join(["ab"] * 20) + ")" * 30 + "+$"
        elapsed, budget = self._bounded(pattern)
        self.assertLess(elapsed, budget)


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


if __name__ == "__main__":
    unittest.main()
