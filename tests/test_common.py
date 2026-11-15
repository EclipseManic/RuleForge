"""Tests for the shared tokenizer and expression parser.

A precedence bug is the single easiest thing to get wrong in a rule parser and
the hardest to see in review, because the rule still parses, still renders, and
still looks right. So the cases below are stated as a TABLE of source text and
the exact tree it must produce, and the comments say which real rule each one
comes from.

Every vendor shares this parser. A bug here is a bug in all eight dialects at
once, which is why these tests live on the shared layer rather than being
duplicated per dialect.
"""

from __future__ import annotations

import unittest

from engine.dialects.common import (
    C_LIKE_PRECEDENCE,
    DialectSpec,
    Parser,
    parse_annotation_header,
    render_annotation_header,
    split_top_level,
    strip_comments,
    tokenize,
)
from engine.ir import BoolOp, render_expr
from engine.values import Duration, Refusal

from decimal import Decimal


KQL = DialectSpec(
    key="sentinel",
    language="KQL",
    precedence=dict(C_LIKE_PRECEDENCE),
    operators={
        "==": "==", "=": "==", "and": "and", "or": "or",
        "=~": "matches", "!~": "!~", "in~": "in", "in": "in",
        "has_any": "has_any", "has_all": "has_all",
        "contains": "contains", "endswith": "endswith",
        "startswith": "startswith",
    },
    keywords=frozenset({
        "between", "ago", "now", "asc", "desc", "by", "and", "or", "not", "in",
        "matches", "contains", "endswith", "startswith", "has_any", "has_all",
        "regex", "nocase", "true", "false", "null", "project", "extend",
        "where", "summarize", "join", "sort", "order", "top", "take", "limit",
        "distinct", "count", "sum", "min", "max", "avg", "dcount", "make_set",
        "make_list", "to_string", "to_int", "iff", "kind", "with", "hint",
        "to_lower", "to_upper", "strcat", "bin",
    }),
    functions={
        "ago": "ago", "now": "now", "make_set": "make_set",
        "make_list": "make_list", "count": "count", "sum": "sum", "min": "min",
        "max": "max", "avg": "avg", "dcount": "dcount",
        "to_string": "to_string", "to_int": "to_int", "to_lower": "lower",
        "to_upper": "upper",
    },
)


def parse(source: str) -> str:
    return render_expr(Parser(tokenize(source), KQL).parse_expression())


class Precedence(unittest.TestCase):
    """The table. Each row is a real rule or a real fragment of one."""

    CASES = [
        # AND binds tighter than OR. Getting this backwards turns
        # `QIDNAME(qid) ILIKE '%LSASS%' OR LOGSOURCENAME(x) ILIKE '%Sysmon%'
        #  AND UTF8(payload) ILIKE '%lsass%'` into a rule that matches any Sysmon
        # event at all.
        ("a == 1 and b == 2 or c == 3",
         "((a == 1 AND b == 2) OR c == 3)"),
        ("a or b and c",
         "(a OR (b AND c))"),
        ("a and b or c and d",
         "((a AND b) OR (c AND d))"),
        # Explicit parens survive and change nothing about the tree shape.
        ("(a or b) and c",
         "((a OR b) AND c)"),
        # NOT binds looser than a comparison. `not a == 1` is `not (a == 1)`;
        # binding it tighter gives `(not a) == 1`, which negates a FIELD and
        # therefore matches every row where the field is non-empty.
        ("not a == 1", "NOT (a == 1)"),
        ("not (a == 1 and b == 2)", "NOT (a == 1 AND b == 2)"),
        ("not not a == 1", "NOT NOT (a == 1)"),
        ("Account == \"svc\" and not (A == 1 or B == 2)",
         "(Account == \"svc\" AND NOT (A == 1 OR B == 2))"),
        # Arithmetic binds tighter than comparison, and * tighter than +.
        ("a + 5 * 2 > 10", "(a + (5 * 2)) > 10"),
        ("10 - 2 - 3 == 5", "((10 - 2) - 3) == 5"),
    ]

    def test_precedence_table(self):
        for source, expected in self.CASES:
            with self.subTest(source=source):
                self.assertEqual(parse(source), expected)

    def test_a_flat_boolop_not_a_left_nest(self):
        # `a and b and c` is one BoolOp, so the rendered form matches what the
        # author wrote instead of growing parentheses that carry no meaning.
        rendered = parse("a == 1 and b == 2 and c == 3")
        self.assertEqual(rendered.count("AND"), 2)
        self.assertFalse(rendered.startswith("(("))


class Durations(unittest.TestCase):
    def test_a_duration_is_one_token(self):
        # Lexed as `10` then `m`, `| where T > ago(10m)` compares against a
        # column called `m` and matches nothing, silently.
        from engine.dialects.common import tokenize as tk
        kinds = [t.kind for t in tk("ago(30m)")]
        self.assertIn("duration", kinds)
        self.assertEqual(parse("T > ago(30m)"), "T > ago(30m)")

    def test_a_duration_becomes_a_duration_value(self):
        parser = Parser(tokenize("10m"), KQL)
        value = parser.parse_expression()
        self.assertIsInstance(value.value, Duration)
        self.assertEqual(value.value.seconds, Decimal(600))

    def test_spelled_out_units_work(self):
        self.assertEqual(parse("T > ago(30 seconds)"), "T > ago(30s)")
        self.assertEqual(parse("T > ago(2h)"), "T > ago(2h)")

    def test_a_number_followed_by_a_word_is_not_a_duration(self):
        # `5 metrics` must not lex as `5m etrics`.
        self.assertEqual(parse("x == 5 metrics"), "x == 5")


class PatternOperators(unittest.TestCase):
    def test_a_modifier_word_is_not_the_operand(self):
        # `x matches regex "lsass"` read as `x matches regex` compares a string
        # to a column called `regex`.
        self.assertEqual(
            parse('x matches regex "lsass"'),
            "x matches /lsass/posix_extended",
        )

    def test_a_trailing_modifier_is_applied(self):
        self.assertEqual(
            parse('x matches regex "a" nocase'),
            "x matches /a/posix_extended nocase",
        )

    def test_tilde_syntax(self):
        self.assertEqual(parse('x =~ "lsass"'), "x matches /lsass/posix_extended")

    def test_negated_tilde(self):
        # The parentheses matter: `NOT x matches /lsass/` reads as
        # `(NOT x) matches /lsass/`, which is the inverse of the rule written.
        self.assertEqual(
            parse('x !~ "lsass"'), "NOT (x matches /lsass/posix_extended)"
        )

    def test_string_operators(self):
        self.assertEqual(parse('x contains "lsass"'), 'x contains "lsass"')
        self.assertEqual(parse('x endswith "lsass"'), 'x endswith "lsass"')
        self.assertEqual(parse('x startswith "lsass"'), 'x startswith "lsass"')

    def test_a_string_containing_a_slash_is_not_split(self):
        self.assertEqual(
            parse('TargetImage endswith @"\\lsass.exe"'),
            'TargetImage endswith "\\lsass.exe"',
        )


class Lists(unittest.TestCase):
    def test_parenthesised_list(self):
        self.assertEqual(parse("EventID in (4624, 4688)"), "EventID in [4624, 4688]")

    def test_bracket_list(self):
        self.assertEqual(parse("EventID in [4624, 4688]"), "EventID in [4624, 4688]")

    def test_a_single_element_parenthesised_list(self):
        # `in (b)` is a one-element list. Read as a group it becomes a
        # comparison against a group, which matches nothing.
        self.assertEqual(parse("a in (b) and c == 1"), "(a in [b] AND c == 1)")

    def test_a_parenthesised_group_is_not_a_list(self):
        # No comma, so it is a group -- the distinction the whole thing rests on.
        # The redundant parens around a single comparison carry no meaning,
        # so the flattened form is the correct tree -- not a lost grouping.
        self.assertEqual(parse("(a == 1) and b == 2"), "(a == 1 AND b == 2)")

    def test_a_comma_inside_a_string_does_not_make_a_list(self):
        self.assertEqual(
            parse('f(a) == "x, y"'), 'f(a) == "x, y"'
        )


class Between(unittest.TestCase):
    def test_between_with_arithmetic_bound(self):
        # The single most important expression in this tool:
        # `where LoginTime between (LSASSTime .. LSASSTime + 10m)`.
        self.assertEqual(
            parse("LoginTime between (LSASSTime .. LSASSTime + 10m)"),
            "LoginTime between (LSASSTime .. (LSASSTime + 10m))",
        )

    def test_between_with_the_and_spelling(self):
        self.assertEqual(
            parse("T between 10 and 20"), "T between (10 .. 20)"
        )

    def test_between_with_a_comparison_bound(self):
        self.assertEqual(
            parse("T between (ago(1h) .. now())"), "T between (ago(1h) .. now())"
        )


class CaseInsensitiveMembership(unittest.TestCase):
    def test_in_tilde_is_one_token(self):
        # As `in` then `~`, the `~` is left unconsumed and everything after the
        # condition goes unread.
        self.assertEqual(
            parse('SourceIp in~ ("10.0.0.1", "10.0.0.2")'),
            'SourceIp in ["10.0.0.1", "10.0.0.2"]',
        )


class Functions(unittest.TestCase):
    def test_a_keyword_that_names_a_function_is_a_function(self):
        # `ago` is in the keyword set, and reading it as a field turns
        # `| where T > ago(30m)` into a comparison against a column called `ago`.
        self.assertEqual(parse("T > ago(30m)"), "T > ago(30m)")

    def test_a_zero_argument_call(self):
        self.assertEqual(parse("count() > 2"), "count() > 2")

    def test_a_multi_argument_call(self):
        self.assertEqual(parse('f(a, b, c) == "x"'), 'f(a, b, c) == "x"')

    def test_a_dialect_function_is_remapped(self):
        self.assertEqual(parse("x == to_lower(y)"), "x == lower(y)")


class Comments(unittest.TestCase):
    def test_a_line_comment_is_removed(self):
        self.assertEqual(parse("a == 1 // trailing"), "a == 1")

    def test_a_block_comment_is_removed(self):
        self.assertEqual(parse("/* lead */ a == 1"), "a == 1")

    def test_a_comment_marker_inside_a_string_is_not_a_comment(self):
        self.assertEqual(parse('x == "http://a"'), 'x == "http://a"')

    def test_an_unterminated_block_comment_is_refused(self):
        # Otherwise the rest of the rule is read as a comment and the rule
        # parses to nothing.
        with self.assertRaises(Refusal) as caught:
            strip_comments("a == 1 /* never closed")
        self.assertEqual(caught.exception.code, "COMMENT_UNTERMINATED")


class Refusals(unittest.TestCase):
    def test_a_reserved_word_in_an_operand_slot_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse("a == and b")
        # The specific answer, not a generic parse error: reading `and` as a
        # FIELD produces a rule that parses, renders, and matches nothing.
        self.assertEqual(caught.exception.code, "RESERVED_WORD_AS_FIELD")
        self.assertIn("missing an operand", caught.exception.message)

    def test_an_unexpected_token_names_its_position(self):
        with self.assertRaises(Refusal) as caught:
            parse("a == (")
        self.assertEqual(caught.exception.code, "PARSE_UNEXPECTED")
        self.assertIn("character", caught.exception.message)

    def test_an_unknown_character_is_refused_with_context(self):
        with self.assertRaises(Refusal) as caught:
            parse("a == 1 § 2")
        self.assertEqual(caught.exception.code, "TOKEN_UNKNOWN")

    def test_an_empty_list_is_refused(self):
        # It matches nothing, which is almost never the intent.
        with self.assertRaises(Refusal) as caught:
            parse("a in ()")
        self.assertEqual(caught.exception.code, "LIST_EMPTY")


class Splitter(unittest.TestCase):
    """A splitter that ignores strings splits `"a, b"` in two."""

    def test_a_comma_inside_a_string_is_not_a_separator(self):
        self.assertEqual(
            split_top_level('a, "x, y", b'), ["a", '"x, y"', "b"]
        )

    def test_nesting_is_respected(self):
        self.assertEqual(split_top_level("f(a, b), c"), ["f(a, b)", "c"])

    def test_a_bracket_inside_a_string_is_not_a_separator(self):
        self.assertEqual(split_top_level('"a]b", c'), ['"a]b"', "c"])


class OperatorCaseIsNotLoadBearingHere(unittest.TestCase):
    """An uppercase word operator must bind, or the expression truncates.

    `precedence_of` looked its token up case-sensitively while
    `build_comparison` lowercased first. The two disagreed, so for a dialect
    that spells its booleans in uppercase -- AQL, YARA-L, SPL's eval syntax --
    `a == 1 AND b == 2` resolved no binding power for `AND`, the parser stopped
    after `a == 1`, and the rest of the condition was SILENTLY UNREAD. The rule
    then matched a strictly larger set of events than it stated, with nothing
    reported.

    A dialect that genuinely cares about the case of a boolean has to decide
    that before the parser runs, because by then the distinction is gone.
    """

    def spec(self) -> DialectSpec:
        return DialectSpec(
            key="probe",
            language="probe",
            precedence=dict(C_LIKE_PRECEDENCE),
            operators={"and": "and", "or": "or", "==": "==", "!=": "!="},
            keywords=frozenset({"and", "or", "not"}),
        )

    def parse(self, text: str):
        return Parser(tokenize(text), self.spec()).parse_expression(0)

    def test_an_uppercase_and_binds(self):
        tree = self.parse("a == 1 AND b == 2")
        self.assertIsInstance(tree, BoolOp)
        self.assertEqual(tree.op, "and")
        self.assertEqual(len(tree.operands), 2)

    def test_an_uppercase_or_binds(self):
        tree = self.parse("a == 1 OR b == 2")
        self.assertEqual(tree.op, "or")

    def test_mixed_case_still_binds(self):
        self.assertEqual(self.parse("a == 1 And b == 2").op, "and")

    def test_uppercase_precedence_matches_lowercase(self):
        # If the uppercase form resolved a DIFFERENT binding power, the same
        # rule would group two ways depending only on how it was typed.
        upper = self.parse("a == 1 OR b == 2 AND c == 3")
        lower = self.parse("a == 1 or b == 2 and c == 3")
        self.assertEqual(upper.op, lower.op)
        self.assertEqual(
            [type(o).__name__ for o in upper.operands],
            [type(o).__name__ for o in lower.operands],
        )

    def test_nothing_is_left_unread(self):
        # The actual symptom: a truncated parse looks like a valid narrower
        # rule rather than like an error.
        tree = self.parse("a == 1 AND b == 2 AND c == 3")
        self.assertEqual(len(tree.operands), 3)


class UnknownEscapesKeepTheirBackslash(unittest.TestCase):
    """`\\l` is not an escape, and dropping the backslash widens the rule.

    `endswith "\\lsass.exe"` became `endswith "lsass.exe"`, which stops
    requiring the path separator: `maliciouslsass.exe` then matches a rule
    written for `\\lsass.exe`. Windows paths are most of what these rules
    test, so this was the most common literal in the corpus.
    """

    def value(self, text: str):
        spec = DialectSpec(
            key="t", language="T", precedence=dict(C_LIKE_PRECEDENCE),
            operators={"==": "==", "and": "and"}, keywords=frozenset(),
        )
        tree = Parser(tokenize(f"a == {text}"), spec).parse_expression(0)
        return tree.right.value

    def test_an_unknown_escape_keeps_both_characters(self):
        self.assertEqual(self.value(r'"\lsass.exe"'), r"\lsass.exe")

    def test_a_known_escape_still_resolves(self):
        self.assertEqual(self.value(r'"a\nb"'), "a\nb")
        self.assertEqual(self.value(r'"a\tb"'), "a\tb")

    def test_an_escaped_quote_still_resolves(self):
        self.assertEqual(self.value(r'"say \"hi\""'), 'say "hi"')

    def test_an_escaped_backslash_collapses_to_one(self):
        self.assertEqual(self.value(r'"a\\b"'), r"a\b")

    def test_a_windows_path_survives_intact(self):
        self.assertEqual(
            self.value(r'"C:\Windows\System32\lsass.exe"'),
            r"C:\Windows\System32\lsass.exe",
        )


class AnnotationHeaders(unittest.TestCase):
    """The `meta:` of the dialects that have no `meta:`.

    KQL, AQL and EQL carry a condition and nothing else, so `ir.Annotations`
    had nowhere to go and five of the eight dialects rendered a rule's title,
    severity, author and ATT&CK mapping as NOTHING. A Sigma rule converted to
    KQL came out unnamed and unrated -- the most common conversion this tool
    will be asked for, and the one whose output a SOC cannot triage.
    """

    class Fake:
        title = "LSASS Access"
        description = "Detects credential dumping"
        severity = "high"
        author = "soc team"
        mitre_attack = (("credential-access", ("T1003.001",)),)
        references = ("https://example.com/a",)
        false_positives = ("Backup software",)

    class Empty:
        title = ""
        description = ""
        severity = ""
        author = ""
        mitre_attack = ()
        references = ()
        false_positives = ()

    def test_every_field_is_written(self):
        lines = render_annotation_header(self.Fake(), "//")
        joined = "\n".join(lines)
        for needle in ("LSASS Access", "credential dumping", "high",
                       "soc team", "T1003.001", "example.com",
                       "Backup software"):
            with self.subTest(field=needle):
                self.assertIn(needle, joined)

    def test_an_empty_annotation_writes_nothing(self):
        # Noise at the top of every rendered rule is what teaches an analyst
        # to skip the top of rendered rules.
        self.assertEqual(render_annotation_header(self.Empty(), "//"), [])

    def test_it_reads_back_exactly(self):
        text = "\n".join(render_annotation_header(self.Fake(), "//"))
        fields, rest = parse_annotation_header(text + "\n\nT | where a == 1", "//")
        self.assertEqual(fields["title"], "LSASS Access")
        self.assertEqual(fields["severity"], "high")
        self.assertEqual(fields["author"], "soc team")
        self.assertEqual(
            fields["mitre_attack"], (("credential-access", ("T1003.001",)),)
        )
        self.assertEqual(fields["references"], ("https://example.com/a",))
        self.assertEqual(fields["false_positives"], ("Backup software",))
        self.assertIn("where a == 1", rest)

    def test_the_body_is_returned_without_the_header(self):
        text = "// title: T\n\nT | where a == 1"
        _fields, rest = parse_annotation_header(text, "//")
        self.assertNotIn("title:", rest)

    def test_an_ordinary_comment_is_left_alone(self):
        # Swallowing it would delete the analyst's note; reading it as
        # metadata would put their prose in the rule's title.
        text = "// this is just a note\nT | where a == 1"
        fields, rest = parse_annotation_header(text, "//")
        self.assertEqual(fields, {})
        self.assertEqual(rest, text)

    def test_a_rule_with_no_comment_is_untouched(self):
        text = "T | where a == 1"
        fields, rest = parse_annotation_header(text, "//")
        self.assertEqual(fields, {})
        self.assertEqual(rest, text)

    def test_a_different_comment_prefix_works(self):
        # AQL uses `--`, not `//`.
        lines = render_annotation_header(self.Fake(), "--")
        self.assertTrue(all(l.startswith("-- ") for l in lines))
        fields, _rest = parse_annotation_header("\n".join(lines), "--")
        self.assertEqual(fields["title"], "LSASS Access")

    def test_a_newline_in_a_description_does_not_break_the_header(self):
        # One comment line per field, so an embedded newline would otherwise
        # produce a second line that is not a comment at all.
        class Multi(AnnotationHeaders.Empty):
            description = "line one\nline two"
        lines = render_annotation_header(Multi(), "//")
        self.assertEqual(len(lines), 1)
        self.assertIn("line one line two", lines[0])


if __name__ == "__main__":
    unittest.main()
