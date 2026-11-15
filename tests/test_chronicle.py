"""Google SecOps YARA-L 2.0.

`EqualsIsThreeDifferentThings` is the class this module exists for. In
`events:` the same `=` is equality, a regex test, or a variable BINDING
depending only on what sits to its right. A binding filters nothing; lowering
it as a comparison asks whether a field equals a column that does not exist,
which goes UNDECIDED and takes the whole conjunction with it. The rule then
matches nothing and says it is fine.

`TheCountIsNotAField` is second. `#e > 5` means "more than five events
matched", and the threshold is strict while `ir.Correlation.frequency` fires
at `>=` -- so it has to lower to six, not five.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from engine import dialects
from engine.dialects.chronicle import (
    DEFAULT_TABLE,
    DIALECT,
    FUNCTIONS,
    OUTCOME_FUNCTIONS,
    REGEX_DIALECT,
    lower_chronicle,
    parse_chronicle,
    render_chronicle,
)
from engine.ir import (
    Aggregate,
    Annotations,
    BoolOp,
    Comparison,
    Correlation,
    Emit,
    Expand,
    FieldRef,
    Filter,
    Literal,
    Read,
    Regex,
    Rule,
    render_expr,
)
from engine.pipeline import evaluate
from engine.values import Refusal

LSASS = r'''rule suspicious_lsass_access {
  meta:
    author = "soc"
    description = "LSASS access"
    severity = "HIGH"
    mitre_attack_tactic = "Credential Access"
  events:
    $e.metadata.event_type = "PROCESS_OPEN"
    $e.target.process.file.full_path = /lsass\.exe$/ nocase
    $e.principal.hostname = $host
  match:
    $host over 5m
  condition:
    $e and #e > 5
}'''

SIMPLE = r'''rule one_shot {
  events:
    $e.metadata.event_type = "PROCESS_OPEN"
  condition:
    $e
}'''


def lower(text: str) -> Rule:
    rule, _ = lower_chronicle(text)
    return rule


def first(rule: Rule, kind: type):
    return next(n for n in rule.pipeline if isinstance(n, kind))


def stages(rule: Rule) -> list[str]:
    return [type(n).__name__ for n in rule.pipeline]


def udm(n=1, host="H1", path=r"c:\windows\LSASS.exe", step=10, start=0,
        event_type="PROCESS_OPEN"):
    return [
        {
            "metadata": {"event_type": event_type,
                         "event_timestamp": start + i * step},
            "target": {"process": {"file": {"full_path": path}}},
            "principal": {"hostname": host},
        }
        for i in range(n)
    ]


class EqualsIsThreeDifferentThings(unittest.TestCase):
    """The defect this module exists to prevent."""

    def test_a_string_on_the_right_is_a_comparison(self):
        rule = lower(SIMPLE)
        condition = first(rule, Filter).condition
        self.assertIsInstance(condition, Comparison)
        self.assertEqual(condition.op, "==")

    def test_a_slash_pattern_on_the_right_is_a_regex_test(self):
        rule = lower(LSASS)
        parts = first(rule, Filter).condition.operands
        pattern = next(
            p for p in parts if isinstance(p.right, Regex)
        )
        self.assertEqual(pattern.op, "matches")
        self.assertEqual(pattern.right.dialect, REGEX_DIALECT)
        self.assertTrue(pattern.right.nocase)

    def test_a_bare_variable_on_the_right_is_a_binding_not_a_test(self):
        # `$e.principal.hostname = $host` declares `$host`. Lowered as a
        # comparison it asks whether the hostname equals a column called
        # `host`, which is absent: the comparison goes UNDECIDED and takes the
        # whole conjunction with it, so the rule matches nothing.
        rule = lower(LSASS)
        rendered = render_expr(first(rule, Filter).condition)
        self.assertNotIn("host ", rendered.replace("hostname", ""))
        self.assertEqual(
            len(first(rule, Filter).condition.operands), 2,
            "the binding line must not become a third predicate",
        )

    def test_the_binding_becomes_the_group_key_instead(self):
        rule = lower(LSASS)
        self.assertEqual(
            [k.full for k in first(rule, Correlation).group_by],
            ["principal.hostname"],
        )

    def test_the_rule_still_matches_once_the_binding_is_not_a_filter(self):
        # The end-to-end proof: read as a comparison this returns nothing.
        rule = lower(LSASS)
        self.assertTrue(evaluate(rule, udm(6)).matched)

    def test_a_function_call_on_the_left_round_trips(self):
        rule = lower(r'''rule x {
  events:
    strings.to_lower($e.principal.user.userid) = "admin"
  condition:
    $e
}''')
        text = render_chronicle(rule)
        self.assertIn("strings.to_lower", text)
        self.assertEqual(render_chronicle(lower(text)), text)

    def test_a_placeholder_on_the_left_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(r'''rule x {
  events:
    $host = $e.principal.hostname
  condition:
    $e
}''')
        self.assertEqual(
            caught.exception.code, "YARAL_PLACEHOLDER_ON_THE_LEFT"
        )

    def test_a_placeholder_compared_with_anything_but_equals_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(r'''rule x {
  events:
    $e.metadata.event_type = "A"
    $e.principal.port != $p
  condition:
    $e
}''')
        self.assertEqual(
            caught.exception.code, "YARAL_PLACEHOLDER_COMPARISON"
        )

    def test_the_same_variable_bound_twice_becomes_a_join_predicate(self):
        # Two fields bound to one variable means they must be equal. Keeping
        # only the first silently drops half the condition.
        rule = lower(r'''rule x {
  events:
    $e.metadata.event_type = "A"
    $e.principal.hostname = $h
    $e.target.hostname = $h
  condition:
    $e
}''')
        rendered = render_expr(first(rule, Filter).condition)
        self.assertIn("target.hostname == principal.hostname", rendered)

    def test_a_rule_that_only_binds_is_refused(self):
        # Every line a binding means no test at all, and a rule with no test
        # matches every event in the stream.
        with self.assertRaises(Refusal) as caught:
            lower(r'''rule x {
  events:
    $e.principal.hostname = $host
  match:
    $host over 5m
  condition:
    $e
}''')
        self.assertEqual(caught.exception.code, "YARAL_NO_PREDICATES")


class TheCountIsNotAField(unittest.TestCase):
    """`#e` is an event count, and `>` is strict."""

    def test_a_strict_threshold_lowers_to_one_higher(self):
        # `#e > 5` fires on the sixth event. `Correlation.frequency` fires at
        # `>=`, so copying the five across makes the rule fire one event early
        # -- an off-by-one that reads as a tuning problem for months.
        self.assertEqual(first(lower(LSASS), Correlation).frequency, 6)

    def test_an_inclusive_threshold_keeps_its_number(self):
        rule = lower(LSASS.replace("#e > 5", "#e >= 5"))
        self.assertEqual(first(rule, Correlation).frequency, 5)

    def test_the_off_by_one_is_visible_when_it_runs(self):
        rule = lower(LSASS)
        self.assertFalse(evaluate(rule, udm(5)).matched)
        self.assertTrue(evaluate(rule, udm(6)).matched)

    def test_it_comes_back_as_the_strict_form_it_came_from(self):
        rule = lower(LSASS)
        self.assertIn("#e > 5", render_chronicle(rule))

    def test_an_upper_bound_is_refused_rather_than_inverted(self):
        with self.assertRaises(Refusal) as caught:
            lower(LSASS.replace("#e > 5", "#e < 5"))
        self.assertEqual(caught.exception.code, "YARAL_THRESHOLD_DIRECTION")

    def test_a_threshold_without_match_is_refused(self):
        # A count with nothing to group on is "anywhere in the log", so a rule
        # written for one host fires on noise spread across the estate.
        with self.assertRaises(Refusal) as caught:
            lower(r'''rule x {
  events:
    $e.metadata.event_type = "A"
  condition:
    $e and #e > 5
}''')
        self.assertEqual(
            caught.exception.code, "YARAL_THRESHOLD_WITHOUT_MATCH"
        )

    def test_a_threshold_without_a_window_is_refused(self):
        # A threshold with no window counts over all time, firing on slow
        # background noise rather than on a burst.
        with self.assertRaises(Refusal) as caught:
            lower(r'''rule x {
  events:
    $e.metadata.event_type = "A"
    $e.principal.hostname = $host
  match:
    $host
  condition:
    $e and #e > 5
}''')
        self.assertEqual(
            caught.exception.code, "YARAL_THRESHOLD_WITHOUT_WINDOW"
        )

    def test_a_missing_condition_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(r'''rule x {
  events:
    $e.metadata.event_type = "A"
}''')
        self.assertEqual(caught.exception.code, "YARAL_NO_CONDITION")


class TheThresholdIsPerGroup(unittest.TestCase):
    """`match:` names what the count is grouped on."""

    def test_the_window_is_honoured(self):
        rule = lower(LSASS)
        self.assertTrue(evaluate(rule, udm(6, step=10)).matched)
        self.assertFalse(evaluate(rule, udm(6, step=4000)).matched)

    def test_events_on_different_hosts_do_not_add_up(self):
        # Six events, one per host. Ungrouped this is six and the rule fires;
        # grouped it is six groups of one and it must not.
        spread = []
        for index in range(6):
            spread.extend(udm(1, host=f"H{index}", start=index))
        self.assertFalse(evaluate(lower(LSASS), spread).matched)

    def test_one_host_crossing_the_threshold_still_fires_among_noise(self):
        sample = list(udm(6, host="TARGET"))
        for index in range(5):
            sample.extend(udm(1, host=f"OTHER{index}", start=index))
        self.assertTrue(evaluate(lower(LSASS), sample).matched)

    def test_the_window_is_measured_per_group_not_globally(self):
        # Three on one host inside the window and three on another outside it.
        # A global window would see six close together and fire.
        sample = udm(3, host="A", step=1, start=0)
        sample += udm(3, host="B", step=1, start=2)
        self.assertFalse(evaluate(lower(LSASS), sample).matched)


class MetaRoundTrips(unittest.TestCase):
    def test_the_annotations_are_read(self):
        rule = lower(LSASS)
        self.assertEqual(rule.annotations.author, "soc")
        self.assertEqual(rule.annotations.severity, "HIGH")
        self.assertEqual(rule.annotations.description, "LSASS access")
        self.assertEqual(rule.annotations.title, "suspicious_lsass_access")

    def test_the_attack_mapping_is_structured_not_a_string(self):
        rule = lower(LSASS)
        self.assertEqual(
            rule.annotations.mitre_attack, (("Credential Access", ()),)
        )

    def test_it_is_written_back_exactly_once(self):
        # Folded into Annotations AND kept in metadata, the tactic was emitted
        # twice and the rule grew a duplicate line on every round trip.
        text = render_chronicle(lower(LSASS))
        self.assertEqual(text.count("mitre_attack_tactic"), 1)

    def test_an_unknown_meta_key_is_kept_rather_than_dropped(self):
        rule = lower(LSASS.replace(
            'author = "soc"', 'author = "soc"\n    priority = "P1"'
        ))
        self.assertEqual(rule.metadata.get("chronicle.meta.priority"), "P1")
        self.assertIn('priority = "P1"', render_chronicle(rule))

    def test_a_meta_line_that_is_not_a_pair_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_chronicle(r'''rule x {
  meta:
    just_a_word
  events:
    $e.a = "1"
  condition:
    $e
}''')
        self.assertEqual(caught.exception.code, "YARAL_META_NOT_A_PAIR")


class RegexIsRe2AndExecutes(unittest.TestCase):
    def test_the_pattern_is_tagged_re2(self):
        rule = lower(LSASS)
        pattern = next(
            p.right for p in first(rule, Filter).condition.operands
            if isinstance(p.right, Regex)
        )
        self.assertEqual(pattern.dialect, REGEX_DIALECT)

    def test_it_actually_runs(self):
        # Unlike PCRE and Java, RE2 has no backreferences or lookaround, so a
        # pattern surviving the portable screen means the same thing here.
        rule = lower(SIMPLE.replace(
            '$e.metadata.event_type = "PROCESS_OPEN"',
            '$e.target.process.file.full_path = /lsass/ nocase',
        ))
        self.assertTrue(evaluate(rule, udm(1)).matched)
        self.assertFalse(
            evaluate(rule, udm(1, path="notepad.exe")).matched
        )

    def test_nocase_is_honoured(self):
        # Dropped, this stops matching the `LSASS.exe` the sample contains.
        rule = lower(SIMPLE.replace(
            '$e.metadata.event_type = "PROCESS_OPEN"',
            '$e.target.process.file.full_path = /lsass/ nocase',
        ))
        self.assertTrue(evaluate(rule, udm(1, path="C:/LSASS.EXE")).matched)

    def test_a_slash_inside_a_pattern_does_not_start_a_comment(self):
        # `//` inside a regex looked like a line comment, and everything after
        # it was stripped -- silently changing the predicate.
        rule = lower(r'''rule x {
  events:
    $e.principal.url = /https:\/\/evil/ nocase
  condition:
    $e
}''')
        pattern = first(rule, Filter).condition.right
        self.assertIn("evil", pattern.pattern)

    def test_a_comment_is_still_stripped(self):
        parsed = parse_chronicle(r'''rule x {
  // this is a comment
  events:
    $e.metadata.event_type = "A"
  condition:
    $e
}''')
        self.assertEqual(parsed.events, ('$e.metadata.event_type = "A"',))


class Outcomes(unittest.TestCase):
    OUTCOME = r'''rule spray {
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.principal.hostname = $host
  match:
    $host over 10m
  outcome:
    $users = count_distinct($e.principal.user.userid)
  condition:
    $e
}'''

    def test_it_becomes_an_aggregate_keyed_on_the_match_variables(self):
        rule = lower(self.OUTCOME)
        aggregate = first(rule, Aggregate)
        self.assertEqual(aggregate.measures[0].function, "dcount")
        self.assertEqual([k.full for k in aggregate.keys],
                         ["principal.hostname"])

    def test_a_distinct_count_counts_distinctly(self):
        rule = lower(self.OUTCOME)
        sample = [
            {"metadata": {"event_type": "USER_LOGIN", "event_timestamp": i},
             "principal": {"hostname": "H1", "user": {"userid": f"u{i}"}}}
            for i in range(4)
        ]
        result = evaluate(rule, sample)
        self.assertEqual(result.rows[0].values["users"], Decimal(4))

    def test_every_outcome_function_lowers(self):
        for name in OUTCOME_FUNCTIONS:
            with self.subTest(outcome=name):
                rule = lower(self.OUTCOME.replace(
                    "count_distinct($e.principal.user.userid)",
                    f"{name}($e.principal.user.userid)",
                ))
                self.assertEqual(len(first(rule, Aggregate).measures), 1)

    def test_an_unknown_outcome_function_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(self.OUTCOME.replace("count_distinct", "frobnicate"))
        self.assertEqual(
            caught.exception.code, "YARAL_OUTCOME_FUNCTION_UNKNOWN"
        )

    def test_a_plain_value_in_outcome_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(self.OUTCOME.replace(
                "count_distinct($e.principal.user.userid)", '"high"'
            ))
        self.assertEqual(
            caught.exception.code, "YARAL_OUTCOME_NOT_AN_AGGREGATE"
        )

    def test_it_round_trips(self):
        rule = lower(self.OUTCOME)
        text = render_chronicle(rule)
        self.assertIn("outcome:", text)
        self.assertIn("count_distinct", text)
        again = lower(text)
        self.assertEqual(render_chronicle(again), text)


class Functions(unittest.TestCase):
    def test_a_cidr_test_lowers_and_runs(self):
        rule = lower(r'''rule x {
  events:
    $e.metadata.event_type = "A"
    net.ip_in_range_cidr($e.principal.ip, "10.0.0.0/8")
  condition:
    $e
}''')
        sample = {"metadata": {"event_type": "A"},
                  "principal": {"ip": "10.1.2.3"}}
        self.assertTrue(evaluate(rule, [sample]).matched)
        outside = {"metadata": {"event_type": "A"},
                   "principal": {"ip": "192.168.0.1"}}
        self.assertFalse(evaluate(rule, [outside]).matched)

    def test_a_substring_test_lowers_and_round_trips(self):
        rule = lower(r'''rule x {
  events:
    strings.contains($e.principal.hostname, "dc-")
  condition:
    $e
}''')
        self.assertEqual(first(rule, Filter).condition.op, "contains")
        self.assertIn("strings.contains", render_chronicle(rule))

    def test_an_unknown_namespaced_function_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(r'''rule x {
  events:
    mystery.thing($e.a, "b")
  condition:
    $e
}''')
        self.assertEqual(caught.exception.code, "YARAL_FUNCTION_UNKNOWN")

    def test_every_mapped_function_has_a_name(self):
        for yaral, engine in FUNCTIONS.items():
            with self.subTest(function=yaral):
                self.assertTrue(engine)


class Parsing(unittest.TestCase):
    def test_the_sections_are_split(self):
        parsed = parse_chronicle(LSASS)
        self.assertEqual(parsed.name, "suspicious_lsass_access")
        self.assertEqual(len(parsed.events), 3)
        self.assertEqual(parsed.match, "$host over 5m")
        self.assertEqual(parsed.condition, "$e and #e > 5")

    def test_text_with_no_rule_block_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_chronicle("events:\n  $e.a = 1")
        self.assertEqual(caught.exception.code, "YARAL_NO_RULE_BLOCK")

    def test_two_rules_are_refused_rather_than_silently_halved(self):
        with self.assertRaises(Refusal) as caught:
            parse_chronicle(SIMPLE + "\n" + SIMPLE.replace("one_shot", "two"))
        self.assertEqual(caught.exception.code, "YARAL_MULTIPLE_RULES")

    def test_a_repeated_section_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_chronicle(r'''rule x {
  events:
    $e.a = "1"
  events:
    $e.b = "2"
  condition:
    $e
}''')
        self.assertEqual(caught.exception.code, "YARAL_SECTION_REPEATED")

    def test_empty_text_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_chronicle("   ")
        self.assertEqual(caught.exception.code, "YARAL_EMPTY")

    def test_an_unquoted_value_is_refused(self):
        # An unquoted word is not a value in YARA-L, and reading it as one
        # compares against text the rule never wrote.
        with self.assertRaises(Refusal) as caught:
            lower(r'''rule x {
  events:
    $e.metadata.event_type = PROCESS_OPEN
  condition:
    $e
}''')
        self.assertEqual(caught.exception.code, "YARAL_VALUE_UNREADABLE")

    def test_a_match_on_an_unbound_variable_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            lower(r'''rule x {
  events:
    $e.metadata.event_type = "A"
  match:
    $nobody over 5m
  condition:
    $e and #e > 2
}''')
        self.assertEqual(caught.exception.code, "YARAL_MATCH_UNBOUND")

    def test_two_event_variables_no_shared_key_are_refused(self):
        # A join tests one stream against another. Two variables related by
        # nothing -- no shared placeholder, no `match:` -- would have to be
        # joined on "any event", which is not the rule the author wrote.
        # Flattening them instead tests both sets against the SAME event.
        with self.assertRaises(Refusal) as caught:
            lower(r'''rule x {
  events:
    $e1.metadata.event_type = "A"
    $e2.metadata.event_type = "B"
  condition:
    $e1 and $e2
}''')
        self.assertEqual(caught.exception.code, "YARAL_JOIN_WITHOUT_MATCH")

    def test_two_event_variables_on_a_shared_placeholder_become_a_join(self):
        # The common real shape: both streams bind `$host` to the same UDM
        # path. That IS the join condition, and it must not be flattened.
        rule, notes = lower_chronicle(r'''rule x {
  events:
    $lsass.metadata.event_type = "PROCESS_ACCESS"
    $lsass.principal.hostname = $host
    $login.metadata.event_type = "USER_LOGIN"
    $login.principal.hostname = $host
  condition:
    $lsass and $login
}''')
        stages = [type(node).__name__ for node in rule.pipeline]
        self.assertIn("Join", stages)
        self.assertEqual(len(rule.bindings), 2)
        join = next(n for n in rule.pipeline if type(n).__name__ == "Join")
        self.assertEqual(len(join.on), 1)
        self.assertEqual(join.on[0][0].full, "principal.hostname")
        self.assertTrue(
            any(n.code == "YARAL_EVENT_ORDER_UNCONSTRAINED" for n in notes)
        )

    def test_a_joined_rule_round_trips(self):
        rule, _ = lower_chronicle(r'''rule x {
  events:
    $lsass.metadata.event_type = "PROCESS_ACCESS"
    $lsass.principal.hostname = $host
    $login.metadata.event_type = "USER_LOGIN"
    $login.principal.hostname = $host
  condition:
    $lsass and $login
}''')
        text = render_chronicle(rule)
        again = lower(text)
        self.assertEqual(
            [type(n).__name__ for n in again.pipeline],
            [type(n).__name__ for n in rule.pipeline],
        )
        self.assertEqual(len(again.bindings), 2)


class Rendering(unittest.TestCase):
    def setUp(self):
        self.rule = lower(LSASS)
        self.text = render_chronicle(self.rule)

    def test_the_sections_come_back_in_order(self):
        order = [
            line.strip().rstrip(":")
            for line in self.text.splitlines()
            if line.strip().endswith(":") and not line.strip().startswith("$")
        ]
        self.assertEqual(order, ["meta", "events", "match", "condition"])

    def test_rendering_is_stable_across_two_round_trips(self):
        again = lower(self.text)
        self.assertEqual(render_chronicle(again), self.text)

    def test_the_analysts_own_variable_name_survives(self):
        # Derived from the field it would come back as `$hostname`, which
        # makes a save look like an edit.
        self.assertIn("$host", self.text)
        self.assertNotIn("$hostname", self.text)

    def test_the_binding_line_is_re_declared_so_match_resolves(self):
        # `match:` can only group on a variable something bound, so dropping
        # the binding produces a rule SecOps rejects.
        self.assertIn("$e.principal.hostname = $host", self.text)

    def test_a_rule_with_no_predicate_is_refused(self):
        rule = Rule(
            rule_id="r",
            pipeline=(Read(id="s", table=DEFAULT_TABLE), Emit(id="o")),
            annotations=Annotations(title="x"),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_chronicle(rule)
        self.assertEqual(caught.exception.code, "YARAL_RENDER_NO_EVENTS")

    def test_an_unrenderable_stage_is_refused_rather_than_dropped(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table=DEFAULT_TABLE),
                Filter(id="f", condition=Comparison(
                    "==", FieldRef(name="a"), Literal(1)
                )),
                Expand(id="e", field=FieldRef(name="a"), into="b"),
                Emit(id="o"),
            ),
            annotations=Annotations(title="x"),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_chronicle(rule)
        self.assertEqual(caught.exception.code, "YARAL_RENDER_STAGE")

    def test_a_foreign_regex_dialect_is_refused(self):
        rule = Rule(
            rule_id="r",
            pipeline=(
                Read(id="s", table=DEFAULT_TABLE),
                Filter(id="f", condition=Comparison(
                    "matches", FieldRef(name="a"), Regex("x", "pcre")
                )),
                Emit(id="o"),
            ),
            annotations=Annotations(title="x"),
            metadata={"dialect": DIALECT},
        )
        with self.assertRaises(Refusal) as caught:
            render_chronicle(rule)
        self.assertEqual(
            caught.exception.code, "YARAL_RENDER_REGEX_DIALECT"
        )

    def test_a_conjunction_becomes_several_lines(self):
        # `events:` lines are implicitly ANDed, so one line per conjunct is
        # the idiomatic form.
        self.assertIn('$e.metadata.event_type = "PROCESS_OPEN"', self.text)
        self.assertIn("full_path = /lsass", self.text)


class RegistryIntegration(unittest.TestCase):
    def test_it_is_registered_and_ready(self):
        entry = dialects.get("chronicle")
        self.assertTrue(entry.can_parse)
        self.assertTrue(entry.can_render)

    def test_it_round_trips_through_the_registry(self):
        rule, _ = dialects.lower("chronicle", LSASS)
        text, notes = dialects.render("chronicle", rule)
        self.assertEqual(notes, [])
        again, _ = dialects.lower("chronicle", text)
        self.assertEqual(stages(again), stages(rule))

    def test_a_simple_rule_crosses_into_sigma(self):
        rule, _ = dialects.lower("chronicle", SIMPLE)
        text, _ = dialects.render("sigma", rule)
        self.assertIn("detection:", text)


class TheParserReadsWhatTheRendererWrites(unittest.TestCase):
    """Four shapes the renderer emitted and the parser refused.

    Each dialect was tested in isolation -- parse, render, compare, all within
    one dialect -- so output produced from a FOREIGN rule was never fed back
    in. `render_chronicle` wrote disjunctions, membership tests, `count(1)`
    and numeric rule names that `lower_chronicle` all rejected.
    """

    def roundtrip(self, source_dialect: str, text: str) -> str:
        rule, _ = dialects.lower(source_dialect, text)
        out, _ = dialects.render("chronicle", rule)
        dialects.lower("chronicle", out)  # must not raise
        return out

    def test_a_disjunction_can_be_read_back(self):
        # `($e.A = 1 or $e.B = 2)` went to `_split_operator`, which found no
        # top-level operator inside the brackets and refused the whole line.
        out = self.roundtrip("sentinel", "T | where A == 1 or B == 2")
        self.assertIn(" or ", out)

    def test_a_disjunction_keeps_its_meaning(self):
        rule, _ = dialects.lower("sentinel", "T | where A == 1 or B == 2")
        out, _ = dialects.render("chronicle", rule)
        back, _ = dialects.lower("chronicle", out)
        condition = first(back, Filter).condition
        self.assertIsInstance(condition, BoolOp)
        self.assertEqual(condition.op, "or")

    def test_a_nested_group_can_be_read_back(self):
        self.roundtrip(
            "sentinel", 'T | where C == "x" and (A == 1 or B == 2)'
        )

    def test_a_membership_test_can_be_read_back(self):
        # `$e.A in [1, 2, 3]` had no recognisable operator, because ` in ` was
        # missing from the operator table.
        out = self.roundtrip("sentinel", "T | where A in (1, 2, 3)")
        self.assertIn(" in [", out)

    def test_a_membership_test_keeps_its_meaning(self):
        rule, _ = dialects.lower("sentinel", "T | where A in (1, 2, 3)")
        out, _ = dialects.render("chronicle", rule)
        back, _ = dialects.lower("chronicle", out)
        self.assertEqual(first(back, Filter).condition.op, "in")

    def test_a_field_containing_in_is_not_split_on_it(self):
        # ` in ` is spelled with spaces for exactly this reason: a field
        # called `instance` or `b.inbound` must not split.
        rule = lower(r'''rule x {
  events:
    $e.principal.instance = "a"
  condition:
    $e
}''')
        self.assertEqual(
            first(rule, Filter).condition.left.full, "principal.instance"
        )

    def test_a_count_with_no_field_is_refused_not_emitted(self):
        # It used to emit `count(1)`, and `_lower_outcome` refuses `1` with
        # "`1` is not a UDM field". The renderer produced a rule its own
        # parser rejects.
        source, _ = dialects.lower(
            "sentinel", "T | where A == 1 | summarize H=count() by B"
        )
        with self.assertRaises(Refusal) as caught:
            dialects.render("chronicle", source)
        self.assertEqual(
            caught.exception.code, "YARAL_RENDER_COUNT_WITHOUT_A_FIELD"
        )

    def test_that_refusal_names_the_spelling_it_would_need(self):
        source, _ = dialects.lower(
            "sentinel", "T | where A == 1 | summarize H=count() by B"
        )
        with self.assertRaises(Refusal) as caught:
            dialects.render("chronicle", source)
        self.assertIn("#e", caught.exception.message)

    def test_a_count_over_a_field_still_renders(self):
        # The refusal must be narrow: counting a FIELD is valid YARA-L.
        source, _ = dialects.lower(
            "splunk",
            "index=a | stats dc(user) as Users by src | where Users > 2",
        )
        out, _ = dialects.render("chronicle", source)
        self.assertIn("count_distinct", out)
        dialects.lower("chronicle", out)

    def test_a_numeric_rule_name_becomes_an_identifier(self):
        # A Wazuh rule with id `100` rendered as `rule 100 {`, and
        # `parse_chronicle` then reported "this text has no `rule <name> {`
        # block" -- because YARA-L names must start with a letter.
        out = self.roundtrip(
            "wazuh",
            '<group name="g,"><rule id="100" level="5">'
            '<field name="EventID">4624</field>'
            "<description>d</description></rule></group>",
        )
        self.assertIn("rule rule_100 {", out)

    def test_the_original_id_stays_readable(self):
        out = self.roundtrip(
            "wazuh",
            '<group name="g,"><rule id="100" level="5">'
            '<field name="EventID">4624</field>'
            "<description>d</description></rule></group>",
        )
        self.assertIn("100", out)

    def test_an_already_valid_name_is_untouched(self):
        out, _ = dialects.render("chronicle", lower(LSASS))
        self.assertIn("rule suspicious_lsass_access {", out)


if __name__ == "__main__":
    unittest.main()
