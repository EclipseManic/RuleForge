"""Log samples to a proposed rule.

This logic lived entirely in `web/static/app.js`, so none of it was tested --
and the decision it makes, which fields become the detection, is the decision
that determines whether the output is a rule or a rule that matches
everything. `NestedEventsAreFlattened` and `TheFlagsMeanWhatTheySay` cover the
two defects that survived in the browser because nothing could see them.
"""

from __future__ import annotations

import unittest
from decimal import Decimal

from engine.ir import Aggregate, Comparison, Filter, Read, render_expr
from engine.pipeline import evaluate
from engine.synthesize import (
    FORMATS,
    MIN_SAMPLES,
    VOLATILE_NAME,
    Options,
    analyse,
    flatten,
    parse_events,
    propose,
)
from engine.values import Refusal

SYSMON = [
    {
        "event": {"category": "process", "id": "aaaa1111"},
        "process": {"name": "procdump.exe", "pid": 1100},
        "host": {"name": "WS-01"},
        "@timestamp": "2026-01-01T10:00:00Z",
    },
    {
        "event": {"category": "process", "id": "bbbb2222"},
        "process": {"name": "procdump.exe", "pid": 2200},
        "host": {"name": "WS-02"},
        "@timestamp": "2026-01-01T10:00:04Z",
    },
]

VARYING = [
    {"cat": "process", "name": "a.exe"},
    {"cat": "process", "name": "b.exe"},
]


def pinned(reports):
    return [r.name for r in reports if r.include]


def predicates(rule):
    return [
        render_expr(n.condition) for n in rule.pipeline
        if isinstance(n, Filter)
    ]


class NestedEventsAreFlattened(unittest.TestCase):
    """Every modern log shape is nested, so this was the common case.

    The browser walked only `Object.keys(event)`, so `{"process": {"name":
    "x"}}` produced one field called `process` whose value was a whole JSON
    object -- and the generated predicate compared an object to an object,
    which no engine can evaluate. ECS, UDM and Sysmon JSON are all nested.
    """

    def test_a_nested_object_becomes_dotted_paths(self):
        self.assertEqual(
            flatten({"process": {"name": "x", "pid": 1}}),
            {"process.name": "x", "process.pid": 1},
        )

    def test_it_goes_more_than_one_level_deep(self):
        self.assertEqual(
            flatten({"a": {"b": {"c": 1}}}), {"a.b.c": 1}
        )

    def test_a_flat_event_is_unchanged(self):
        self.assertEqual(flatten({"a": 1, "b": "x"}), {"a": 1, "b": "x"})

    def test_a_list_is_left_whole_rather_than_indexed(self):
        # `args[0]` is a position, not a field. Pinning it makes the rule
        # depend on argument order, which the next agent version may change.
        self.assertEqual(flatten({"args": ["a", "b"]}), {"args": ["a", "b"]})

    def test_the_dotted_name_is_a_field_the_model_understands(self):
        reports = analyse(SYSMON)
        self.assertIn("process.name", pinned(reports))
        rule, _reports, _diags = propose(SYSMON)
        self.assertIn('process.name == "procdump.exe"', predicates(rule))

    def test_the_proposed_rule_actually_matches_its_own_samples(self):
        # The end-to-end property the object-comparison bug destroyed.
        rule, _reports, _diags = propose(SYSMON)
        self.assertTrue(evaluate(rule, SYSMON).matched)

    def test_an_empty_nested_object_is_not_a_predicate(self):
        events = [{"a": {}, "k": "x"}, {"a": {}, "k": "x"}]
        report = next(r for r in analyse(events) if r.name == "a")
        self.assertFalse(report.include)


class TheFlagsMeanWhatTheySay(unittest.TestCase):
    """`skip_volatile` could not be turned off.

    The browser ended its decision with an UNCONDITIONAL
    `if (include && distinct > 1) include = false`, so a field that differed
    between samples was always dropped -- while the error message told the
    analyst to untick the filter "to decide yourself", which did nothing.
    """

    def test_on_by_default_a_varying_field_is_dropped(self):
        self.assertEqual(pinned(analyse(VARYING)), ["cat"])

    def test_turning_it_off_keeps_the_varying_field(self):
        self.assertEqual(
            pinned(analyse(VARYING, Options(skip_volatile=False))),
            ["cat", "name"],
        )

    def test_keeping_it_is_reported_as_a_problem(self):
        # Pinned to the first sample, the rule matches that one value rather
        # than the behaviour the samples share.
        _rule, _reports, diags = propose(
            VARYING, Options(skip_volatile=False)
        )
        note = next(
            d for d in diags if d.code == "SYNTH_PINNED_A_VARYING_FIELD"
        )
        self.assertEqual(note.severity, "problem")
        self.assertIn("name", note.message)

    def test_the_clean_path_raises_no_problem(self):
        # A warning that fires on good input gets dismissed on bad input.
        _rule, _reports, diags = propose(SYSMON)
        self.assertEqual(
            [d.code for d in diags if d.severity == "problem"], []
        )

    def test_skip_timestamps_can_also_be_turned_off(self):
        events = [{"k": "x", "ts": "2026-01-01T10:00:00Z"},
                  {"k": "x", "ts": "2026-01-01T10:00:00Z"}]
        self.assertEqual(pinned(analyse(events)), ["k"])
        self.assertEqual(
            pinned(analyse(events, Options(skip_timestamps=False))),
            ["k", "ts"],
        )

    def test_keeping_a_volatile_field_is_reported(self):
        events = [{"k": "x", "ts": "2026-01-01T10:00:00Z"},
                  {"k": "x", "ts": "2026-01-01T10:00:00Z"}]
        _rule, _reports, diags = propose(
            events, Options(skip_timestamps=False)
        )
        self.assertIn(
            "SYNTH_PINNED_A_VOLATILE_FIELD", [d.code for d in diags]
        )

    def test_a_partial_field_is_reported_when_kept(self):
        # Requiring it means the rule cannot match the samples it is missing
        # from -- including some of the ones pasted here.
        events = [{"k": "x", "extra": "y"}, {"k": "x"}]
        _rule, _reports, diags = propose(
            events, Options(skip_volatile=False)
        )
        self.assertIn(
            "SYNTH_PINNED_A_PARTIAL_FIELD", [d.code for d in diags]
        )


class SomeValuesCannotBeADetection(unittest.TestCase):
    """Refused whatever the flags say, because no setting makes them work."""

    def ask(self, value):
        events = [{"a": value, "k": "x"}, {"a": value, "k": "x"}]
        reports = analyse(
            events, Options(skip_volatile=False, skip_timestamps=False)
        )
        return next(r for r in reports if r.name == "a")

    def test_a_null_is_refused(self):
        # `== null` is undecidable by design, so a rule pinned to one can
        # never return an answer at all.
        report = self.ask(None)
        self.assertFalse(report.include)
        self.assertIn("undecidable", " ".join(report.reasons))

    def test_an_empty_string_is_refused(self):
        # An empty string is not the same question as an absent field.
        self.assertFalse(self.ask("").include)

    def test_a_list_value_is_refused(self):
        self.assertFalse(self.ask([1, 2]).include)

    def test_a_dict_value_never_reaches_this_check(self):
        # It is FLATTENED first, so there is no field `a` to judge -- there is
        # a usable `a.x` instead. That is the whole point of flattening: the
        # browser kept `a` as an object and compared object to object.
        events = [{"a": {"x": 1}, "k": "y"}, {"a": {"x": 1}, "k": "y"}]
        names = [r.name for r in analyse(events)]
        self.assertNotIn("a", names)
        self.assertIn("a.x", names)
        self.assertIn("a.x", pinned(analyse(events)))

    def test_a_zero_is_not_refused(self):
        # Zero is a value. Treating it as empty would drop `EventID=0` and
        # `failures=0`, which are real predicates.
        self.assertTrue(self.ask(Decimal(0)).include)

    def test_false_is_not_refused(self):
        self.assertTrue(self.ask(False).include)


class VolatilityHeuristics(unittest.TestCase):
    def test_names_that_read_as_per_event_are_caught(self):
        for name in ("timestamp", "event_id", "session_id", "sha256",
                     "request.id", "trace-id", "pid", "duration_ms"):
            with self.subTest(name=name):
                self.assertTrue(VOLATILE_NAME.search(name))

    def test_ordinary_field_names_are_not_caught(self):
        # A heuristic that fires on `process.name` or `hostname` drops the
        # fields the detection is made of.
        for name in ("process.name", "hostname", "user", "action",
                     "image", "command_line", "category"):
            with self.subTest(name=name):
                self.assertFalse(VOLATILE_NAME.search(name))

    def test_values_that_look_per_event_are_caught(self):
        shapes = {
            "iso": "2026-01-01T10:00:00Z",
            "epoch": "1791687349",
            "uuid": "123e4567-e89b-12d3-a456-426614174000",
            "sha256": "a" * 64,
            "md5": "b" * 32,
        }
        for label, value in shapes.items():
            with self.subTest(shape=label):
                events = [{"f": value, "k": "x"}, {"f": value, "k": "x"}]
                report = next(r for r in analyse(events) if r.name == "f")
                self.assertFalse(report.include, label)

    def test_an_ordinary_value_is_not_caught_by_shape(self):
        events = [{"f": "procdump.exe", "k": "x"},
                  {"f": "procdump.exe", "k": "x"}]
        report = next(r for r in analyse(events) if r.name == "f")
        self.assertTrue(report.include)


class Refusals(unittest.TestCase):
    def test_one_sample_is_refused(self):
        # Every field looks constant, so the proposal pins all of them and the
        # rule matches exactly the line pasted. The analyst then has a rule
        # that passes its own test and never fires again.
        with self.assertRaises(Refusal) as caught:
            analyse([{"a": 1}])
        self.assertEqual(caught.exception.code, "SYNTH_TOO_FEW_SAMPLES")

    def test_the_floor_is_stated_as_data(self):
        self.assertEqual(MIN_SAMPLES, 2)

    def test_samples_with_nothing_stable_are_refused(self):
        events = [{"ts": "2026-01-01T10:00:00Z", "id": "a"},
                  {"ts": "2026-01-01T10:00:05Z", "id": "b"}]
        with self.assertRaises(Refusal) as caught:
            propose(events)
        self.assertEqual(caught.exception.code, "SYNTH_NO_STABLE_FIELDS")

    def test_that_refusal_names_what_it_dropped(self):
        # "Nothing was stable" sends the analyst back to the paste box with no
        # idea which field to look at.
        events = [{"ts": "2026-01-01T10:00:00Z"},
                  {"ts": "2026-01-01T10:00:05Z"}]
        with self.assertRaises(Refusal) as caught:
            propose(events)
        self.assertIn("ts", caught.exception.message)

    def test_a_threshold_of_one_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            propose(SYSMON, Options(threshold=True, frequency=1))
        self.assertEqual(
            caught.exception.code, "SYNTH_THRESHOLD_NOT_A_THRESHOLD"
        )

    def test_a_window_of_zero_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            propose(SYSMON, Options(threshold=True, window_seconds=0))
        self.assertEqual(caught.exception.code, "SYNTH_WINDOW_NOT_POSITIVE")


class TheThresholdIsStatedNotImplied(unittest.TestCase):
    """A count and a window are invented here, not found in the data."""

    def test_the_numbers_are_parameters(self):
        rule, _reports, _diags = propose(
            SYSMON, Options(threshold=True, group_by=("host.name",),
                            frequency=9, window_seconds=600)
        )
        aggregate = next(
            n for n in rule.pipeline if isinstance(n, Aggregate)
        )
        self.assertEqual(aggregate.window.size.seconds, Decimal(600))
        threshold = [n for n in rule.pipeline if isinstance(n, Filter)][-1]
        self.assertEqual(threshold.condition.right.value, Decimal(9))

    def test_the_invention_is_disclosed(self):
        _rule, _reports, diags = propose(
            SYSMON, Options(threshold=True, group_by=("host.name",))
        )
        note = next(
            d for d in diags if d.code == "SYNTH_THRESHOLD_INVENTED"
        )
        self.assertIn("5", note.message)
        self.assertIn("300", note.message)

    def test_it_is_also_in_the_rules_own_description(self):
        # The diagnostics are not saved with the rule; the description is.
        rule, _reports, _diags = propose(
            SYSMON, Options(threshold=True, group_by=("host.name",))
        )
        self.assertIn("chosen by the generator", rule.annotations.description)

    def test_a_missing_group_key_is_a_reported_guess(self):
        # A count grouped on nothing counts across the whole estate, so a rule
        # meant for "five from one host" fires on ordinary background noise.
        _rule, _reports, diags = propose(SYSMON, Options(threshold=True))
        self.assertIn("SYNTH_GROUP_KEY_ASSUMED", [d.code for d in diags])

    def test_no_threshold_by_default(self):
        # A generator whose defaults produce the widest rule produces wide
        # rules.
        rule, _reports, _diags = propose(SYSMON)
        self.assertEqual(
            [n for n in rule.pipeline if isinstance(n, Aggregate)], []
        )


class TheProposalSaysItIsAProposal(unittest.TestCase):
    def test_every_run_carries_the_hypothesis_caveat(self):
        _rule, _reports, diags = propose(SYSMON)
        self.assertIn("SYNTH_IS_A_HYPOTHESIS", [d.code for d in diags])

    def test_the_rule_itself_says_it_was_generated(self):
        rule, _reports, _diags = propose(SYSMON)
        self.assertIn("not authored", rule.annotations.description)
        self.assertIn("process.name", rule.annotations.description)

    def test_the_sample_count_is_recorded(self):
        rule, _reports, _diags = propose(SYSMON)
        self.assertEqual(rule.metadata["synthesize.samples"], "2")

    def test_the_report_comes_back_with_the_rule(self):
        # A generated rule without the reasoning behind it is a rule the
        # analyst has to reverse-engineer before they can trust it.
        _rule, reports, _diags = propose(SYSMON)
        self.assertTrue(reports)
        skipped = [r for r in reports if not r.include]
        self.assertTrue(all(r.reasons for r in skipped))

    def test_the_proposed_rule_is_valid_and_renderable(self):
        from engine import dialects

        rule, _reports, _diags = propose(SYSMON)
        text, _notes = dialects.render("sentinel", rule)
        self.assertIn("where", text)

    def test_the_proposed_rule_survives_the_codec(self):
        # The GUI and the history store both go through it, so a rule that
        # proposes but will not encode is a rule the tool cannot save.
        from engine.codec import rule_from_dict, rule_to_dict

        rule, _reports, _diags = propose(SYSMON)
        self.assertEqual(rule_from_dict(rule_to_dict(rule)), rule)


class Parsers(unittest.TestCase):
    def test_jsonl(self):
        self.assertEqual(
            parse_events('{"a":1}\n{"a":2}', "jsonl"), [{"a": 1}, {"a": 2}]
        )

    def test_json_array(self):
        self.assertEqual(
            parse_events('[{"a":1},{"a":2}]', "json"), [{"a": 1}, {"a": 2}]
        )

    def test_key_value(self):
        events = parse_events('a=1 b="two words"\na=2 b=x', "kv")
        self.assertEqual(events[0]["b"], "two words")
        self.assertEqual(events[0]["a"], Decimal(1))

    def test_a_number_becomes_a_decimal(self):
        # Left as text, `EventCode=4625` compares as a string against a rule
        # written with an integer.
        events = parse_events("EventCode=4625\nEventCode=4625", "kv")
        self.assertEqual(events[0]["EventCode"], Decimal(4625))

    def test_syslog_drops_the_header(self):
        # Otherwise the priority, timestamp and host become three volatile
        # fields and crowd out the real ones.
        events = parse_events(
            "<34>Jan  1 10:00:00 host app: user=bob action=login\n"
            "<34>Jan  1 10:00:01 host app: user=sue action=login",
            "syslog",
        )
        self.assertEqual(sorted(events[0]), ["action", "user"])

    def test_every_declared_format_parses_something(self):
        samples = {
            "json": '[{"a":1},{"a":2}]',
            "jsonl": '{"a":1}\n{"a":2}',
            "kv": "a=1\na=2",
            "syslog": "host app: a=1\nhost app: a=2",
        }
        self.assertEqual(sorted(samples), sorted(FORMATS))
        for fmt, text in samples.items():
            with self.subTest(format=fmt):
                self.assertEqual(len(parse_events(text, fmt)), 2)

    def test_an_unknown_format_is_refused_by_name(self):
        with self.assertRaises(Refusal) as caught:
            parse_events("a,b\n1,2", "csv")
        self.assertEqual(caught.exception.code, "SYNTH_FORMAT_UNKNOWN")

    def test_invalid_json_names_the_position(self):
        # "Could not parse the samples" sends an analyst scanning two hundred
        # lines by eye.
        with self.assertRaises(Refusal) as caught:
            parse_events("{nope", "json")
        self.assertEqual(caught.exception.code, "SYNTH_JSON_INVALID")
        self.assertIn("line", caught.exception.message)

    def test_a_single_json_object_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_events('{"a":1}', "json")
        self.assertEqual(caught.exception.code, "SYNTH_JSON_NOT_A_LIST")

    def test_a_bad_jsonl_line_names_the_line(self):
        with self.assertRaises(Refusal) as caught:
            parse_events('{"a":1}\nnope\n{"a":2}', "jsonl")
        self.assertEqual(caught.exception.code, "SYNTH_JSONL_INVALID")
        self.assertIn("line 2", caught.exception.message)

    def test_a_bad_line_is_refused_rather_than_skipped(self):
        # Skipping it would change every other field's presence count, and so
        # change which fields the rule pins.
        with self.assertRaises(Refusal):
            parse_events('{"a":1}\nnope', "jsonl")

    def test_a_line_with_no_pairs_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_events("just prose\nmore prose", "kv")
        self.assertEqual(caught.exception.code, "SYNTH_NO_FIELDS_ON_LINE")

    def test_empty_text_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_events("   ", "jsonl")
        self.assertEqual(caught.exception.code, "SYNTH_NO_SAMPLES")

    def test_a_non_object_sample_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            parse_events('[{"a":1}, "just a string"]', "json")
        self.assertEqual(
            caught.exception.code, "SYNTH_SAMPLE_NOT_AN_OBJECT"
        )


if __name__ == "__main__":
    unittest.main()
