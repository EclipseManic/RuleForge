"""The local HTTP API.

Two layers, tested separately: `Api` is the handlers with no HTTP in them, and
`RuleForgeHandler` is routing and transport. The first set of tests drives `Api`
directly because that is where the behaviour is; the second opens a real socket,
because routing, path traversal and body limits only exist at that layer and a
test that skips them is testing nothing an attacker would try.
"""

from __future__ import annotations

import json
import pathlib
import threading
import unittest
import urllib.error
import urllib.request
from decimal import Decimal

from engine.codec import rule_to_dict
from engine.dialects.kql import lower_kql
from engine.store import RuleStore
from engine.values import Refusal
from web import api as api_module
from web.api import (
    MAX_BODY_BYTES,
    MAX_EVENTS,
    Api,
    _display,
    build_server,
)

from . import planned_dialect

USER_RULE = """
let LSASSAccess =
SecurityEvent
| where EventID == 10
| where TargetImage endswith @"\\lsass.exe"
| project LSASSTime=TimeGenerated, Computer, Account, SourceImage, SourceIp;

let LateralMovement =
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| project LoginTime=TimeGenerated, Computer, Account, IpAddress;

LSASSAccess
| join kind=inner (LateralMovement) on Computer, Account
| where LoginTime between (LSASSTime .. LSASSTime + 10m)
| summarize Hits=count(), FirstSeen=min(LSASSTime), SourceIPs=make_set(SourceIp) by Computer, Account
| where Hits >= 1
| extend DetectionName="Credential Access Followed By NTLM Lateral Movement"
"""

SIMPLE_RULE = """
SecurityEvent
| where EventID == 4624
| where LogonType == 3
"""


def lsass_event(host="HOST1", account="svc", when=1000):
    return {
        "EventID": 10,
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "Computer": host,
        "Account": account,
        "SourceImage": "C:\\evil.exe",
        "SourceIp": "10.0.0.5",
        "TimeGenerated": when,
    }


def logon_event(host="HOST1", account="svc", when=1100):
    return {
        "EventID": 4624,
        "LogonType": 3,
        "AuthenticationPackageName": "NTLM",
        "Computer": host,
        "Account": account,
        "IpAddress": "10.0.0.9",
        "TimeGenerated": when,
    }


class ApiCase(unittest.TestCase):
    def setUp(self):
        self.api = Api(RuleStore(":memory:"))

    def tearDown(self):
        self.api.store.close()

    def encoded(self, text=SIMPLE_RULE):
        rule, _ = lower_kql(text)
        return rule_to_dict(rule)


class Dialects(ApiCase):
    def test_all_eight_dialects_are_listed(self):
        # Three docstrings in this codebase promise eight dialects, and all
        # eight now ship.
        rows = self.api.dialects()["dialects"]
        self.assertEqual(len(rows), 8)
        self.assertEqual({r["status"] for r in rows}, {"ready"})

    def test_every_row_says_whether_it_can_be_read_and_written(self):
        for row in self.api.dialects()["dialects"]:
            with self.subTest(key=row["key"]):
                self.assertIn("can_parse", row)
                self.assertIn("can_render", row)

    def test_a_planned_dialect_is_listed_not_hidden(self):
        # A greyed-out entry with a reason is navigable. A missing one looks
        # like a bug. Nothing is planned today, so this runs against a
        # synthetic entry rather than silently testing nothing.
        with planned_dialect() as key:
            rows = {r["key"]: r for r in self.api.dialects()["dialects"]}
            self.assertIn(key, rows)
            self.assertEqual(rows[key]["status"], "planned")

    def test_a_planned_dialect_explains_what_it_needs(self):
        # A planned row with an empty note is a greyed-out dropdown entry with
        # no reason given, which is a dead end in the UI.
        with planned_dialect() as key:
            rows = {r["key"]: r for r in self.api.dialects()["dialects"]}
            self.assertTrue(rows[key]["note"].strip())


class Lowering(ApiCase):
    """Pillar 2: paste a rule, read what it says, tune it."""

    def test_pasted_text_comes_back_as_an_editable_rule(self):
        body = self.api.lower({"dialect": "sentinel", "text": USER_RULE})
        self.assertEqual(sorted(body), ["diagnostics", "outline", "rule"])
        self.assertEqual(body["rule"]["schema"], 1)

    def test_the_outline_names_every_stage(self):
        body = self.api.lower({"dialect": "sentinel", "text": USER_RULE})
        self.assertEqual(
            [s["kind"] for s in body["outline"]["pipeline"]],
            ["Read", "Join", "Aggregate", "Filter", "Derive", "Emit"],
        )

    def test_the_outline_carries_the_bindings(self):
        body = self.api.lower({"dialect": "sentinel", "text": USER_RULE})
        self.assertEqual(
            [b["name"] for b in body["outline"]["bindings"]],
            ["LSASSAccess", "LateralMovement"],
        )

    def test_the_outline_renders_conditions_as_readable_text(self):
        # This is what the builder shows an analyst who pasted a rule they did
        # not write. A blank condition would make the import look lossy.
        body = self.api.lower({"dialect": "sentinel", "text": SIMPLE_RULE})
        conditions = [s.get("condition") for s in body["outline"]["pipeline"]]
        self.assertTrue(any(c and "EventID" in c for c in conditions))

    def test_the_rule_id_is_the_callers_to_choose(self):
        body = self.api.lower(
            {"dialect": "sentinel", "text": SIMPLE_RULE, "rule_id": "lsass-001"}
        )
        self.assertEqual(body["outline"]["rule_id"], "lsass-001")

    def test_an_unknown_dialect_is_refused_by_name(self):
        with self.assertRaises(Refusal) as caught:
            self.api.lower({"dialect": "splonk", "text": SIMPLE_RULE})
        self.assertEqual(caught.exception.code, "DIALECT_UNKNOWN")

    def test_a_planned_dialect_is_refused_differently(self):
        # "Not Yet is planned" sends the analyst to the roadmap. "_notyet is
        # not a dialect" sends them hunting for a typo they did not make. All
        # eight dialects ship, so this runs against a synthetic entry rather
        # than going vacuous.
        with planned_dialect() as key:
            with self.assertRaises(Refusal) as caught:
                self.api.lower({"dialect": key, "text": "anything"})
            self.assertEqual(
                caught.exception.code, "DIALECT_NOT_IMPLEMENTED"
            )

    def test_empty_text_is_refused_rather_than_producing_an_empty_rule(self):
        with self.assertRaises(Refusal) as caught:
            self.api.lower({"dialect": "sentinel", "text": "   \n  "})
        self.assertEqual(caught.exception.code, "REQUEST_EMPTY")

    def test_a_missing_field_is_named(self):
        with self.assertRaises(Refusal) as caught:
            self.api.lower({"dialect": "sentinel"})
        self.assertEqual(caught.exception.code, "REQUEST_FIELD_MISSING")
        self.assertIn("text", caught.exception.message)

    def test_a_field_of_the_wrong_type_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.api.lower({"dialect": "sentinel", "text": 42})
        self.assertEqual(caught.exception.code, "REQUEST_FIELD_TYPE")

    def test_rule_text_that_does_not_parse_refuses_with_the_engines_reason(self):
        with self.assertRaises(Refusal) as caught:
            self.api.lower({"dialect": "sentinel", "text": "T | frobnicate x"})
        self.assertTrue(caught.exception.code.startswith("KQL_"))


class Rendering(ApiCase):
    def test_a_rule_renders_back_to_native_text(self):
        body = self.api.render(
            {"dialect": "sentinel", "rule": self.encoded(USER_RULE)}
        )
        self.assertIn("let LSASSAccess", body["text"])
        self.assertIn("join kind=inner", body["text"])

    def test_render_reports_a_clause_it_could_not_carry_across(self):
        # The GUI reads this seam, and it used to be handed text alone. A Wazuh
        # rule guarded by `<if_sid>5700</if_sid>` renders to KQL without the
        # guard, so the output matches MORE than the rule the analyst pasted.
        # Returning the text with no `diagnostics` key is what let the pane
        # show "Nothing to report" over a silently widened detection.
        from engine import dialects

        rule, _ = dialects.lower(
            "wazuh",
            '<group name="sshd,"><rule id="5710" level="5">'
            "<if_sid>5700</if_sid><match>Failed password</match>"
            "<description>auth failed</description></rule></group>",
        )
        body = self.api.render(
            {"dialect": "sentinel", "rule": rule_to_dict(rule)}
        )
        self.assertNotIn("5700", body["text"])
        self.assertIn("diagnostics", body)
        codes = [d["code"] for d in body["diagnostics"]]
        self.assertIn("SELECTOR_NOT_TRANSFERABLE", codes)

    def test_a_same_dialect_render_reports_nothing(self):
        # A warning on the clean path gets dismissed on the dirty one.
        body = self.api.render(
            {"dialect": "sentinel", "rule": self.encoded(USER_RULE)}
        )
        self.assertEqual(body["diagnostics"], [])

    def test_rendering_into_a_planned_dialect_is_refused(self):
        # Pinned to `wazuh` once, and the day Wazuh shipped it started
        # asserting that a READY dialect refuses to render -- the opposite of
        # the property it exists to check, and green either way. Looked up
        # dynamically it then went vacuous when the last dialect shipped. A
        # synthetic entry is neither.
        with planned_dialect() as key:
            with self.assertRaises(Refusal) as caught:
                self.api.render({"dialect": key, "rule": self.encoded()})
            self.assertEqual(
                caught.exception.code, "DIALECT_NOT_IMPLEMENTED"
            )

    def test_a_rule_that_is_not_an_object_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.api.render({"dialect": "sentinel", "rule": "oops"})
        self.assertEqual(caught.exception.code, "REQUEST_FIELD_TYPE")

    def test_a_tampered_rule_payload_is_refused_by_the_codec(self):
        payload = self.encoded()
        payload["rule"]["pipeline"]["v"][0]["@"] = "Backdoor"
        with self.assertRaises(Refusal) as caught:
            self.api.render({"dialect": "sentinel", "rule": payload})
        self.assertEqual(caught.exception.code, "CODEC_TYPE_UNKNOWN")


class TheOutlineShowsAnOrderedSequence(ApiCase):
    """The outline pane is pillar 2: reading what a pasted rule says.

    A Sequence keeps its conditions on its STEPS rather than on a `condition`
    attribute, so the generic lookups found nothing and the most complex stage
    in the model rendered as the bare word "Sequence". The ORDER is the entire
    point of the node -- `procdump` then `lsass` is credential dumping and the
    reverse is not -- so an outline that omits it leaves the analyst reading
    raw IR to find out what the rule waits for.
    """

    QUERY = (
        'sequence by host.id with maxspan=5m\n'
        '  [process where process.name == "procdump.exe"] with runs=2\n'
        '  [process where process.name : "LSASS*"]\n'
        'until [process where event.type == "end"]'
    )

    def outline(self) -> dict:
        body = self.api.lower({"dialect": "elastic", "text": self.QUERY})
        return next(
            s for s in body["outline"]["pipeline"] if s["kind"] == "Sequence"
        )

    def test_the_steps_are_listed_in_order(self):
        stage = self.outline()
        self.assertEqual([s["position"] for s in stage["steps"]], [1, 2])
        self.assertIn("procdump.exe", stage["steps"][0]["condition"])
        self.assertIn("LSASS", stage["steps"][1]["condition"])

    def test_it_is_marked_as_ordered(self):
        # The GUI needs to know the steps are a sequence rather than a set,
        # or it would list them like interchangeable selections.
        self.assertTrue(self.outline()["ordered"])

    def test_the_join_key_and_window_are_shown(self):
        # A sequence without either means something far broader, so both
        # belong next to the steps.
        stage = self.outline()
        self.assertEqual(stage["by"], ["host.id"])
        self.assertEqual(stage["maxspan"], "5m")

    def test_the_window_is_a_span_not_a_repr(self):
        # `Duration(300s)` in the pane reads as a bug rather than as five
        # minutes.
        self.assertNotIn("Duration", self.outline()["maxspan"])

    def test_a_repeated_step_shows_its_count(self):
        self.assertEqual(self.outline()["steps"][0]["runs"], 2)

    def test_the_cancellation_is_shown(self):
        # A chain that was cancelled is not a detection, so `until` is part of
        # what the rule says.
        self.assertIn("event.type", self.outline()["until"])

    def test_an_ordinary_stage_is_not_marked_ordered(self):
        body = self.api.lower({"dialect": "sentinel", "text": SIMPLE_RULE})
        for stage in body["outline"]["pipeline"]:
            with self.subTest(kind=stage["kind"]):
                self.assertNotIn("ordered", stage)


    def test_a_sample_can_be_sent_as_text_for_the_server_to_parse(self):
        # The browser used to parse log samples itself, with a `coerce` that
        # disagreed with the Python one: JavaScript left `1.5` a string and
        # `-` a string where Python produced a decimal and a null. The same
        # pasted line meant different things in the Run tab and the From Log
        # tab, and only one of the two parsers could be reached by a test.
        rule = self.encoded(SIMPLE_RULE)
        body = self.api.evaluate({
            "rule": rule,
            "text": '{"EventID": 10, "TargetImage": "x"}',
            "format": "jsonl",
        })
        self.assertIn("verdict", body)

    def test_the_text_path_reads_the_formats_the_browser_could_not(self):
        # `kv` and `syslog` were unreachable from the Run box, because the
        # browser-side parser only did JSON.
        rule = self.encoded(SIMPLE_RULE)
        for fmt, text in (
            ("kv", "EventID=10 TargetImage=x"),
            ("syslog", "<34>Jan  1 10:00:00 h app: EventID=10 TargetImage=x"),
        ):
            with self.subTest(format=fmt):
                body = self.api.evaluate({
                    "rule": rule, "text": text, "format": fmt,
                })
                self.assertIn("verdict", body)

    def test_both_tabs_coerce_a_sample_identically(self):
        # The property the duplicate parser broke. One parser now, so a value
        # cannot mean two things depending on which tab read it.
        from engine import synthesize

        text = "ratio=1.5 missing=- count=4625 flag=true"
        parsed = synthesize.parse_events(text, "kv")[0]
        self.assertEqual(parsed["ratio"], Decimal("1.5"))
        self.assertIsNone(parsed["missing"])
        self.assertEqual(parsed["count"], Decimal(4625))
        self.assertIs(parsed["flag"], True)

    def test_events_and_text_are_not_both_required(self):
        rule = self.encoded(SIMPLE_RULE)
        from_list = self.api.evaluate({
            "rule": rule, "events": [{"EventID": 10, "TargetImage": "x"}],
        })
        from_text = self.api.evaluate({
            "rule": rule, "text": '{"EventID": 10, "TargetImage": "x"}',
        })
        self.assertEqual(from_list["verdict"], from_text["verdict"])

    def test_a_malformed_text_sample_names_the_line(self):
        rule = self.encoded(SIMPLE_RULE)
        with self.assertRaises(Refusal) as caught:
            self.api.evaluate({
                "rule": rule, "text": '{"a":1}\nnot json', "format": "jsonl",
            })
        self.assertEqual(caught.exception.code, "SYNTH_JSONL_INVALID")
        self.assertIn("line 2", caught.exception.message)

    def test_events_must_still_be_a_list_when_given(self):
        rule = self.encoded(SIMPLE_RULE)
        with self.assertRaises(Refusal) as caught:
            self.api.evaluate({"rule": rule, "events": "nope"})
        self.assertEqual(caught.exception.code, "REQUEST_FIELD_TYPE")

    def test_the_builders_measure_list_matches_what_the_engine_computes(self):
        # A measure offered in the GUI that the engine cannot compute produces
        # a rule reporting `matched` with an empty column; one the engine can
        # compute but the GUI omits is a feature nobody can reach. This drifted
        # the moment `percentile` and friends were implemented.
        import pathlib
        import re

        source = pathlib.Path(
            api_module.__file__
        ).resolve().parent.joinpath("static", "app.js").read_text(
            encoding="utf-8"
        )
        block = re.search(
            r"const MEASURE_FUNCTIONS = \[([\s\S]*?)\];", source
        )
        self.assertIsNotNone(block)
        offered = set(re.findall(r"'([a-z_]+)'", block.group(1)))

        from decimal import Decimal as D

        from engine.ir import (
            Aggregate, Annotations, Emit, FieldRef, Measure, Read, Rule,
        )
        from engine.pipeline import evaluate as run_rule

        rows = [{"ts": i, "h": "A", "n": D(i)} for i in range(4)]
        uncomputed = []
        for name in sorted(offered):
            measure = Measure(
                function=name, name="v", field=FieldRef("n"),
                param=D(50) if "percentile" in name else "h",
            )
            result = run_rule(Rule(
                rule_id="r",
                pipeline=(
                    Read(id="s", table="t", time_field="ts"),
                    Aggregate(id="a", measures=(measure,),
                              keys=(FieldRef("h"),)),
                    Emit(id="o"),
                ),
                annotations=Annotations(title=""),
            ), rows)
            if "MEASURE_UNKNOWN" in [c.code for c in result.caveats]:
                uncomputed.append(name)
        self.assertEqual(
            uncomputed, [],
            f"the builder offers aggregates the engine does not compute: "
            f"{uncomputed}",
        )


class Synthesizing(ApiCase):
    """The third pillar's HTTP seam.

    This had no endpoint at all: field analysis and rule assembly ran in the
    browser, so the decision that determines whether the output is a rule or a
    rule that matches everything was the one decision no test could reach.
    """

    SAMPLES = (
        '{"event":{"category":"process"},'
        '"process":{"name":"p.exe","pid":1},"ts":"2026-01-01T10:00:00Z"}\n'
        '{"event":{"category":"process"},'
        '"process":{"name":"p.exe","pid":2},"ts":"2026-01-01T10:00:05Z"}'
    )

    def test_it_proposes_a_rule(self):
        body = self.api.synthesize(
            {"text": self.SAMPLES, "format": "jsonl"}
        )
        self.assertEqual(body["samples"], 2)
        self.assertIn("rule", body)
        kinds = [s["kind"] for s in body["outline"]["pipeline"]]
        self.assertEqual(kinds, ["Read", "Filter", "Filter", "Emit"])

    def test_the_field_report_comes_back_with_it(self):
        # A generated rule without the reasoning behind it is a rule the
        # analyst has to reverse-engineer before they can trust it.
        body = self.api.synthesize(
            {"text": self.SAMPLES, "format": "jsonl"}
        )
        fields = {f["name"]: f for f in body["fields"]}
        self.assertTrue(fields["process.name"]["include"])
        self.assertFalse(fields["process.pid"]["include"])
        self.assertTrue(fields["process.pid"]["reasons"])

    def test_it_says_the_result_is_a_hypothesis(self):
        body = self.api.synthesize(
            {"text": self.SAMPLES, "format": "jsonl"}
        )
        self.assertIn(
            "SYNTH_IS_A_HYPOTHESIS", [d["code"] for d in body["diagnostics"]]
        )

    def test_the_default_format_is_jsonl(self):
        body = self.api.synthesize({"text": self.SAMPLES})
        self.assertEqual(body["samples"], 2)

    def test_the_options_are_honoured(self):
        # `host` is used rather than `process.pid`, because `pid` also trips
        # the volatile-NAME heuristic and would stay excluded by the other
        # flag -- which would make this test pass for the wrong reason.
        samples = (
            '{"cat":"process","host":"WS-01"}\n'
            '{"cat":"process","host":"WS-02"}'
        )
        body = self.api.synthesize({
            "text": samples,
            "format": "jsonl",
            "options": {"skip_volatile": False},
        })
        fields = {f["name"]: f for f in body["fields"]}
        self.assertTrue(fields["host"]["include"])
        self.assertIn(
            "SYNTH_PINNED_A_VARYING_FIELD",
            [d["code"] for d in body["diagnostics"]],
        )

    def test_a_threshold_can_be_requested(self):
        body = self.api.synthesize({
            "text": self.SAMPLES,
            "format": "jsonl",
            "options": {"threshold": True, "group_by": ["process.name"],
                        "frequency": 7, "window_seconds": 60},
        })
        kinds = [s["kind"] for s in body["outline"]["pipeline"]]
        self.assertIn("Aggregate", kinds)
        self.assertIn(
            "SYNTH_THRESHOLD_INVENTED",
            [d["code"] for d in body["diagnostics"]],
        )

    def test_a_bad_option_type_is_refused_rather_than_coerced(self):
        # A `frequency` of "five" silently becoming the default would hand
        # back a threshold the analyst did not ask for and cannot see.
        for options in (
            {"frequency": "five"},
            {"skip_volatile": "yes"},
            {"window_seconds": 1.5},
            {"group_by": [1, 2]},
            {"table": 7},
        ):
            with self.subTest(options=options):
                with self.assertRaises(Refusal) as caught:
                    self.api.synthesize({
                        "text": self.SAMPLES, "options": options,
                    })
                self.assertEqual(
                    caught.exception.code, "REQUEST_FIELD_TYPE"
                )

    def test_options_must_be_an_object(self):
        with self.assertRaises(Refusal) as caught:
            self.api.synthesize({"text": self.SAMPLES, "options": []})
        self.assertEqual(caught.exception.code, "REQUEST_FIELD_TYPE")

    def test_one_sample_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.api.synthesize({"text": '{"a":1}', "format": "jsonl"})
        self.assertEqual(
            caught.exception.code, "SYNTH_TOO_FEW_SAMPLES"
        )

    def test_an_unknown_format_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.api.synthesize({"text": "a,b", "format": "csv"})
        self.assertEqual(caught.exception.code, "SYNTH_FORMAT_UNKNOWN")

    def test_the_proposed_rule_can_be_rendered_and_saved(self):
        # The whole point of returning IR rather than text: the proposal has to
        # flow into the rest of the tool.
        body = self.api.synthesize(
            {"text": self.SAMPLES, "format": "jsonl"}
        )
        rendered = self.api.render(
            {"dialect": "sentinel", "rule": body["rule"]}
        )
        self.assertIn("where", rendered["text"])
        saved = self.api.history_save({
            "rule": body["rule"], "origin": "synthesized",
        })
        self.assertEqual(saved["origin"], "synthesized")

    def test_the_proposed_rule_matches_its_own_samples(self):
        body = self.api.synthesize(
            {"text": self.SAMPLES, "format": "jsonl"}
        )
        events = [json.loads(l) for l in self.SAMPLES.splitlines()]
        result = self.api.evaluate({"rule": body["rule"], "events": events})
        self.assertEqual(result["verdict"], "matched")


class Validating(ApiCase):
    def test_a_sound_rule_validates(self):
        self.assertTrue(self.api.validate({"rule": self.encoded()})["ok"])

    def test_a_catastrophic_pattern_is_refused_on_the_deploy_path(self):
        # The screen exists because a pattern that would hang the VENDOR's
        # engine must never be authored or rendered, not merely refused at
        # local-run time.
        rule, _ = lower_kql(SIMPLE_RULE)
        payload = rule_to_dict(rule)
        condition = payload["rule"]["pipeline"]["v"][1]["condition"]
        condition["@"] = "Comparison"
        condition["op"] = {"@": "str", "v": "matches"}
        condition["right"] = {
            "@": "Regex",
            "pattern": {"@": "str", "v": "(a+)+$"},
            "dialect": {"@": "str", "v": "posix_extended"},
            "nocase": {"@": "bool", "v": False},
        }
        with self.assertRaises(Refusal) as caught:
            self.api.validate({"rule": payload})
        self.assertEqual(
            caught.exception.code, "REGEX_CATASTROPHIC_BACKTRACKING"
        )


class Evaluating(ApiCase):
    """The tuning loop: run a rule and say why it did or did not match."""

    def test_a_correlation_fires_on_matching_evidence(self):
        rule = self.encoded(USER_RULE)
        body = self.api.evaluate(
            {"rule": rule, "events": [lsass_event(), logon_event()]}
        )
        self.assertEqual(body["verdict"], "matched")
        self.assertTrue(body["matched"])
        self.assertEqual(len(body["rows"]), 1)

    def test_evidence_out_of_the_window_does_not_fire(self):
        rule = self.encoded(USER_RULE)
        body = self.api.evaluate({
            "rule": rule,
            "events": [lsass_event(when=1000), logon_event(when=99999)],
        })
        self.assertEqual(body["verdict"], "no_match")

    def test_a_missing_field_reports_not_evaluated_not_no_match(self):
        # THE distinction this engine exists for. A confident "no" on evidence
        # the engine never had is the one answer a detection engineer must
        # never be given.
        rule = self.encoded(USER_RULE)
        stripped = lsass_event()
        del stripped["TargetImage"]
        body = self.api.evaluate({"rule": rule, "events": [stripped, logon_event()]})
        self.assertEqual(body["verdict"], "not_evaluated")
        self.assertGreater(len(body["caveats"]), 0)

    def test_a_caveat_names_the_field_the_analyst_must_look_at(self):
        rule = self.encoded(USER_RULE)
        stripped = lsass_event()
        del stripped["TargetImage"]
        body = self.api.evaluate({"rule": rule, "events": [stripped, logon_event()]})
        messages = " ".join(c["message"] for c in body["caveats"])
        self.assertIn("TargetImage", messages)
        # The caveat must not leak the engine's internal sentinel at an analyst.
        self.assertNotIn("ABSENT", messages)

    def test_the_trace_accounts_for_rows_at_every_stage(self):
        # Read top to bottom, this is how an analyst finds the stage that
        # dropped the rows they expected to keep.
        rule = self.encoded(USER_RULE)
        body = self.api.evaluate(
            {"rule": rule, "events": [lsass_event(), logon_event()]}
        )
        self.assertGreater(len(body["trace"]), 0)
        for entry in body["trace"]:
            with self.subTest(stage=entry["stage"]):
                self.assertEqual(
                    sorted(entry),
                    ["detail", "dropped", "kind", "rows_in", "rows_out",
                     "stage", "undecided"],
                )

    def test_an_empty_sample_is_allowed_and_does_not_claim_a_match(self):
        body = self.api.evaluate({"rule": self.encoded(), "events": []})
        self.assertNotEqual(body["verdict"], "matched")

    def test_events_that_are_not_a_list_are_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.api.evaluate({"rule": self.encoded(), "events": {"a": 1}})
        self.assertEqual(caught.exception.code, "REQUEST_FIELD_TYPE")

    def test_a_raw_log_line_is_refused_rather_than_guessed_at(self):
        # The engine takes parsed events. Accepting a string here would mean
        # inventing a schema, which is the one thing a detection tool must not
        # do silently.
        #
        # Note the shape: this comes back as a RESULT carrying a refusal, not as
        # a raised exception. That is deliberate -- the verdict, trace and
        # caveats still reach the analyst alongside the reason, where a thrown
        # exception would discard them.
        body = self.api.evaluate({
            "rule": self.encoded(),
            "events": ["Jan  1 00:00:00 host sshd[1]: Failed password"],
        })
        self.assertEqual(body["verdict"], "not_evaluated")
        self.assertIsNotNone(body["refusal"])
        self.assertEqual(body["refusal"]["code"], "EVENT_NOT_AN_OBJECT")
        self.assertIn("str", body["refusal"]["message"])

    def test_a_refused_sample_never_reports_a_match(self):
        # The default-deny posture: a rule that could not be run must not be
        # able to come back as `matched`.
        body = self.api.evaluate({
            "rule": self.encoded(),
            "events": [{"EventID": 4624}, "a raw line", {"EventID": 4624}],
        })
        self.assertFalse(body["matched"])

    def test_too_many_events_is_refused_with_the_ceiling(self):
        with self.assertRaises(Refusal) as caught:
            self.api.evaluate({
                "rule": self.encoded(),
                "events": [{"EventID": 4624}] * (MAX_EVENTS + 1),
            })
        self.assertEqual(caught.exception.code, "REQUEST_TOO_MANY_EVENTS")
        self.assertIn(f"{MAX_EVENTS:,}", caught.exception.message)


class DisplayEncoding(unittest.TestCase):
    """One-way, for the browser. Not the codec -- but the three-state
    distinction still has to survive, or the whole point is lost."""

    def test_absent_undecided_and_null_stay_three_different_things(self):
        from engine.values import ABSENT, UNDECIDED

        self.assertEqual(_display(ABSENT), {"$": "absent"})
        self.assertEqual(_display(UNDECIDED), {"$": "undecided"})
        self.assertIsNone(_display(None))
        self.assertEqual(_display(""), "")

    def test_a_decimal_is_sent_as_text_not_a_float(self):
        # A count of 5 arrives as "5", which renders identically in the browser
        # and cannot quietly become 4.999999.
        self.assertEqual(_display(Decimal("10.5")), "10.5")
        self.assertIsInstance(_display(Decimal("5")), str)

    def test_a_seq_keeps_its_distinct_flag(self):
        from engine.values import Seq

        body = _display(Seq(("a", "b"), distinct=True))
        self.assertEqual(body["$"], "seq")
        self.assertTrue(body["distinct"])
        self.assertEqual(body["items"], ["a", "b"])

    def test_a_bool_is_not_turned_into_a_number(self):
        self.assertIs(_display(True), True)

    def test_everything_it_emits_is_json_serialisable(self):
        from engine.values import ABSENT, UNDECIDED, Duration, Seq

        payload = _display({
            "a": ABSENT, "b": UNDECIDED, "c": None, "d": Decimal("1.5"),
            "e": Seq((1, 2)), "f": Duration(Decimal(600)), "g": (1, 2),
            "h": True, "i": "text",
        })
        json.dumps(payload, allow_nan=False)


class History(ApiCase):
    """Pillar 4."""

    def test_a_saved_rule_appears_in_the_history(self):
        saved = self.api.history_save(
            {"rule": self.encoded(), "origin": "imported",
             "source_text": SIMPLE_RULE}
        )
        listing = self.api.history({})
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["entries"][0]["id"], saved["id"])

    def test_the_origin_is_recorded_because_it_changes_how_much_to_trust_it(self):
        saved = self.api.history_save(
            {"rule": self.encoded(), "origin": "synthesized"}
        )
        self.assertEqual(saved["origin"], "synthesized")

    def test_an_unknown_origin_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.api.history_save({"rule": self.encoded(), "origin": "vibes"})
        self.assertEqual(caught.exception.code, "STORE_ORIGIN_UNKNOWN")

    def test_opening_a_version_returns_the_rule_and_an_outline(self):
        saved = self.api.history_save(
            {"rule": self.encoded(USER_RULE), "origin": "imported",
             "source_text": USER_RULE}
        )
        body = self.api.history_entry(saved["id"])
        self.assertEqual(body["source_text"], USER_RULE)
        self.assertEqual(body["rule"]["schema"], 1)
        self.assertEqual(
            [s["kind"] for s in body["outline"]["pipeline"]][0], "Read"
        )

    def test_a_list_row_does_not_ship_the_whole_rule(self):
        self.api.history_save({"rule": self.encoded(), "origin": "authored"})
        row = self.api.history({})["entries"][0]
        self.assertNotIn("rule", row)
        self.assertNotIn("source_text", row)

    def test_lineage_reads_oldest_first(self):
        first = self.api.history_save(
            {"rule": self.encoded(), "origin": "imported"}
        )
        second = self.api.history_save({
            "rule": self.encoded(), "origin": "authored",
            "parent_id": first["id"], "note": "raised the threshold",
        })
        lineage = self.api.history_lineage(second["id"])["lineage"]
        self.assertEqual([e["id"] for e in lineage], [first["id"], second["id"]])

    def test_a_parent_id_of_the_wrong_type_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.api.history_save({
                "rule": self.encoded(), "origin": "authored",
                "parent_id": "the first one",
            })
        self.assertEqual(caught.exception.code, "REQUEST_FIELD_TYPE")

    def test_filtering_by_origin(self):
        self.api.history_save({"rule": self.encoded(), "origin": "imported"})
        self.api.history_save({"rule": self.encoded(), "origin": "synthesized"})
        found = self.api.history({"origin": ["synthesized"]})
        self.assertEqual(len(found["entries"]), 1)

    def test_a_non_numeric_page_size_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            self.api.history({"limit": ["lots"]})
        self.assertEqual(caught.exception.code, "REQUEST_FIELD_TYPE")

    def test_a_version_can_be_forgotten(self):
        saved = self.api.history_save({"rule": self.encoded(), "origin": "authored"})
        self.api.history_forget(saved["id"])
        self.assertEqual(self.api.history({})["total"], 0)

    def test_a_version_later_ones_came_from_cannot_be_forgotten(self):
        parent = self.api.history_save({"rule": self.encoded(), "origin": "imported"})
        self.api.history_save({
            "rule": self.encoded(), "origin": "authored",
            "parent_id": parent["id"],
        })
        with self.assertRaises(Refusal) as caught:
            self.api.history_forget(parent["id"])
        self.assertEqual(caught.exception.code, "STORE_ENTRY_HAS_CHILDREN")


class Evidence(ApiCase):
    def test_a_dataset_can_be_created_and_listed(self):
        created = self.api.dataset_save({
            "name": "Windows login samples",
            "description": "Small local fixture",
            "format": "jsonl",
            "table": "SecurityEvent",
            "labels": ["benign", "windows"],
            "text": '{"EventID": 4624, "Computer": "WS-01"}',
        })
        self.assertEqual(created["event_count"], 1)
        self.assertEqual(created["table"], "SecurityEvent")
        listing = self.api.datasets({})
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["datasets"][0]["id"], created["id"])

    def test_dataset_detail_contains_normalized_events(self):
        created = self.api.dataset_save({
            "name": "numeric sample",
            "format": "kv",
            "text": "EventID=4624 ratio=1.5",
        })
        detail = self.api.dataset(created["id"])
        self.assertEqual(detail["events"][0]["EventID"], "4624")
        self.assertEqual(detail["events"][0]["ratio"], "1.5")

    def test_a_test_run_saves_expected_and_actual_verdicts(self):
        dataset = self.api.dataset_save({
            "name": "positive login",
            "format": "jsonl",
            "text": '{"EventID": 4624, "LogonType": 3}',
        })
        saved_rule = self.api.history_save({
            "rule": self.encoded(SIMPLE_RULE), "origin": "authored"
        })
        run = self.api.test_run_save({
            "rule": self.encoded(SIMPLE_RULE),
            "dataset_id": dataset["id"],
            "rule_entry_id": saved_rule["id"],
            "expected_verdict": "matched",
            "purpose": "positive",
        })
        self.assertEqual(run["actual_verdict"], "matched")
        self.assertTrue(run["matches_expected"])
        self.assertEqual(self.api.test_runs({})["total"], 1)
        detail = self.api.test_run(run["id"])
        self.assertEqual(detail["result"]["verdict"], "matched")

    def test_a_test_run_cannot_use_an_unknown_dataset(self):
        with self.assertRaises(Refusal) as caught:
            self.api.test_run_save({
                "rule": self.encoded(), "dataset_id": 12345
            })
        self.assertEqual(caught.exception.code, "STORE_DATASET_UNKNOWN")


class OverHttp(unittest.TestCase):
    """A real socket. Routing, traversal and body limits only exist here."""

    @classmethod
    def setUpClass(cls):
        cls.store = RuleStore(":memory:")
        cls.server = build_server("127.0.0.1", 0, cls.store)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.store.close()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def get(self, path):
        with urllib.request.urlopen(self.url(path), timeout=10) as response:
            return response.status, json.loads(response.read() or b"{}")

    def post(self, path, payload):
        request = urllib.request.Request(
            self.url(path),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read() or b"{}")

    def expect_error(self, method, path, payload=None, raw=None):
        if raw is not None:
            request = urllib.request.Request(
                self.url(path), data=raw, method=method,
                headers={"Content-Type": "application/json"},
            )
        else:
            data = None if payload is None else json.dumps(payload).encode("utf-8")
            request = urllib.request.Request(self.url(path), data=data, method=method)
        try:
            urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read() or b"{}")
        self.fail(f"{method} {path} was expected to fail")

    # -- happy paths ------------------------------------------------------

    def test_health(self):
        status, body = self.get("/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_the_gui_is_served_at_the_root(self):
        with urllib.request.urlopen(self.url("/"), timeout=10) as response:
            self.assertEqual(response.status, 200)
            self.assertIn("text/html", response.headers["Content-Type"])
            self.assertIn(b"RuleForge", response.read())

    def test_the_stylesheet_and_script_are_served(self):
        for path, expected in (("/static/app.css", "css"),
                               ("/static/app.js", "javascript")):
            with self.subTest(path=path):
                with urllib.request.urlopen(self.url(path), timeout=10) as response:
                    self.assertEqual(response.status, 200)
                    self.assertIn(expected, response.headers["Content-Type"])

    def test_the_builder_can_show_a_regex_operand(self):
        # It showed an EMPTY value box. `literalToText` only understood a
        # `Literal`, so `ObjectName endswith "lsass.exe"` -- which the KQL
        # dialect folds into a case-folding regex -- appeared as the operator
        # `matches` with no value at all. The analyst could not see the
        # pattern, and typing in that box replaced the Regex with a plain
        # string: a case-insensitive suffix test became a case-sensitive exact
        # match, silently. The rendered pane showed the truth while the editor
        # showed something else.
        source = self._app_js()
        self.assertIn("const isRegex = expr.right['@'] === 'Regex'", source)
        self.assertIn("expr.right.pattern.v", source)

    def test_editing_a_regex_keeps_its_flavour_and_case_rule(self):
        source = self._app_js()
        block = source[source.find("const isRegex"):][:1600]
        self.assertIn("dialect: expr.right.dialect", block)
        self.assertIn("nocase: expr.right.nocase", block)

    def test_a_case_insensitive_pattern_says_so(self):
        # A pattern that ignores case reads identically to one that does not.
        self.assertIn("regex \u00b7 any case", self._app_js())

    def test_the_app_opens_on_a_start_pane(self):
        # It used to open onto the Build form: eleven blank metadata fields,
        # a placeholder condition, an output box reading em-dash, and nothing
        # saying what any of it was for. A person who had not written a
        # detection rule had no entry point, and a person who had still could
        # not tell which of the four tabs did what.
        html = self._index_html()
        self.assertIn('id="pane-home"', html)
        self.assertIn('data-pane="home"', html)
        self.assertIn('class="pane active" id="pane-home"', html)

    def test_the_build_pane_is_no_longer_the_default(self):
        html = self._index_html()
        self.assertIn('<section class="pane" id="pane-build">', html)

    def test_the_start_pane_offers_a_worked_example(self):
        # A filled-in rule teaches the shape of one faster than any amount of
        # label text, and there was nothing to learn from.
        html = self._index_html()
        self.assertIn('id="home-example"', html)
        self.assertIn('id="home-blank"', html)

    def test_the_example_is_real_rule_text_not_hand_built_ir(self):
        # Lowered by the server, so it cannot drift out of step with what the
        # parser accepts. An example that no longer loads is worse than none.
        source = self._app_js()
        self.assertIn("EXAMPLE_RULE", source)
        self.assertIn("'/api/lower'", source)

    def test_the_example_actually_lowers_and_renders(self):
        # The guard that matters: if the example stops loading, the first
        # thing a new user does is see an error.
        import re

        source = self._app_js()
        block = re.search(
            r"const EXAMPLE_RULE = \[([\s\S]*?)\]\.join\('\\n'\);", source
        )
        self.assertIsNotNone(block, "the example text could not be located")
        lines = re.findall(r"'((?:[^'\\]|\\.)*)'", block.group(1))
        text = "\n".join(l.replace("\\\\", "\\").replace("\\'", "'")
                         for l in lines)
        dialect = re.search(
            r"const EXAMPLE_DIALECT = '(\w+)'", source
        ).group(1)

        status, body = self.post(
            "/api/lower", {"dialect": dialect, "text": text}
        )
        self.assertEqual(status, 200)
        self.assertIn("rule", body)
        status, rendered = self.post(
            "/api/render", {"dialect": dialect, "rule": body["rule"]}
        )
        self.assertEqual(status, 200)
        self.assertTrue(rendered["text"].strip())

    def test_the_example_carries_a_sample_it_matches(self):
        # An example that renders but cannot be tested teaches half of what
        # the tool does.
        import json
        import re

        source = self._app_js()
        self.assertIn("EXAMPLE_SAMPLE", source)

        def literals(pattern: str) -> str:
            block = re.search(pattern, source)
            self.assertIsNotNone(block)
            return [
                l.replace("\\\\", "\\").replace("\\'", "'")
                for l in re.findall(r"'((?:[^'\\]|\\.)*)'", block.group(1))
            ]

        sample = "".join(literals(
            r"const EXAMPLE_SAMPLE = \[([\s\S]*?)\]\.join\(''\);"
        ))
        event = json.loads(sample)
        rule_text = "\n".join(literals(
            r"const EXAMPLE_RULE = \[([\s\S]*?)\]\.join\('\\n'\);"
        ))

        status, body = self.post(
            "/api/lower", {"dialect": "sentinel", "text": rule_text}
        )
        self.assertEqual(status, 200)
        status, result = self.post(
            "/api/evaluate", {"rule": body["rule"], "events": [event]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            result["verdict"], "matched",
            "the example's own sample no longer matches its own rule",
        )

    def test_the_start_pane_lists_dialects_from_the_api(self):
        # Named from `/api/dialects` rather than written into the page, so the
        # landing copy cannot claim a dialect count that has gone stale.
        self.assertIn('id="home-dialects"', self._index_html())
        self.assertIn("#home-dialects", self._app_js())

    def _index_html(self) -> str:
        return pathlib.Path(
            api_module.__file__
        ).resolve().parent.joinpath("templates", "index.html").read_text(
            encoding="utf-8"
        )

    def test_the_builder_does_not_show_a_stale_render(self):
        # There is no JavaScript test runner here -- stdlib only -- so these
        # are static guards on specific defects rather than unit tests.
        #
        # The rendered pane showed text that was not the rule in front of you:
        # editing a value from 4624 to 9999 left the old query on screen, and
        # switching the dialect from Sentinel to Splunk left KQL on screen
        # while the dropdown read Splunk, so the LABEL contradicted the
        # content. An analyst copies that into their SIEM and deploys the old
        # threshold, or the wrong language entirely.
        source = self._app_js()
        for needle, why in (
            ("function markStale(",
             "nothing invalidates the pane when the rule changes"),
            ("scheduleRender(",
             "nothing re-renders after an edit"),
            ("if (want !== state.dialect)",
             "an in-flight render can land under the wrong dialect label"),
            ("rendered-for",
             "the output is not labelled with its language"),
        ):
            with self.subTest(guard=needle):
                self.assertIn(needle, source, why)

    def test_a_dialect_change_re_renders(self):
        source = self._app_js()
        handler = source[source.find("$('#dialect').onchange"):][:400]
        self.assertIn(
            "scheduleRender", handler,
            "switching dialect leaves the previous language on screen",
        )

    def test_the_builder_does_not_show_a_stale_verdict(self):
        # The worse half. Changing `EventID == 4624` to `9999` re-rendered the
        # query correctly and left "Matched" on screen -- the answer for the
        # old rule. The two panes then contradicted each other, and the fresh
        # one made the stale verdict look trustworthy: a rule that cannot
        # match reported a successful match. That is a false confirmation.
        source = self._app_js()
        marker = source[source.find("function markStale("):][:1800]
        self.assertIn(
            "#evaluation", marker,
            "a rule change does not invalidate the verdict",
        )
        self.assertIn(
            "The sample has changed", source,
            "a sample change does not invalidate the verdict",
        )

    def test_the_stale_state_is_visible_not_just_a_class(self):
        # Colour alone is not a message, and the person most likely to act on
        # stale output is the one not reading it closely.
        css = pathlib.Path(
            api_module.__file__
        ).resolve().parent.joinpath("static", "app.css").read_text(
            encoding="utf-8"
        )
        self.assertIn("#rendered.stale", css)
        self.assertIn("#evaluation.stale", css)
        self.assertIn(".stale-note", css)

    def _app_js(self) -> str:
        return pathlib.Path(
            api_module.__file__
        ).resolve().parent.joinpath("static", "app.js").read_text(
            encoding="utf-8"
        )

    def test_the_builder_does_not_overwrite_a_rules_provenance(self):
        # There is no JavaScript test runner here -- stdlib only -- so this is
        # a static guard on one specific defect rather than a unit test.
        #
        # `readRule` used to replace the whole metadata dict with three keys
        # derived from `state.dialect`, which is the dialect the dropdown
        # renders INTO, not the one the rule came FROM. Reading the form
        # therefore relabelled an imported Wazuh rule as Sentinel and dropped
        # every `wazuh.*` key, so the rule stopped round-tripping through its
        # own dialect (`<if_sid>` gone, `level="5"` reset to the default) and
        # the cross-dialect audit went permanently quiet, because provenance
        # and target always matched.
        #
        # Matched narrowly on the defect's exact idiom so ordinary edits to
        # this function do not trip it.
        source = pathlib.Path(
            api_module.__file__
        ).resolve().parent.joinpath("static", "app.js").read_text(
            encoding="utf-8"
        )
        self.assertNotRegex(
            source,
            r"metadata\s*=\s*T\.dict\(\[\s*\[\s*T\.str\(\s*'dialect'\s*\)\s*,"
            r"\s*T\.str\(\s*state\.dialect\s*\)",
            "readRule is rebuilding metadata from the selected output dialect "
            "again. That discards the rule's provenance and every "
            "dialect-specific key with it.",
        )
        self.assertIn(
            "if (!meta.has('dialect'))",
            source,
            "readRule should fill in `dialect` only when the rule arrived "
            "without one, never overwrite it.",
        )

    def test_lowering_over_http(self):
        status, body = self.post(
            "/api/lower", {"dialect": "sentinel", "text": SIMPLE_RULE}
        )
        self.assertEqual(status, 200)
        self.assertIn("outline", body)

    def test_the_whole_round_trip_over_http(self):
        # paste -> IR -> render -> evaluate -> save, which is the actual
        # workflow the GUI performs.
        _, lowered = self.post(
            "/api/lower", {"dialect": "sentinel", "text": USER_RULE}
        )
        _, rendered = self.post(
            "/api/render", {"dialect": "sentinel", "rule": lowered["rule"]}
        )
        self.assertIn("summarize", rendered["text"])
        _, result = self.post("/api/evaluate", {
            "rule": lowered["rule"],
            "events": [lsass_event(), logon_event()],
        })
        self.assertEqual(result["verdict"], "matched")
        _, saved = self.post("/api/history", {
            "rule": lowered["rule"], "origin": "imported",
            "source_text": USER_RULE,
        })
        status, opened = self.get(f"/api/history/{saved['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(opened["source_text"], USER_RULE)
        status, lineage = self.get(f"/api/history/{saved['id']}/lineage")
        self.assertEqual(status, 200)
        self.assertEqual(len(lineage["lineage"]), 1)

    # -- failure paths ----------------------------------------------------

    def test_an_unknown_route_is_a_404_with_a_code(self):
        status, body = self.expect_error("GET", "/api/nope")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "ROUTE_UNKNOWN")

    def test_a_refusal_is_a_400_carrying_the_engines_reason(self):
        status, body = self.expect_error(
            "POST", "/api/lower", {"dialect": "splonk", "text": "x"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "DIALECT_UNKNOWN")
        self.assertIn("sentinel", body["error"]["message"])

    def test_a_body_that_is_not_json_is_refused_with_a_position(self):
        status, body = self.expect_error(
            "POST", "/api/lower", raw=b"{not json"
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "REQUEST_NOT_JSON")
        self.assertIn("line", body["error"]["message"])

    def test_a_body_that_is_not_an_object_is_refused(self):
        status, body = self.expect_error("POST", "/api/lower", raw=b"[1,2,3]")
        self.assertEqual(body["error"]["code"], "REQUEST_NOT_OBJECT")

    def test_a_body_that_is_not_utf8_is_refused(self):
        status, body = self.expect_error("POST", "/api/lower", raw=b"\xff\xfe\x00")
        self.assertEqual(status, 400)
        self.assertIn(
            body["error"]["code"], ("REQUEST_NOT_UTF8", "REQUEST_NOT_JSON")
        )

    def test_path_traversal_out_of_the_static_directory_is_forbidden(self):
        # Checking for ".." in the raw string misses encoded traversal, so the
        # handler resolves the path and confirms containment instead.
        for attempt in (
            "/static/../api.py",
            "/static/..%2fapi.py",
            "/static/%2e%2e/%2e%2e/ir.py",
            "/static/....//api.py",
        ):
            with self.subTest(path=attempt):
                status, body = self.expect_error("GET", attempt)
                self.assertIn(status, (403, 404))
                self.assertNotEqual(body.get("error", {}).get("code"), "INTERNAL")

    def test_a_static_file_that_does_not_exist_is_a_404(self):
        status, body = self.expect_error("GET", "/static/nope.css")
        self.assertEqual(status, 404)

    def test_a_history_id_that_is_not_a_number_is_not_a_crash(self):
        status, body = self.expect_error("GET", "/api/history/abc")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "ROUTE_UNKNOWN")

    def test_a_history_id_that_does_not_exist_is_refused_cleanly(self):
        status, body = self.expect_error("GET", "/api/history/99999")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "STORE_ENTRY_UNKNOWN")

    def raw_exchange(self, header: bytes, body: bytes, close: bool = True,
                     timeout: float = 45.0) -> bytes:
        """One request over a bare socket, returning the whole response.

        `urllib` sends its own Content-Length and will not let a test lie
        about it, so the transport-level cases have to be driven by hand.
        """
        import socket

        sock = socket.create_connection(
            ("127.0.0.1", self.port), timeout=timeout
        )
        try:
            sock.sendall(header)
            sent = 0
            while sent < len(body):
                try:
                    sock.sendall(body[sent:sent + 65536])
                except OSError:
                    break
                sent += 65536
            if close:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            answer = b""
            try:
                while True:
                    part = sock.recv(8192)
                    if not part:
                        break
                    answer += part
            except OSError:
                pass
            return answer
        finally:
            sock.close()

    def test_an_oversized_body_is_refused_with_an_explanation(self):
        # This test used to assert arithmetic -- that 16 MB is less than
        # 64 MB -- and never touched the socket, which is exactly why the real
        # behaviour went unnoticed: the server refused internally, answered,
        # and closed while the client was still writing, so the connection
        # reset and the client saw NOTHING. A 16 MB paste into the From Log
        # box reported "network error" rather than "your sample is too large",
        # which is the one message that would have told the analyst what to do.
        body = (
            b'{"dialect":"sentinel","text":"'
            + b"x" * (MAX_BODY_BYTES + 32)
            + b'"}'
        )
        header = (
            b"POST /api/lower HTTP/1.1\r\nHost: x\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
        )
        answer = self.raw_exchange(header, body)
        self.assertIn(b"413", answer.split(b"\r\n")[0])
        self.assertIn(b"REQUEST_TOO_LARGE", answer)

    def test_a_size_refusal_uses_413_not_400(self):
        # So a client can tell "too big" from "malformed" without reading
        # prose.
        from web.api import _TOO_LARGE_CODES

        self.assertIn("REQUEST_TOO_LARGE", _TOO_LARGE_CODES)
        self.assertIn("REQUEST_TOO_MANY_EVENTS", _TOO_LARGE_CODES)

    def test_a_short_body_is_named_rather_than_parsed(self):
        # A body shorter than its Content-Length would parse as truncated
        # JSON and report a syntax error that is not in the text, sending the
        # analyst hunting for a bracket they did not miss.
        body = b'{"dialect":"sentinel","text":"T"}'
        header = (
            b"POST /api/lower HTTP/1.1\r\nHost: x\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 500\r\n\r\n"
        )
        answer = self.raw_exchange(header, body)
        self.assertIn(b"400", answer.split(b"\r\n")[0])
        self.assertIn(b"REQUEST_INCOMPLETE", answer)
        self.assertNotIn(b"REQUEST_NOT_JSON", answer)

    def test_the_handler_sets_a_socket_timeout(self):
        # Without one, `BaseHTTPRequestHandler` blocks forever: a client that
        # declares 16 MB and sends ten bytes holds its thread indefinitely,
        # and with HTTP/1.1 keep-alive and a thread per connection a handful
        # of those takes the workbench down. Asserted as a property rather
        # than by waiting 30 seconds in the suite.
        from web.api import RuleForgeHandler

        self.assertIsInstance(RuleForgeHandler.timeout, (int, float))
        self.assertGreater(RuleForgeHandler.timeout, 0)

    def test_a_dropped_connection_is_not_a_server_error(self):
        # `socketserver` prints a full traceback for each dropped connection,
        # and that noise buries the one traceback that means the workbench is
        # actually broken.
        import socket

        sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        sock.sendall(b"POST /api/lower HTTP/1.1\r\nHost: x\r\n")
        sock.close()
        # The server must still answer the next request on a new connection.
        status, body = self.post(
            "/api/lower", {"dialect": "sentinel", "text": "T | where a == 1"}
        )
        self.assertEqual(status, 200)
        self.assertIn("rule", body)

    def test_responses_carry_the_hardening_headers(self):
        # This endpoint renders rule text and log samples that came from
        # elsewhere, so nosniff is the cheap half of not turning a pasted rule
        # into script execution.
        with urllib.request.urlopen(self.url("/api/health"), timeout=10) as response:
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")

    def test_a_version_can_be_deleted_over_http(self):
        _, lowered = self.post(
            "/api/lower", {"dialect": "sentinel", "text": SIMPLE_RULE}
        )
        _, saved = self.post(
            "/api/history", {"rule": lowered["rule"], "origin": "authored"}
        )
        request = urllib.request.Request(
            self.url(f"/api/history/{saved['id']}"), method="DELETE"
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            self.assertEqual(response.status, 200)


if __name__ == "__main__":
    unittest.main()
