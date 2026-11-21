"""Regressions for defects found in the second deep review.

Each test names the wrong behaviour it prevents. Most of these were SILENT:
the rule converted or evaluated without error and meant something else.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import socket
import tempfile
import textwrap
import threading
import unittest

from engine import dialects
from engine.pipeline import evaluate
from engine.sandbox import evaluate_with_timeout
from engine.store import RuleStore
from engine.values import Refusal
from web.api import build_server


def sigma(detection: str) -> str:
    body = textwrap.indent(textwrap.dedent(detection).strip("\n"), "  ")
    return f"title: t\nlogsource:\n  category: x\ndetection:\n{body}\n"


def verdict(dialect: str, text: str, event: dict) -> str:
    rule, _ = dialects.lower(dialect, text)
    return evaluate(rule, [event]).verdict


class SplunkSearchSemantics(unittest.TestCase):
    def test_not_after_a_term_is_kept(self):
        # `a=1 NOT b=2` lowered to `a == 1`: the exclusion vanished.
        text = 'index=a EventCode=4688 NOT Image="x.exe"'
        self.assertEqual(verdict("splunk", text, {"EventCode": 4688, "Image": "x.exe"}), "no_match")
        self.assertEqual(verdict("splunk", text, {"EventCode": 4688, "Image": "y.exe"}), "matched")

    def test_trailing_tokens_in_where_are_refused(self):
        for text in ("index=a | where x=1 y=2", "index=a | where x=1 not y=2"):
            with self.assertRaises(Refusal) as ctx:
                dialects.lower("splunk", text)
            self.assertEqual(ctx.exception.code, "SPL_EXPRESSION_TRAILING")

    def test_unquoted_value_is_text_not_a_field(self):
        self.assertEqual(verdict("splunk", "index=a user=bob", {"user": "bob"}), "matched")
        self.assertEqual(verdict("splunk", "index=a user=bob", {"user": "alice"}), "no_match")
        self.assertEqual(
            verdict("splunk", "index=a Account_Name!=SYSTEM", {"Account_Name": "alice"}), "matched"
        )

    def test_search_values_ignore_case(self):
        self.assertEqual(verdict("splunk", 'index=a Image="cmd.exe"', {"Image": "CMD.EXE"}), "matched")
        # ...but `where` compares exactly, as eval does.
        self.assertEqual(verdict("splunk", 'index=a | where Image=="cmd.exe"', {"Image": "CMD.EXE"}), "no_match")

    def test_wildcards_match(self):
        cases = [
            ('CommandLine="*mimikatz*"', {"CommandLine": "C:\\x\\Mimikatz.exe"}, "matched"),
            ('CommandLine="*mimikatz*"', {"CommandLine": "notepad"}, "no_match"),
            ('Image="C:\\\\Windows\\\\*"', {"Image": "C:\\Windows\\x.exe"}, "matched"),
            ('Image="C:\\\\Windows\\\\*"', {"Image": "D:\\Windows\\x.exe"}, "no_match"),
            ("host=web*", {"host": "web01"}, "matched"),
            ('A="a\\*b"', {"A": "a*b"}, "matched"),
            ('A="a\\*b"', {"A": "aXb"}, "no_match"),
            ('A IN ("foo*","bar")', {"A": "FOOD"}, "matched"),
        ]
        for term, event, expected in cases:
            with self.subTest(term=term):
                self.assertEqual(verdict("splunk", f"index=a {term}", event), expected)

    def test_earliest_is_not_a_field(self):
        rule, _ = dialects.lower("splunk", "index=a earliest=-10m x=1")
        self.assertEqual(evaluate(rule, [{"x": 1}]).verdict, "matched")


class SigmaValues(unittest.TestCase):
    def test_wildcards_and_escapes(self):
        cases = [
            ("A: 'foo*'", {"A": "foobar"}, "matched"),
            ("A: '*bar'", {"A": "foobar"}, "matched"),
            ("A: 'f*r'", {"A": "foobar"}, "matched"),
            ("A: 'fo?bar'", {"A": "foobar"}, "matched"),
            ("A: 'fo?bar'", {"A": "fobar"}, "no_match"),
            ("A: 'a\\*b'", {"A": "a*b"}, "matched"),
            ("A: 'a\\*b'", {"A": "aXb"}, "no_match"),
            ("A|contains: 'o*b'", {"A": "foobar"}, "matched"),
            ("A|endswith: '\\cmd.exe'", {"A": "c:\\w\\cmd.exe"}, "matched"),
        ]
        for line, event, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(
                    verdict("sigma", sigma(f"s:\n  {line}\ncondition: s"), event), expected
                )

    def test_literal_star_from_another_dialect_is_escaped(self):
        # `A == "*"` exported as `A: '*'` matched every event.
        rule, _ = dialects.lower("sentinel", 'T | where A == "*"')
        text, _ = dialects.render("sigma", rule)
        again, _ = dialects.lower("sigma", text)
        self.assertEqual(evaluate(again, [{"A": "anything"}]).verdict, "no_match")
        self.assertEqual(evaluate(again, [{"A": "*"}]).verdict, "matched")

    def test_exact_case_equality_keeps_cased(self):
        rule, _ = dialects.lower("sentinel", 'T | where Account == "SYSTEM"')
        text, _ = dialects.render("sigma", rule)
        self.assertIn("|cased", text)

    def test_yaml_quoted_key_comment_and_numbers(self):
        def ir(line):
            rule, _ = dialects.lower("sigma", sigma(f"s:\n  {line}\ncondition: s"))
            return evaluate(rule, [{}]).caveats and None, rule
        # quoted key: the field name has no quote characters
        rule, _ = dialects.lower("sigma", sigma("s:\n  'Event Data.Name': foo\ncondition: s"))
        self.assertEqual(evaluate(rule, [{"Event Data": {"Name": "foo"}}]).verdict, "matched")
        # an apostrophe in a plain scalar does not hide the comment
        self.assertEqual(
            verdict("sigma", sigma("s:\n  A: it's here # note\ncondition: s"), {"A": "it's here"}),
            "matched",
        )
        # an escaped quote inside a double-quoted scalar
        self.assertEqual(
            verdict("sigma", sigma('s:\n  A: "a\\"b" # c\ncondition: s'), {"A": 'a"b'}), "matched"
        )
        # leading zeros are an identifier, not the number 7
        rule, _ = dialects.lower("sigma", sigma("s:\n  A: 007\ncondition: s"))
        rendered, _ = dialects.render("sentinel", rule)
        self.assertIn('"007"', rendered)          # kept as text, not the number 7
        self.assertEqual(evaluate(rule, [{"A": "007"}]).verdict, "matched")

    def test_huge_integer_is_text_not_a_crash(self):
        text = sigma("s:\n  A: " + "9" * 5000 + "\ncondition: s")
        dialects.lower("sigma", text)  # must not raise ValueError


class RenderQuoting(unittest.TestCase):
    def test_splunk_double_quote_is_escaped_once(self):
        for value in ('powershell -c "iex', 'a"b'):
            with self.subTest(value=value):
                text, _ = dialects.render(
                    "splunk",
                    dialects.lower("sigma", sigma(f"s:\n  C|contains: '{value}'\ncondition: s"))[0],
                )
                self.assertNotIn('\\\\"', text)
                again, _ = dialects.lower("splunk", text)
                self.assertEqual(evaluate(again, [{"C": f"x {value} y"}]).verdict, "matched")

    def test_crowdstrike_apostrophe_is_escaped_once(self):
        for value in ("it''s", "a''b''c"):  # YAML-doubled
            with self.subTest(value=value):
                text, _ = dialects.render(
                    "crowdstrike",
                    dialects.lower("sigma", sigma(f"s:\n  C|contains: '{value}'\ncondition: s"))[0],
                )
                self.assertNotIn("\\\\'", text)
                again, _ = dialects.lower("crowdstrike", text)
                plain = value.replace("''", "'")
                self.assertEqual(evaluate(again, [{"C": f"z {plain} z"}]).verdict, "matched")

    def test_exact_case_into_case_folding_dialect_warns(self):
        rule, _ = dialects.lower("sentinel", 'T | where Account == "SYSTEM"')
        _, diags = dialects.render("crowdstrike", rule)
        self.assertIn("RENDER_CASE_FOLD_ADDED", [d.code for d in diags])

    def test_elastic_refuses_literal_wildcard_in_folded_equality(self):
        with self.assertRaises(Refusal) as ctx:
            dialects.render("elastic", dialects.lower("sigma", sigma("s:\n  A: 'a\\*b'\ncondition: s"))[0])
        self.assertEqual(ctx.exception.code, "EQL_RENDER_LITERAL_WILDCARD")

    def test_wazuh_rule_id_is_numeric(self):
        sig = sigma("s:\n  A: x\ncondition: s").replace(
            "title: t", "title: t\nid: 12345678-aaaa-bbbb-cccc-123456789012"
        )
        text, _ = dialects.render("wazuh", dialects.lower("sigma", sig)[0])
        self.assertRegex(text, r'<rule id="\d+"')


def _events(minutes, user="bob"):
    base = dt.datetime(2026, 1, 1, 12, 0, 0)
    return [
        {"EventID": 4625, "TargetUserName": user,
         "TimeGenerated": (base + dt.timedelta(minutes=m)).isoformat() + "Z"}
        for m in minutes
    ]


class Windows(unittest.TestCase):
    KQL = (
        "SecurityEvent\n| where EventID == 4625\n"
        "| summarize FailCount = count() by TargetUserName, bin(TimeGenerated, 10m)\n"
        "| where FailCount > 5"
    )

    def test_kql_bin_counts_inside_a_bucket(self):
        rule, _ = dialects.lower("sentinel", self.KQL)
        self.assertEqual(evaluate(rule, _events([1, 2, 3, 4, 5, 6])).verdict, "matched")
        self.assertEqual(evaluate(rule, _events([0, 60, 120, 180, 240, 300])).verdict, "no_match")

    def test_kql_bin_is_not_also_a_group_key(self):
        rule, _ = dialects.lower("sentinel", self.KQL)
        text, _ = dialects.render("sigma", rule)
        self.assertNotIn("TimeGenerated", text.split("group-by:")[1])

    def test_splunk_bin_keeps_the_window(self):
        rule, _ = dialects.lower(
            "splunk",
            "index=w EventID=4625 | bin _time span=10m | stats count by _time, TargetUserName | where count > 5",
        )
        spread = [dict(e, _time=e["TimeGenerated"]) for e in _events([0, 60, 120, 180, 240, 300])]
        tight = [dict(e, _time=e["TimeGenerated"]) for e in _events([0, 1, 2, 3, 4, 5])]
        self.assertEqual(evaluate(rule, spread).verdict, "no_match")
        self.assertEqual(evaluate(rule, tight).verdict, "matched")

    def test_splunk_render_uses_bin_not_by_span(self):
        rule, _ = dialects.lower("sentinel", self.KQL)
        text, _ = dialects.render("splunk", rule)
        self.assertIn("| bin ", text)
        self.assertNotIn("by _time span", text)

    def test_qradar_refuses_a_window_it_cannot_express(self):
        rule, _ = dialects.lower("sentinel", self.KQL)
        with self.assertRaises(Refusal) as ctx:
            dialects.render("qradar", rule)
        self.assertEqual(ctx.exception.code, "AQL_RENDER_WINDOW")

    def test_kql_default_aggregate_names(self):
        rule, _ = dialects.lower(
            "sentinel", "T | summarize dcount(Computer) by U | where dcount_Computer > 1"
        )
        events = [{"U": "a", "Computer": "c1"}, {"U": "a", "Computer": "c2"}]
        self.assertEqual(evaluate(rule, events).verdict, "matched")


class Sandbox(unittest.TestCase):
    def test_catastrophic_regex_is_stopped_not_hung(self):
        rule, _ = dialects.lower(
            "sigma", sigma('s:\n  A|re: "(a{1,10}){1,10}$"\ncondition: s')
        )
        with self.assertRaises(Refusal) as ctx:
            evaluate_with_timeout(rule, [{"A": "a" * 60 + "!"}], seconds=3)
        self.assertEqual(ctx.exception.code, "EVALUATION_TIMEOUT")

    def test_ordinary_regex_still_evaluates(self):
        rule, _ = dialects.lower("sigma", sigma("s:\n  A|re: '^ab+c$'\ncondition: s"))
        self.assertEqual(evaluate_with_timeout(rule, [{"A": "abbbc"}]).verdict, "matched")


class Boundaries(unittest.TestCase):
    def test_deep_nesting_is_a_refusal(self):
        text = "t | where " + "(" * 5000 + "A == 1" + ")" * 5000
        with self.assertRaises(Refusal) as ctx:
            dialects.lower("sentinel", text)
        self.assertEqual(ctx.exception.code, "INPUT_TOO_DEEPLY_NESTED")

    def test_store_is_owner_only(self):
        if os.name == "nt":
            self.skipTest("POSIX modes")
        path = os.path.join(tempfile.mkdtemp(), "sub", "h.sqlite3")
        RuleStore(path)
        self.assertEqual(os.stat(path).st_mode & 0o077, 0)
        self.assertEqual(os.stat(os.path.dirname(path)).st_mode & 0o077, 0)


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        store = RuleStore(os.path.join(tempfile.mkdtemp(), "t.sqlite3"))
        cls.server = build_server("127.0.0.1", 0, store)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def raw(self, request: bytes) -> str:
        sock = socket.create_connection(("127.0.0.1", self.port))
        sock.settimeout(1.0)
        sock.sendall(request)
        out = b""
        try:
            while chunk := sock.recv(65536):
                out += chunk
        except OSError:
            pass
        sock.close()
        return out.decode(errors="replace")

    def test_reads_need_a_loopback_host(self):
        for host in ("evil.example", "127.0.0.1.evil.com", "127.attacker.com"):
            with self.subTest(host=host):
                reply = self.raw(
                    f"GET /api/history HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
                )
                self.assertIn(" 403 ", reply.split("\r\n")[0])
        ok = self.raw(
            f"GET /api/history HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nConnection: close\r\n\r\n".encode()
        )
        self.assertIn(" 200 ", ok.split("\r\n")[0])

    def test_unread_body_cannot_become_the_next_request(self):
        smuggled = b"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        reply = self.raw(
            b"POST /api/nope HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
            b"Content-Length: %d\r\n\r\n%s" % (len(smuggled), smuggled)
        )
        self.assertEqual(reply.count("HTTP/1.1 "), 1)

    def test_null_byte_in_a_static_path(self):
        reply = self.raw(b"GET /static/%00 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        self.assertIn(" 404 ", reply.split("\r\n")[0])


if __name__ == "__main__":
    unittest.main()
