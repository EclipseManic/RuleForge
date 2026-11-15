"""Run every corpus rule through the tool and report what fails.

This is the external-corpus harness the user asked for: real-shaped rules for
all eight dialects, driven through lower -> render -> re-lower, plus a
cross-render to every other dialect. Nothing is sent anywhere; every rule runs
locally against the in-process engine.

Usage:
    python corpus/run_corpus.py            # summary
    python corpus/run_corpus.py --full     # every rule's outcome
    python corpus/run_corpus.py --dialect sigma

Or through the one entry point:

    python run.py corpus --full
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import dialects                                   # noqa: E402
from engine.values import Refusal                             # noqa: E402


HERE = os.path.dirname(os.path.abspath(__file__))
TARGETS = [
    "sentinel", "sigma", "splunk", "qradar",
    "elastic", "wazuh", "chronicle", "crowdstrike",
]


def load(dialect: str) -> dict[str, str]:
    path = os.path.join(HERE, "rules", f"{dialect}.json")
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"corpus is missing for dialect `{dialect}`: {path}"
        )
    with io.open(path, encoding="utf-8") as handle:
        return json.load(handle)


def check(dialect: str, name: str, text: str, cross: bool) -> dict:
    """One rule's full journey. Every step is recorded, none is fatal."""
    report = {"dialect": dialect, "name": name, "problems": [], "ok": True}
    try:
        rule, notes = dialects.lower(dialect, text)
    except Refusal as exc:
        report["ok"] = False
        report["problems"].append(("lower", exc.code, exc.message[:180]))
        return report
    except Exception as exc:                                # noqa: BLE001
        report["ok"] = False
        report["problems"].append(
            ("lower-crash", type(exc).__name__, str(exc)[:180])
        )
        return report

    for note in notes:
        if note.severity == "problem":
            report["problems"].append(("lower-note", note.code, note.message[:180]))

    try:
        out, rnotes = dialects.render(dialect, rule)
    except Refusal as exc:
        report["ok"] = False
        report["problems"].append(("render", exc.code, exc.message[:180]))
        return report
    except Exception as exc:                                # noqa: BLE001
        report["ok"] = False
        report["problems"].append(
            ("render-crash", type(exc).__name__, str(exc)[:180])
        )
        return report

    for note in rnotes:
        if note.severity == "problem":
            report["problems"].append(("render-note", note.code, note.message[:180]))

    try:
        again, _ = dialects.lower(dialect, out)
        report["stable"] = [type(n).__name__ for n in again.pipeline] == [
            type(n).__name__ for n in rule.pipeline
        ]
        if not report["stable"]:
            report["problems"].append(
                ("round-trip", "STAGE_SHAPE_CHANGED",
                 f"{[type(n).__name__ for n in rule.pipeline]} -> "
                 f"{[type(n).__name__ for n in again.pipeline]}")
            )
            report["ok"] = False
    except Refusal as exc:
        report["ok"] = False
        report["problems"].append(
            ("re-lower", exc.code, exc.message[:180])
        )
    except Exception as exc:                                # noqa: BLE001
        report["ok"] = False
        report["problems"].append(
            ("re-lower-crash", type(exc).__name__, str(exc)[:180])
        )

    if cross:
        report["cross"] = {}
        for target in TARGETS:
            if target == dialect:
                continue
            try:
                other, notes = dialects.render(target, rule)
                severity = [
                    n.code for n in notes if n.severity == "problem"
                ]
                if severity:
                    report["cross"][target] = {
                        "status": "refused-problem",
                        "diagnostics": severity,
                    }
                    continue
                try:
                    dialects.lower(target, other)
                except Refusal as exc:
                    report["cross"][target] = {
                        "status": "self-parse-refusal",
                        "code": exc.code,
                    }
                    report["ok"] = False
                except Exception as exc:                        # noqa: BLE001
                    report["cross"][target] = {
                        "status": "self-parse-crash",
                        "error": type(exc).__name__,
                    }
                    report["ok"] = False
                else:
                    report["cross"][target] = {"status": "ok"}
            except Refusal as exc:
                report["cross"][target] = {
                    "status": "refused",
                    "code": exc.code,
                }
            except Exception as exc:                        # noqa: BLE001
                report["cross"][target] = {
                    "status": "crash",
                    "error": type(exc).__name__,
                }
                report["ok"] = False

    report["ok"] = report["ok"] and not report["problems"]
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--dialect")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--cross", action="store_true")
    args = parser.parse_args()

    chosen = [args.dialect] if args.dialect else TARGETS
    all_reports = []
    missing = []
    for dialect in chosen:
        try:
            rules = load(dialect)
        except FileNotFoundError as exc:
            missing.append((dialect, str(exc)))
            continue
        for name, text in rules.items():
            report = check(dialect, name, text, args.cross)
            all_reports.append(report)

    if args.json:
        print(json.dumps({"reports": all_reports, "missing": missing},
                         indent=2, default=str))
        return 1 if missing or any(not r["ok"] for r in all_reports) else 0

    by_dialect: dict[str, list[dict]] = {}
    for report in all_reports:
        by_dialect.setdefault(report["dialect"], []).append(report)

    total = len(all_reports)
    broken = [r for r in all_reports if not r["ok"]]
    print(f"{total} rules, {total - len(broken)} clean, {len(broken)} with problems\n")

    for dialect in chosen:
        reports = by_dialect.get(dialect, [])
        bad = [r for r in reports if not r["ok"]]
        if not reports and any(name == dialect for name, _ in missing):
            print(f"{dialect:12s} MISSING CORPUS")
            continue
        print(f"{dialect:12s} {len(reports):3d} rules  {len(bad):3d} broken")
        for report in bad:
            for step, code, message in report["problems"]:
                print(f"    {report['name']:34s} {step:12s} {code}")
                if args.full:
                    print(f"        {message}")
    if missing:
        print("\nMissing corpus coverage:")
        for dialect, message in missing:
            print(f"  {dialect}: {message}")
    return 1 if broken or missing else 0


if __name__ == "__main__":
    sys.exit(main())
