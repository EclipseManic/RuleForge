"""Log samples to a proposed rule: the third pillar, moved to the backend.

This logic lived entirely in `web/static/app.js`, which made it the one part
of the tool the test suite could not reach. That matters more here than
anywhere else, because the decision this module makes -- WHICH fields become
the detection -- is the decision that determines whether the result is a rule
or a rule that matches everything. Pin too few fields and the rule fires on
the whole estate; pin a field that only happened to be constant across three
samples and it fires on nothing in production.

So the output is a HYPOTHESIS, and every judgement it makes is reported rather
than applied quietly:

**A field that varies is not a detection.** If `Image` is `a.exe` in one
sample and `b.exe` in the next, no single equality test covers both. The
default is to drop it and say so. `skip_volatile=False` keeps it, pinned to
the FIRST sample's value, and the result carries a caution saying the rule now
matches that one value rather than the behaviour.

**A field that is absent from some samples cannot be required.** Pinning it
produces a rule that cannot match the samples it is missing from -- which the
analyst will read as "the rule is broken" long before they suspect the
generator.

**A null is not a value.** `field: null` lowers to a comparison the evaluator
reports as UNDECIDED by design (see `ir.Comparison`), so a rule pinned to one
can never return an answer at all. Those fields are refused as detection
material no matter what the flags say.

**Nested events are flattened to dotted paths.** `{"process": {"name": "x"}}`
becomes `process.name`, which `FieldRef.parse` already understands. Reading
only the top level -- which the JavaScript did -- pinned `process` to a whole
JSON object and produced a predicate no engine can evaluate. Every modern log
shape is nested, so that was the common case rather than an edge one.

**The threshold is stated, not implied.** A count and a window are invented by
this module, not found in the data, so both are parameters and both are named
in the rule's own description.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field as dc_field
from decimal import Decimal, InvalidOperation
from typing import Any, Final

from .dialects.common import Diagnostic
from .ir import (
    Aggregate,
    Annotations,
    Comparison,
    Emit,
    FieldRef,
    Filter,
    Literal,
    Measure,
    Node,
    Read,
    Rule,
    Window,
)
from .validate import validate
from .values import Duration, Refusal

__all__ = [
    "FORMATS",
    "VOLATILE_NAME",
    "VOLATILE_SHAPES",
    "MIN_SAMPLES",
    "Options",
    "FieldReport",
    "parse_events",
    "flatten",
    "analyse",
    "propose",
]

#: The sample formats this module reads.
FORMATS: Final[frozenset[str]] = frozenset({"json", "jsonl", "kv", "syslog"})

#: Two samples is the floor, and it is a refusal rather than a warning.
#:
#: One event cannot distinguish a stable field from a volatile one, so every
#: field looks constant and the proposal pins all of them -- a rule that
#: matches exactly the line that was pasted and nothing else. The analyst then
#: has a rule that passes its own test and never fires again.
MIN_SAMPLES: Final = 2

#: Field NAMES that are per-event by convention.
VOLATILE_NAME: Final = re.compile(
    r"(^|[._-])("
    r"time|timestamp|ts|date|datetime|created|modified|received"
    r"|id|uuid|guid|pid|ppid|tid|sid|seq|sequence|offset|cursor"
    r"|hash|md5|sha1|sha256|sha512|checksum|etag"
    r"|duration|elapsed|latency|bytes|size|count|port"
    r"|session|request|trace|span|correlation|nonce|token"
    r")($|[._-])",
    re.I,
)

#: Field VALUES that are per-event by shape.
VOLATILE_SHAPES: Final[tuple[re.Pattern[str], ...]] = (
    # ISO-8601 and common log timestamps
    re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}"),
    re.compile(r"^\d{2}/\w{3}/\d{4}:\d{2}:\d{2}"),
    # epoch seconds or milliseconds
    re.compile(r"^1[0-9]{9}(\.[0-9]+)?$"),
    re.compile(r"^1[0-9]{12}$"),
    # UUID
    re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.I,
    ),
    # hex digests
    re.compile(r"^[0-9a-f]{32}$", re.I),
    re.compile(r"^[0-9a-f]{40}$", re.I),
    re.compile(r"^[0-9a-f]{64}$", re.I),
)

#: Keys whose value is a per-event identifier even when the shape looks tame.
_KV_PATTERN: Final = re.compile(
    r"([A-Za-z_][\w.\-]*)=(\"([^\"]*)\"|'([^']*)'|(\S*))"
)
_FIRST_KV: Final = re.compile(r"[A-Za-z_][\w.\-]*=")


@dataclass(frozen=True, slots=True)
class Options:
    """What the caller decided, as data.

    Defaults are the cautious ones: drop anything that varies, drop anything
    that looks per-event, and propose no threshold. A generator whose defaults
    produce the widest rule is a generator that produces wide rules.
    """

    table: str = "events"
    skip_volatile: bool = True
    skip_timestamps: bool = True
    threshold: bool = False
    group_by: tuple[str, ...] = ()
    #: Only used when `threshold` is set. Named rather than hardcoded, because
    #: a count and a window are invented by this module and an analyst is
    #: entitled to know which numbers were chosen for them.
    frequency: int = 5
    window_seconds: int = 300
    max_fields: int = 200


@dataclass(frozen=True, slots=True)
class FieldReport:
    """One field, and why it was pinned or passed over."""

    name: str
    sample: Any
    distinct: int
    present: int
    total: int
    include: bool
    reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "sample": self.sample,
            "distinct": self.distinct,
            "present": self.present,
            "total": self.total,
            "include": self.include,
            "reasons": list(self.reasons),
        }


# ---------------------------------------------------------------------------
# Reading samples
# ---------------------------------------------------------------------------


def _coerce(text: str) -> Any:
    """A key=value string to a typed value.

    Numbers become `Decimal` because the whole engine compares numbers as
    Decimal; leaving them as strings would make `EventCode=4625` compare as
    text against a rule written with an integer.
    """
    # A BOM makes `json.loads` fail outright, and in `kv` form it
    # renames the first key. Windows tooling writes them constantly.
    body = text.lstrip("\ufeff").strip()
    if not body:
        return ""
    lowered = body.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in ("null", "none", "-"):
        return None
    try:
        return Decimal(body)
    except InvalidOperation:
        return body


def parse_events(text: str, fmt: str) -> list[dict[str, Any]]:
    """Sample text to a list of events.

    Every failure names the line it failed on. "Could not parse the samples"
    sends an analyst scanning two hundred lines by eye.
    """
    if fmt not in FORMATS:
        raise Refusal(
            "SYNTH_FORMAT_UNKNOWN",
            f"`{fmt}` is not a sample format this tool reads. Known formats: "
            f"{', '.join(sorted(FORMATS))}.",
            "synthesize",
        )

    # A BOM makes `json.loads` fail outright ("Unexpected UTF-8 BOM") and in
    # `kv` form it renames the first key. Windows editors, PowerShell
    # redirection and Git on Windows all write them, so a pasted or uploaded
    # sample carrying one is the common case rather than an exotic one.
    body = text.lstrip("\ufeff").strip()
    if not body:
        raise Refusal(
            "SYNTH_NO_SAMPLES",
            "there is no sample text to read.",
            "synthesize",
        )

    if fmt == "json":
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise Refusal(
                "SYNTH_JSON_INVALID",
                f"this is not valid JSON: {exc.msg} at line {exc.lineno} "
                f"column {exc.colno}.",
                "synthesize",
            ) from None
        if not isinstance(parsed, list):
            raise Refusal(
                "SYNTH_JSON_NOT_A_LIST",
                f"the JSON format expects an ARRAY of events and this is a "
                f"{type(parsed).__name__}. A single object is one sample, and "
                f"one sample cannot tell a stable field from a volatile one.",
                "synthesize",
            )
        return [_as_event(e, index) for index, e in enumerate(parsed, 1)]

    lines = [l.strip() for l in body.splitlines() if l.strip()]

    if fmt == "jsonl":
        out: list[dict[str, Any]] = []
        for number, line in enumerate(lines, 1):
            try:
                out.append(_as_event(json.loads(line), number))
            except json.JSONDecodeError as exc:
                raise Refusal(
                    "SYNTH_JSONL_INVALID",
                    f"line {number} is not valid JSON: {exc.msg}. The whole "
                    f"sample is refused rather than silently skipping the "
                    f"line, because a field's stability is measured across "
                    f"the samples and a missing one changes the answer.",
                    "synthesize",
                ) from None
        return out

    # kv and syslog
    out = []
    for number, line in enumerate(lines, 1):
        text_body = line
        if fmt == "syslog":
            # Drop the leading priority/timestamp/host header so it does not
            # become three volatile fields.
            first = _FIRST_KV.search(text_body)
            if first is not None and first.start() > 0:
                text_body = text_body[first.start():]
        event: dict[str, Any] = {}
        for match in _KV_PATTERN.finditer(text_body):
            raw = (
                match.group(3) if match.group(3) is not None
                else match.group(4) if match.group(4) is not None
                else match.group(5)
            )
            event[match.group(1)] = _coerce(raw or "")
        if not event:
            raise Refusal(
                "SYNTH_NO_FIELDS_ON_LINE",
                f"line {number} has no `key=value` pairs, so it contributes "
                f"no fields. A sample that parses to nothing would make every "
                f"other field look absent from one event.",
                "synthesize",
            )
        out.append(event)
    return out


def _as_event(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Refusal(
            "SYNTH_SAMPLE_NOT_AN_OBJECT",
            f"sample {index} is a {type(value).__name__}, not an object with "
            f"fields. There is nothing to build a predicate from.",
            "synthesize",
        )
    return value


# ---------------------------------------------------------------------------
# Flattening
# ---------------------------------------------------------------------------


def flatten(event: dict[str, Any], limit: int = 200) -> dict[str, Any]:
    """Nested objects to dotted paths.

    `{"process": {"name": "x"}}` becomes `{"process.name": "x"}`, which is the
    shape `FieldRef.parse` already reads. Walking only the top level pinned
    `process` to a whole JSON object and produced a predicate comparing an
    object to an object -- something no engine can evaluate, and the common
    case rather than an edge one, because ECS, UDM and Sysmon JSON are all
    nested.

    A LIST is left whole rather than indexed. `args[0]` is a position, not a
    field: pinning it would make the rule depend on argument order, which the
    next version of the logging agent is free to change.
    """
    out: dict[str, Any] = {}

    def walk(prefix: str, value: Any) -> None:
        if len(out) >= limit:
            return
        if isinstance(value, dict):
            if not value:
                # An empty object holds no field to test. Recorded as itself so
                # the report can say the field was present and had nothing in
                # it.
                out[prefix] = value
                return
            for key, inner in value.items():
                child = f"{prefix}.{key}" if prefix else str(key)
                walk(child, inner)
            return
        out[prefix] = value

    walk("", event)
    out.pop("", None)
    return out


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def _looks_volatile(name: str, sample: Any) -> str:
    """Why this field looks per-event, or an empty string."""
    if VOLATILE_NAME.search(name):
        return "the name suggests a per-event value"
    if isinstance(sample, str):
        for shape in VOLATILE_SHAPES:
            if shape.match(sample):
                return "the value looks like a timestamp, an id or a hash"
    return ""


def _usable_as_a_predicate(value: Any) -> str:
    """Why this value cannot be a detection, or an empty string.

    A null pins to a comparison the evaluator reports as UNDECIDED by design,
    so the rule can never return an answer. A container has no equality any
    vendor spells the same way. Both are refused regardless of the flags,
    because no setting makes them work.
    """
    if value is None:
        return (
            "its value is null, and a comparison against null is undecidable "
            "by design -- a rule pinned to it can never return an answer"
        )
    if isinstance(value, (dict, list, tuple, set)):
        return (
            "its value is a container, and no two vendors spell container "
            "equality the same way"
        )
    if isinstance(value, str) and not value.strip():
        return (
            "its value is empty, and an empty string is not the same question "
            "as an absent field"
        )
    return ""


def analyse(
    events: list[dict[str, Any]], options: Options | None = None
) -> list[FieldReport]:
    """Every field across the samples, with a verdict and its reasons.

    Order follows first appearance, so the report reads in the same order as
    the pasted sample rather than alphabetically.
    """
    settings = options or Options()
    if len(events) < MIN_SAMPLES:
        raise Refusal(
            "SYNTH_TOO_FEW_SAMPLES",
            f"{len(events)} sample(s) is not enough. One event cannot "
            f"distinguish a stable field from a volatile one, so every field "
            f"looks constant and the proposal pins all of them -- a rule that "
            f"matches exactly the line pasted and nothing else. Paste at "
            f"least {MIN_SAMPLES} samples of the same behaviour.",
            "synthesize",
        )

    flattened = [flatten(e, settings.max_fields) for e in events]

    names: list[str] = []
    for event in flattened:
        for key in event:
            if key not in names:
                names.append(key)

    reports: list[FieldReport] = []
    for name in names:
        holders = [e for e in flattened if name in e]
        values = [e[name] for e in holders]
        # Compared by their JSON spelling so two equal values of different
        # types do not read as distinct, and unhashable values can still be
        # counted.
        seen: list[str] = []
        for value in values:
            token = json.dumps(value, sort_keys=True, default=str)
            if token not in seen:
                seen.append(token)
        sample = values[0] if values else None

        reasons: list[str] = []
        missing = len(events) - len(holders)
        if missing:
            reasons.append(
                f"missing from {missing} of {len(events)} samples"
            )
        if len(seen) > 1:
            reasons.append(f"differs between samples ({len(seen)} values)")
        volatile = _looks_volatile(name, sample)
        if volatile:
            reasons.append(volatile)
        unusable = _usable_as_a_predicate(sample)
        if unusable:
            reasons.append(unusable)

        # The decision, as a chain where each step says what it rules out.
        #
        # The JavaScript this replaces ended with an UNCONDITIONAL
        # `if (include && distinct > 1) include = false`, so a varying field
        # was always dropped and `skip_volatile` could not be turned off --
        # while the error message told the analyst to untick it "to decide
        # yourself". The flags now mean what they say.
        include = True
        if unusable:
            include = False
        elif settings.skip_volatile and len(seen) > 1:
            include = False
        elif settings.skip_volatile and missing:
            include = False
        elif settings.skip_timestamps and volatile:
            include = False

        reports.append(FieldReport(
            name=name,
            sample=sample,
            distinct=len(seen),
            present=len(holders),
            total=len(events),
            include=include,
            reasons=tuple(reasons),
        ))
    return reports


# ---------------------------------------------------------------------------
# Proposal
# ---------------------------------------------------------------------------


def propose(
    events: list[dict[str, Any]],
    options: Options | None = None,
    rule_id: str = "from-log-sample",
) -> tuple[Rule, list[FieldReport], list[Diagnostic]]:
    """A proposed Rule, the field report behind it, and what to be wary of.

    The report is returned alongside the rule on purpose: a generated rule
    without the reasoning that produced it is a rule an analyst has to
    reverse-engineer before they can trust it.
    """
    settings = options or Options()
    reports = analyse(events, settings)
    chosen = [r for r in reports if r.include]
    diagnostics: list[Diagnostic] = []

    if not chosen:
        dropped = "; ".join(
            f"{r.name} ({r.reasons[0]})" for r in reports if r.reasons
        )[:600]
        raise Refusal(
            "SYNTH_NO_STABLE_FIELDS",
            f"none of these {len(reports)} fields can carry a detection, so "
            f"any rule built from them would match only the exact events "
            f"pasted. {dropped or 'No field was constant across the samples.'} "
            f"Paste samples of the SAME behaviour, or turn off the field "
            f"filters to pin them yourself.",
            "synthesize",
        )

    # Every generated rule says it was generated. A proposal that reads like an
    # authored rule is a proposal that gets deployed without review.
    diagnostics.append(Diagnostic(
        code="SYNTH_IS_A_HYPOTHESIS",
        message=(
            f"this rule was derived from {len(events)} log samples, not "
            f"authored. It pins {len(chosen)} field(s): "
            f"{', '.join(r.name for r in chosen)}. A field that happened to be "
            f"constant across these samples is not necessarily constant in "
            f"production -- check every one before deploying."
        ),
        severity="caution",
        verified=True,
    ))

    varying = [r for r in chosen if r.distinct > 1]
    if varying:
        diagnostics.append(Diagnostic(
            code="SYNTH_PINNED_A_VARYING_FIELD",
            message=(
                f"{', '.join(r.name for r in varying)} differ between the "
                f"samples and have been pinned to the FIRST sample's value "
                f"because the volatile-field filter is off. The rule now "
                f"matches that one value rather than the behaviour the samples "
                f"share."
            ),
            severity="problem",
            verified=True,
        ))

    partial = [r for r in chosen if r.present < r.total]
    if partial:
        diagnostics.append(Diagnostic(
            code="SYNTH_PINNED_A_PARTIAL_FIELD",
            message=(
                f"{', '.join(r.name for r in partial)} are absent from some of "
                f"the samples. Requiring them means the rule cannot match the "
                f"events they are missing from -- including, probably, some of "
                f"the ones pasted here."
            ),
            severity="problem",
            verified=True,
        ))

    volatile_kept = [
        r for r in chosen if _looks_volatile(r.name, r.sample)
    ]
    if volatile_kept:
        diagnostics.append(Diagnostic(
            code="SYNTH_PINNED_A_VOLATILE_FIELD",
            message=(
                f"{', '.join(r.name for r in volatile_kept)} look like "
                f"per-event values (a timestamp, an id or a hash). Pinning one "
                f"produces a rule that matches a single past event and nothing "
                f"after it."
            ),
            severity="problem",
            verified=True,
        ))

    nodes: list[Node] = [
        Read(id="source", table=settings.table or "events")
    ]
    for index, report in enumerate(chosen, start=1):
        nodes.append(Filter(
            id=f"where_{index}",
            condition=Comparison(
                "==", FieldRef.parse(report.name), Literal(report.sample)
            ),
        ))

    if settings.threshold:
        keys = tuple(
            FieldRef.parse(name) for name in settings.group_by if name.strip()
        )
        if not keys:
            # Grouping on nothing counts across the whole stream, so a rule
            # meant for "five from one host" fires on five spread across the
            # estate. The first pinned field is a guess, and it is reported as
            # one.
            keys = (FieldRef.parse(chosen[0].name),)
            diagnostics.append(Diagnostic(
                code="SYNTH_GROUP_KEY_ASSUMED",
                message=(
                    f"a threshold was requested with no grouping, so it is "
                    f"grouped by `{chosen[0].name}` -- the first pinned field. "
                    f"That is a guess. A count grouped on the wrong field is "
                    f"a count across the whole estate, which fires on ordinary "
                    f"background noise."
                ),
                severity="problem",
                verified=True,
            ))
        if settings.frequency < 2:
            raise Refusal(
                "SYNTH_THRESHOLD_NOT_A_THRESHOLD",
                f"a threshold of {settings.frequency} fires on the first "
                f"matching event, which is the same rule without the "
                f"threshold and a slower way to run it.",
                "synthesize",
            )
        if settings.window_seconds <= 0:
            raise Refusal(
                "SYNTH_WINDOW_NOT_POSITIVE",
                f"a window of {settings.window_seconds} seconds holds no "
                f"events, so the rule can never fire.",
                "synthesize",
            )
        nodes.append(Aggregate(
            id="summarize",
            measures=(Measure(function="count", name="Hits"),),
            keys=keys,
            window=Window(
                kind="tumbling",
                size=Duration(Decimal(settings.window_seconds)),
            ),
        ))
        nodes.append(Filter(
            id="threshold",
            condition=Comparison(
                ">=", FieldRef.parse("Hits"),
                Literal(Decimal(settings.frequency)),
            ),
        ))
        diagnostics.append(Diagnostic(
            code="SYNTH_THRESHOLD_INVENTED",
            message=(
                f"the threshold of {settings.frequency} events per "
                f"{settings.window_seconds}s was chosen by this tool, not "
                f"found in the samples. Nothing in {len(events)} log lines "
                f"says what a normal rate looks like, so tune it against your "
                f"own volume before deploying."
            ),
            severity="caution",
            verified=True,
        ))

    nodes.append(Emit(id="out"))

    pinned = ", ".join(r.name for r in chosen)
    rule = Rule(
        rule_id=rule_id,
        pipeline=tuple(nodes),
        bindings=(),
        annotations=Annotations(
            title=f"Proposed from {len(events)} log samples",
            description=(
                f"Generated from a log sample, not authored. Pinned fields: "
                f"{pinned}. Review every one before deploying: a field that "
                f"happened to be constant across these samples is not "
                f"necessarily constant in production."
                + (
                    f" The threshold of {settings.frequency} per "
                    f"{settings.window_seconds}s was chosen by the generator."
                    if settings.threshold else ""
                )
            ),
        ),
        metadata={
            "dialect": "",
            "language": "",
            "artifact": "rule",
            "synthesize.samples": str(len(events)),
            "synthesize.pinned": pinned,
        },
    )
    validate(rule)
    return rule, reports, diagnostics
