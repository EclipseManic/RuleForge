"""YARA-L <-> RuleIR, and render.

The central decision, and the one worth stating plainly:

    A CROSS-EVENT COMPARISON IS A SEQUENCE ORDER, NOT A ROW COMPARISON.

`$lsass.metadata.event_timestamp <= $login.metadata.event_timestamp` compares a
value from one event against a value from a DIFFERENT event. Lowered as a
same-row comparison it would compare the login's timestamp to the login's
timestamp, which is always true, and the rule would fire on every NTLM logon
regardless of whether any credential access happened. That is the single most
dangerous possible misreading of this rule, so the lowering emits an ORDERING
between the two events rather than a predicate, and says so in a diagnostic.

`<=` is representable as ordering because a pattern's stages are "at or after"
the start row. A STRICT `<` is not the same claim and is refused.
"""

from __future__ import annotations

import re
from typing import Any, Final

from ..dialects.aql import Diagnostic
from ..engine import (
    Duration,
    Emit,
    FieldRef,
    Filter,
    Literal,
    Pattern,
    Read,
    Refusal,
    RuleIR,
    SourceSelector,
)
from ..engine.ir import BoolOp, Call, Comparison
from .yaral import (
    DIALECT,
    ParsedYaraL,
    YaraCondition,
    YaraEvent,
)

#: UDM field that carries the event timestamp. Used ONLY when the rule itself
#: names it in a cross-event comparison -- never guessed from a column that
#: happens to look like a time.
TIMESTAMP_FIELD: Final = "metadata.event_timestamp"


def lower(parsed: ParsedYaraL) -> tuple[RuleIR, list[Diagnostic]]:
    """Lower a parsed YARA-L rule into a runnable graph."""
    diagnostics = list(parsed.diagnostics)

    if parsed.match.bucket_seconds is not None:
        diagnostics.append(Diagnostic(
            "YARAL_UNSUPPORTED_BUCKET_WITHOUT_MEASURE",
            f"`by {parsed.match.bucket_seconds}s` buckets events into time windows, "
            f"but this rule declares no outcome metric, so there is nothing to "
            f"compute per bucket. A bucket with no measure is a grouping, not an "
            f"aggregate, and this IR requires an aggregate to hold measures.",
            "refusal"))
        raise Refusal(
            "YARAL_UNSUPPORTED_BUCKET_WITHOUT_MEASURE",
            "a `by` window with no outcome metric cannot be represented", "YARA-L")

    time_field = _resolve_time_field(parsed, diagnostics)

    if parsed.match.window_seconds is not None:
        ir = _lower_correlation(parsed, time_field, diagnostics)
    else:
        ir = _lower_single_event(parsed, diagnostics)

    return ir, diagnostics


def _resolve_time_field(parsed: ParsedYaraL,
                        diagnostics: list[Diagnostic]) -> str | None:
    """Which field orders the sequence, taken from the rule or refused.

    NOT guessed. An earlier engine version scanned rows for a numeric column
    whose name ended in `time`, which is how a rule keyed on `timestamp` ends up
    ordered by `eventtime` and the sequence becomes a different one.
    """
    for left, right, _operator in parsed.cross_event_order:
        for side in (left, right):
            if side.endswith(TIMESTAMP_FIELD):
                # The rule says $lsass.metadata.event_timestamp. The FIELD is
                # metadata.event_timestamp; keeping the $var. prefix would
                # produce a Pattern whose time_field names no column in any row.
                return side.split(chr(46), 1)[-1] if chr(46) in side else side
    if parsed.match.window_seconds is not None:
        diagnostics.append(Diagnostic(
            "YARAL_NO_TIME_FIELD",
            "This rule has a match window but never compares a timestamp, so it "
            "does not say which field orders the events. A pattern cannot be "
            "ordered without one, and picking a column that looks like a time "
            "would be a guess that changes which events count as 'then'.",
            "refusal"))
        return None
    return None


def _lower_single_event(parsed: ParsedYaraL, diagnostics: list[Diagnostic]) -> RuleIR:
    """No match window: Read -> Filter -> Emit."""
    conditions = [_condition_for_event(event, parsed, diagnostics)
                  for event in parsed.events]
    condition = conditions[0] if len(conditions) == 1 else BoolOp("and",
                                                                 tuple(conditions))
    # `diagnostics` is the caller's list, passed in rather than created here. An
    # earlier version built it locally and never returned it, so a single-event
    # rule containing a PCRE regex lowered with NO diagnostic at all -- the
    # analyst got silence where they needed "this cannot run locally".
    return RuleIR(
        rule_id=parsed.name or "yaral",
        nodes=(
            Read(id="read", selector=SourceSelector(name="udm_events")),
            Filter(id="flt", input="read", condition=condition),
            Emit(id="out", input="flt"),
        ),
        output="out",
        title=parsed.name,
        metadata={"dialect": DIALECT, "artifact": "rule",
                  **{f"meta_{k}": v for k, v in parsed.meta.items()}})


def _lower_correlation(parsed: ParsedYaraL, time_field: str | None,
                       diagnostics: list[Diagnostic]) -> RuleIR:
    """A match window: Read -> Pattern -> Emit."""
    by_var: dict[str, list[YaraEvent]] = {}
    for event in parsed.events:
        if event.is_placeholder:
            # A placeholder line is a GROUPING BINDING, not a predicate.
            # `$lsass.principal.hostname = $host` says the value of that field
            # BECOMES the correlation key. Lowered as a comparison it would
            # resolve `$host` as a field name that exists in no row, and every
            # row would go undecidable. The binding lives on the Pattern's key.
            continue
        by_var.setdefault(event.var, []).append(event)

    condition = parsed.condition
    if isinstance(condition, YaraCondition) and condition.op == "exists":
        order = [condition.operands[0]]
    elif isinstance(condition, YaraCondition) and condition.op in ("and", "or"):
        order = [c.operands[0] for c in condition.operands
                 if isinstance(c, YaraCondition) and c.op == "exists"]
    else:
        order = list(by_var)

    stages = tuple(
        tuple(_condition_for_event(e, parsed, diagnostics) for e in by_var[var])
        for var in order if var in by_var)

    keys: list[FieldRef] = []
    for placeholder in parsed.match.keys:
        # The match section names a PLACEHOLDER (`$host`). The field it binds
        # comes from the event that referenced it: `$lsass.principal.hostname`
        # = `$host` means the correlation key is `principal.hostname`.
        for event in parsed.events:
            if event.is_placeholder and str(event.value) == placeholder:
                keys.append(FieldRef(event.field))

    if parsed.cross_event_order:
        diagnostics.append(Diagnostic(
            "YARAL_CROSS_EVENT_BECAME_STAGE_ORDER",
            "The rule compares a value from one event against a value from a "
            "different event. That became an ORDERING between the two event "
            "stages, not a same-row comparison: comparing them within one row "
            "would compare the logon's timestamp to itself, which is always true, "
            "and the rule would fire on every logon regardless of whether any "
            "credential access occurred.", "warning"))

    node = Pattern(
        id="pat", input="read", stages=stages or ((Literal(True),),),
        within=Duration(parsed.match.window_seconds or 0),
        key=tuple(dict.fromkeys(keys)),
        time_field=time_field,
    )

    return RuleIR(
        rule_id=parsed.name or "yaral",
        nodes=(
            Read(id="read", selector=SourceSelector(name="udm_events")),
            node,
            Emit(id="out", input="pat"),
        ),
        output="out",
        title=parsed.name,
        metadata={"dialect": DIALECT, "artifact": "rule",
                  **{f"meta_{k}": v for k, v in parsed.meta.items()}})


def _condition_for_event(event: YaraEvent, parsed: ParsedYaraL,
                         diagnostics: list[Diagnostic]) -> Any:
    """Turn one `$var.field = value` line into a predicate.

    TWO DIFFERENT FAILURES, DELIBERATELY NOT MERGED:

      * a case-insensitive REGEX is REPRESENTABLE EXACTLY -- the pattern plus a
        `nocase` flag. It lowers, it renders back in YARA-L's own
        `/pattern/ nocase` form, and SecOps will run it correctly. Only a LOCAL run
        is impossible, because the dialect is PCRE and this engine has no PCRE
        engine. So it lowers with a DIAGNOSTIC, and the refusal happens at
        evaluation where it belongs.

      * a case-insensitive COMPARISON is NOT representable. There is no
        case-insensitive equality or prefix operator here. Reaching for
        `contains` would be a different and BROADER test than the rule states, and
        the render would silently change the rule. So that one refuses at lower
        time, because a faithful render is impossible.

    Refusing the first at lower time would have been a category error: it would
    make the user's own rule un-openable, un-editable and un-renderable in a tool
    whose job is to let them work on exactly that rule.
    """
    ref = FieldExpr(FieldRef(event.field))

    if event.is_placeholder:
        # A placeholder binding is an EQUALITY between two fields of the SAME
        # event, which is decidable and exact.
        return Comparison("=", ref, FieldExpr(FieldRef(str(event.value))))

    if event.is_regex:
        if event.nocase:
            diagnostics.append(Diagnostic(
                "YARAL_REGEX_NOT_EXECUTABLE_LOCALLY",
                f"The pattern on {event.field!r} is a case-insensitive PCRE regex. "
                f"It is preserved exactly and rendered back as "
                f"`/pattern/ nocase`, and SecOps will run it correctly. This tool "
                f"CANNOT run it locally, because it implements no PCRE engine and "
                f"evaluating a PCRE pattern with Python's `re` would report matches "
                f"PCRE would not produce. A local run will say so.", "refusal"))
        return Call("matches_regex", (ref, Literal(str(event.value))),
                    dialect="pcre",
                    flags=frozenset({"nocase"}) if event.nocase else frozenset())

    if event.nocase:
        raise Refusal(
            "YARAL_UNSUPPORTED_NOCASE_COMPARISON",
            f"{event.field!r} is compared case-insensitively. This engine has no "
            f"case-insensitive equality or prefix operator. Using `contains` would "
            f"be a different, broader test than the rule states, and the rendered "
            f"rule would quietly differ from the one written -- so it is refused "
            f"rather than approximated.", "YARA-L")

    return Comparison("=", ref, Literal(str(event.value)))


from ..engine import FieldExpr  # noqa: E402  (used by _condition_for_event)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render(ir: RuleIR) -> str:
    """Render RuleIR back to YARA-L 2.0.

    `nocase` is written in YARA-L's own `/pattern/ nocase` form. The pattern
    text is emitted EXACTLY as it was given: it is not rewritten to `(?i)...`,
    which would preserve the matched language but change the analyst's bytes and
    break the diff against the rule they pasted.
    """
    meta_lines: list[str] = []
    for key, value in sorted(ir.metadata.items()):
        if key.startswith("meta_"):
            meta_lines.append(f"  {key[len('meta_'):]} = {json_escape(value)}")

    event_lines: list[str] = []
    condition_terms: list[str] = []
    match_keys: list[str] = []
    used: set[str] = set()
    window: str | None = None

    for node in ir.nodes:
        kind = type(node).__name__
        if kind == "Pattern":
            for index, stage in enumerate(node.stages):
                var = f"$e{index}"
                for condition in stage:
                    event_lines.extend(_render_event(condition, var))
                condition_terms.append(var)
            for key in node.key:
                placeholder = _placeholder_name(key.name, used)
                event_lines.append(f"    $e0.{key.name} = {placeholder}")
                match_keys.append(placeholder)
            window = str(node.within)
        elif kind == "Filter":
            # A single-event rule has no match window, so it lowers to
            # Read -> Filter -> Emit. The render originally only understood
            # Pattern, so every single-event rule rendered as ONE empty event and
            # an empty condition -- a rule that had parsed perfectly came back
            # looking deleted.
            event_lines.extend(_render_event(node.condition, "$e0"))
            condition_terms.append("$e0")

    out_lines = ["rule " + (ir.title or ir.rule_id), "{", "  meta:"]
    out_lines.extend(meta_lines or ["    author = \"unknown\""])
    out_lines.append("")
    out_lines.append("  events:")
    out_lines.extend(event_lines or ["    $e0.metadata.event_type = \"\""])
    out_lines.append("")
    if match_keys and window:
        out_lines.append("  match:")
        out_lines.append(f"    {', '.join(match_keys)} over {window}")
        out_lines.append("")
    out_lines.append("  condition:")
    out_lines.append("    " + " and ".join(condition_terms))
    out_lines.append("}")
    return "\n".join(out_lines)


def _placeholder_name(field_path: str, used: set[str]) -> str:
    """A short, valid, collision-free `$name` for a correlation key.

    `principal.hostname` becomes `$hostname`, not `$principal.hostname` (a dotted
    placeholder is not valid YARA-L) and not `$hostname` twice for two different
    fields (which would silently merge two correlation keys into one).
    """
    base = re.sub(r"[^A-Za-z0-9_]", "_", field_path.split(".")[-1])
    if not base or not base[0].isalpha():
        base = f"k_{base}"
    candidate = f"${base}"
    suffix = 2
    while candidate in used:
        candidate = f"${base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _render_event(condition: Any, var: str) -> list[str]:
    if isinstance(condition, BoolOp):
        # A conjunction of predicates is SEVERAL events lines, not one. The
        # original renderer had no BoolOp branch, so a rule with two conditions
        # rendered a single line with an empty value and silently lost one of them.
        lines: list[str] = []
        for operand in condition.operands:
            lines.extend(_render_event(operand, var))
        return lines
    if isinstance(condition, Call) and condition.function == "matches_regex":
        pattern = str(condition.args[1].value)
        # nocase is a NODE FIELD, rendered in the vendor's syntax. The pattern
        # itself is untouched.
        modifier = " nocase" if "nocase" in condition.flags else ""
        return [f"    {var}.{_field_of(condition.args[0])} = /{pattern}/{modifier}"]
    if isinstance(condition, Comparison):
        left = _field_of(condition.left)
        right = condition.right
        if isinstance(right, FieldExpr):
            return [f"    {var}.{left} = {_var_of(right)}"]
        return [f"    {var}.{left} = {json_escape(str(right.value))}"]
    return []


def _field_of(node: Any) -> str:
    if isinstance(node, FieldExpr):
        return node.ref.name
    return str(node)


def _var_of(node: Any) -> str:
    if isinstance(node, FieldExpr):
        name = node.ref.name.split('.')[-1]
        return name if name.startswith('$') else "`"
    return "$x"


def json_escape(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
