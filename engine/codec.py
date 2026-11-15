"""JSON codec for the rule IR.

A `Rule` has to cross a process boundary and come back unchanged. A GUI builder
edits one, an HTTP API carries one, a history tab stores one -- and all three
are useless if the rule that comes back is subtly not the rule that went out.

The encoding is TAGGED and GENERIC rather than hand-written per type. Every
value carries an `@` tag naming what it is, and every dataclass is walked with
`dataclasses.fields()`, so adding an IR node does not mean adding a codec
branch. That matters because the alternative -- twenty-three hand-written
encode/decode pairs -- rots silently: the node gets added, the codec keeps
working on every rule that does not use it, and the one rule that does loses a
stage. `tests/test_codec.py` asserts the allowlist covers `ir.EXPR_TYPES` and
`ir.NODE_TYPES` by reflection, so a new node breaks the test rather than a
user's rule.

Three things the tags exist to protect, each of which a naive `json.dumps`
would quietly destroy:

**Decimal.** Numbers in this engine are `Decimal` end to end. A threshold that
goes out as `10.5` and comes back as the float `10.499999999999998` is a
different security control. Decimals travel as their exact string form.

**The four-way distinction between ABSENT, None, "" and UNDECIDED.** These are
four different answers in this engine -- see `values.py` and
`tests/test_core.py::AbsentIsNotNullIsNotEmpty` -- and JSON has one `null`.
Collapsing any two of them corrupts what the rule means, so each gets its own
tag and none of them is ever written as a bare JSON `null`.

**Tuples.** The IR is tuples throughout, and its dataclasses are frozen with
`slots=True`, so a tuple that comes back as a list compares unequal and the
round trip fails loudly -- which is the good case. The bad case is a renderer
that accepts the list and emits a subtly different rule. Tuples and lists carry
different tags.

Two ordering hazards are load-bearing here and are easy to get wrong:
`Capability` subclasses `str`, so it must be tested before `str` or it encodes
as its own value and decodes as the wrong type; and `bool` subclasses `int`, so
it must be tested before `int` or `True` comes back as `1`.
"""

from __future__ import annotations

import dataclasses
import json
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Final

from . import ir
from .ir import Rule
from .validate import validate
from .values import ABSENT, UNDECIDED, Capability, Duration, Refusal, Seq

__all__ = [
    "SCHEMA_VERSION",
    "KNOWN_TYPES",
    "MAX_DEPTH",
    "rule_to_dict",
    "rule_from_dict",
    "rule_to_json",
    "rule_from_json",
]

#: Bumped when the wire shape changes incompatibly. Stored rules carry it so a
#: future reader can migrate instead of mis-reading: a payload written by a
#: newer RuleForge is refused by name rather than decoded into a rule that is
#: almost right.
SCHEMA_VERSION: Final = 1

#: The dataclasses that may cross the boundary.
#:
#: An ALLOWLIST. A codec that encoded "any dataclass it met" would happily
#: serialise `Scoper`, which holds a live row of event data -- so a saved rule
#: would carry a sample of somebody's logs into the history file.
#:
#: `SequenceStep` is listed alongside `Window` and `Measure` rather than
#: arriving through `NODE_TYPES`, because it is not a stage: it is a part of
#: one. Leaving it out made `Sequence` encodable and its steps not, so a saved
#: sequence rule refused on the way out instead of losing its steps quietly --
#: the right failure, but still a failure.
KNOWN_TYPES: Final[tuple[type, ...]] = (
    ir.EXPR_TYPES
    + ir.NODE_TYPES
    + (ir.Window, ir.Measure, ir.SequenceStep, ir.Binding, ir.Annotations,
       ir.Rule, Duration, Seq)
)

_BY_NAME: Final[dict[str, type]] = {t.__name__: t for t in KNOWN_TYPES}

#: Nesting ceiling. A hand-written payload can nest expressions until the
#: decoder blows the C stack, and a `RecursionError` escaping this module would
#: reach the caller as a crash rather than as a refusal.
MAX_DEPTH: Final = 200

_TAG: Final = "@"


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------


def _encode(value: Any, depth: int = 0) -> Any:
    """One value to a tagged JSON structure.

    The identity tests come first and the `str`/`int` tests come last, because
    `Capability` IS a `str` and `bool` IS an `int`. Reordering this function is
    how the round trip starts returning the right shape with the wrong types.
    """
    if depth > MAX_DEPTH:
        raise Refusal(
            "CODEC_TOO_DEEP",
            f"this rule nests more than {MAX_DEPTH} levels deep. Encoding it "
            f"would be writing a payload nothing can read back.",
            "codec",
        )

    if value is ABSENT:
        return {_TAG: "absent"}
    if value is UNDECIDED:
        return {_TAG: "undecided"}
    if value is None:
        return {_TAG: "null"}

    # Capability before str: Capability subclasses str.
    if isinstance(value, Capability):
        return {_TAG: "capability", "v": value.value}
    if isinstance(value, Enum):
        raise Refusal(
            "CODEC_UNKNOWN_ENUM",
            f"`{type(value).__name__}` is an enum this codec does not carry. "
            f"Add it deliberately rather than letting it encode as its value.",
            "codec",
        )

    # bool before int: bool subclasses int.
    if isinstance(value, bool):
        return {_TAG: "bool", "v": value}
    if isinstance(value, Decimal):
        # The exact string form. `float(Decimal("10.5"))` is where a threshold
        # stops being the number the analyst typed.
        return {_TAG: "decimal", "v": str(value)}
    if isinstance(value, int):
        return {_TAG: "int", "v": value}
    if isinstance(value, float):
        # repr() round-trips exactly in Python 3. Floats should not be in the
        # IR at all -- it is Decimal throughout -- but refusing here would
        # refuse a rule a dialect already built, so carry it losslessly and
        # let the dialect be the thing that gets fixed.
        return {_TAG: "float", "v": repr(value)}
    if isinstance(value, str):
        return {_TAG: "str", "v": value}

    if isinstance(value, tuple):
        return {_TAG: "tuple", "v": [_encode(i, depth + 1) for i in value]}
    if isinstance(value, list):
        return {_TAG: "list", "v": [_encode(i, depth + 1) for i in value]}
    if isinstance(value, dict):
        # Pairs, not a JSON object: IR dict keys are strings today, but a
        # structure that only works while that stays true is a trap.
        return {
            _TAG: "dict",
            "v": [
                [_encode(k, depth + 1), _encode(v, depth + 1)]
                for k, v in value.items()
            ],
        }

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        name = type(value).__name__
        if name not in _BY_NAME or _BY_NAME[name] is not type(value):
            raise Refusal(
                "CODEC_TYPE_NOT_CARRIED",
                f"`{name}` is a dataclass this codec does not carry. It is an "
                f"allowlist on purpose: encoding whatever dataclass it met "
                f"would let a rule smuggle out a row of event data.",
                "codec",
            )
        body: dict[str, Any] = {_TAG: name}
        for field in dataclasses.fields(value):
            body[field.name] = _encode(getattr(value, field.name), depth + 1)
        return body

    raise Refusal(
        "CODEC_VALUE_NOT_ENCODABLE",
        f"a value of type `{type(value).__name__}` cannot be written to JSON by "
        f"this codec. Encoding it as its text form would produce a rule that "
        f"reads back as something else.",
        "codec",
    )


def rule_to_dict(rule: Rule) -> dict[str, Any]:
    """A Rule to a JSON-ready dict, schema version included."""
    if not isinstance(rule, Rule):
        raise Refusal(
            "CODEC_NOT_A_RULE",
            f"`{type(rule).__name__}` is not a Rule.",
            "codec",
        )
    return {"schema": SCHEMA_VERSION, "rule": _encode(rule)}


def rule_to_json(rule: Rule, *, indent: int | None = 2) -> str:
    """A Rule as JSON text. `sort_keys` so two equal rules give equal bytes."""
    return json.dumps(rule_to_dict(rule), indent=indent, sort_keys=True)


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def _bad(what: str, detail: str) -> Refusal:
    return Refusal("CODEC_MALFORMED", f"{what}: {detail}", "codec")


def _decode(data: Any, depth: int = 0) -> Any:
    """A tagged JSON structure back to the value it came from.

    Every branch of the tag dispatch ends in a refusal. A silent fallback here
    would return `None` for an unrecognised tag, and a `None` where a predicate
    belongs is a rule that matches differently than it reads.
    """
    if depth > MAX_DEPTH:
        raise Refusal(
            "CODEC_TOO_DEEP",
            f"this payload nests more than {MAX_DEPTH} levels deep, which is "
            f"deeper than any real rule and is refused rather than decoded.",
            "codec",
        )
    if not isinstance(data, dict):
        raise _bad(
            "every encoded value is a tagged object",
            f"found a bare {type(data).__name__}. A payload written by hand has "
            f"to carry the same tags the encoder writes.",
        )

    tag = data.get(_TAG)
    if not isinstance(tag, str) or not tag:
        raise _bad(
            f"an encoded value needs a `{_TAG}` tag naming its type",
            f"got {data.get(_TAG)!r}",
        )

    if tag == "absent":
        return ABSENT
    if tag == "undecided":
        return UNDECIDED
    if tag == "null":
        return None

    if tag in ("bool", "int", "str", "decimal", "float", "capability"):
        if "v" not in data:
            raise _bad(f"a `{tag}` carries its payload in `v`", "`v` is missing")
        raw = data["v"]
        if tag == "bool":
            if not isinstance(raw, bool):
                raise _bad("a `bool`", f"got {type(raw).__name__}")
            return raw
        if tag == "int":
            if not isinstance(raw, int) or isinstance(raw, bool):
                raise _bad("an `int`", f"got {raw!r}")
            return raw
        if tag == "str":
            if not isinstance(raw, str):
                raise _bad("a `str`", f"got {type(raw).__name__}")
            return raw
        if tag == "decimal":
            if not isinstance(raw, str):
                raise _bad(
                    "a `decimal` travels as its exact string form",
                    f"got {type(raw).__name__}. A JSON number here would have "
                    f"already lost the precision this tag exists to keep.",
                )
            try:
                return Decimal(raw)
            except InvalidOperation as exc:
                raise _bad("a `decimal`", f"`{raw}` is not a number") from exc
        if tag == "float":
            if not isinstance(raw, str):
                raise _bad("a `float` travels as repr text", f"got {raw!r}")
            try:
                return float(raw)
            except ValueError as exc:
                raise _bad("a `float`", f"`{raw}` is not a number") from exc
        try:
            return Capability(raw)
        except ValueError as exc:
            known = ", ".join(c.value for c in Capability)
            raise _bad(
                "a `capability`", f"`{raw}` is not one of: {known}"
            ) from exc

    if tag in ("tuple", "list"):
        raw = data.get("v")
        if not isinstance(raw, list):
            raise _bad(f"a `{tag}` carries a JSON array in `v`", f"got {raw!r}")
        items = [_decode(i, depth + 1) for i in raw]
        return tuple(items) if tag == "tuple" else items

    if tag == "dict":
        raw = data.get("v")
        if not isinstance(raw, list):
            raise _bad("a `dict` carries an array of pairs in `v`", f"got {raw!r}")
        out: dict[Any, Any] = {}
        for pair in raw:
            if not isinstance(pair, list) or len(pair) != 2:
                raise _bad("a `dict` entry is a two-element pair", f"got {pair!r}")
            out[_decode(pair[0], depth + 1)] = _decode(pair[1], depth + 1)
        return out

    target = _BY_NAME.get(tag)
    if target is None:
        raise Refusal(
            "CODEC_TYPE_UNKNOWN",
            f"`{tag}` is not a type this codec carries. Known: "
            f"{', '.join(sorted(_BY_NAME))}.",
            "codec",
        )

    expected = {f.name for f in dataclasses.fields(target)}
    supplied = {k for k in data if k != _TAG}
    missing = expected - supplied
    if missing:
        raise _bad(
            f"a `{tag}`",
            f"the field(s) {sorted(missing)} are missing. A partial node would "
            f"be constructed with defaults, which silently changes the rule.",
        )
    unexpected = supplied - expected
    if unexpected:
        raise _bad(
            f"a `{tag}`",
            f"the field(s) {sorted(unexpected)} are not part of it. Ignoring "
            f"them would be ignoring something the writer meant.",
        )

    kwargs = {name: _decode(data[name], depth + 1) for name in expected}
    try:
        return target(**kwargs)
    except Refusal:
        # The IR's own construction-time refusals are the point: a payload that
        # describes an impossible node must not become one. Let it through.
        raise
    except (TypeError, ValueError) as exc:
        raise _bad(f"a `{tag}`", f"it will not construct: {exc}") from exc


def rule_from_dict(data: dict[str, Any]) -> Rule:
    """A dict from `rule_to_dict` back to the Rule it came from.

    Validated before it is returned, so a hand-edited or hostile payload cannot
    hand the rest of the tool a Rule the tool would never have built.
    """
    if not isinstance(data, dict):
        raise _bad(
            "a rule payload is an object",
            f"got a {type(data).__name__}",
        )

    if "schema" not in data:
        raise _bad(
            "a rule payload names its schema version",
            "`schema` is missing, so there is no way to tell which shape this "
            "is. An untagged payload is refused rather than assumed current.",
        )
    schema = data["schema"]
    if schema != SCHEMA_VERSION:
        raise Refusal(
            "CODEC_SCHEMA_UNSUPPORTED",
            f"this rule was written with schema version {schema!r} and this "
            f"build reads version {SCHEMA_VERSION}. Reading it anyway would be "
            f"guessing at what changed.",
            "codec",
        )

    if "rule" not in data:
        raise _bad("a rule payload carries the rule under `rule`", "it is missing")

    decoded = _decode(data["rule"])
    if not isinstance(decoded, Rule):
        raise _bad(
            "the payload decoded to something other than a Rule",
            f"got a {type(decoded).__name__}",
        )
    validate(decoded)
    return decoded


def rule_from_json(text: str) -> Rule:
    """JSON text back to a Rule."""
    if not isinstance(text, str):
        raise _bad("rule JSON is text", f"got a {type(text).__name__}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise Refusal(
            "CODEC_NOT_JSON",
            f"this is not JSON: {exc.msg} at line {exc.lineno} column {exc.colno}.",
            "codec",
        ) from exc
    return rule_from_dict(data)
