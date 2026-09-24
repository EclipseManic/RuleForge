"""Full correlation model for the single-analyst workbench.

Replaces the flat field/operator/value row with a tree that can express
RF-01..RF-12: nested AND/OR/NOT, lists/regex, exclusions, thresholds,
group-by, windows, sequences, joins, lookups, absence, outcome.
RF-13..RF-18 are explicitly unsupported (see compiler.UNSUPPORTED_MAP).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


OPERATORS = {"equals", "contains", "starts_with", "ends_with", "regex", "in_list", "wildcard",
             "windash", "base64", "base64offset", "exists", "cidr"}

LOGIC = {"and", "or", "not"}

FIDELITY = ("exact", "safe_normalized", "partial", "unsupported")


@dataclass(frozen=True)
class Predicate:
    field: str
    operator: str
    value: Any  # str | list[str]

    def describe(self) -> str:
        val = self.value if not isinstance(self.value, list) else f"[{', '.join(map(str, self.value))}]"
        return f"{self.field} {self.operator} {val}"


@dataclass(frozen=True)
class LogicNode:
    op: str  # and | or | not
    children: tuple[Any, ...]  # Predicate | LogicNode

    def __post_init__(self) -> None:
        object.__setattr__(self, "children", tuple(self.children or ()))

    def describe(self, depth: int = 0) -> str:
        pad = "  " * depth
        lines = [f"{pad}{self.op.upper()}:"]
        for child in self.children:
            if isinstance(child, LogicNode):
                lines.append(child.describe(depth + 1))
            else:
                lines.append(f"{pad}  - {child.describe()}")
        return "\n".join(lines)


@dataclass(frozen=True)
class SequenceStage:
    event: str
    condition: str
    negated: bool = False


@dataclass(frozen=True)
class Sequence:
    join_by: str
    maxspan: str
    stages: tuple[SequenceStage, ...]
    ordered: bool = True


@dataclass(frozen=True)
class Join:
    kind: str  # inner | leftanti | leftouter ...
    left: str
    right: str
    on: str


@dataclass(frozen=True)
class Aggregation:
    function: str  # count | dc | values | sum | min | max | make_set
    field: str = ""
    alias: str = ""
    threshold: int | None = None


@dataclass(frozen=True)
class Lookup:
    name: str
    arguments: str = ""


@dataclass
class CorrelationModel:
    """Structured analyst workspace for one rule."""

    logic: Any | None = None  # Predicate | LogicNode
    source: str = "*"
    exclusions: list[Any] = field(default_factory=list)
    sequences: list[Sequence] = field(default_factory=list)
    joins: list[Join] = field(default_factory=list)
    aggregations: list[Aggregation] = field(default_factory=list)
    lookups: list[Lookup] = field(default_factory=list)
    event_streams: list[dict[str, str]] = field(default_factory=list)
    time_constraints: list[str] = field(default_factory=list)
    group_by: list[str] = field(default_factory=list)
    window: str = "5m"
    threshold: int | None = 1
    outcome: dict[str, Any] = field(default_factory=dict)
    native_sections: dict[str, str] = field(default_factory=dict)
    native_metadata: dict[str, Any] = field(default_factory=dict)
    unsupported_features: list[str] = field(default_factory=list)
    fidelity: str = "partial"

    def predicate_count(self) -> int:
        def count(node: Any) -> int:
            if node is None:
                return 0
            if isinstance(node, Predicate):
                return 1
            if isinstance(node, LogicNode):
                return sum(count(c) for c in node.children)
            return 0

        return count(self.logic) + sum(
            count(e) for e in self.exclusions
        )

    def is_multi_event(self) -> bool:
        return bool(self.sequences or self.joins or (self.threshold or 0) > 1)

    def to_dict(self) -> dict[str, Any]:
        def ser(node: Any) -> Any:
            if isinstance(node, Predicate):
                return {"field": node.field, "operator": node.operator, "value": node.value}
            if isinstance(node, LogicNode):
                return {"op": node.op, "children": [ser(c) for c in node.children]}
            return node

        return {
            "logic": ser(self.logic),
            "exclusions": [ser(e) for e in self.exclusions],
            "sequences": [
                {"join_by": s.join_by, "maxspan": s.maxspan, "ordered": s.ordered,
                 "stages": [{"event": st.event, "condition": st.condition, "negated": st.negated} for st in s.stages]}
                for s in self.sequences
            ],
            "joins": [{"kind": j.kind, "left": j.left, "right": j.right, "on": j.on} for j in self.joins],
            "aggregations": [{"function": a.function, "field": a.field, "alias": a.alias, "threshold": a.threshold} for a in self.aggregations],
            "lookups": [{"name": l.name, "arguments": l.arguments} for l in self.lookups],
            "event_streams": self.event_streams,
            "time_constraints": self.time_constraints,
            "group_by": self.group_by,
            "window": self.window,
            "threshold": self.threshold,
            "outcome": self.outcome,
            "native_sections": self.native_sections,
            "native_metadata": self.native_metadata,
            "unsupported_features": self.unsupported_features,
            "fidelity": self.fidelity,
            "multi_event": self.is_multi_event(),
            "predicate_count": self.predicate_count(),
        }


def _ctext(value: Any, label: str, limit: int = 160) -> str:
    text = "" if value is None else str(value).strip()
    if not text:
        raise ValueError(f"{label} is required.")
    if len(text) > limit or any(char in text for char in "\r\n\x00"):
        raise ValueError(f"{label} contains unsupported characters.")
    return text


def _cwindow(value: Any, label: str = "Max span") -> str:
    import re as _re
    text = _ctext(value, label, 10).lower()
    if not _re.fullmatch(r"\d{1,3}[smhd]", text) or int(text[:-1]) < 1:
        raise ValueError(f"{label} must look like 30s, 5m, 1h, or 1d.")
    return text


def parse_correlation(raw: Any) -> tuple[list["Sequence"], list["Join"], list["Aggregation"], list["Lookup"]]:
    """Parse/validate the studio `correlation` payload into model dataclasses (F4).

    Shape: {"sequences": [{"join_by", "maxspan", "stages": [{"event", "condition", "negated"}]}],
             "joins": [{"kind", "left", "right", "on"}],
             "aggregations": [{"function", "field", "alias"}],
             "lookups": [{"name", "arguments"}]}.
    Raises ValueError with a clear message on bad input. Empty/missing -> all empty.
    """
    if raw is None:
        return [], [], [], []
    if not isinstance(raw, dict):
        raise ValueError("Correlation must be an object.")
    sequences: list[Sequence] = []
    for index, entry in enumerate(raw.get("sequences") or []):
        label = f"Sequence {index + 1}"
        if not isinstance(entry, dict):
            raise ValueError(f"{label} must be an object.")
        stages_raw = entry.get("stages")
        if not isinstance(stages_raw, list) or not 2 <= len(stages_raw) <= 10:
            raise ValueError(f"{label} needs between 2 and 10 stages.")
        stages = []
        for pos, stage in enumerate(stages_raw):
            if not isinstance(stage, dict):
                raise ValueError(f"{label} stage {pos + 1} must be an object.")
            flag = stage.get("negated", False)
            negated = flag if isinstance(flag, bool) else str(flag).lower() in {"true", "1", "yes", "on"}
            event = _ctext(stage.get("event"), f"{label} stage {pos + 1} event")
            import re as _re3
            if not _re3.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", event):
                raise ValueError(f"{label} stage {pos + 1} event must be a single token (letters, digits, _, ., -).")
            stages.append(SequenceStage(event=event,
                                        condition=_ctext(stage.get("condition", ""), f"{label} stage {pos + 1} condition", 500) if str(stage.get("condition", "")).strip() else "",
                                        negated=negated))
        sequences.append(Sequence(join_by=_ctext(entry.get("join_by"), f"{label} join-by"),
                                  maxspan=_cwindow(entry.get("maxspan"), f"{label} max span"),
                                  stages=tuple(stages)))
        if len(sequences) > 3:
            raise ValueError("At most 3 sequences per rule.")
    joins: list[Join] = []
    for index, entry in enumerate(raw.get("joins") or []):
        label = f"Join {index + 1}"
        if not isinstance(entry, dict):
            raise ValueError(f"{label} must be an object.")
        kind = str(entry.get("kind", "inner")).lower()
        if kind not in {"inner", "leftouter", "leftanti", "rightouter", "fullouter", "equality"}:
            raise ValueError(f"{label} kind must be inner, leftouter, leftanti, rightouter, fullouter, or equality.")
        joins.append(Join(kind=kind, left=_ctext(entry.get("left"), f"{label} left stream"),
                          right=_ctext(entry.get("right"), f"{label} right stream"),
                          on=_ctext(entry.get("on"), f"{label} join key")))
        if len(joins) > 3:
            raise ValueError("At most 3 joins per rule.")
    aggregations: list[Aggregation] = []
    for index, entry in enumerate(raw.get("aggregations") or []):
        label = f"Aggregation {index + 1}"
        if not isinstance(entry, dict):
            raise ValueError(f"{label} must be an object.")
        function = str(entry.get("function", "count")).lower()
        if function not in {"count", "dc", "values", "sum", "min", "max", "avg", "dcount", "make_set", "arg_min", "arg_max"}:
            raise ValueError(f"{label} function is not supported.")
        field = "" if entry.get("field") in (None, "", "*") else _ctext(entry.get("field"), f"{label} field")
        alias = str(entry.get("alias", "") or "")
        import re as _re2
        if alias and not _re2.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias):
            raise ValueError(f"{label} alias must be letters, digits, or _ starting with a letter or _.")
        aggregations.append(Aggregation(function=function, field=field, alias=alias))
        if len(aggregations) > 3:
            raise ValueError("At most 3 aggregations per rule.")
    lookups: list[Lookup] = []
    for index, entry in enumerate(raw.get("lookups") or []):
        label = f"Lookup {index + 1}"
        if not isinstance(entry, dict):
            raise ValueError(f"{label} must be an object.")
        lookups.append(Lookup(name=_ctext(entry.get("name"), f"{label} name"),
                              arguments="" if entry.get("arguments") in (None, "") else _ctext(entry.get("arguments"), f"{label} arguments", 500)))
        if len(lookups) > 3:
            raise ValueError("At most 3 lookups per rule.")
    return sequences, joins, aggregations, lookups


def flat_conditions_to_logic(conditions: list[dict[str, str]], logic: str = "all") -> Any:
    preds = []
    for c in conditions:
        operator = c.get("operator", "contains")
        if operator not in OPERATORS:
            raise ValueError(f"Unsupported operator: {operator}.")
        preds.append(Predicate(field=c["field"], operator=operator, value=c.get("value", "")))
    if not preds:
        return None
    if len(preds) == 1:
        return preds[0]
    return LogicNode(op="and" if logic == "all" else "or", children=tuple(preds))


def _node_from_dict(data: Any) -> Any:
    if not isinstance(data, dict):
        return None
    if "field" in data:
        operator = data.get("operator", "contains")
        if operator not in OPERATORS:
            raise ValueError(f"Unsupported operator: {operator}.")
        return Predicate(field=data.get("field", ""), operator=operator, value=data.get("value", ""))
    if "op" in data:
        op = data.get("op", "and")
        if op not in LOGIC:
            raise ValueError(f"Unsupported logic operator: {op}.")
        kids = tuple(k for k in (_node_from_dict(c) for c in data.get("children", []) or []) if k is not None)
        return LogicNode(op=op, children=kids) if kids else None
    return None


def _agg_threshold(value: Any) -> int | None:
    """Round-trip tolerant aggregation threshold: invalid values become None, never crash."""
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 1 else None


def _coerce_threshold(value: Any) -> int | None:
    if value is None or value == "":
        return 1
    if isinstance(value, bool):
        raise ValueError(f"Threshold must be a whole number, got {value!r}.")
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Threshold must be a whole number, got {value!r}.") from error
    if number < 1:
        raise ValueError("Threshold must be at least 1.")
    return number


def model_from_dict(data: dict[str, Any]) -> "CorrelationModel":
    """Rebuild a CorrelationModel from to_dict()/compile output (G9 verdict-diff)."""
    if not isinstance(data, dict):
        raise ValueError("Model dict must be an object.")
    model = CorrelationModel()
    model.logic = _node_from_dict(data.get("logic"))
    model.exclusions = [e for e in (_node_from_dict(x) for x in data.get("exclusions", []) or []) if e is not None]
    model.threshold = _coerce_threshold(data.get("threshold", 1))
    model.window = str(data.get("window", "5m"))
    group_by = data.get("group_by", [])
    model.group_by = [group_by] if isinstance(group_by, str) else [str(g) for g in group_by or []]
    model.source = str(data.get("source", "*"))
    model.sequences = [Sequence(join_by=s.get("join_by", ""), maxspan=s.get("maxspan", ""),
                                stages=tuple(SequenceStage(event=st.get("event", ""), condition=st.get("condition", ""),
                                                           negated=bool(st.get("negated", False)))
                                             for st in s.get("stages", []) if isinstance(st, dict)))
                       for s in data.get("sequences", []) if isinstance(s, dict)] if isinstance(data.get("sequences"), list) else []
    model.joins = [Join(kind=j.get("kind", "inner"), left=str(j.get("left", "")), right=str(j.get("right", "")), on=str(j.get("on", "")))
                   for j in data.get("joins", []) if isinstance(j, dict)] if isinstance(data.get("joins"), list) else []
    model.lookups = [Lookup(name=str(l.get("name", "")), arguments=str(l.get("arguments", "")))
                     for l in data.get("lookups", []) if isinstance(l, dict)] if isinstance(data.get("lookups"), list) else []
    model.aggregations = [Aggregation(function=a.get("function", "count"), field=str(a.get("field", "")), alias=str(a.get("alias", "")),
                                          threshold=_agg_threshold(a.get("threshold")))
                          for a in data.get("aggregations", []) if isinstance(a, dict)] if isinstance(data.get("aggregations"), list) else []
    model.outcome = dict(data.get("outcome", {})) if isinstance(data.get("outcome"), dict) else {}
    model.fidelity = str(data.get("fidelity", "partial"))
    native = data.get("native_sections", {})
    model.native_sections = dict(native) if isinstance(native, dict) else {}
    meta = data.get("native_metadata", {})
    model.native_metadata = dict(meta) if isinstance(meta, dict) else {}
    unsupported = data.get("unsupported_features", [])
    model.unsupported_features = [str(u) for u in unsupported] if isinstance(unsupported, list) else []
    streams = data.get("event_streams", [])
    model.event_streams = [dict(s) for s in streams if isinstance(s, dict)] if isinstance(streams, list) else []
    constraints = data.get("time_constraints", [])
    model.time_constraints = [str(t) for t in constraints] if isinstance(constraints, list) else []
    return model
