"""Full Sigma parser: metadata, logsource, selections, lists, modifiers, filters, condition."""
from __future__ import annotations

import re
from typing import Any

import yaml

from models.correlation import CorrelationModel, LogicNode, Predicate


MODIFIERS = {"contains", "startswith", "endswith", "re", "base64", "base64offset",
             "windash", "cidr", "exists", "all", "expand", "utf16", "utf16le", "utf16be", "wide"}


def _split_field(raw: str) -> tuple[str, str]:
    """Image|endswith -> (Image, endswith); CommandLine|contains|all -> (CommandLine, contains)."""
    parts = str(raw).split("|")
    base = parts[0]
    # chained modifiers (windash|contains): the most specific operator wins
    specific = ""
    fallback = "equals"
    for part in parts[1:]:
        low = part.lower()
        if low in MODIFIERS and low not in {"all", "expand", "utf16", "utf16le", "utf16be", "wide"}:
            if low in ("windash", "base64", "base64offset", "cidr", "exists"):
                specific = low
            elif low == "re":
                specific = "regex"
            elif fallback == "equals":
                fallback = low
    modifier = specific or fallback
    return base, modifier


def _selection_to_node(selection: dict[str, Any]) -> Any:
    preds: list[Predicate] = []
    skipped: list[str] = []
    for raw_field, raw_value in selection.items():
        base, modifier = _split_field(str(raw_field))
        if raw_value is None:
            skipped.append(f"{base} (null value skipped)")
            continue
        if isinstance(raw_value, dict):
            skipped.append(f"{base} (mapping value like {{gte: ..}} not expressible — skipped)")
            continue
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        if len(values) > 1:
            preds.append(Predicate(field=base, operator="in_list", value=[str(v) for v in values]))
        else:
            preds.append(Predicate(field=base, operator=modifier, value=str(values[0])))
    node = None
    if len(preds) == 1:
        node = preds[0]
    elif preds:
        node = LogicNode(op="and", children=tuple(preds))
    return node, skipped


def parse_sigma(yaml_text: str) -> tuple[CorrelationModel, dict[str, Any]]:
    """Return (model, meta). Raises ValueError with a clear message on bad input."""
    from safe_yaml import safe_yaml_load

    try:
        doc = safe_yaml_load(yaml_text)
    except ValueError as error:
        raise ValueError(f"Invalid Sigma YAML: {error}") from error
    if not isinstance(doc, dict) or not isinstance(doc.get("detection"), dict):
        raise ValueError("Sigma rule must contain a detection section.")
    detection = doc["detection"]
    named: dict[str, Any] = {}
    skipped_notes: list[str] = []
    for name, selection in detection.items():
        if name == "condition" or not isinstance(selection, dict):
            continue
        node, skipped = _selection_to_node(selection)
        named[name] = node
        skipped_notes.extend(skipped)
    # Condition: support 'selection', 'selection and not filter', '1 of selection_*', 'all of selection_*',
    # and multiple negations ('a and not b and not c'). Only filters referenced
    # via NOT become exclusions; filters used positively stay in logic.
    condition_raw = str(detection.get("condition", "selection"))
    logic = _resolve_condition(condition_raw, named)
    negated = {name.lower() for name in re.findall(r"not\s+([A-Za-z_][A-Za-z0-9_*]*)", condition_raw, re.IGNORECASE)}
    exclusions = [named[name] for name in named
                  if name.lower().startswith("filter") and (name.lower() in negated or f"{name.lower()}_" in condition_raw.lower() or "not filter" in condition_raw.lower())
                  and named[name] is not None]
    model = CorrelationModel(logic=logic, exclusions=[e for e in exclusions if e is not None])
    meta = {k: doc.get(k) for k in ("title", "id", "status", "author", "description", "tags", "references", "falsepositives", "level", "logsource") if k in doc}
    meta["detection_raw"] = detection
    meta["sigma_condition"] = condition_raw
    model.native_sections = {k: yaml.safe_dump(v, sort_keys=False).strip() for k, v in doc.items() if k in {"logsource", "detection", "references"}}
    model.native_metadata = {k: v for k, v in meta.items() if k not in ("logsource",)}
    model.native_sections["sigma_condition"] = condition_raw
    # fidelity: simple selections -> safe_normalized (needs pipeline mapping at compile)
    model.fidelity = "safe_normalized" if logic is not None else "unsupported"
    # list values with match modifiers lose the modifier in the flat model
    for selection in detection.values():
        if not isinstance(selection, dict):
            continue
        for raw_field, raw_value in selection.items():
            _, modifier = _split_field(str(raw_field))
            if isinstance(raw_value, list) and len(raw_value) > 1 and modifier not in {"equals", "in_list"}:
                model.unsupported_features.append(f"list modifier |{modifier} on '{raw_field}' approximated as list match")
            if str(raw_field).lower().endswith("|all"):
                model.unsupported_features.append(f"quantifier |all on '{raw_field}' approximated as OR list; use AND conditions for exact semantics")
    model.unsupported_features = list(dict.fromkeys(model.unsupported_features + skipped_notes))
    return model, meta


def _resolve_condition(condition_raw: str, named: dict[str, Any], _depth: int = 0) -> Any:
    if _depth > 10:
        raise ValueError("Sigma condition is too deeply nested.")
    text = condition_raw.strip()
    # strip one layer of wrapping parentheses: (a and b)
    while len(text) > 2 and text.startswith("(") and text.endswith(")") and _balanced(text[1:-1]):
        text = text[1:-1].strip()
    low = text.lower()
    # 'selection and not filter' (case-insensitive split, remainder re-resolved)
    if " and not " in low:
        parts = [p.strip() for p in re.split(r" and not ", text, flags=re.IGNORECASE)]
        base = _resolve_condition(parts[0], named, _depth + 1)
        tails = []
        for tail in parts[1:]:
            node = _resolve_condition(tail, named, _depth + 1)
            if node is not None:
                tails.append(node)
        # positive tails rejoin logic; filter* tails live in exclusions
        rest = [t for t in tails if t not in [named.get(n) for n in named if n.lower().startswith("filter")]]
        if not rest:
            return base
        kids = ([base] if base is not None else []) + rest
        if len(kids) == 1:
            return kids[0]
        return LogicNode(op="and", children=tuple(kids))
    if low.startswith("1 of ") or low.startswith("any of "):
        prefix = "1 of " if low.startswith("1 of ") else "any of "
        pattern = text[len(prefix):].strip().rstrip("*")
        members = [n for pat, n in named.items() if pat.startswith(pattern.rstrip("*").rstrip("_"))]
        members = [m for m in members if m is not None]
        if not members:
            return None
        return LogicNode(op="or", children=tuple(members))
    if low.startswith("all of "):
        pattern = text[len("all of "):].strip()
        members = [n for pat, n in named.items() if pat.startswith(pattern.rstrip("*").rstrip("_"))]
        members = [m for m in members if m is not None]
        if not members:
            return None
        return LogicNode(op="and", children=tuple(members))
    # 'a and b', 'a or b' (case-insensitive split at top level)
    for joiner, op in ((" or ", "or"), (" and ", "and")):
        if joiner in low:
            chunks = re.split(joiner, text, flags=re.IGNORECASE)
            kids = [k for k in (_resolve_condition(c, named, _depth + 1) for c in chunks) if k is not None]
            if not kids:
                return None
            if len(kids) == 1:
                return kids[0]
            return LogicNode(op=op, children=tuple(kids))
    name = text.strip()
    if name.lower().startswith("not "):
        inner = _resolve_condition(name[4:], named, _depth + 1)
        return LogicNode(op="not", children=(inner,)) if inner is not None else None
    return named.get(name)


def _balanced(text: str) -> bool:
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0
