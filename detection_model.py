"""Shared intermediate representation for imported detection rules."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DetectionDocument:
    raw_rule: str
    source_siem: str
    fidelity: str
    equivalent_recompile: bool
    conditions: list[dict[str, str]] = field(default_factory=list)
    sequences: list[dict[str, Any]] = field(default_factory=list)
    joins: list[dict[str, str]] = field(default_factory=list)
    aggregations: list[dict[str, str]] = field(default_factory=list)
    lookups: list[dict[str, str]] = field(default_factory=list)
    native_sections: dict[str, str] = field(default_factory=dict)
    native_metadata: dict[str, Any] = field(default_factory=dict)
    unsupported_features: list[str] = field(default_factory=list)

    @classmethod
    def from_analysis(cls, analysis: dict[str, Any]) -> "DetectionDocument":
        return cls(
            raw_rule=analysis.get("raw_rule", ""),
            source_siem=analysis.get("siem", ""),
            fidelity=analysis.get("fidelity", "unsupported"),
            equivalent_recompile=bool(analysis.get("equivalent_recompile", False)),
            conditions=analysis.get("conditions", []),
            sequences=analysis.get("sequences", []),
            joins=analysis.get("joins", []),
            aggregations=analysis.get("aggregations", []),
            lookups=analysis.get("lookups", []),
            native_sections=analysis.get("native_sections", {}),
            native_metadata=analysis.get("native_metadata", {}),
            unsupported_features=analysis.get("unsupported_features", []),
        )

    def compile_decision(self, *, preserve_source: bool, target_siem: str) -> dict[str, Any]:
        same_source = target_siem == self.source_siem
        if preserve_source and same_source and self.raw_rule:
            return {"mode": "preserve_source", "fidelity": "exact", "equivalent": True}
        if self.equivalent_recompile and same_source:
            return {"mode": "native_recompile", "fidelity": "exact", "equivalent": True}
        return {
            "mode": "blocked_unsafe_edit",
            "fidelity": "partial" if self.conditions else "unsupported",
            "equivalent": False,
            "reason": self.unsupported_features or ["This imported rule contains native correlation logic that the normalized editor cannot safely regenerate."],
        }