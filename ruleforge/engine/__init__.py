"""RuleForge engine.

Built from scratch. Imports nothing outside this directory and opens no
connection to any SIEM.
"""

from __future__ import annotations

from .evaluate import (
    Budget,
    Caveat,
    EvaluationContext,
    EvaluationResult,
    NodeTrace,
    Row,
    Verdict,
    eval_expr,
)
from .ir import (
    AGGREGATES,
    EXECUTABLE_DIALECTS,
    MAX_NODES,
    NODE_TYPES,
    REGEX_DIALECTS,
    SCHEMA_VERSION,
    Aggregate,
    Arith,
    Arrange,
    BoolOp,
    Call,
    Comparison,
    Derive,
    Duration,
    Emit,
    Expand,
    FieldExpr,
    FieldRef,
    Filter,
    Frame,
    Join,
    Literal,
    Measure,
    Pattern,
    Package,
    Read,
    RuleIR,
    SetOp,
    SourceSelector,
    TimeRef,
)
from .run import evaluate
from .validate import validate_graph
from .values import (
    ABSENT,
    UNDECIDED,
    ComparisonResult,
    Refusal,
    Undecided,
    and_,
    compare,
    has_value,
    not_,
    or_,
    presence,
)

__all__ = [
    "evaluate", "validate_graph", "Verdict", "EvaluationResult", "Row", "Caveat",
    "NodeTrace", "EvaluationContext", "Budget", "eval_expr",
    "RuleIR", "Read", "Filter", "Derive", "Frame", "Aggregate", "Arrange",
    "SetOp", "Join", "Expand", "Pattern", "Package", "Emit", "SourceSelector",
    "Measure",
    "Duration", "TimeRef", "Call", "Comparison", "BoolOp", "Arith", "FieldExpr",
    "FieldRef", "Literal",
    "SCHEMA_VERSION", "NODE_TYPES", "AGGREGATES", "REGEX_DIALECTS",
    "EXECUTABLE_DIALECTS", "MAX_NODES",
    "Refusal", "ABSENT", "UNDECIDED", "Undecided", "ComparisonResult",
    "compare", "presence", "and_", "or_", "not_", "has_value",
]
