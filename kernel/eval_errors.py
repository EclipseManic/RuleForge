"""Refusals from the semantic execution kernel.

Mirrors `models.rule_ir.RuleIRValidationError` deliberately, so a refusal names the construct
instead of surfacing as a bare ValueError that a UI, a regression test and an API response
would each have to string-match differently.

THE THREE FAMILIES, NEVER BLURRED
----------------------------------
  IR_UNSUPPORTED_CONSTRUCT   our MODEL cannot represent the thing. Never used for a phase gap.
  EVAL_PHASE_NOT_IMPLEMENTED representable in the IR, not yet executed by THIS phase. Carries
                             `deferred_to`.
  EVAL_UNSUPPORTED_*         the slot exists but the semantics are undecidable from the data
                             we have.

A phase gap is not an IR deficiency and not a vendor limitation. Three different things, three
different codes, because they send an engineer to three different places.

NO CODE IN THIS MODULE MAY EVER BE PHRASED OR GROUPED AS "VENDOR X CANNOT DO THIS". Every code
concerns our model, our data, or our phase. That is the Phase 2b lesson applied a second time.

THE REGISTRY IS ENFORCED, NOT DOCUMENTED
-----------------------------------------
`KERNEL_EVAL_CODES` is the complete set of codes this kernel may raise, and a test greps the
source for every literal passed to `EvaluationRefusal` and asserts it appears here. Without
that gate the list rots into fiction within two phases - which is precisely how
`emitters_for()` shipped six fabricated `aql.*` capabilities while every test passed.
"""

from __future__ import annotations

from typing import Any

#: The complete, enforced set of refusal codes.
KERNEL_EVAL_CODES: frozenset[str] = frozenset({
    # --- the input contract is not satisfied -------------------------------
    "EVAL_INPUT_SOURCE_NOT_PROVIDED",
    "EVAL_INPUT_TOO_LARGE",
    "EVAL_INPUT_INVALID",

    # --- the clock cannot be resolved ---------------------------------------
    "TIME_FIELD_UNRESOLVED",
    "TIME_BINDING_CONFLICT",
    "TIME_UNRESOLVED_ON_ALL_ROWS",

    # --- a slot exists but its semantics are undecidable --------------------
    "FRAME_ALIGNMENT_UNANCHORED",
    "FRAME_SLIDING_STEP_UNDECLARED",
    "FRAME_OFFSET_NOT_APPLICABLE",
    "FRAME_SIZE_NOT_APPLICABLE",
    "MEASURE_ARG_EXTREME_UNDER_SPECIFIED",
    "MEASURE_FIELD_NOT_APPLICABLE",
    "MEASURE_FIELD_REQUIRED",
    "ARITH_STRING_CONCAT_UNSUPPORTED",
    "UNKNOWN_ARITHMETIC_OPERATOR",
    "FUNCTION_DIALECT_UNDECLARED",
    "ARRANGE_NEGATIVE_OFFSET",

    # --- representable, but this phase does not execute it -------------------
    "EVAL_PHASE_NOT_IMPLEMENTED",

    # --- two-input execution (3B) --------------------------------------------
    "JOIN_KIND_INEXPRESSIBLE",
    "UNKNOWN_JOIN_KIND",
    "JOIN_KIND_UNMATCHED_CONTRADICTION",
    "JOIN_TEMPORAL_WINDOW_WITHOUT_PREDICATE",
    "JOIN_CARDINALITY_VIOLATION",
    "JOIN_FIELD_COLLISION",
    "EVENT_SIDE_NOT_AVAILABLE",
    "EVENT_REF_OUT_OF_SCOPE",
    "TIME_SIDE_AMBIGUOUS",
    "EXPAND_MODE_INEXPRESSIBLE",
    "EXPAND_VALUE_NOT_A_SEQUENCE",
    "EVAL_OUTPUT_TOO_LARGE",
    "EVAL_JOIN_WORK_EXCEEDED",
    "EXPAND_OUTPUT_TOO_LARGE",

    # --- our model cannot represent it, or cannot be trusted here -----------
    "IR_UNSUPPORTED_CONSTRUCT",
    "IR_UNSUPPORTED_PARAMETERS",
    "NOT_A_KERNEL_NODE",
    "UNRESOLVED_SOURCE",
    "UNVERIFIED_SOURCE_REFERENCE",
    "UNVERIFIED_FIELD_REFERENCE",
    "UNKNOWN_SOURCE_STRATEGY",
    "ACCELERATED_SOURCE_WITHOUT_SCHEMA",
    "PRIOR_EMISSION_WITHOUT_PACKAGE",
    "UNKNOWN_COMPARISON_OPERATOR",
    "UNKNOWN_BOOLEAN_OPERATOR",
    "UNKNOWN_SET_OPERATION",
    "UNKNOWN_FUNCTION",
    "FUNCTION_ARITY_VIOLATION",
    "UNKNOWN_AGGREGATE_FUNCTION",
    "UNKNOWN_MEASURE_REFERENCE",
    "EXPRESSION_TOO_DEEP",
    "EVAL_DERIVE_FIELD_COLLISION",
    "MEASURE_OUT_OF_SCOPE",
})


class EvaluationRefusal(ValueError):
    """A refusal that names the construct. Never raised as a bare ValueError.

    Subclasses ValueError, so it must be caught BEFORE any `except ValueError` in a caller -
    the same trap as `RuleIRValidationError`, and for the same reason.
    """

    def __init__(self, code: str, message: str, path: str | None = None,
                 deferred_to: str | None = None) -> None:
        if code not in KERNEL_EVAL_CODES:
            # Fail closed on our own mistake: an unregistered code is a bug, and letting it
            # through is how the code list becomes fiction.
            raise AssertionError(
                f"refusal code {code!r} is not in KERNEL_EVAL_CODES; add it to the registry "
                f"in kernel/eval_errors.py rather than inventing it at the call site")
        if deferred_to is not None and code != "EVAL_PHASE_NOT_IMPLEMENTED":
            raise AssertionError(
                f"deferred_to is only meaningful for EVAL_PHASE_NOT_IMPLEMENTED, not {code!r}")
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.path = path
        self.deferred_to = deferred_to

    def __reduce__(self) -> tuple[Any, ...]:
        return (self.__class__, (self.code, self.message, self.path, self.deferred_to))

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "path": self.path,
                "deferred_to": self.deferred_to}


def not_evaluated(reason: EvaluationRefusal, counts: Any = None, trace: tuple = (),
                  caveats: tuple = (), unmodelled: tuple = ()) -> Any:
    """Build a `not_evaluated` result. The single place that state is constructed."""
    from kernel.eval_types import EvalCounts, EvalState, EvaluationResult
    return EvaluationResult(
        state=EvalState.NOT_EVALUATED,
        reason=reason,
        trace=trace,
        counts=counts if counts is not None else EvalCounts(),
        caveats=caveats,
        unmodelled=unmodelled,
    )
