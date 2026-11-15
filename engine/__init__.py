"""The vendor-neutral engine: one rule model, eight dialects, no dependencies.

    parse    native text  -> parsed structure
    lower    parsed       -> Rule          (the model in ir.py)
    render   Rule         -> native text

Nothing in here is allowed to know a vendor's syntax, and nothing outside is
allowed to be needed to run it. That is what makes eight dialects possible
without eight tools, and it is enforced by `tests/test_dialects.py` rather
than by good intentions.

    ir.py          the rule model: 11 expression nodes, 13 stage nodes
    values.py      ABSENT, UNDECIDED, Refusal, Duration, Capability
    evaluate.py    three-valued expression evaluation, regex screening
    pipeline.py    pipeline execution, verdicts, the stage trace
    validate.py    structural lint and the ReDoS screen
    codec.py       lossless tagged-JSON serialisation of a rule
    store.py       append-only SQLite history with lineage
    synthesize.py  log samples to a proposed rule
    cli.py         the headless subcommands `run.py` hands over to
    dialects/      the eight vendor languages and their shared parser
"""

from __future__ import annotations
