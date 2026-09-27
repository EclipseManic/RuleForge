# RuleForge

Paste a detection rule, find out what it actually does, and see whether the
engine you'd deploy it to would agree with you.

Five SIEM dialects: **QRadar AQL**, **Splunk SPL**, **Microsoft Sentinel KQL**,
**Wazuh Ruleset XML**, and **Google SecOps YARA-L 2.0**.

## Run it

```
pip install -r requirements.txt
python run.py
```

That opens the tool in your browser. No arguments, no environment variables, no
configuration. If port 5001 is busy it takes the next free one and tells you
which.

## What it is for

You have a rule — yours, or one from a vendor, or one an LLM wrote — and you
want to know three things before you deploy it:

1. **What does it match?** Paste a handful of events, see exactly which ones
   the rule selects, and get a reason for every row it rejected.
2. **Does this dialect's engine agree with the author?** Several rules are
   written in a *different* dialect than the one you will deploy them to. The
   tool lowers them into a common model and refuses the round trip when the two
   genuinely disagree, rather than producing something that looks like your rule.
3. **What did the tool refuse, and why?** It is built to say "I cannot honestly
   represent this" far more often than a normal tool would. Every refusal names
   the construct and the reason.

### The part that matters most

`ABSENT`, `NULL` and `""` are three different things, and this tool keeps them
different. A great deal of real-world detection breakage is a rule quietly
treating a missing field as an empty string. Here, a condition that cannot be
decided is `UNDECIDABLE` — never silently `False`.

The corollary is that **an empty answer is not a safe answer.** When a rule
cannot be executed faithfully, the tool refuses. It will not hand you a rule
that matches every event while telling you it worked.

## Layout

```
run.py            the launcher - this is what you run
engine/           the dialect-neutral rule model and evaluator
  ir.py           typed nodes; three-valued values
  evaluate.py     expression evaluation, field resolution
  run.py          graph execution, windows, joins, packages
  regex.py        regex dialects; only what can honestly be executed
  redos.py        catastrophic-backtracking analysis
  validate.py     graph validation, and the deploy-path regex screen
dialects/         parse -> lower -> render, one module per vendor
jobs.py           the five jobs the UI calls
history.py        append-only local history
web.py            Flask routes
tests/            the suite
```

Everything is flat: `run.py` sits beside the code it launches, so Python puts
the whole tool on `sys.path` by itself and the launcher has no import
arrangement to get wrong. There is no package to install and no `PYTHONPATH` to
set.

## Boundaries

- **Local only.** It binds `127.0.0.1`. There is no login, and pasted rules and
  event samples are stored on disk, so it is not exposed to your network.
- **No AI, no cloud, no field mapping, no SIEM credentials.** It never sends
  anything anywhere.
- **Where it cannot run a pattern faithfully, it refuses rather than
  approximating.** YARA-L is PCRE and this engine is not, so a local run of a
  YARA-L regex says so instead of guessing with Python's `re`. Splunk `tstats`
  reads index-time fields and is likewise refused locally. Both still parse,
  lower, and render correctly.
- **History is local, append-only, and has no delete path.** That is deliberate
  — an audit trail you can quietly edit is not an audit trail.

## Tests

```
python -m pytest tests -q
ruff check .
python mutation_check.py
```

The mutation harness exists because a green suite in this project has repeatedly
meant nothing on its own: a control can be in the code, exercised by its own
tests, and still not be on the path the product actually uses.
