# RuleForge

A local detection-rule workbench. Author a rule once, read it in eight SIEM
dialects, test it against real log samples, and keep the history of how it
changed.

**Standard library only.** Zero third-party imports, by design — it is meant to
run inside a locked-down SOC where `pip install` is not an option. No PyYAML,
no Flask, no pytest; the YAML reader, the HTTP server and the test harness are
all written against the stdlib.

```
python run.py                # http://127.0.0.1:8765/
python run.py verify         # the test suite, then the corpus sweep
```

Python 3.10 or newer. No build step, no dependencies, no configuration.

`run.py` is the front door. It serves the workbench, runs the checks, and
passes anything else through to the engine CLI, so
`python run.py convert sigma sentinel rule.yml` is the whole interface:
there is no second entry point to learn.

## Headless

The same engine without a browser, because a detection engineer cannot put one
in CI. Refusals go to stderr; the exit code carries the answer.

```
python run.py dialects
python run.py check     sigma      rule.yml
python run.py explain   sigma      rule.yml
python run.py convert   sigma   sentinel   rule.yml
python run.py test      sigma      rule.yml   events.jsonl
python run.py propose   samples.jsonl --target sigma
```

```
0  the work succeeded
1  a rule was refused, or a conversion lost something
2  the arguments were wrong
```

A **lossy conversion exits 1 even though it printed the text**, so a pipeline
cannot deploy a widened rule without noticing. `-` reads stdin, so the
subcommands compose:

```
python run.py convert sigma splunk rule.yml | python run.py check splunk -
```

## What it does

**Read a rule you did not write.** Paste a Sigma rule, a Splunk search, a KQL
query, Wazuh XML, AQL, EQL, YARA-L or an FQL filter. It comes back as a
structured rule with an outline that says, in prose, what the thing actually
matches — including the parts that do not mean what they look like.

**Convert between dialects.** Any ready dialect to any other. What *cannot*
cross is reported rather than dropped: see "Refusals" below, which is the part
of this tool that matters most.

**Test against samples.** Paste events and get `matched`, `no_match` or
`not_evaluated`, with a stage-by-stage trace of where rows were lost. The third
verdict is the important one — see "Three verdicts".

**Propose a rule from logs.** Paste several samples of the same behaviour and
it reports which fields are stable enough to be a detection and which only
looked stable. The output is labelled a hypothesis, because it is one.

**Keep the history.** Every saved rule records where it came from — `authored`,
`imported` or `synthesized` — and its parent, so a rule's lineage is readable.

## Dialects

| Key | Vendor | Language | Reads | Writes | Carries metadata |
|---|---|---|---|---|---|
| `sentinel` | Microsoft Sentinel | KQL | yes | yes | as a `//` header |
| `sigma` | Sigma | YAML | yes | yes | natively |
| `splunk` | Splunk | SPL | yes | yes | no — see below |
| `qradar` | IBM QRadar | AQL | yes | yes | as a `--` header |
| `elastic` | Elastic Security | EQL | yes | yes | as a `//` header |
| `wazuh` | Wazuh | XML | yes | yes | `<description>` |
| `chronicle` | Google SecOps | YARA-L 2.0 | yes | yes | `meta:` |
| `crowdstrike` | CrowdStrike Falcon | FQL | yes | yes | no — see below |

SPL and FQL cannot carry a rule's triage header: Splunk keeps that in a
`savedsearches.conf` stanza, and an FQL filter is a single string with no
comment syntax. Rendering into either reports `ANNOTATIONS_NOT_TRANSFERABLE`
rather than losing the title and severity quietly.

## The idea behind it

Every design decision in here comes from one failure: **a rule that matches
more than its author intended, while reporting success.** That is worse than a
crash, because nobody investigates a green result.

So the rules of the codebase are:

**Every dispatch chain ends in a refusal.** Not a silent `else`, not a `pass`,
not a `continue`. If a renderer meets a stage it cannot express, it says so by
name. This is enforced by `tests/test_fidelity.py`, which sweeps every rule in
a corpus through every dialect and fails if any field name or literal value
disappears without a diagnostic. That test exists because two renderers were
cherry-picking stages out of the pipeline and dropping the rest — including
thresholds, which turned "five failed logons from one account" into "any failed
logon".

**Absent, null, empty and undecided are four different things.** A missing
field is not an empty one. `Sigma`'s `field: null` asks whether a field is
present and null; KQL's `isnull()` has no such distinction because its schema
is fixed. They lower to different predicates, deliberately.

**Numbers are `Decimal` end to end.** A float threshold that compares unequal
to itself is not a threshold.

**A regex is only executed when the flavour can be honoured.** PCRE, PCRE2,
OS-Regex and Java regex are refused rather than run through Python's `re` and
reported as though they were the real thing. RE2 and POSIX ERE do execute,
because on the portable subset they agree. Every pattern is screened for
catastrophic backtracking first.

## Three verdicts

```
matched        rows survived the pipeline
no_match       nothing survived, and the engine is confident
not_evaluated  nothing survived, and the engine cannot be confident
```

`not_evaluated` is the whole point. A rule testing a field your sample does not
contain has not failed to match — the question was never answered, and saying
`no_match` would be a lie an analyst would act on.

An unapplied index-time filter is the one caveat that does *not* block a
confident negative, because removing rows cannot create a match — unless the
rule contains an anti-join, which asks for rows with no counterpart. Those keep
the strict verdict.

## Refusals

A refusal is a feature. Each one carries a code, the stage it came from, and a
sentence saying what would have gone wrong:

```
SEQUENCE_NO_JOIN_KEY      this sequence has nothing to join the steps on, so
                          any first event would pair with any later one
                          anywhere in the estate

WAZUH_RENDER_NO_SORT      Wazuh has no ordering. A rule whose meaning depends
                          on order has no Wazuh form, and writing it without
                          the ordering returns a different event

SPL_GENERATING_TSTATS     `tstats` reads an accelerated summary, not events,
                          so there is nothing for a sample to be tested
                          against. Rewrite it as a `search` over an index
```

The list is long on purpose. A tool that accepts everything and quietly
approximates the hard parts is a tool that produces rules nobody can trust.

run.py             the one entry point: serve, verify, corpus, and the CLI
engine/            the whole vendor-neutral engine, in one package
  cli.py           the headless subcommands and the exit-code contract
  ir.py            the vendor-neutral rule model: 11 expression nodes,
                   13 stage nodes, and the invariants they enforce
  values.py        ABSENT, UNDECIDED, Refusal, Duration, Capability
  evaluate.py      three-valued expression evaluation, regex screening
  pipeline.py      pipeline execution, verdicts, the stage trace
  validate.py      structural lint and the ReDoS screen
  codec.py         lossless tagged-JSON serialisation of a rule
  store.py         append-only SQLite history with lineage
  synthesize.py    log samples to a proposed rule
  dialects/
    common.py      shared tokenizer and Pratt parser; a bug here is a bug
                   in all eight dialects at once
    kql.py sigma.py splunk.py qradar.py
    elastic.py wazuh.py chronicle.py crowdstrike.py
web/               the browser half: stdlib http.server plus the interface
  api.py           routing, limits, hardening
  templates/ static/   the Home + Studio interface
tests/             1345 tests, stdlib unittest
corpus/            403 real-shaped rules, swept across every dialect pair
examples/          a rule pack with positive and negative fixtures per dialect
data/              runtime only: saved rule history, never in git



## Testing

```
python run.py verify
```

That runs the suite and then the corpus sweep: 403 real-shaped rules through
all eight dialects, in every direction. The suite alone is:

```
python -m unittest discover -s tests -t .
```


Three test modules are worth knowing about:

`tests/test_fidelity.py` is a **sweep, not a set of cases**. It walks a corpus
of rules through every dialect pair and asserts general properties: that no
field name or literal value disappears without a diagnostic, and that every
renderer emits text its own parser accepts.

It exists because the suite was fully green while a renderer silently dropped
thresholds — every test checked a conversion somebody had thought to check. A
case tests what its author remembered; a sweep tests what nobody thought of.
The second property, re-reading the output, found eight more defects the first
one could not see, including a renderer emitting `count(1)` that the same
module's parser rejects.

`tests/test_cli.py` holds the BOM tests. A UTF-8 BOM silently renamed the
first key of a rule, so a Sigma file saved by a Windows editor reported "this
rule has no title" about a rule whose first line was the title. It was found
because the CLI's own fixture was written with PowerShell, which adds one.

`tests/__init__.py` holds `planned_dialect`, a synthetic registry entry. All
eight dialects ship, so the planned-dialect refusal paths have no real dialect
to point at — and pinning them to one that later shipped inverted them twice,
silently, in this repository's history.

## Known limits

Stated because a tool that hides these is worse than one that does not have
them:

- **The sweeps are bounded by their corpus.** This is the honest limit, not a
  disclaimer: it is the mechanism by which two separate silent-widening bugs
  survived earlier rounds of "it's complete". A rule shape not in
  `tests/test_fidelity.py` is unexamined.
- **An ABSENT field makes a comparison UNDECIDED, not False.** This is a
  deliberate open-world choice, and it has a cost worth knowing before you
  trust a verdict: `selection and not filter` — the commonest idiom in
  SigmaHQ — reports `not_evaluated` rather than matching when the filter's
  field is missing from the sample event, because `NOT UNDECIDED` is
  `UNDECIDED`. The real SIEM, compiling that rule against a fixed schema,
  would fire. So a sample event must carry the fields a rule's filters
  mention for the verdict to be decided. The engine says `not_evaluated` and
  names the absent field rather than reporting a confident non-match, which
  is the tradeoff being made: a loud "I don't know" instead of a quiet wrong
  answer. `RealRulesMatchTheRightEvents` pins it so it cannot change silently.
- **The browser code has no behavioural tests.** Logic has been moved out of
  it where possible — synthesis, log parsing — but the form-to-IR binding and
  all rendering are unverified by the suite.
- **Every dialect covers a subset of its language.** The refusals are honest,
  but `tstats`, `sample`, `eventstats`, multi-event YARA-L and a long list
  more are refused rather than supported. Known gaps found by running real
  vendor rules: Sigma's bare `keywords:` full-text search, multi-document
  Sigma (so `correlation` rules must be lowered one document at a time), SPL
  subsearches (`[ search ... ]`), and computed AQL `SELECT` expressions such
  as `LOGSOURCENAME(logsourceid) AS "Log Source"`. All four refuse by name
  rather than misreading.
- **PCRE, PCRE2 and Java regex are modelled and rendered but never executed**,
  so a Sigma `|re` carrying PCRE or an AQL `MATCHES` is reported
  `not_evaluated` rather than guessed at. Wazuh OS-Regex and POSIX BRE are
  refused for a different reason — specific characters mean different things
  there — so a pattern containing none of those characters is executed
  exactly, which is what makes an ordinary Wazuh `<field>` rule locally
  testable.
- **SPL and FQL cannot carry a rule's triage header**, and say so.

## Scope

This is a workbench, not a service. It parses untrusted rule text and
evaluates rules against untrusted samples, so it binds to `127.0.0.1` and warns
if told to do otherwise. It does not ship rules to a SIEM, and it does not
pretend to know your data volume: a threshold it proposes is a number it chose,
and it says so.
