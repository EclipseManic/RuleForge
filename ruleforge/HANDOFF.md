# RuleForge — Handoff

**Written mid-build so the next session can resume without re-deriving anything.**
Read this file first. It is the state of the world, not a plan.

---

## 1. What this tool is

A standalone detection-rule workbench. It imports **nothing** from the project it
sits inside — a test enforces that, because an earlier draft bridged into the
parent tree with `sys.path` and was reverted.

Four jobs only, per the user's instruction:

| Job | Meaning |
|---|---|
| **Author** | Paste a native rule, edit it, re-render it |
| **Tune** | Structural always; behavioural when the user supplies events |
| **Debug** | rule → the query that returns triggering events; and log → rule |
| **Understand** | Explain, trace, cost at target, named refusals |

No auth, no plugins, no field-mapping layer, no database, no marketplace, no AI.

---

## 2. Repo location and history

Repo: `D:\visual code file\Combined Project\Siem-Rule-Generator`
Tool: `ruleforge/`

| Commit | What it contains |
|---|---|
| `0e01e82` | Engine from scratch + QRadar AQL |
| `b54b1ab` | YARA-L 2.0 + `Call.flags` |
| `fb5cc33` | Sentinel KQL dialect |
| `e0a37a8` | KQL post-join column resolution (WIP) |
| `0dfbda2` | **`in_set` fixed** — the big one |
| `7f64b15` | `Package` node for Wazuh parent/child |
| `466e6d3` | Wazuh XML dialect, from the real ruleset |
| `19c4e36` | Splunk SPL dialect, from Splunk's SearchReference |

Earlier session commits in the same repo (the *parent* tool, not RuleForge):
`e520b7d`, `9b4b3d7`, `6a992e3`, `d43b53c`, `ba57e22`, `d1fc6a0`, `f1c9f28`,
`e484165`, `53036df`, `d89217e`. None of it is a dependency.

**Current state: 251 tests passing, Ruff clean, 15/15 mutations caught.**

Verify with:
```
python -m pytest ruleforge/tests -q -p no:cacheprovider
ruff check ruleforge
python ruleforge/mutation_check.py
```

---

## 3. The one invariant everything is built on

**An undecidable comparison is never `False`.**

```
ABSENT   the field is not in the row
NULL     the field is there and its value is null
""       the field is there and its value is empty
```

Three states, not two. `NOT UNDECIDED` is `UNDECIDED`, never `True`.

`values.py` is the one file an independent review could **not** break. Every leak
found was in the nodes feeding it — which is the lesson worth carrying.

---

## 4. Dialect status

| Dialect | Parse | Lower | Render | Execute |
|---|---|---|---|---|
| **QRadar AQL** | ✅ | ✅ | ✅ | partial — `QIDNAME` unevaluable (correct: appliance-side) |
| **YARA-L 2.0** | ✅ | ✅ | ✅ | partial — PCRE declared, not executable (correct) |
| **Sentinel KQL** | ✅ | ✅ | ❌ | ✅ two bugs fixed |
| **Wazuh XML** | ✅ | ✅ | ❌ | ✅ |
| **Splunk SPL** | ✅ | ✅ | ❌ | ✅ `stats`; `tstats` refused by name |
| Elastic EQL / Falcon CQL / Sigma | ❌ | ❌ | ❌ | ❌ not started |

### THE FOUR OF FIVE USER RULES ARE VERBATIM IN THE TESTS

`test_aql.py`, `test_yaral.py`, `test_kql.py`, `test_wazuh.py` hold the user's own
rules. `test_spl.py` does **NOT** — the user's SPL rule is nowhere in the repo, so
those tests use this project's own `docs/advanced-rule-corpus.md` reference search
and say so. **Getting the real SPL rule is an open task.**

`test_wazuh.py` uses the **real shipped Wazuh ruleset** (60000/60001 from
`0575-win-base_rules.xml`, 60102/60104/60107/60203/60205/60206 from
`0580-win-security_rules.xml`), because the child's meaning lives entirely behind
`if_matched_sid` and a fixture I wrote would have proved nothing.

---

## 5. Findings about the vendors' own rules — do not "fix" these

**Wazuh rule 60000 is `\.+`.** `\.` is an *escaped dot*, so the pattern means
"one or more literal dots", not "any character". The real provider name,
`Microsoft-Windows-Security-Auditing`, has none. On the literal reading 60000 does
not match its own channel's events, so neither do 60001, 60104, 60107, 60203 or
60205 — **the whole 60xxx Windows security chain is gated behind a pattern that
cannot match a normal provider name.** The author almost certainly meant `.+`.
RuleForge reports what the rule SAYS. Rewriting it would report matches the
deployed agent does not produce.

**Wazuh rule 60206 is correlated with no `same_*` element.** Genuinely that broad.
Refused, because honouring it means counting anywhere in the log.

**Wazuh `frequency="$MS_FREQ"`** is an ossec.conf preprocessor variable, not a
number. Refused by name unless the caller supplies the value. Defaulting to 1
would invert the rule's meaning silently.

**Splunk `dc` is not a `tstats` function.** `dc` is the `stats` alias; tstats
spells it `distinct_count`. Accepting `dc` under tstats would claim the agent runs
a function tstats does not have.

**Splunk `BY _time` requires `span=`.** Without one every event collapses into a
single bucket, which is a different report.

**A bare term in Splunk search is ambiguous.** `index=main EventCode` asserts the
field exists — but only if the index has such a field. Otherwise Splunk searches
the raw event for that string, matching a *superset*. Which applies depends on the
deployment's field inventory, not the rule text. Lowered as field-existence plus a
diagnostic. Refusing would reject an ordinary Splunk search.

---

## 6. Architecture

```
native syntax ──parse──▶ parsed ──lower──▶ RuleIR ──render──▶ native syntax
   (5 dialects)                                          (+ evaluate for tune/debug)
                              │
                     refuse by name at every edge
```

Node types: `Read Filter Derive Aggregate Arrange SetOp Join Expand Pattern Package Emit`

`Package` exists because Wazuh parent/child is **not** a `Pattern`. A `Pattern`
requires every stage. A Wazuh parent is a complete rule that fires on its own and
the child is a *reaction* — so a childless parent is a real alert.

Two Wazuh semantics that are easy to get wrong and cost real time:

- A child rule with **no `<field>` of its own** means "the parent, N times", i.e.
  `count_subject="parent"`. Modelling it as a childless correlation fires on the
  FIRST event, turning a frequency-5 password-spray detector into a rule that
  alerts on one wrong password.
- The frequency window **slides** (trailing `[t - timeframe, t]`). Anchoring a
  forward window on the first event means "5 times in 240s" needs five *further*
  events after the first, and a spray of exactly five never fires.

### Files

| File | Role |
|---|---|
| `engine/values.py` | Three-valued logic, `Refusal`, ABSENT/UNDECIDED |
| `engine/ir.py` | Typed IR, closed vocabularies, construction-time refusals |
| `engine/validate.py` | Cycles, dangling refs, unreachable nodes, bounds |
| `engine/evaluate.py` | Expression eval, `Row`, `Caveat` |
| `engine/nodes.py` | Windows, joins, patterns, packages, `resolve_field` |
| `engine/run.py` | Iterative topological walk, `_verdict` |
| `engine/regex.py` | Allowlist scanner; `posix_extended` executable only |
| `dialects/aql.py` + `aql_ir.py` | QRadar AQL + CRE split |
| `dialects/yaral.py` + `yaral_ir.py` | YARA-L 2.0 |
| `dialects/kql.py` + `kql_ir.py` | Sentinel KQL |
| `dialects/wazuh.py` + `wazuh_ir.py` | Wazuh Ruleset XML |
| `dialects/spl.py` + `spl_ir.py` | Splunk SPL |
| `mutation_check.py` | 15 mutations |

---

## 7. Defects found in this build — do not reintroduce

Each was live and wrong at some point. Each has a test. **The ones marked ⚠ were
found by a dialect, not by a review — a review had not caught them.**

1. `Pattern` stage 0 validated then **discarded**.
2. `Pattern.within` referenced **nowhere**.
3. `until` vetoed the last row, not the **window**.
4. POSIX BRE translation **unfaithful**; `posix_basic` now declared, not executable.
5. Lookaround/named groups sat behind a literal `pass` in the refuse table.
6. `and_` treated any non-`False` as `True`.
7. `Emit(dedupe_by=…)` collapsed 50 events to 1.
8. `exists`/`is_not_null` **always** UNDECIDED.
9. `contains` operands **reversed**.
10. `ILIKE '%x%'` lowered with the `%` wildcards intact.
11. `Join`/`SetOp` missing from the dispatch table.
12. `Not` did not exist in the IR.
13. `FieldRef.path` honoured by expressions, ignored by every node.
14. `Derive`/`Aggregate` fabricated `NULL` from `ABSENT`.
15. `Field` listed in `NODE_TYPES` but is a parameter, not a node.
16. `coalesce` UNDECIDED whenever any arg was ABSENT.
17. `evaluate` fed both Reads the same rows.
18. Undecidability allowlisted two codes; now default-deny.
19. `REGEX` used a **blocklist**; now an allowlist.
20. `nocase` had nowhere to live → `Call.flags`.
21. A **cross-event comparison** lowered as a same-row comparison.
22. `$host` placeholder lowered as a predicate.
23. A single-event YARA-L rule rendered as **one empty event**.
24. `let` bindings terminated by the next `let` instead of `;`.
25. `let timeframe = 30m` → `ago(timeframe)` resolved a field.
26. ⚠ **`in_set` compared a value against a TUPLE.** The arity table allows
    variadic `in_set(v, a, b, c)`, so the evaluator iterated `args[1:]` — but all
    dialects emit `in_set(field, Literal(tuple))`, so `args[1:]` yielded one item,
    the collection, and every membership test was `False`. **Every `IN (...)`
    filter in the tool dropped every row.** In the Sentinel rule that emptied the
    LSASS branch so the join never ran and the correlation reported a clean
    `no_match`. QRadar and YARA-L were quietly wrong too. An `UNDECIDED` nested
    inside the collection also escaped the top-level guard and became a confident
    `False`.
27. ⚠ **`_lookup` in `evaluate.py` was a SECOND field resolver** alongside
    `resolve_field` in `nodes.py` — precisely what `resolve_field`'s own docstring
    warns against, and it had already caused defect 13. It bit again the moment
    the two diverged. Deleted, not kept in step.
28. ⚠ **Flat dotted keys were unresolvable.** Agents deliver fields nested (Wazuh's
    decoder) and flat (exported samples). Nested-only resolution made every dotted
    field silently `ABSENT` on flat input, so rules matched nothing and reported a
    clean `no_match` — looking like working rules. The nested walk is tried first,
    the flat key is the fallback. It must **not** `return ABSENT` from inside the
    walk loop, which is what defeated the first attempt.
29. ⚠ **The backslash allowlist was too broad.** Refusing every escape made Wazuh's
    own shipped `\.+` unexecutable over a character with exactly one meaning. `\.`
    `\+` `\\` are literals in ERE *and* BRE and are now allowed; `\d` `\w` `\s` `\b`
    `\1` genuinely differ and stay refused.
30. ⚠ **`dict(parent_row)` on a dataclass** in `eval_package` raised `TypeError`,
    which was swallowed; the node returned zero rows and reported a clean
    `no_match` with **no caveat**. The most expensive shape of silent failure.
31. ⚠ **Splunk's tokeniser split only on whitespace and parens**, so `index=windows`
    arrived as one token and the parser could not read a single real Splunk search.
32. ⚠ **A bare `count` has no parentheses.** Only `name(` was recognised, so the
    most common aggregate in SPL was dropped while the rest still parsed and the
    output still looked well formed.
33. ⚠ **`BY host user` split on commas alone** produced the single key
    `"host user"`, a field that does not exist.
34. ⚠ **Splunk's FROM clause was cut only at BY**, swallowing the whole WHERE as
    part of the datamodel name and never parsing it.
35. ⚠ **Splunk IN lists kept their separator**: `IN ("a.exe", "b.exe")` yielded
    `('"a.exe",', 'b.exe')`, so the first option matched nothing.
36. ⚠ **SPL `index=` and `sourcetype=` built a separate Read each**, which *unions*
    them. A guard then refused the combination outright — fixing the union by
    rejecting the most common opening line in SPL. Both were wrong; it is one
    ANDed filter now.
37. ⚠ **`_term_condition` had `if False else` dead code** from a careless edit, and
    `TimeRef(field=…)` / `FieldRef.from_dotted` were called with signatures that
    do not exist (`field_name`, and none). Read the target's signature.

---

## 8. Engineering discipline

- `sequentialthinking` MCP **fails with NaN argument corruption** in this session.
  Fall back to `skill({name:"structured-reasoning"})`; do not block. It worked
  again in a later turn, so try it first each time.
- Every agent in the configured list is **review-only** and cannot write files.
  Delegating a write task fails silently. Write code yourself.
- **Do not use bulk string replacement** on Python files. It duplicated a variable
  and dropped another in `kql_ir.py`, costing several turns. Use the edit tool.
- `python -c` in PowerShell mangles `$` and quotes. **Write a debug script to
  `$env:TEMP\opencode\` and run it.** Two debugging rounds were lost to `\$`
  escaping and a `dict.values` builtin shadowing.
- `evaluate.py` and several others are **CRLF**. A `'\n'` anchor in a Python
  string never matches them — normalise or use newline-agnostic slicing.
- Mutation-test any new guard. A test that cannot fail is decoration. The `in_set`
  fix was proven by reverting it and watching `InSetTests` go red (2 failed, 3 passed).
- Never claim a test passes without running it in this session.
- **Never invent a fixture and call it the user's rule.** That cost two wasted
  rounds on Wazuh (`^\+.+$` and `\.+` were both wrong) and is why the SPL tests
  label their provenance honestly.

---

## 9. Next tasks, in order

1. **Get the user's verbatim SPL rule** and add it as an acceptance test. It is the
   one input the tool claims to handle that is not actually verified.
2. **KQL renderer.** Must invert the Join's column map to recover the bare KQL
   name. **NEVER strip the prefix by string match** — `l_Process` is a legal KQL
   field name, so a blind strip silently corrupts it. The IR does not yet carry the
   column map, so that has to be added to `Join` first.
3. **Wazuh and SPL renderers**, for the round-trip.
4. **Web app** — home page + workshop, 4 tabs, append-only History JSON.
5. **The four jobs** wired to the engine, then the full 5-rule acceptance suite.

Final gate: `python-reviewer` **and** `security-reviewer` over the whole tool.
