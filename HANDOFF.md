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

Repo: `D:\visual code file\Combined Project\RuleForge`
Tool: the repository root — **flat, no package**

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
| `114550e` | Old SIEM tool deleted; `run.py` moved into the package |
| _(this commit)_ | **Package flattened** — `ruleforge/` removed, code at the root |

Earlier session commits belonged to the *parent* tool, not RuleForge. None of it
was ever a dependency, and it is now deleted outright.

**Current state: 468 tests passing, Ruff clean, 15/15 mutations caught.**

Verify with:
```
python -m pytest tests -q -p no:cacheprovider
ruff check .
python mutation_check.py
```

### The layout, and why it changed

It used to be `ruleforge/` containing everything, imported as `ruleforge.engine`
and friends. Two things made that shape wrong rather than merely verbose:

* The launcher could not live beside the code without ambiguity, and could not
  live *inside* the package without a `sys.path` insert that had to be granted a
  documented exemption in `test_nothing_widens_the_import_path`. Flat, both
  problems disappear and so does the exemption.
* The package boundary existed to keep the tool from importing the older project
  that shared the root. That project is gone (`114550e`). The boundary was
  protecting against nothing, and enforcing it was pure cost.

`StandaloneTests` still enforces the property that matters — no module may import
anything outside this repository — but its allowlist is now **derived from the
directory** rather than naming a package, so it cannot drift when a module is
renamed.

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

---

## 10. Review rounds -- the most important section

**Four independent review rounds. Every one found real criticals. The suite was
green through all of them.** 339 -> 376 -> 403 -> 407 -> 424 tests.

| Round | Found | Fixed in |
|---|---|---|
| 1 (python + security, parallel) | 5 criticals, 2 injection bugs, 7 highs | `58655e2` |
| 2 (verification) | 13/14 + 7/7 confirmed fixed; found 7 NEW incl. 2 criticals | `5730957` |
| 3 (verification) | 13/14 confirmed; `Derive.projects` still dead; 2 NEW criticals | `e6e8b35`, `db64b11` |

### What each round taught

**The recurring class is a SECOND SOURCE OF TRUTH.** Every critical was some
other piece of code holding its own opinion about what something means:
`in_set` iterating `args[1:]` while dialects emitted a collection; a duplicate
`_lookup` field resolver; the KQL renderer stripping a prefix instead of
inverting a recorded map; `project` vs `extend` decided by a node-id string;
`_eval_boolop` overriding `or_`; `is_not_null` meaning both "not null" and "is
null" depending on which dialect minted it. When you add a feature, ask what
now knows this twice.

**The second class is a SILENT `else`.** AQL's renderer dropped 6 node types.
Wazuh's parser dropped `<match>`. Both produced a complete-looking artifact with
the detection missing. Every `if/elif` chain over node types or XML elements now
ends in a refusal.

**The third is A LIMIT ON ONE ENTRANCE.** The event cap was only in the parser.
`validate_graph` was only on `author`. The standalone test only scanned `engine/`,
which is 22% of the package -- and the moment it was widened to all of it, it
found six test files putting the PARENT TREE on `sys.path` for the whole suite.

### The two criticals from round 3, in case they regress

- A Wazuh `<match>` was dropped, so the rule matched **every event** and
  reported "the rule matched 3 of 3 events" with no warning.
- The ReDoS control was defeated by `a*a*a*a*a*a*a*a*$` -- **12 characters, no
  parentheses**. The detector only looked inside groups. It is now
  `engine/redos.py` and works on the precise condition: many unbounded
  quantifiers, or prefix-overlapping alternatives inside a repeated group.

## 11. Current state

468 tests, ruff clean, 15/15 mutations, 93 subtests. ReDoS: 0 catastrophic
accepted, 0 ordinary refused.

**A test here is a wall-clock flake, and it is not new.** `test_deeply_nested_groups`
in `tests/test_round4_findings.py` asserts the ReDoS analysis finishes in under
250ms. Measured on an idle machine it takes ~270-300ms, so it passes alone and
fails roughly one run in three under full-suite load. Verified against commit
`114550e` in a clean worktree: it fails there too, at the same rate, so it is not
caused by the flattening. The 250ms budget has almost no headroom on this
hardware and the assertion should be given real margin or dropped in favour of a
depth-scaling check.

Still open, honestly:

- **The last independent review was round 7.** Each round has found real
  criticals. Treat the current state as unverified against a fresh eye.
- **11 known defects remain** from round 7. Highest is Wazuh `level`
  unvalidated: `'abc'`, `'10.5'` and `'99999'` reach the artifact, and a rule
  pasted with no level is emitted as `level=0` silently — a detection deployed at
  level 0 with nothing said. The rest are listed in the session transcript; they
  are two false comments in `yaral_ir.py`, a vanishing second `Derive` in
  `wazuh_render`, SPL `head` dropping sort direction, a ReDoS screen that
  accepts `(?:a|aa)+$` while refusing `(a|aa)+$`, a dead `SetRule` in a safety
  allowlist, uncapped `debug_logs_to_rule`, and dead code in `regex.py`/`redos.py`.
- History is 0600 on POSIX via `mkstemp`; on Windows `os.chmod` does not model
  POSIX bits, so the `.gitignore` comment claiming 0600 is false there.
- `history.py` rewrites the whole file per append: O(N^2*S), ~1 TB of writes at
  the caps.
- XML entity expansion is bounded by libexpat's amplification limit, which is a
  platform accident rather than a stated invariant. `defusedxml` would fix it.
- Elastic EQL and Falcon CQL are not started. **Sigma is not a target** — it is an
  interchange format with no execution semantics, and counting it as missing work
  inflated the scope for several rounds.
- **Blocked on the user:** their verbatim SPL rule is not in the repository, and
  three commits are unpushed.
