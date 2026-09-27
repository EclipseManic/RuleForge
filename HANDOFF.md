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
| **Sentinel KQL** | ✅ | ✅ | ✅ | ✅ |
| **Wazuh XML** | ✅ | ✅ | ✅ | ✅ `negate`, level, multi-`Derive` all round-trip |
| **Splunk SPL** | ✅ | ✅ | ✅ | ✅ 8/8 commands; `fillnull` refused by name |
| Elastic EQL / Falcon CQL | ❌ | ❌ | ❌ | ❌ **not started — the real remaining gap** |

### SPL IS COMPLETE EXCEPT `fillnull`, AND THE REASON IS THE IR

All 8 pipeline commands lower and round-trip: `fields`, `rename`, `sort`, `head`,
`eval`, `regex`, `stats`, `dedup`. `fillnull` is the only refusal left, and it is
refused because `engine/ir.py` has **no node for "fill an empty value"** — not
because the parser cannot read it. It is also not safe to ignore, because filling
an empty field makes a LATER `where` match rows it otherwise would not, so
dropping it would quietly **widen** the rule. The refusal message says so and
suggests the `coalesce(...)` rewrite that does work.

`dedup` rides on `Emit.dedupe_by` and **must be the last stage** — `Emit` is the
graph's terminal, so there is nowhere to put a de-duplicating node mid-chain. A
mid-pipeline `dedup` is refused, not relocated, because collapsing rows at a
different point in the pipeline returns a different set of events.

### THE FOUR OF FIVE USER RULES ARE VERBATIM IN THE TESTS

`test_aql.py`, `test_yaral.py`, `test_kql.py`, `test_wazuh.py` hold the user's own
rules. `test_spl.py` does **NOT** — the user has confirmed they have no verbatim
SPL rule to supply, so those tests use this project's own
`docs/advanced-rule-corpus.md` reference search and **say so in the test
docstring**. This is no longer an open task; do not keep asking for the rule.

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

**Everything previously listed here is DONE** and the list was not updated. The
real remaining work, in order:

1. **Elastic EQL** — the largest remaining gap, and the hardest. EQL is *stateful
   and sequential* (`sequence by host with maxspan=5m`, `sample`, transitions,
   join events), which does **not** fit the flat relational vocabulary in
   `engine/ir.py`. Lowering sequences into a flat filter graph would be exactly
   the class of quiet-wrongness this project spent its whole history removing.
   **Read the real EQL grammar first**; do not lower against a guessed one.
2. **Falcon CQL** — smaller, same category of new work.
3. **Sigma** — **not a target.** It is validation *material*: the public
   repositories the user listed (SigmaHQ/sigma, ThreatClaw detection-rules-samples,
   `Hatchepsoute/sigma-rules`, Sigma Rules Hub) are a corpus to test the existing
   dialects against, not a sixth dialect to implement. `requirements.txt` still
   pins `pysigma` and five backends that **nothing imports** — either use them to
   read the corpus or drop the pins; do not leave them implying a feature that is
   not there.
4. `python-reviewer` **and** `security-reviewer` over anything landing from 1–3,
   before its commit.

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

**"Still open, honestly" was also obsolete** — every item in it was fixed. They
are listed in the table above with the fix that closed them. The two that were
most worth keeping the history of:

- **SPL `head` was correct in the renderer and UNREACHABLE**, because the lowerer
  refused every pipeline command, so no pasted rule could reach the renderer and
  no end-to-end test could catch a regression in it. `head` takes no fields:
  Splunk's documented syntax is `head [keeplast] [while "<expr>"] [<limit>]`
  with no field and no sort-order argument, and the docs say to `sort` first. So
  "first N in this order" is two stages, `| sort <ordering> | head <N>`.
  **The fix was to lower the commands, not to keep hardening the renderer.** A
  renderer branch that nothing can reach is not tested, however correct it looks.
- **Wazuh `negate="yes"` was reported by reading, not executed.** It needed one
  `author()` call to confirm, and the real cause was the same unreachable-branch
  pattern: the lowerer emitted `Not(Comparison(...))`, `_flatten` passed the
  `Not` through, and `_field` had no branch for it.
- **`rule_id` defaults to `"rule"`, but Wazuh looks the rule UP by id.** So
  every Wazuh job refuses a valid ruleset with `WAZUH_RULE_NOT_IN_DOCUMENT`
  unless the analyst also types the rule's numeric id into a second field.
- **A REFUSED rule is still recorded in the history as saved.** A render refusal
  becomes a *finding*, so `outcome.ok` stays `True` and `web.py` writes the entry
  and reports `saved: true` for an artifact that was never produced.

**The defect list this section used to carry is OBSOLETE.** All 11 round-7
defects were fixed and each fix is pinned by a test that fails without it:

| Was listed as a defect | Now |
|---|---|
| Wazuh `level` unvalidated (`'abc'`, `'10.5'`, `'99999'`, missing→`0`) | 4 named refusals; range 0–16; explicit `0` valid |
| Wazuh `negate` drops, `_field` blames arithmetic | renders; tests cover it |
| Wazuh second `Derive` vanishes | `WAZUH_TWO_DERIVES_NOT_RENDERABLE` |
| Wazuh `rule_id` defaulting to `"rule"` | single-rule docs infer; multi-rule refuse |
| SPL `head` drops sort direction | documented two-stage `sort` \| `head` |
| ReDoS accepts `(?:a\|aa)+$` | fixed, plus nested groups and `\w` escapes |
| dead `SetRule` in an allowlist | removed |
| uncapped `debug_logs_to_rule` | capped |
| dead code in `regex.py` / `redos.py` | removed |
| XML entity expansion a platform accident | `defusedxml`, `forbid_dtd=True` |
| a REFUSED rule still saved as `saved: true` | `Outcome(ok=False, rendered="", refusal=...)` |
| history O(N^2), ~1 TB of writes at the caps | JSONL: 1.02 GB, 1000x less |
| `.gitignore` claims 0600 on Windows | corrected; the real control is the ACL |

**The recurring lesson, now with four instances of it:** a renderer carrying
code for a shape it could not receive, silently discarding the part that
mattered. Wazuh `negate=`, SPL `regex`, SPL `dedup` (`if kind == "Emit":
continue` reached the node and dropped the dedup), and the Wazuh integer
grammar. All four looked like working code. Grep for `continue` and for
unreachable `if` branches before trusting any renderer branch.

- **The last independent review was round 7**, and it predates every fix above.
  Every review round in this project's history found real criticals while the
  suite was green. **Treat the current state as unverified against a fresh eye**
  — in particular the `dialects/spl_*.py` changes and the `history.py` format
  change have had no independent review.
- `history.py` is now **JSON lines**, and the **old JSON array is still read**.
  An existing history is upgraded by the next *save*, never by a *read* — a
  reader must never rewrite the analyst's file, because the corruption refusals
  promise it "has not been overwritten". A torn final line is tolerated (costs
  the tail entry only) but only when a good entry precedes it, so a damaged file
  is still reported as damaged.
- Elastic EQL and Falcon CQL are not started. **Sigma is not a target** — it is an
  interchange format with no execution semantics, and counting it as missing work
  inflated the scope for several rounds. Its value here is as a test corpus.
- Nothing is blocked on the user. Everything is committed and pushed;
  `origin/master` is at the tip.
