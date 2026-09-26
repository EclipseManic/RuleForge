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
| `0e01e82` | Engine from scratch + QRadar AQL. 139 tests. |
| `b54b1ab` | YARA-L 2.0 dialect + `Call.flags`. 166 tests. |
| `fb5cc33` | Sentinel KQL dialect. 184 tests. |
| *(uncommitted)* | KQL post-join column resolution — **2 tests failing** |

Earlier session commits in the same repo (the *parent* tool, not RuleForge):
`e520b7d`, `9b4b3d7`, `6a992e3`, `d43b53c`, `ba57e22`, `d1fc6a0`, `f1c9f28`,
`e484165`, `53036df`, `d89217e`.

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

## 4. Current test state

```
183 passed, 2 failed
```

Verify with:
```
python -m pytest ruleforge/tests -q -p no:cacheprovider
ruff check ruleforge
python ruleforge/mutation_check.py     # 15 mutations, all must go red
```

### THE TWO OPEN FAILURES — START HERE

**Bug A — `in_set` silently drops every row.** (in progress)

`GrantedAccess in ("0x1fffff", "0x1010", "0x1410", "0x143a")` in the user's
Sentinel rule filters the LSASS branch to **zero rows**, so the join never happens
and the correlation reports a clean `no_match`. Right verdict shape, wrong cause —
the dangerous kind of failure.

One cause found and fixed: options were built as `Literal` **objects nested inside**
a `Literal`, so every comparison was against a `Literal` instance instead of a
string. **A second cause remains unfound.**

Next step: read `_eval_call`'s `in_set` branch in `ruleforge/engine/evaluate.py`
directly. Do not patch blind. Note there were **two** `in_set` construction sites
in `kql_ir.py` (`has_any` at ~line 660 and the `in`/`in~` loop at ~line 689) and
only the first was corrected — check both.

**Bug B — `test_the_aggregate_carries_the_four_measures_and_two_keys`.** Not yet
diagnosed. It asserts the `summarize` produces `count`/`min`/`max`/`set` measures
and `Computer`/`Account` keys.

---

## 5. Architecture

```
native syntax ──parse──▶ parsed ──lower──▶ RuleIR ──render──▶ native syntax
   (5 dialects)                                          (+ evaluate for tune/debug)
                              │
                     refuse by name at every edge
```

Node types: `Read Filter Derive Aggregate Arrange SetOp Join Expand Pattern Emit`

### Files

| File | Lines | Role |
|---|---|---|
| `engine/values.py` | ~350 | Three-valued logic, `Refusal`, ABSENT/UNDECIDED |
| `engine/ir.py` | ~1000 | Typed IR, closed vocabularies, construction-time refusals |
| `engine/validate.py` | ~250 | Cycles, dangling refs, unreachable nodes, bounds |
| `engine/evaluate.py` | ~500 | Expression eval, `Budget`, `Row`, `Caveat` |
| `engine/nodes.py` | ~700 | Windows, joins, patterns, sets, unnest, `resolve_field` |
| `engine/run.py` | ~300 | Iterative topological walk, `_verdict` |
| `engine/regex.py` | ~200 | Allowlist scanner; `posix_extended` executable only |
| `dialects/aql.py` + `aql_ir.py` | ~800 | QRadar AQL + CRE split |
| `dialects/yaral.py` + `yaral_ir.py` | ~700 | YARA-L 2.0 |
| `dialects/kql.py` + `kql_ir.py` | ~900 | Sentinel KQL (**mid-fix**) |
| `mutation_check.py` | 70 | 15 mutations |

---

## 6. Dialect status

| Dialect | Parse | Lower | Render | Execute |
|---|---|---|---|---|
| **QRadar AQL** | ✅ | ✅ | ✅ | partial — `QIDNAME` reported unevaluable (correct: appliance-side) |
| **YARA-L 2.0** | ✅ | ✅ | ✅ | partial — PCRE declared, not executable (correct) |
| **Sentinel KQL** | ✅ | ✅ | ❌ | ❌ two open bugs |
| **Wazuh XML** | ❌ | ❌ | ❌ | needs parent/child `Package` node |
| **Splunk SPL** | ❌ | ❌ | ❌ | needs `tstats`/datamodel handling |
| Elastic EQL / Falcon CQL / Sigma | ❌ | ❌ | ❌ | not started |

---

## 7. The user's five acceptance rules

Verbatim in the test files, **not** rewritten fixtures:

| Rule | File |
|---|---|
| Wazuh XML | not yet written as a test — this is the next one |
| Splunk SPL | not yet written |
| Sentinel KQL | `tests/test_kql.py` ✅ |
| QRadar AQL | `tests/test_aql.py` ✅ |
| YARA-L 2.0 | `tests/test_yaral.py` ✅ |

Using the real rules is the point. A fixture I wrote myself would have been
correct by construction and would have tested nothing.

---

## 8. Verified vendor facts (do not re-derive)

- **YARA-L 2.0** — `match: $k over <n><m|h|d>`, min 1m max 48h; `by` is a
  tumbling bucket; `after $e1` is a pivot-relative window (**refused** here);
  regex literals `/p/ nocase`; cross-event comparison is a **sequence order**.
- **Wazuh** — `if_matched_sid` + `frequency` + `timeframe` + `same_srcip`
  **require a shared field**; there is no time-only correlation. Rule 100211
  cannot exist without 100210.
- **Splunk** — `tstats` runs only over indexed fields or an **accelerated
  datamodel**; `span=` is mandatory when grouping by `_time`.
- **Sentinel** — scheduled rules run a **five-minute ingestion delay**;
  `make_set` returns a collection, not a count.
- **QRadar** — an AQL search is **not** a CRE rule. AQL queries Ariel; a CRE
  object is tests + response, and building blocks are tested before rules.

---

## 9. Defects found in this build — do not reintroduce

Every one of these was live and wrong at some point. Each has a test.

1. `Pattern` stage 0 validated then **discarded** — correlation fired on any rows.
2. `Pattern.within` referenced **nowhere** — "within 10 minutes" matched 3 hours.
3. `until` vetoed the last row, not the **window**.
4. POSIX BRE translation **unfaithful** — `+ ? { | ( )` are literals in BRE.
   `posix_basic` is now declared but **not executable**.
5. Lookaround/named groups sat behind a literal `pass` in the refuse table.
6. `and_` treated any non-`False` as `True` — ABSENT became a match.
7. `Emit(dedupe_by=…)` collapsed 50 events to 1, silently.
8. `exists`/`is_not_null` **always** returned UNDECIDED — checked the value
   instead of the expression.
9. `contains` operands **reversed** (`value in pattern`) — every
   case-insensitive filter matched nothing.
10. `ILIKE '%x%'` lowered with the `%` wildcards intact.
11. `Join`/`SetOp` absent from the dispatch table — validated then refused.
12. `Not` did not exist in the IR at all.
13. `FieldRef.path` honoured by expressions, ignored by every node.
14. `Derive`/`Aggregate` fabricated `NULL` from `ABSENT`.
15. `Field` was listed in `NODE_TYPES` but is a parameter, not a node.
16. `coalesce` returned UNDECIDED whenever any arg was ABSENT — the only case it
    exists for.
17. `evaluate` fed both Reads the same rows — a join returned the square of its
    input.
18. Undecidability allowlisted two caveat codes; now default-deny.
19. `REGEX` used a **blocklist**; now an allowlist.
20. `nocase` had nowhere to live → `Call.flags`.
21. A **cross-event comparison** lowered as a same-row comparison would compare
    the login's timestamp to itself.
22. `$host` placeholder lowered as a predicate resolved a field present in no row.
23. A single-event YARA-L rule rendered as **one empty event** (no `Filter` branch).
24. `let` bindings terminated by the next `let` instead of `;` — the final binding
    swallowed the runnable expression.
25. `let timeframe = 30m` → `ago(timeframe)` resolved `timeframe` as a field.

---

## 10. Engineering discipline

- `sequentialthinking` MCP **fails with NaN argument corruption** in this session.
  Fall back to `skill({name:"structured-reasoning"})`; do not block.
- Every agent in the configured list is **review-only** and cannot write files.
  Delegating a write task fails silently. Write code yourself.
- **Do not use bulk string replacement** on Python files. It duplicated a variable
  and dropped one in `kql_ir.py`, costing several turns. Use the edit tool.
- Mutation-test any new guard. A test that cannot fail is decoration.
- Never claim a test passes without running it in this session.

---

## 11. Next five tasks, in order

1. **Fix the `in_set` drop** (Bug A) and the aggregate test (Bug B). Suite green.
2. **Wazuh XML** dialect + the parent/child `Package` node for `if_matched_sid`.
   `RulePackage` exists in the IR but is **not** a node type.
3. **Splunk SPL** — `tstats`, datamodel, `span`, subsearch-in-`join`.
4. **Web app** — home page + workshop, 4 tabs, append-only History JSON.
5. **The four jobs** wired to the engine, then the full 5-rule acceptance suite.

Final gate: `python-reviewer` **and** `security-reviewer` over the whole tool.
