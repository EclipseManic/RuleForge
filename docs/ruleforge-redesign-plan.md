# RuleForge — Core Architecture Redesign Plan

**Status:** proposal, awaiting approval. No product code is written against this yet.
**Date:** 2026-09-25
**Relates to:** `docs/readiness-assessment.md` (adds to it, supersedes nothing)

---

## 1. The decision this document asks for

Approve a full core redesign of RuleForge: replace the rule model, the authoring surface,
the source parsers, the target renderers and the local evaluator, delivered in reversible
phases.

This is not a UI polish job and not a bug list. The ceiling the tool cannot reach is
**structural**, and no amount of fixing individual features lifts it.

---

## 2. Root cause, with measurements

`models/correlation.py::CorrelationModel` is a **bag of parallel lists**:

```
conditions · exclude_conditions · sequences · joins · aggregations · lookups
```

There is no ordering and no dataflow. Therefore it cannot represent
"filter → aggregate → filter on the aggregate".

The shapes a professional detection engineer actually writes are therefore
**unrepresentable**, not merely unimplemented:

| Real-world construct | Representable today? |
|---|---|
| Filter → aggregate → **filter on the aggregate** | No |
| Several **named measures** in one summarize | No |
| **Tumbling time bucket** correlation | No |
| **Temporal join** (`b between (a .. a+10m)`) | No |
| **Cross-event** timestamp comparison (YARA-L) | No — would be conflated with a sequence |
| **Rule bundle** with parent/child IDs (`if_matched_sid`) | No |
| **Subquery** in brackets / `let` bindings | No |

Every layer inherits the ceiling: the form emits only *N* predicates, the parsers flatten
to *N* predicates, the renderers render *N* predicates, the local evaluator evaluates *N*
predicates, the ATT&CK catalog stores *N* predicates. This is why fixing any single
renderer or parser has never moved the ceiling.

### 2.1 Measured evidence

**A Sigma rule the editor cannot represent** (`selection | count() by User > 5`) had a
fabricated `process.name contains example.exe` injected into real, copyable, downloadable
SPL and AQL. HTTP 200, `compile_allowed: true`. Now it refuses instead.

**A 3-stage Splunk pipeline** (`| where … | stats count by … | where count >= 1`) came
back `mode: simple`, **one** condition, `fidelity: exact`. The aggregate and the
post-aggregate filter were deleted and the verdict claimed nothing was lost. Now a
flattened pipeline is `partial` and names what it dropped.

**The ATT&CK catalog** advertised 337 templates and 164 "buildable". 317 of 339 templates
(93%) carry `default_value: "*"` — a wildcard matching every event. Clicking one produced
a field and no predicate. Only 22 of 339 had a matchable value; after the fix **20**
qualify and 317 are labelled guidance-only.

---

## 3. What the last 10 hours did — and did not do

**Did:** eliminate silent-wrong-output defects (fabricated fields/values, an `exact`
verdict on a reduced pipeline, a strict-mode bypass, 500s on malformed input), make
refusals honest, fix the information architecture, and stop flattering numbers from being
presented as capability.

**Did not:** add a single unit of authoring power. The ten rules below are exactly as
un-authorable as they were before that work began. Safety and honesty are necessary but
they are not the product's core motive — being able to author a real rule is.

---

## 4. The rules used to validate this design

Ten real rules are the **acceptance corpus** — the suite that tests the design, not the
source of it. The design in section 6 is derived from first principles; these rules are
what proves it handles reality. Five are pipeline-shaped; five are harder and were used to
stress-test an earlier draft of the node list.

### Tier 1 — pipeline shape

| # | Rule | Shape |
|---|---|---|
| 1 | Splunk: credential dump + LSASS + network in 5 min | filter → aggregate → filter on aggregate |
| 2 | Sentinel: impossible travel + MFA burst | dual `countif` + time bin + predicate over measures |
| 3 | Wazuh: PowerShell → download → encoded command | ordered stages, per-stage windows |
| 4 | QRadar: brute force → success → privileged action | stateful `WHEN` / `FOLLOWED BY`, shared window |
| 5 | YARA-L: process + suspicious PowerShell + external conn | two event streams, join, outcome/risk |

### Tier 2 — the harder batch (stress-tested against the design)

| # | Rule | What it forces |
|---|---|---|
| **R1** | **Wazuh rule bundle** — parent `100210` with `<if_group>sysmon_event_10</if_group>`, child `100211` with `<if_matched_sid>100210</if_matched_sid>` + `<same_srcip/>` + `frequency="2" timeframe="300"` | A graph of **rule-alert dependencies and correlator state**, not a query. Needs a `RuleSet` container, `rule_group_match` / `rule_alert` sources, and a stateful sliding counter anchored to the current event. |
| **R2** | **Splunk** — `tstats summariesonly` over two datamodels, bracketed subquery, `join type=inner dest user`, second `stats` with `min/max/values`, `where` on aggregates, `eval` risk/mitre/name | Accelerated-summary source semantics, derived bindings, `span=5m` as **buckets not correlation windows**, a join with **no** temporal constraint, and Splunk's real subquery defaults. |
| **R3** | **Sentinel** — two `let` bindings, `join kind=inner on Computer, Account`, `LoginTime between (LSASSTime .. LSASSTime + 10m)`, `summarize` with aliases and `make_set`, `extend` | An equality join plus an **asymmetric inclusive temporal predicate** over joined rows, where `count()` counts **joined pairs, not distinct events**. |
| **R4** | **QRadar AQL** — `QIDNAME(qid)`, `LOGSOURCENAME(logsourceid)`, `UTF8(payload) ILIKE`, `GROUP BY`, `HAVING`, `ORDER BY` | A **grouped historical search, not an event sequence.** The production artifact for a real-time sequence is the **Custom Rules Engine**, which is an engine, not a file format. |
| **R5** | **YARA-L 2.0** — two event variables sharing `$host`, `match: $host over 10m`, and a **cross-event timestamp comparison** | A distinct `EventRelation` construct. Reusing `Sequence` would wrongly couple event pairing, stage order and span. The pasted `meta:` block is not valid YARA-L syntax. |

Two corrections the stress test produced, which the current tool gets wrong:

- **R2 is not temporal correlation.** The two `span=5m` are buckets; the join has no time
  constraint. The final `stats` proves only that, per entity, at least one left bucket
  matched a right row. It does **not** prove LSASS preceded NTLM. The rule's own
  `rule_name` is more specific than its semantics — preserve the text without adopting
  that interpretation.
- **R4 is not a sequence.** Its boolean means `LSASS OR (Sysmon AND lsass) OR (NTLM AND
  logon3)`. Two rows satisfying only the first branch meet `COUNT(*) >= 2`. It also has no
  `LAST`/`START`/`STOP`, so as pasted it is not a complete standalone AQL artifact.

---

## 5. The honest ceiling — read this before approving

**Not every rule will be fully production-authorable in every target, and no redesign
changes that.** The vendors are genuinely different:

- **Wazuh** has no fixed time buckets, no multi-measure aggregation, and only linear
  `if_sid` chains with a single sliding `if_matched_sid` counter.
- **QRadar** real-time sequences require CRE; AQL cannot express them. `LAST n MINUTES` is
  scan scope, not a correlation window.
- **Elastic** ES|QL has no event-stream sequence; EQL covers a restricted simple subset.
  `LOOKUP JOIN` is enrichment, not temporal event correlation.
- **Sigma** has no scheduling semantics at all.

**The bar this plan holds to:**

> Represent **every** construct that is expressible as an effect on rows, ordering, state
> and time, in one canonical kernel. Then, per target, either **emit faithfully** or
> **refuse naming the exact missing construct** and what the analyst must build by hand.

A refusal with a precise reason is worth more than a query that deploys and does not
fire. After the redesign **all ten corpus rules become representable**, and **each retains
at least one target refusal** — that is the goal, not a shortfall.

**And the general case, for rules not in the corpus:** a rule whose constructs all fall
inside the twelve primitives and the expression algebra is handled with **no new code**.
Anything outside fails loudly at the model layer with `IR_UNSUPPORTED_CONSTRUCT` — our
gap, not the vendor's — and is then a deliberate IR version rather than a silent bolt-on.
Section 6.7 lists what sits outside the kernel on purpose, and why.

---

## 6. The target design: RuleIR v2

A versioned, typed **DAG** replacing the parallel lists. Frozen dataclasses, stdlib only,
no new dependencies. `RuleRequest` and `CorrelationModel` remain as v1 compatibility
facades (`to_ir()` / `from_ir()`) so the 308 existing tests and stored history survive.

### 6.1 Nodes

> **Derivation note.** An earlier draft of this section listed thirteen nodes derived
> directly from the ten sample rules. That was overfitting: `RuleSet` came from R1,
> `EventRelation` from R5, `Transform` from R2. An adversarial check showed four ordinary
> relational operations were missing entirely, and several listed nodes were one primitive
> wearing a vendor costume. The kernel below is derived from **first principles** — from
> what a detection rule *is* — and the ten rules are demoted to an **acceptance corpus**
> that tests it. See section 6.8.

### 6.1 What a detection rule fundamentally is

> **Input records + transformations + temporal/state semantics → result rows, under an
> execution and deployment contract.**

That statement yields a small, closed primitive set. It is closed because every plan can
only have a finite set of **effects** on row identity, row multiplicity, schema, ordering,
grouping, state, and time visibility. A construct that fits one of those effects is a node
*parameter* or a typed *expression*. A construct introducing a genuinely new effect
requires a deliberate IR version — it cannot be smuggled in as an ad-hoc node, which is
exactly how the current parallel-list sprawl happened.

### 6.2 The twelve-primitive semantic kernel

| Primitive | Effect it has |
|---|---|
| `Read` | The only boundary where records, reference data, or prior emissions enter. |
| `Derive` | Changes a row's values or schema without changing whether the row exists. |
| `Filter` | Changes row membership by Boolean predicate. |
| `Expand` | Changes row **multiplicity** — one row becomes zero, one, or many. |
| `Frame` | Changes temporal/partition visibility: tumbling, sliding, session, per-event, cumulative. |
| `Aggregate` | Collapses groups into **named measures**. |
| `Arrange` | Relation-wide ordering, distinct, offset, limit, top-N. |
| `Join` | Combines rows from independent inputs by predicate, optionally with time. |
| `SetOp` | Combines sibling result sets: union, intersect, except, append. |
| `Pattern` | Recognises ordered, unordered, absent, repeating or session-related event structures. |
| `Iterate` | Recursive / fixed-point relations (graph closure, path traversal). |
| `Emit` | Defines the terminal result and alert contract. |

**Deliberately excluded from the kernel:** grouping (an `Aggregate` parameter or a `Frame`
partition), execution policy (program metadata), and packaging (a package root). None has
an independent result, so none belongs in the executable graph. Because `Iterate` exists,
the IR is a typed *graph*; ordinary rules remain acyclic.

### 6.3 How the ten rules map onto the kernel

This is the proof that the kernel is general rather than invented — the sample rules
dissolve into primitive compositions, needing **no vendor-specific nodes**:

| Node I originally proposed | Verdict | Canonical form |
|---|---|---|
| `Source` + 4 variants | Genuine primitive, bad variant design | one `Read` with a typed binding spec; raw/accelerated/reference/prior-emission are *strategies*, not subclasses |
| `Filter` | Genuine primitive | retained; a post-aggregate filter is the same node with a stricter input scope |
| `Transform` | Real operation, vendor name | `Derive` (projection, extension, rename, cast) |
| `TimeBucket` | **Not a primitive** | `Frame(kind=tumbling)` + a bucket expression |
| `Aggregate` | Genuine primitive | retained; grouping and measures are parameters; threshold is a following `Filter` |
| `PostAggregationFilter` | **Composition** | ordinary `Filter` over `MeasureRef` |
| `Join` | Genuine primitive | retained, generalised |
| `EventRelation` | **Composition / YARA-L costume** | `Frame + Join + Filter`; the timestamp comparison is a scoped expression |
| `Sequence` | Genuine family, too narrow a name | one `Pattern` mode — must also cover `until`, missing stages, unordered "two of three", and sessions |
| `Enrich` | **Composition** | `Read(reference) + Join + Derive` |
| `Outcome` | **Composition + terminal contract** | risk/score assignment is `Derive`; the match guard is `Filter`; alerting is `Emit` |
| `RuleSet` | **Not a graph node** | package/root: programs, IDs, dependency closure, artifact wrappers |
| `ExecutionPolicy` | **Not a graph node** | typed program metadata (lookback, lateness, state retention, suppression) |

So the Wazuh parent/child bundle is a **package** with a dependency graph, not a node. The
YARA-L cross-event rule is `Frame + Join + Filter`, not a special relation node. That is
the difference between a kernel and a costume rack.

### 6.4 Time semantics, separated and never collapsed

The current single `window` field conflates five different things. Each gets one home:

| Meaning | Where it lives |
|---|---|
| source scan / lookback range | `Read` bound + execution metadata |
| tumbling bucket | `Frame(kind=tumbling)` + group key |
| rows visible to an aggregate | `Aggregate` input frame |
| join time relationship | typed predicate inside `Join` |
| sequence / sample max span | `Pattern` constraint |
| alert cooldown / suppression | `Emit` + execution policy |

Concretely: Splunk `span=5m` is a bucket; Wazuh `frequency/timeframe` is an aggregate
frame; EQL `maxspan` is a `Pattern` constraint; YARA-L `match … over` is a `Frame` plus a
scoped `Join`; AQL `LAST n MINUTES` is a source bound.

### 6.5 The closed expression algebra

Expressions compute scalars and predicates **inside one typed row scope**. They may not
contain subqueries, joins, state machines, or target-language fragments.

Literals (null, bool, int, decimal, string, bytes, timestamp, duration, IP/CIDR, regex,
typed list) · `FieldRef` · `MeasureRef` (legal only after its producer) · `EventRef`
(scoped left/right/stage, legal only inside `Join` or `Pattern`) · `TimeRef` (never
silently replaced with a guessed timestamp field) · allowlisted `FunctionCall` · explicit
casts · comparisons · `AND`/`OR`/`NOT` · arithmetic · list form.

`if`, `coalesce`, regex match, string containment and CIDR membership are **registered
functions**, not syntax variants. Unknown function IDs are refused; there is no raw
function-name escape hatch.

Type rules: booleans are three-valued (`TRUE`/`FALSE`/`UNKNOWN`); `Filter` emits only
`TRUE`; runtime `NULL` and compile-time `UNRESOLVED` are different states; an unresolved
field/source/measure blocks deployment; no implicit coercion, case folding, ordering,
rounding, timezone handling, or regex dialect; function signatures declare null, collation,
ordering, timezone, purity and determinism.

**This is what makes the system general.** An unforeseen rule becomes *data* — a new
expression or a new composition of the twelve primitives — not new architecture.

### 6.6 Vendor capability registry

Three versioned, data-only catalogs: a **function catalog** (canonical IDs and full
semantic contracts), an **operator catalog** (per-node schemas, cardinality, ordering,
time behaviour, state, evaluator identity), and a **target profile** keyed by
`(product, engine, artifact kind, target version)`. Note that `qradar + AQL + saved
search` and `qradar + CRE + custom rule content` are **separate profiles**.

Each entry declares a support level — `native`, `equivalent rewrite`, `partial` (never
produces a downloadable equivalent), or `unsupported` — plus machine-checkable
preconditions, the lowering recipe, required proof obligations, the refusal code, and the
inference policy. Resolution runs over the **whole typed graph path**, not one node at a
time; profiles are **default-deny**; missing profile data means refusal.

### 6.7 What remains genuinely outside the kernel — stated plainly

A closed kernel plus a rich algebra is not universal, and pretending otherwise would be
the exact failure mode we are redesigning away from. These are **refused or require an
explicit registered contract**, not silently approximated:

- free-form full-text / fuzzy / semantic search (needs a typed search AST; never an opaque
  query string passed to a "fulltext function")
- custom UDFs, custom SPL/CQL functions, procedural scripts (register a trusted callable, or refuse; never store executable source as IR)
- rule output that **mutates** offenses, reference sets or suppression state and thereby changes future matching (a genuine state-transition gap)
- arbitrary SOAR actions, host isolation, case creation, external callbacks
- custom decoders, file scanners, malware engines, ingestion plugins
- approximate sketches (HLL, t-digest, sampling) except where algorithm, seed, error and merge semantics are explicit
- out-of-order events, watermarks, exactly-once, cross-source snapshot consistency (policy-level, not node-level)

And one limit worth stating explicitly: **a registry entry cannot invent a missing parser
or emitter.** A new target profile can always be added as data that declares everything
unsupported; a *useful* target is entry-only if its surface assembles from already
registered emitter operations. Genuinely new syntax requires a versioned backend addition,
while the core IR stays unchanged.

### 6.8 The general acceptance property

This is the guarantee the whole redesign exists to provide:

> **For every supported source version and target profile, compilation is a total,
> versioned, loss-audited function returning either a deployable artifact with a
> discharged semantic-coverage proof, or a refusal / non-deployable blueprint with a precise
> diagnostic and source location. Every source semantic must be consumed by a typed node,
> parameter, registered operator/function, or execution/package field. No unresolved
> reference, opaque construct, or partial capability may cross into deployable output.**

Operationally: complete consumption and zero `must`-loss are required for `exact`;
unresolved means `not_evaluated` and non-deployable; partial support yields no equivalent
artifact; Wazuh and QRadar remain inferred; and **an IR deficiency reports
`IR_UNSUPPORTED_CONSTRUCT`, never a misleading vendor limitation** — so a gap in *our*
model is never blamed on the vendor.

That last clause is the direct answer to "will this work for rules I haven't shown you".
The kernel covers every construct expressible as an effect on rows and time. Anything
outside it fails loudly at the model layer, and adding support is a deliberate IR version
rather than a silent bolt-on.

### 6.9 Provenance and the exactness rule

Every semantic leaf is `authored` · `parsed` · `mapped` · `unverified` · `inferred`.
Wazuh and QRadar always carry `inferred_target`.

A parser may claim `exact` **only** when the entire document was consumed: every construct
mapped to a node or expression, every reference resolved, no flattening, reordering or
widening, and no `must`-severity loss. Regex extraction is capped at `partial`. This is the
rule that would have caught the 3-stage Splunk case on day one.

---

## 7. Phases

Each phase is independently shippable and independently verifiable. v2 ships **dark**
(shadow mode) first, so nothing user-visible changes until it is proven.

| # | Phase | Size | Delivers | Acceptance gate | Rollback |
|---|---|---|---|---|---|
| **0** | Freeze baseline + 10-rule corpus | S | 10 fixtures with expected IR, per-target outcome, evaluator cases. A 10 × 7 = **70-cell matrix** where every cell is *faithful artifact* or *named refusal*. | 308 tests green; all 70 cells have an explicit expected outcome | test-only change |
| **1** | **RuleIR v2 core, shadow** | L | The twelve-primitive kernel + closed expression algebra + validator (cycles, dangling refs, measure-before-production, illegal predicate scope, collisions, invalid transitions) + stable serialisation + loss contract. No vendor-specific nodes. | Round-trip lossless; invalid graphs rejected with exact codes; **API output byte-identical**; 308 green | package stays dark |
| **2** | v1 facades + shadow conversion | M/L | `RuleRequest.to_ir()`, `CorrelationModel.to_ir()`. v1 stays authoritative. `Aggregation.threshold` → `Filter` over a measure; global `threshold` → `Measure("EventCount")` + `Filter`. Ambiguous v1 lists become explicit losses, never a guessed order. | v1 responses unchanged; v1↔IR compatibility green; 308 green | disable shadow |
| **2b** | **Capability registry + kernel adversarial suite** | M | Function catalog, operator catalog, target profiles keyed by `(product, engine, artifact kind, version)`, default-deny resolution over the whole graph path. A suite proving the primitives that the sample rules did *not* exercise: `SetOp`, `Expand`, `Arrange`, `Iterate`, general `Pattern`. | Every primitive has positive/negative/boundary cases; a missing profile entry refuses; `IR_UNSUPPORTED_CONSTRUCT` distinguishable from a vendor refusal | registry is data-only, disable per target |
| **3** | **Semantic execution kernel** | XL | Evaluate the IR directly: **3A** stateless (`Derive`, `Filter`, `Frame`, `Aggregate`, `Arrange`, `SetOp`) → **3B** relational (`Join` incl. temporal, `Expand`, scoped expressions) → **3C** stateful (`Pattern` incl. until/missing/unordered, `Iterate`, stateful counters, package parent/child). | Positive/negative/boundary/mutation cases per operator. Deleting a required node must change the verdict or return `not_evaluated`. | hide v2 evaluator |
| **4** | **QRadar R4 vertical slice** | M | Grouped-historical authoring + import via `Read → Filter → Aggregate → Filter → Arrange`; `qr_aql_saved_search` labelled `is_event_sequence: false`; `QRADAR_CRE_CUSTOM_RULE_REQUIRED` when a detecting rule is wanted. | R4 parses as grouped historical, **not** a sequence; grouping/HAVING/ORDER BY preserved; no invented time range | disable QRadar lowerer |
| **5** | **Sentinel R3 vertical slice** | L | Two named bindings, `Join`, asymmetric inclusive temporal predicate, joined-row aggregates, `make_set`, `Derive` for `extend`. Refuse the full analytic-rule artifact. | Exact lower/upper boundary tests; non-matching account; no promotion to a full analytic rule | disable Sentinel slice |
| **6** | **YARA-L R5 vertical slice** | L | `Frame + Join + Filter` with shared match key and cross-event scoped comparison. Refuse the invalid literal `meta:` while keeping the semantic core modelable. | Same host + in-window fires; different host does not; reversed timestamp order does not; **no `Pattern` semantics smuggled in** | disable YARA-L lowerer |
| **7** | **Splunk R2 vertical slice** | XL | `Read` over an accelerated binding, `Frame` buckets, non-temporal `Join`, second `Aggregate`, `Filter` over measures, `Derive` for `eval`. Cross-target refusal where `summariesonly` has no equivalent. | The two `span=5m` are buckets; no correlation window invented; join has no temporal constraint; non-Splunk refuses | disable Splunk lowerer |
| **8** | **Wazuh R1 vertical slice** | XL | **Package** with two rules and a dependency edge, `Read` from a prior rule's emissions, `Aggregate` with a stateful sliding frame, current-event anchoring. Refuse standalone deployment while `sysmon_event_10` is unresolved. | Both IDs and the parent/child dependency present; valid XML; 300 s state boundary tested; refusal names the external dependency | disable Wazuh lowerer |
| **9** | Complete the 70-cell matrix | XL | All ten rules × seven targets, each *faithful* or *named refusal*. | No cell passes by containing the base predicate with a warning attached | disable v2 per target |
| **9b** | **Generalisation suite** | M | A construct **not** in the ten-rule corpus, per primitive, proving the kernel generalises: `union`/`except` branches, `mv-expand`, top-N, recursive closure, EQL `until` and unordered "two of three". | Each is representable without a new node; each still refuses correctly where a target lacks it | n/a — this suite is the generality gate |
| **10** | Exact parser + loss-ledger waves | XL | Full source-consumption tracking per target, in order: QRadar AQL, Wazuh XML, Sentinel KQL, YARA-L, Splunk SPL, Elastic EQL, Falcon CQL. | Every token consumed or explicitly accounted for; unknown syntax refused, not guessed; **no parser may claim `exact` with an unconsumed `must` range** | disable one parser at a time |
| **11** | Shadow integration + append-only history | L | v2 runs alongside v1, differential comparison of artifacts/refusals/coverage. History stored additively; no row rewritten or deleted. | All legacy IDs and JSON readable and unchanged; rollback drill on a copied DB returns to working v1 | staged disable order |
| **12** | Gated cutover + workbench UI | M/L | v2 promoted per endpoint and per target. IR-native authoring, tuning, explanation, diff. | 308 v1 + new v2 suites green; 70 cells correct; browser journeys prove author → tune → debug → refuse → recover | revert one target to v1 |

**Critical path:** 0 → 1 → 2 → 2b → 3 → (4, 5, 6 in parallel) → 7 → 8 → 9 → 11 → 12.
Phases 5 and 6 can run concurrently once the relational/event evaluator is stable. Phases
7 and 8 are independent vertical tails and both are high-risk. **2b and 9b are the phases
that prove the design is general rather than fitted to the ten rules** — 9b is the gate
before any cutover.

**Minimum viable slice:** phases 0–8. That is the first point where each of the ten rules
is authorable for at least one target with an honest refusal everywhere else. It is the
fastest way to prove the redesign works, and it is what I would build first.

---

## 8. UI workstream — carried inside every phase, not at the end

These complaints are recorded as acceptance cases in Phase 0 and addressed by a named
phase, not a final cleanup pass:

| Complaint | Addressed in |
|---|---|
| Everything is collapsed behind disclosures; base 1 / base 2 hidden | **Phase 1–2**: a permanent, always-visible rule-shape status and a kernel outline (`Read → Filter → Frame → Aggregate → Filter → Emit`). Optional controls may stay collapsed; the **active semantic shape may not**. |
| No clear statement that a rule is a single-event projection | **Phase 2**: explicit `single-event projection` label, permanent and outside any disclosure. |
| "This is what you deploy" shown on a refused or projected result | **Phase 9–12**: the backend `deployable`/refusal contract becomes authoritative and is rendered outside any disclosure. |
| Cannot tell what happened to the pasted rule | **Phase 10**: consumed vs unconsumed source and the loss ledger, per rule. |
| Cannot tune or debug meaningfully | **Phase 3**: evaluator traces; `evaluated` vs `not_evaluated`; contextual controls per primitive — measures, frames, join windows, pattern spans — instead of one scalar threshold. |

A note on current wording: **"Complete rule — this is what you deploy"** is acceptable
only when the artifact is genuinely deployable as written. Under this design it is
suppressed for any refused, projected, or placeholder-scoped result.

---

## 9. Test strategy

The **10 × 7 = 70-cell matrix** is the backbone. Every cell records: expected IR shape,
expected evaluator verdict, expected artifact type, expected semantic coverage, expected
refusal code and missing construct, and whether it is deployable.

### 9.1 Semantic obligations, not substrings

A test must fail if any of these happen:

- a join collapses into a single-event filter
- a tumbling frame becomes a correlation window
- a filter over measures moves before the aggregate
- a cross-event relation is re-expressed as a `Pattern` (or vice versa)
- a package of dependent rules flattens into one rule
- a second named measure disappears
- a temporal boundary shifts
- a set operation silently becomes a union when it was an `except`
- a refusal emits a non-empty downloadable artifact

### 9.2 Anti-vacuity discipline

This project has shipped vacuous tests before, so every important test requires:

- a **positive twin** and a **negative twin**
- a **boundary or mutation case**
- a deliberate **source-mutation check** proving the test fails for its intended reason
  (`git stash push -- <files>`, re-run, confirm the specific test goes red)
- an assertion that the corpus is non-empty

Known trap: a `-k` filter that silently does not select a new test, so the mutation check
passes for the wrong reason. Verify the selection count every time.

### 9.3 Never-invent regression gates

A deployable artifact must satisfy **all** of these:

1. Every field, value, source, rule ID, join key, time bound and relation traces to source IR, explicit analyst input, a recorded mapping, or declared deployment metadata.
2. No hidden fallback field, table, source, value, rule ID or time range appears.
3. Unresolved placeholders are permitted **only** in a non-deployable blueprint or refusal.
4. `exact` requires complete source consumption and zero `must` loss.
5. A partial result cannot be downloaded as an equivalent rule.
6. `not_evaluated` is never displayed as `would_fire`.
7. A refused result has an empty artifact body plus a specific missing-construct reason.
8. A single-event result visibly says it is a single-event projection.
9. Wazuh and QRadar output always carries `inferred_target`.

### 9.4 Offline proof vs live proof

The suite can prove IR semantics, source coverage, structural validity, evaluator
behaviour, refusal behaviour and artifact classification. It **cannot** prove a real SIEM
has the expected schema, data, permissions or runtime behaviour. That limitation stays
visible in the product and in the docs.

---

## 10. Migration and rollback

**No big-bang cutover.** Expand and contract:

1. v2 ships as a dark package → 2. v1→v2 adapters → 3. v2 runs in shadow → 4. one
target/operator at a time → 5. dual-write history → 6. promote per endpoint and target →
7. v1 facades and legacy history retained indefinitely.

**Existing tests:** the 308 become the **v1 compatibility suite**. They are not rewritten
to match v2. v2 gets its own contract suites. Both must pass before any promotion. If an
expected behaviour must change, that is recorded as an explicit migration change, never a
quiet assertion edit.

**Stored history:** purely additive. Existing `rule_history` JSON and lineage columns stay
untouched; v2 data goes to an append-only sidecar. Old rows convert lazily **only** when
the original source is available — never by reinterpreting previously generated output.
Unreadable rows are classified `legacy-only` and stay readable.

**Rollback:** independent switches for v2 shadow, evaluator, parser per target, lowerer
per target, history read/write, and UI mode. Rollback never requires dropping a table,
rewriting JSON, or restoring every history row.

---

## 11. Top risks

| # | Risk | Type | Mitigation |
|---|---|---|---|
| 1 | **IR underfit / node conflation** — a primitive wearing a vendor costume, or a real primitive missing | Architectural, hard to reverse | Derive the kernel from first principles (section 6.1–6.2), not from the corpus. **Phase 2b** proves the primitives the samples never exercised (`SetOp`, `Expand`, `Arrange`, `Iterate`, general `Pattern`); **9b** re-proves generality with constructs outside the corpus before cutover |
| 2 | **Expression algebra leaks opacity** — a raw string smuggled back in as a "fulltext" or "udf" function, reintroducing the old ceiling under a new name | Architectural | Closed function catalog with declared semantics; unknown IDs refused; no raw-function escape hatch; a subquery is a named graph edge, never a string in an expression |
| 3 | **False parser exactness** — heuristic extraction reporting `exact` | Architectural | Full-consumption ledger; unconsumed logic forces refusal; parser mutation tests; `IR_UNSUPPORTED_CONSTRUCT` never reported as a vendor limitation |
| 4 | **Capability drift** between v1 and v2 producing silent projections | Architectural | One v2 compile contract; data-only capability registry, default-deny, resolved over the whole graph path; the 70-cell matrix; no partial deployable output |
| 5 | **False tuning confidence** from evaluator shortcuts or wrong window/state semantics | Architectural | Execute the IR directly; boundary and mutation tests; return `not_evaluated`, never a guess |
| 6 | **History/provenance corruption** during migration | Architectural/operational | Append-only sidecars; preserve raw v1 data; rollback drill on a copied database |
| 7 | **Registry overreach** — someone assumes adding a target is always entry-only | Architectural | Documented explicitly: a registry entry cannot invent a missing parser or emitter. New syntax needs a versioned backend addition; the core IR stays unchanged |

**UI risk, stated plainly:** collapsed disclosures and "this is what you deploy" on a
non-deployable result are not cosmetic. A result that looks deployable but is not is a
safety defect, so the backend contract must be authoritative and the UI must expose it
outside any disclosure.

---

## 12. Questions I need answered before starting

1. **Approve the full redesign**, or start narrower? My recommendation is **phases 0–2
   only as a first checkpoint**: the IR proven dark, nothing user-visible changed, 308
   tests still green. Cheap, reversible, and it proves the foundation before the large
   phases begin.
2. **Minimum viable slice or full build?** Phases 0–8 make all ten rules authorable for at
   least one target. Phases 9–12 complete the matrix, the parsers and the cutover.
3. **Are these ten rules the right acceptance corpus, or do you have the production rules
   you actually maintain?** The corpus drives every fixture and every gate, so its accuracy
   matters more than anything else in this document.
4. **QRadar CRE:** emit a CRE rule-test plan as a non-deployable blueprint with
   `QRADAR_CRE_CUSTOM_RULE_REQUIRED`, or target a specific CRE export version?
5. **Wazuh `sysmon_event_10`** is an external dependency the pasted rule does not define.
   Keep that a hard standalone-deployment refusal, or allow a declared-assumption mode?
6. **Migration posture:** during shadow, should legacy v1 drafts stay visible with an
   explicit "legacy" label, or be hidden from new users?

---

## 13. What is explicitly not changing

- No new runtime dependencies. Stdlib only.
- The local-only posture: nothing leaves the machine, nothing is deployed.
- The public repo, its history and its 308-test baseline.
- `data/*.json` catalogs stay committed; the SQLite runtime DB stays gitignored.
- The honesty work already shipped. That is not reverted or weakened.
