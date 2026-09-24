# RuleForge — Detection‑Engineer Readiness Assessment & Roadmap

- **Date:** 2026‑09‑23
- **Scope:** Answers three questions — *why isn't this ready for a working detection engineer, what should be fixed, and how.*
- **Target user:** A detection engineer who wants to (1) **build complex, industry‑grade rules**, (2) **tune complex rules**, and (3) **understand complex rules**.
- **Method:** Grounded in a full read of the codebase. Every claim below cites `file:line` so you can verify it.
- **Verdict in one line:** RuleForge is a genuinely good **teaching / scaffolding workbench**, but it is **not yet a working instrument for complex rules**, because the main authoring path can only express simple rules, half the dialect analysis is regex‑based, and the field/technique libraries are toy‑sized.

---

## 0. TL;DR

| | Where it stands |
|---|---|
| **Runs, offline, safe** | ✅ Yes. Flask app, 82 tests pass, no telemetry leaves the machine. |
| **Simple rules (single event, boolean, lists, exclusions, count, group‑by)** | ✅ Solid — this is the tool's real strength. |
| **Complex rules (sequence, join, aggregation, lookup, absence, chained…)** | ⚠️ **Modeled but not authorable** — you can only get them by *pasting* an existing rule, and most dialects render them as a single‑event approximation. |
| **Understanding pasted rules** | ⚠️ **Trustworthy only for Sigma & Wazuh.** The other 6 dialects are parsed with regex and will silently miss logic. |
| **Tuning** | ⚠️ Good primitives (threshold/window/exclusions/match‑test/evasion), but you tune the *model*, not the *emitted query*, and there's no realistic data volume. |
| **Honesty of the UI** | ❌ Overclaims ("18 rule families", pySigma‑backed) vs. reality (12 modeled, pySigma dormant). This is the fastest thing to lose an engineer's trust. |

**Biggest single finding:** the model can represent complex correlations, but **there is no way to *author* one** — `involved_families()` only ever produces 7 of 18 families from the form (`compiler/pipeline.py:110`), and the studio UI has no editor for sequences, joins, aggregations, or lookups. The engine is more capable than the cockpit exposes.

---

## 1. The bar: what "ready for a detection engineer" means

Your three stated use cases set the bar. Concretely:

**A. Making really complex rules for industry**
- Author multi‑event logic *from scratch* (A → B → not‑C within N minutes, grouped by entity), not just simple field matches.
- Map to the field schemas real SIEMs use (ECS, Splunk CIM, Sentinel/ASIM, Google UDM, QRadar, LogScale, Wazuh decoders) — hundreds of fields, not seven.
- Pick from a real ATT&CK technique library, not five.
- Trust that the emitted query actually expresses the logic in each target dialect (or be told loudly where it can't).

**B. Tuning complex rules**
- Feed realistic volumes of benign + malicious events and get meaningful precision / recall / FP‑rate.
- Tune thresholds, windows, and exclusions and see the effect on the *actual output that will run*, not just an internal model.
- Discover fields from sample data instead of typing them by hand.

**C. Understanding complex rules**
- Paste a rule in any of the 8 dialects and get a *faithful* structural breakdown + plain‑English explanation.
- Have confidence the breakdown is correct (round‑trip / grammar‑validated), not a best‑effort regex guess.

RuleForge partially meets C for two dialects, meets A/B for *simple* rules, and does not yet meet A/B/C for *complex* rules. The rest of this document is why, and what to do.

---

## 2. What already works (keep this — don't rewrite it)

Being honest about strengths matters, because the fix is *extension*, not a rebuild.

1. **Clean canonical IR.** `models/correlation.py` already models `Predicate` / `LogicNode` trees, `Sequence`, `Join`, `Aggregation`, `Lookup`, thresholds, group‑by, windows, outcome. **The hard data‑modeling work for complex rules is already done** (`models/correlation.py:52-159`). This is the foundation everything else builds on.
2. **Single source of truth for compilation.** Both `/api/generate` and `/api/compile` flow through `compile_request()` (`compiler/pipeline.py:144`). No divergent code paths.
3. **Honest fidelity vocabulary.** `exact / safe_normalized / partial / unsupported` is exactly the right mental model (`models/correlation.py:19`), and the capability matrix (`compiler/pipeline.py:14-105`) is grounded in real backend limits (e.g., Elastic clock‑aligned buckets, `compiler/pipeline.py:23`).
4. **Real offline evaluation.** `evaluator/match_tester.py` genuinely evaluates predicates (incl. CIDR via `ipaddress`, windash, base64), does sliding‑window thresholds, group‑by partitions, and TP/FP/FN/TN scoring. This is not fake.
5. **Evasion self‑test.** `evaluator/evasion.py` mutates matching events (case‑flip, slash‑swap, `powershell`→`pwsh`, whitespace pad) — a real, useful tuning aid.
6. **Sigma done properly.** `parsers/sigma_parser.py` + `compiler/spec_checks.py` do structured parsing and mirror pySigma's validator taxonomy offline. Sigma is the one dialect handled at professional quality.
7. **Versioned local history with lineage** (`storage.py`) and **diffing** (`diff_tool.py`).
8. **Explainer + section view** turn a model into plain‑English bullets and labelled UI blocks (`explainer.py`, `section_view.py`).

Keep all of it. The gaps below are about *reach* and *trust*, not correctness of what exists.

---

## 3. Why it's not ready yet (grounded gap analysis)

Severity: 🔴 blocks the use case · 🟠 degrades it · 🟡 erodes trust.

### 3.1 Use case A — "making really complex rules"

**GAP A1 🔴 — You cannot author a complex rule from scratch; only simple ones.**
The studio form collects field/operator/value conditions, exclusions, one threshold, one window, one group‑by. When that becomes a `RuleRequest`, `involved_families()` can only ever return a subset of **{single, boolean, lists, exclusion, count, group, window}** — 7 families (`compiler/pipeline.py:110-124`). There is **no form control** for sequences, joins, aggregations (dc/sum/make_set), lookups, absence, or chaining. So 11 of the 18 capability families (`compiler/pipeline.py:14-105`) are **unreachable by authoring** — they exist in the matrix and the model but nothing in the UI can produce them.
*Impact:* a detection engineer literally cannot build "failed logon then success from same source within 10m, excluding service accounts" in the tool. They can only build one‑shot field matches.

**GAP A2 🔴 — Multi‑event logic degrades to a single‑event projection on emit.**
Even if a model *has* a sequence/join/lookup (via paste), the compiler renders most dialects as a flat single‑event query and marks it `partial` (`compiler/sigma_compiler.py:193-195`). Only Elastic/EQL and Google/YARA‑L express ordering natively (`compiler/pipeline.py:30-39`). So generating a complex rule for Splunk/Sentinel/QRadar/Falcon/Wazuh yields output that **does not actually correlate** — it just matches one of the stages.

**GAP A3 🔴 — The Wazuh bridge silently drops all but the first predicate.**
`compile_model(... "wazuh")` builds the Wazuh rule from `_first_predicate` only (`compiler/sigma_compiler.py:141-162`). A complex rule loses every other condition and all exclusions. There *is* a note appended, but the output looks complete and isn't.

**GAP A4 🟠 — Field mapping is toy‑sized (7 fields).**
`FIELD_MAPPINGS` maps exactly 7 canonical fields per SIEM (`rule_engine.py:83-92`). Real detections touch dozens–hundreds (ECS/CIM/ASIM/UDM). Unmapped fields pass through untranslated (by design, `rule_engine.py:81-82`), so a realistic "industry" rule emerges peppered with fields that are correct for none of the targets and must be hand‑fixed 8 times.

**GAP A5 🟠 — Technique library is toy‑sized (5 techniques).**
`TECHNIQUES` has 5 entries (`rule_engine.py:33-79`); `TECHNIQUE_GUIDANCE` covers 5 IDs (per `compiler/spec_checks.py`). An engineer working across ATT&CK needs the technique catalog, not a demo set.

### 3.2 Use case B — "tuning complex rules"

**GAP B1 🟠 — You tune the model, not the query that will run.**
`/api/test_match` and the tuning steppers evaluate the `CorrelationModel` (`evaluator/match_tester.py`). For any family marked `partial`, the emitted native query behaves differently from the model — but nothing tells the analyst "your tuning reflects the model; the Splunk output won't match this behavior." Tuning confidence is therefore only as good as the fidelity, and the UI doesn't couple the two.

**GAP B2 🟠 — No realistic data volume.**
Tuning quality = data quality. Today you hand‑paste a JSON array or use 3 tiny presets (`templates/index.html:91`). `benign_fire_rate`/precision/recall are computed (`evaluator/match_tester.py`) but over a handful of events, so the numbers aren't decision‑grade. There's no ndjson/CSV ingest and no field auto‑discovery from the sample.

**GAP B3 🟡 — Threshold/window semantics aren't modeled per dialect.**
The Elastic clock‑aligned‑bucket caveat is a *note* (`compiler/pipeline.py:23`), not something the tuner accounts for; tuning a window to `5m` implies a sliding window that some targets won't honor.

### 3.3 Use case C — "understanding complex rules"

**GAP C1 🔴 — 6 of 8 dialects are understood via regex, not parsing.**
`analyze_rule()` does structured parsing only for Sigma (YAML) and Wazuh (XML). For SPL, KQL, EQL, AQL, YARA‑L, and CQL it runs ~10 generic regexes over the raw text (`rule_engine.py:740-778`). Regex extraction:
- flattens AND/OR/NOT structure (you lose the boolean tree),
- misattributes operators (everything collapses to contains/equals/regex),
- silently misses anything the patterns don't anticipate.
So "paste this complex Splunk correlation search and explain it" produces an **incomplete and possibly wrong** model → a confidently wrong explanation. For understanding, wrong is worse than nothing.

**GAP C2 🟠 — No round‑trip / faithfulness check.**
Nothing verifies "the model I extracted, recompiled, reproduces the source." Understanding is asserted, never validated.

**GAP C3 🟡 — pySigma is advertised but dormant.**
`_try_pysigma()` always returns `None` (`compiler/sigma_compiler.py:284-292`); code comments and README imply pySigma backs the output. The one place a battle‑tested library could give real correctness is wired to a stub.

### 3.4 Cross‑cutting trust gaps

**GAP X1 🟡 — UI overclaims coverage.** The stat strip says **"18 Rule families (RF‑01…RF‑18)"** (`templates/index.html:54`), but `models/correlation.py:1-7` and `UNSUPPORTED_MAP` (`compiler/sigma_compiler.py:15-20`) state RF‑13…RF‑18 are unsupported / preserved‑as‑source. An engineer will spot this immediately.

**GAP X2 🟡 — Fidelity is asserted from a static matrix, not validated against grammar.** `target_check()` (`compiler/validators.py`) does regex/balance/structural sanity, not real grammar validation. "This SPL is valid" is not actually checked; "this Sigma is valid" *is* (via `spec_checks`) — inconsistent trust across dialects.

**GAP X3 🟡 — No "does it run?" signal.** There's no validation against vendor grammars/APIs (README already discloses this is out of scope). Fine for a workbench; a blocker for "industry‑grade."

---

## 4. What to fix — prioritized backlog

Priorities are ordered by *trust‑per‑effort* first, then by unlocking the three workflows.

| ID | Fix | Fixes gap | Priority | Rough effort |
|----|-----|-----------|----------|--------------|
| **F1** | Make the UI/README tell the truth about coverage | X1, C3 | **P0** | XS |
| **F2** | Make `partial`/`unsupported` **loud** in results (banner, not footnote) | A2, B1, X2 | **P0** | S |
| **F3** | Wazuh: emit *all* predicates + exclusions, or refuse honestly | A3 | **P0** | S |
| **F4** | Authoring UI + pipeline for advanced families (sequence/join/agg/lookup/absence) | A1 | **P1** | L |
| **F5** | Wire real parsers: pySigma for Sigma; structured parsers (or honest downgrade) for SPL/KQL/EQL | C1, C2, C3 | **P1** | L |
| **F6** | Real field‑mapping libraries (ECS→CIM/ASIM/UDM/QRadar/LogScale/Wazuh) + unmapped flagging | A4 | **P1** | M |
| **F7** | Real ATT&CK technique/guidance library, searchable | A5 | **P1** | M |
| **F8** | Sample‑data ingestion (ndjson/CSV) + field auto‑discovery for tuning | B2 | **P2** | M |
| **F9** | Round‑trip faithfulness check + grammar validation per dialect | C2, X2, X3 | **P2** | M |
| **F10** | Honesty tests: multi‑event render must express or be labelled partial‑with‑reason | A2 | **P2** | S |

---

## 5. How to fix — item by item

### F1 — Tell the truth about coverage · P0
- **Files:** `templates/index.html:54`, `README.md`, `compiler/sigma_compiler.py:291`.
- **Do:** Change the stat to "**12 modeled families · 6 preserved‑as‑source**" (or "RF‑01…RF‑12 modeled"). Add a small coverage legend on the Overview tab that renders the capability matrix. Remove/adjust pySigma phrasing until F5 lands.
- **Done when:** No UI/README statement contradicts `models/correlation.py:1-7` or `UNSUPPORTED_MAP`.

### F2 — Make fidelity loud · P0
- **Files:** `static/app.js` (`renderRules`), `templates/index.html:90` (`#quality-gates`), `compiler/pipeline.py:164-179` (already returns `fidelity`, `capability_notes`).
- **Do:** For each result card, when `fidelity ∈ {partial, unsupported}`, render a colored banner at the top of that card ("⚠ Partial: sequences render as single‑event projection for Splunk — this query matches one stage only") sourced from `capability_notes`. When you tune in the workbench, show the current model's worst fidelity next to the precision/recall numbers so the analyst knows the numbers describe the *model*, not necessarily the emitted query.
- **Done when:** A partial rule can never *look* finished; the caveat is impossible to miss.

### F3 — Wazuh: stop dropping logic · P0
- **Files:** `compiler/sigma_compiler.py:141-162`, `rule_engine.py:559` (`render_wazuh`).
- **Do:** Walk the whole `LogicNode` and emit one `<field>`/`<match>` element per predicate; emit exclusions as `<field negate="yes">`. For OR logic (which Wazuh can't AND cleanly), either split into sibling rules with a shared `if_group` or emit `partial` with an explicit "split into N rules" instruction — but never silently keep only predicate #1. Add a test that a 3‑predicate model yields 3 elements.
- **Done when:** Predicate count in → predicate count out (or an explicit, tested refusal).

### F4 — Author advanced families from scratch · P1 (the big one for use case A)
The model already supports this; the gap is UI + wiring.
- **Files:** `templates/index.html` (studio form, section 02), `static/app.js` (form → payload), `app.py` (`_payload_to_model`), `compiler/pipeline.py:110` (`involved_families`), `compiler/sigma_compiler.py:125` (`compile_model`).
- **Do:**
  1. Add a **"Correlation type"** selector to section 02: *single / threshold‑by‑entity / sequence / join / absence*.
  2. When "sequence" is chosen, reveal a **stage editor** (ordered rows: event label + condition + "negated" checkbox) that maps to `Sequence`/`SequenceStage` (`models/correlation.py:52-64`). Similarly a join editor → `Join`, an aggregation editor → `Aggregation`.
  3. In `app.py`, extend `_payload_to_model()` to populate `model.sequences/joins/aggregations/lookups` from that payload (the dataclasses already exist).
  4. Extend `involved_families()` to detect these from the model (add branches for sequence/join/aggregation/lookup/absence) so fidelity/notes are computed.
  5. Route the flat form through `compile_model()` when advanced families are present (so multi‑event dialects like EQL/YARA‑L render natively).
- **Done when:** You can build a 3‑stage sequence in the UI, compile it, and get native EQL/YARA‑L sequences + honestly‑labelled partials elsewhere — no paste required.

### F5 — Real parsing instead of regex · P1 (the big one for use case C)
- **Files:** `compiler/sigma_compiler.py:284` (`_try_pysigma`), `rule_engine.py:659-778` (`analyze_rule`).
- **Do:**
  1. **Sigma:** actually implement `_try_pysigma()` — when pySigma + a backend is installed, convert via `SigmaCollection` and return the backend query as `exact`; keep the built‑in renderer as the offline fallback. Remove the "not yet wired" note once real.
  2. **SPL/KQL/EQL:** replace the shared regex block for these with structured parsers. Two acceptable routes: (a) integrate a real grammar (e.g., a KQL/SPL tokenizer) behind an optional dependency, or (b) if that's too heavy, **keep regex but downgrade the fidelity to `partial` and warn "regex‑extracted — verify boolean structure"** so understanding is never silently wrong.
  3. Add a **round‑trip check** (see F9): parse → model → recompile → compare; surface a "faithful ✓ / lossy ⚠" badge on analysis.
- **Done when:** Sigma analysis is pySigma‑grade; SPL/KQL/EQL analysis either parses structurally or is clearly labelled lossy — no confident‑but‑wrong explanations.

### F6 — Field libraries at scale · P1
- **Files:** `rule_engine.py:81-92` (`FIELD_MAPPINGS`), new `data/mappings/*.json`.
- **Do:** Externalize mappings to data files keyed on an ECS‑style canonical taxonomy; load at startup. Add a **field browser / autocomplete** in the studio backed by the taxonomy. When a field has no mapping for a target, render it unchanged **and tag it "unmapped — verify"** in that card (don't hide it). Seed with the highest‑value fields (process, auth, network, file, registry, cloud/identity).
- **Done when:** Common ECS fields translate correctly to all 8 targets, and unmapped fields are visibly flagged, not silently wrong.

### F7 — Technique library at scale · P1
- **Files:** `rule_engine.py:33-79` (`TECHNIQUES`), `compiler/spec_checks.py` (`TECHNIQUE_GUIDANCE`), new `data/techniques.json`.
- **Do:** Load techniques + guidance from a data file (ATT&CK id, name, tactic, default field/filter, FP guidance). Make the studio technique picker searchable. Keep the 5 curated ones as "quick starts."
- **Done when:** An engineer can search ATT&CK techniques, not scroll a list of five.

### F8 — Real tuning data · P2
- **Files:** `evaluator/match_tester.py`, `templates/index.html:91` (workbench), `static/app.js`.
- **Do:** Accept an uploaded ndjson/CSV of events (stays local), auto‑discover field names to populate autocomplete, run the whole corpus through the model, and report precision/recall/FP‑rate over real volume with a per‑event verdict table. Let `_expected` labels come from a column.
- **Done when:** Tuning numbers are computed over hundreds/thousands of events, not three.

### F9 — Faithfulness & grammar validation · P2
- **Files:** new `compiler/roundtrip.py`, `compiler/validators.py`, `compiler/spec_checks.py` (already validates Sigma).
- **Do:** (a) Round‑trip: `analyze → model → compile` back to the source dialect and diff; show faithful/lossy. (b) Per‑dialect grammar checks: run generated Sigma through the existing `spec_checks` validators; add lightweight parse checks for others; label "grammar‑checked" vs "sanity‑checked" so trust is explicit and consistent.
- **Done when:** Every output card states how strongly it was validated.

### F10 — Honesty tests for multi‑event render · P2
- **Files:** `tests/` (new cases), `compiler/sigma_compiler.py`.
- **Do:** Add tests asserting that for a model with a sequence/join, each dialect's output *either* contains the ordering construct *or* is returned with `fidelity == "partial"` and a note explaining the projection. Lock the honesty in so a future refactor can't quietly regress it.
- **Done when:** CI fails if a multi‑event rule is ever emitted as a silent single‑event query.

---

## 6. Phased roadmap

**Phase 0 — Trust & honesty (≈1–2 days): F1, F2, F3, F10.**
Cheap, high‑impact. After this the tool never lies about what it produced, and Wazuh stops dropping logic. Ship this first — it's the difference between "demo" and "I can rely on what it tells me."

**Phase 1 — Reach the three workflows (the core): F4, F5, F6, F7.**
This is what turns it into a detection‑engineer tool: author complex rules (F4), understand them faithfully (F5), at real field/technique scale (F6/F7). Suggested order: F5 (understanding pays off immediately on rules you paste) → F4 (authoring) → F6/F7 (scale, can proceed in parallel).

**Phase 2 — Confidence & depth: F8, F9.**
Decision‑grade tuning and explicit validation. Makes the numbers and labels trustworthy enough to act on.

**Out of scope on purpose (keep it local):** SSO/RBAC, live SIEM deployment, vendor‑API validation. The README already draws this line correctly — don't cross it; it's what keeps the tool 100% local.

---

## 7. Appendices

### Appendix A — Family reachability (the core insight)

18 capability families exist (`compiler/pipeline.py:14-105`). Here's how you can actually get to each **today**:

| Family | In model? | Authorable from form? | Emitted natively? |
|--------|-----------|-----------------------|-------------------|
| single, boolean, lists, exclusion, count, group, window | ✅ | ✅ (7 families via `involved_families`) | ✅ mostly exact |
| sequence | ✅ | ❌ paste‑only | EQL/YARA‑L exact; others partial |
| join | ✅ | ❌ paste‑only | Sentinel/Google exact; others partial |
| aggregation | ✅ | ❌ paste‑only | several exact, Elastic/Wazuh partial |
| lookup | ✅ | ❌ paste‑only | mixed |
| absence | ✅ | ❌ paste‑only | Sentinel/Elastic/Google exact; others partial |
| outcome | ✅ | ❌ | mixed |
| entity | ✅ | ❌ (only via group‑by) | exact |
| anomaly | ⛔ unsupported | ❌ | preserved‑as‑source |
| composite, ioc, chained | ⛔/partial | ❌ | preserved‑as‑source / partial |

**Reading of the table:** the tool's *ceiling* (the model + matrix) is high; the *authorable surface* (the form) is low. F4 closes that specific gap.

### Appendix B — Claims vs reality

| UI/doc claim | Reality | Fix |
|---|---|---|
| "18 Rule families (RF‑01…RF‑18)" (`templates/index.html:54`) | 12 modeled (RF‑01…RF‑12), 6 preserved‑as‑source | F1 |
| pySigma‑backed output (comments/README) | `_try_pysigma` always returns None (`compiler/sigma_compiler.py:291`) | F1, F5 |
| Rules analyzed across 8 dialects | Structured only for Sigma+Wazuh; regex for 6 (`rule_engine.py:740`) | F5 |
| Wazuh rule generated from model | First predicate only (`compiler/sigma_compiler.py:141`) | F3 |
| Fidelity labels | Asserted from static matrix, not grammar‑validated | F2, F9 |

### Appendix C — Architecture map (for newcomers)

```
Request ─┬─ /api/generate ─┐
         └─ /api/compile ──┴─► compiler/pipeline.py: compile_request()
                                   │  involved_families() ─► capability_for()  [fidelity + notes]
                                   └► rule_engine.RENDERERS[siem]  ─────────────► native query
Paste ──► /api/analyze ─► rule_engine.analyze_rule()  [Sigma/Wazuh: parse · others: regex]
                                   └► _analysis_to_model() ─► CorrelationModel ─► explainer.explain()
Model ──► compiler/sigma_compiler.py: compile_model()  [Sigma exact · Wazuh 1‑predicate · others projection]
Tune  ──► evaluator/match_tester.py: test_events()  [evaluates the MODEL] · evaluator/evasion.py
Store ──► storage.py (SQLite, versioned)  · Diff ──► diff_tool.py
```

- **Core IR:** `models/correlation.py`
- **Truth for compile:** `compiler/pipeline.py`
- **Renderers + analysis:** `rule_engine.py`
- **Sigma quality path:** `parsers/sigma_parser.py`, `compiler/spec_checks.py`
- **UI:** `templates/index.html`, `static/app.js`
- **Teaching corpus:** `docs/advanced-rule-corpus.md`

---

*This assessment is deliberately blunt about gaps because that's what makes it useful. The codebase is well‑structured and the model layer is ahead of the UI — most of the work below is exposing and validating capability that's already half‑built, not starting over.*
