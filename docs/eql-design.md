# Elastic EQL — grammar, and why the IR is not ready for it

Written before any EQL code, deliberately, so the parser is built against
Elastic's real syntax rather than a plausible guess. Sources:

- <https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax>
- <https://github.com/elastic/elasticsearch/blob/main/docs/reference/query-languages/eql/eql-syntax.md>
- <https://www.elastic.co/docs/reference/query-languages/eql-function-ref>

## The grammar, as Elastic documents it

**Sequence** — an ordered series of events, ascending chronological order, most
recent last. Each item is `[ category where condition ]`, optionally followed by
its own `by` join keys:

```
sequence [by field [, field ...]] [with maxspan=<time> | with runs=<n>]
  [ category_1 where condition_1 ] [by k1, k2]
  [ category_2 where condition_2 ] [by k3]
  [ category_3 where condition_3 ]
[until [ category_4 where condition_4 ]]
```

- `by` **after an item** = join keys for that step, and the values may come from
  *different fields* in different steps.
- `sequence by f` = the same field, shared across every event in the sequence.
  Elastic states this is equivalent to repeating `by f` on every item, and the
  per-item form is the more general one — so the IR must model per-step keys, not
  just a global key set.
- `!` before `[ ... ]` = a **missing** event: a timespan-constrained sequence in
  which the condition is *not* met. Legal at the start, end, or middle.
  **`with maxspan` is MANDATORY whenever any `!` clause is present**, and a
  sequence needs at least one positive clause.
- `until` = an **expiration** event. If it occurs *between* matching events the
  sequence expires and does not match; if it occurs *after* the match, the
  sequence still matches. It is excluded from results. This is a genuinely
  order-sensitive rule and not expressible as a filter.
- `with runs=<n>` = the pattern must repeat `n` consecutive times.
- `?` after a `by` field marks it **optional**, allowing `null` join keys. By
  default a join key must be non-null.

**Sample** — a chronologically *unordered* series; can run on data with no
timestamp:

```
sample by join_key
  [ category_1 where condition_1 ]
  [ category_2 where condition_2 ]
```

- Requires at least one `by`; **up to five** filters.
- `with maxspan`, `with runs` and `until` are **not supported**.
- "Pipes are not supported for sample queries."

**Operators** — `==`, `!=`, `>`, `<`, `>=`, `<=`, `and`/`and not`/`or`/`not`, the
wildcard-match operator `:`, `like` (`*` and `?` globs), `in (...)`, and
`?:`-style optional-field handling. Functions are in the function reference —
`stringContains`, `startsWith`, and so on. `[ network where true ]` is a legal
bare item, i.e. "any event of this category".

## The IR ALREADY HAS THE NODE. An earlier version of this file said it did not.

The first draft of this document claimed the vocabulary could not express an
ordered series of steps, and recommended refusing `sequence` until a
`Sequence`/`SequenceMachine` node existed. **That was wrong, and it was checked
by reading the IR rather than by reading it.** `engine/ir.py` has had
`class Pattern` all along, and `engine/nodes.py` has an evaluator for it:

```python
class Pattern:
    stages                # tuple of conditions, matched in order
    within                # Duration -- the window, measured from the start row
    key                   # tuple[FieldRef, ...] -- join keys
    until                 # a condition -- an EXPIRATION event, checked as a veto
    ordered               # bool
    time_field            # FieldRef -- which field orders events
    max_matches_per_key   # cap, default 100
```

`eval_pattern` groups rows by `key`, sorts by `time_field`, walks forward
matching `stages` in order within `within` of the start row, and treats `until`
as a veto. `Pattern.__post_init__` already enforces two of the invariants EQL
needs: `PATTERN_NEEDS_TWO_STAGES` ("a pattern describes a sequence; with one
stage it is a filter") and `PATTERN_REQUIRES_TIME_FIELD` (an ordered pattern must
name the field that orders events, because guessing one from a column that looks
like a timestamp could order by the wrong field and produce a different sequence).

YARA-L already uses it for cross-event rules (`dialects/yaral_ir.py:239`).

## So the mapping is mostly already there

| EQL | `Pattern` | Status |
|---|---|---|
| `[a where c1] [b where c2]` ordered | `stages` | have it |
| `with maxspan=15m` | `within` | have it |
| `by user.name` | `key` | have it |
| `until [c where c3]` — expires only if it falls BETWEEN matches | `until` as a veto | **present but DIVERGES — see below** |
| `with runs=3` — N consecutive repeats | `Pattern(runs=N)` | have it — enforced in the evaluator, not just carried |
| `![ c where cond ]` — missing event, `maxspan` mandatory | — | **missing** |
| `sample` — unordered, no `maxspan`/`until`/`runs` | `ordered=False` + no `until` | nearly: `ordered=False` is all `sample` needs |
| per-step `by` (different fields per step) | `key` is global | **missing** — and the vendor says why, see below |

### `runs=N` is a count of COMPLETE REPEATS, all inside one `maxspan`

`runs=2` on a two-stage sequence with `maxspan=5m` needs **four events within
five minutes** — not two events spread over ten. "This happened twice" and
"this took twice as long" are unrelated claims, and reading N as a window
multiplier is not the conservative mistake it looks like: it makes the rule
match MORE than the analyst wrote.

Two further properties the tests pin, because both are ways to get a
plausible-looking wrong answer:

- **Repeats must be DISJOINT.** The second repeat starts where the first
  *ended*, so one event cannot satisfy two stages of two different runs.
  Otherwise two events would satisfy `runs=2` and "happened twice" would become
  "happened once, counted twice".
- **The window still bounds the whole thing.** A second repeat two hours after
  the first does not match, even though `maxspan` is unchanged.

`Pattern.runs` defaults to 1, which is what YARA-L — which never sets it — has
always meant. That keeps the field additive in the same way `until_scope` is:
the default is the pre-existing behaviour, so adding it cannot re-break a rule.
`runs=0` is refused at both the parser and the node, because zero would mean the
pattern matches when it does *not* occur — an inverted rule, not a weaker one.

| `?` optional join key (allow null) | — | **missing** |

That is a much shorter gap than "no node exists". The honest first slice is
therefore bigger than a single-event query, and the previous recommendation to
start there was based on a false premise.

### `until` DIVERGES FROM EQL, AND IT MUST BE FIXED BEFORE LOWERING `sequence`

This is the one place the existing node is *close but wrong*, and it is exactly
the shape of bug this project keeps finding: a plausible mapping that means
something else.

EQL, from Elastic's documentation: "If this expiration event occurs **between**
matching events in a sequence, the sequence expires and is not considered a
match. If the expiration event occurs **after** matching events in a sequence,
the sequence is still considered a match."

`eval_pattern` does not do that. It walks the stages, and if they all matched it
then calls:

```python
if node.until is not None and _window_satisfies(
        node.until, group, times, start_index, window_end, ctx):
    continue
```

and `_window_satisfies` scans from `start_index` to `window_end` — the WHOLE
window, from the first event of the candidate to the end of the window, not the
span *between* the matched events.

So for `A, B, C` where `C` is the `until` condition and all three are inside the
window:

| | result |
|---|---|
| EQL | `A, B` **matches** (C comes after the matching events) |
| `Pattern` today | `A, B` is **discarded** (C satisfies somewhere in the window) |

EQL's own worked example is exactly this shape — the dataset contains `A, B`,
`A, B, C` and `A, C, B`, and the query must match the first two and reject the
third. `Pattern` would match only `A, B, C` and reject `A, B`.

For YARA-L, where `until` is the negative twin of a two-stage rule and the
comment above the code says the intent explicitly, the current behaviour is
defensible. For EQL it is wrong, and it is a divergence to fix in
`eval_pattern` (scan from the LAST MATCHED event, not from `start_index`) before
EQL `until` can be lowered onto it. Do not paper over it in the lowerer.

## Recommended order

1. A single-event query (`[ process where process.name == "regsvr32.exe" ]`),
   which really is just a filter. Cheap, and it proves the EQL front end.
2. `sequence` with no `by`, no `maxspan`, no `until`, no `!` — lower onto
   `Pattern` with `within=None`. This is where the mapping gets tested against
   the real grammar rather than against my reading of it.
3. Join keys (`key`), then `maxspan` (`within`), then `until` (veto semantics
   above), then `!`, then `runs`, then `sample` via `ordered=False`.
4. Per-step `by` needs a `Pattern` change -- `key` is global today, and EQL allows
   different fields per step. Do not fake it with a global key.

## The trap, unchanged

A single-event query is easy to mistake for "EQL support". It is not. What
whatever ships says plainly which of these are supported, and refuses the rest by
name.
