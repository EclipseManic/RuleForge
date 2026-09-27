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

## Why this does not fit the current IR

`engine/ir.py` is a flat relational vocabulary: `Read`, `Filter`, `Derive`,
`Aggregate`, `Arrange`, `SetOp`, `Join`, `Expand`, `Pattern`, `Emit`. It has
`Frame`, `Duration` and `TimeRef`, which is enough for a windowed aggregate, but
there is **no node that matches an ordered series of steps against a stream**.

A `sequence` is a state machine over event time. It needs, at minimum:

- ordered steps, each with its own condition **and its own join keys**
- partial-match state carried between events, keyed by the join values
- an expiry (`maxspan` measured from the *first* event, `until`, and the
  "expires only if `until` falls between matching events" rule)
- `runs=<n>` as a repeat count
- `!` as a negative step, which is only legal under a mandatory `maxspan`

Fitting that into `Filter` + `Join` would be a plausible-looking lowering that
silently means something else — which is precisely the failure class this project
has spent its history removing. **So `sequence` and `sample` must be refused by
name until the IR has a real node for them**, not approximated.

The independent IR design review reached the same conclusion independently and
proposed `Sequence` / `SequenceMachine` nodes in a versioned RuleIR v2.

## Recommended first slice

A **single-event** EQL query is genuinely just a filter, and lowers honestly onto
nodes that already exist:

```
[ process where process.name == "regsvr32.exe" ]
```

That is a complete, verifiable, non-approximating first commit: parse it, lower
to `Read` → `Filter` → `Emit`, execute it, and render it back. It is the same
shape as the SPL work that had to land `fields`/`sort`/`head` before the
`head` renderer was reachable at all.

Then, in order:

1. `sequence` with no `by`, no `maxspan`, no `until`, no `!` — only valid if a
   real step node exists; otherwise refuse.
2. Join keys, then `maxspan`, then `until`, then `!`, then `runs`, then `sample`.
   Each step is its own commit with its own refusal test for the step below it.

## The trap to avoid

The single-event slice is easy to mistake for "EQL support". It is not. The value
of EQL is overwhelmingly the sequences — every real detection written in it is a
`sequence` or a `sample` — and a tool that parses `[ x where y ]` while refusing
`sequence` has the easy 5% and none of the rest. Whatever ships must say plainly
which of these are supported.
