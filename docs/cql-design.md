# CrowdStrike Falcon CQL — measured grammar, and the mapping

Written before any CQL code, deliberately, so the parser is built against the
real syntax rather than a plausible guess. Sources:

- <https://developer.crowdstrike.com/api-reference/falcon-query-language> (FQL)
- <https://library.humio.com/crowdstrike-query-language/syntax.html> (CQL/LogScale)
- <https://github.com/straw-hat-kjones/cql-best-practices/blob/main/SKILL.md>
- <https://library.humio.com/logscale-terminology/terminology-cql.html>

## There are TWO languages, and they share a name

**FQL (Falcon Query Language)** is the API filter syntax. Flat boolean
expressions over properties:

```
<property>:[operator]<value>
hostname:'g*' + platform_name:!'Linux'
(hostname:'a*'),(hostname:'b*'+platform_name:'Linux')
```

- Properties: alphanumeric plus underscore only, first character a letter,
  always lowercase (uppercase accepted and converted). Dotted for complex ones
  (`author.name`).
- Operators: default is equal; `!` not-equal; `>` `>=` `<` `<=`; `~` text-match
  (tokenises, ignores case/punctuation); `!~` not-text-match; `*` wildcard
  (one or more chars). `[ 'value' ]` forces an exact, case-sensitive match.
- Values: strings in single quotes, dates in UTC in single quotes, booleans
  lowercase unquoted (`featured:true`), integers unquoted (`posts.count:>10`).
- Boolean structure: `+` is AND, `,` is OR, `(...)` groups. Max 20 properties
  per statement.

**CQL (CrowdStrike Query Language, LogScale)** is a PIPELINE language: a chain
of commands linked by pipes, each passing its result to the next. This
architecture is explicitly Unix-pipe-like, which means it maps onto the same
structural vocabulary the IR already has (Filter, Aggregate, Arrange, Derive):

```
#event_simpleName=ProcessRollup2
UserName = "admin*"
@timestamp > now() - 24h
newField := oldField + "_suffix"
| table ComputerName, ImageFileName
| sort(field, limit=20000)
| rename ContextProcessId_decimal as TargetProcessId_decimal
| join TargetProcessId_decimal [ search event_simpleName=ProcessRollup2 ]
```

- `#name` is a TAG field (indexed, fast). `@name` is METADATA (`@timestamp`).
  Bare names are event fields. Wildcards allowed in values (`"admin*"`).
- Comparison: `=`, `!=`, `<`, `>`, `<=`, `>=`. Logical: `AND`, `OR`, `NOT`, `!`.
- `field = *` means EXISTS; `field != *` means NOT EXISTS.
- `in(field, values=["a", "b"])` for membership.
- Regex: `field=/pattern/i` (inline with flags), `regex("...", field=...)`.
- `:=` assigns a new field. `//` and `/* */` are comments.

## The mapping, and why CQL/LogScale is the easier second dialect

The pipeline shape is SPL-shaped: filters, then transforms, then output. So the
IR vocabulary built for SPL applies almost directly:

| CQL | IR | Status |
|---|---|---|
| `field = "value"`, `#tag=...`, `@ts > ...` | `Filter` | shipped |
| `AND` / `OR` / `NOT` | `BoolOp` / `Not` | shipped; NOT > AND > OR |
| `field = *` (exists) | presence test | refused — `CQL_EXISTS_NOT_LOWERED` |
| `field = "a*"` (wildcard) | `Call(matches_regex)` | refused — `CQL_WILDCARD_NOT_LOWERED` |
| `field=/re/i` (regex) | `Call(matches_regex)` | refused — `CQL_REGEX_NOT_LOWERED` |
| `now()`, `now() - 24h` | `TimeRef`/`Duration` | refused — would freeze an instant into the rule |
| `x := operand` | `Derive(kind="eval")` | shipped, SINGLE OPERAND only (field, quoted string, or number) |
| `x := oldField + "_suffix"` | `Derive(kind="eval")` | **refused** — `CQL_ASSIGN_EXPRESSION_NOT_LOWERED` |
| `\| table a, b` | `Derive(kind="fields")` | shipped |
| `\| sort(f)` | `Arrange` | shipped, ascending + optional `limit=` |
| `\| rename a as b` | `Derive(kind="rename")` | shipped |
| `\| count()` | `Aggregate(count)`, `Frame(kind="per_event")` | shipped, NULLARY only |
| `\| count(field=x)` | `Aggregate` over a field | **refused** — a different count |
| `\| count(by=x)` | `Aggregate` with keys | **refused** — grouped, not one number |
| `in(field, [...])` | `BoolOp("or", equalities)` | shipped, lowered EXACTLY as a disjunction |
| `join()` | — | **refused** — see "Why `join()` is refused" below |
| `timechart()`, other aggregates | `Aggregate` | **not lowered yet** — have the node; per-function mapping needed |

The two header examples above are deliberately NOT both shipped. The pipeline
sample at the top of this file uses `newField := oldField + "_suffix"`, which is
an expression; the slice takes a single operand and refuses the rest by name.
That refusal is the correct behaviour, not a missing feature to be papered over.

### Why `join()` is refused — the design doc's first guess was wrong

This file originally proposed `| join k [ search ... ]` mapping onto the IR's
`Join` node, on the assumption that it was a pipeline stage shaped like the one
KQL builds. Measured against LogScale's own `join()` reference, that is wrong in
ways that matter, so the proposal is withdrawn rather than softened.

`join()` is a FILTER function with eleven named parameters whose **defaults
change which rows come back**:

| Parameter | Default | Why the IR's `Join` cannot hold it |
|---|---|---|
| `mode` | `inner` | `left` keeps every left event. The node has `how`, so this one is fine. |
| `max` | `1` | Takes ONE subquery row per key. Two subquery rows sharing a key yield ONE output row. No field for a per-key fan-in limit. |
| `include` | none | Adds named subquery fields to matching events — and per the docs, a subquery event missing one outputs **the empty string**. |
| `limit` | `100000` | Caps the subquery. |
| `repo` / `view` / `start` / `end` | inherited | The subquery may read a **different repository or time range**. |

The `include` row is the decisive one, and it is not a missing-feature problem.
This engine keeps `NULL` and `""` distinct throughout, because a detection that
cannot tell "field absent" from "field empty" cannot be trusted. LogScale's
`join` documents filling a missing include field with the empty string. Lowering
it onto the IR would put a fabricated value into the output row — so the honest
answer is a refusal naming the behaviour, not a join node one commit away.

What the IR's `Join` CAN express, per `kql_ir.py`: same-named key equality,
`inner` or `left`, and a `column_map` recording which merged column came from
which side. That is what `mode=inner` with no `include`, no `max`, and no
cross-repo read would reduce to. A future slice can take exactly that subset —
and must say so, rather than accepting a `join(` and dropping what it ignores.

### The shape traps this slice already hit

- **THE RIGHT OF `:=` IS NOT A COMPARISON.** `x := lit` copies the FIELD named
  `lit`; `x := "lit"` assigns the CONSTANT. Everywhere else in CQL a bare token
  and a quoted string mean the same thing, so a renderer that normalises quotes
  everywhere else quietly turns a fixed value into a field read here — a rule
  that fails open on rows where that field is absent. The renderer quotes string
  literals specifically on this path. (A *filter* comparison is unaffected:
  `a = lit` already means "equals the string lit".)
- **`:=` MUST BE SCANNED BEFORE ANY PAREN CHECK, quote- and paren-aware.** An
  assignment RHS may contain a paren *inside a string* (`x := "a(b"`), and a
  naive `(` split misreads that as a function call. A `:=` inside a value, or
  inside parens, must not misroute the other way either.

### Stage ORDER is load-bearing, so it is STORED

`CqlQuery` holds `stages: tuple[CqlStage, ...]` — one ordered list, not one
optional slot per pipe kind. The slot version emitted every non-table pipe
before `| table`, so `| table a,b | sort(x)` (project, then order by a column
that survived the projection) became `| sort(x) | table a,b`: a different rule
that can order by a column the analyst's own query had already dropped. The
parse looked right, the node chain looked plausible, and the suite stayed green
— which is why `mutation_check.py` M16 now pins it.

FQL (the API form) is SMALLER: one flat boolean filter with `+`/`,`/`()`.
It lowers to a single `Filter` and nothing else. It is the natural slice 1,
because it cannot be half-done -- it is either a filter or a refusal.

## Recommended order

1. **FQL flat filters** (`field:value`, operators, `+`/`,`/`()`). One `Filter`,
   refused by name for anything else. Small, complete, verifiable.
2. **CQL filter stage** (`#tag`, `@meta`, `field op value`, `AND`/`OR`/`NOT`,
   exists, regex). Same `Filter`, richer leaf syntax.
3. **CQL pipes** (`table`, `sort`, `rename`, `:=`) onto the existing SPL-shaped
   nodes. The renderer work for these already exists in another dialect; do not
   write a third copy -- share the stage builder or say why not.
4. **`join` + sub-search, aggregates, `in()`** -- each its own commit with its
   own refusal test for the step below it.

## The traps, named in advance

- **Do not mix the two languages.** FQL's `field:value` and CQL's `field =
  "value"` look similar and are different grammars with different operators
  (`+`/`,` vs `AND`/`OR`, `~` vs `=`, `[...]` exact-match vs `[...]` event
  brackets in EQL). A parser that accepts both shapes in one grammar will accept
  strings that are valid in neither.
- **The label must say which one.** Registering "CrowdStrike Falcon" for an
  FQL-only slice claims the pipeline language too. Name the slice in the label,
  the way EQL's says "single event".
- **`@timestamp > now() - 24h`** needs `now()` evaluated at lower time, not
  stored as a literal -- otherwise the rendered rule carries a stale instant.
  Refuse it until `now()` is handled, because a frozen timestamp is a rule that
  silently stops matching new events.
