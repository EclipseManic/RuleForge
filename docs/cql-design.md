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
| `field = "value"`, `#tag=...`, `@ts > ...` | `Filter` | same as SPL search terms |
| `AND` / `OR` / `NOT` | `BoolOp` / `Not` | same precedence work as SPL `where` |
| `field = *` (exists) | presence test | engine already has exists/is_not_null |
| `field = "a*"` (wildcard) | `Call(matches_regex)` | needs glob-to-regex, refused until then |
| `field=/re/i` (regex) | `Call(matches_regex)` | have it |
| `x := expr` | `Derive(kind="eval")` | have it |
| `\| table a, b` | `Derive(kind="fields")` | have it |
| `\| sort(f)` | `Arrange` | have it, direction as a parameter |
| `\| rename a as b` | `Derive(kind="rename")` | have it |
| `\| join k [ search ... ]` | `Join` + sub-search | IR has Join; SPL renderer has the sub-search path |
| `in(field, [...])` | — | **missing**: membership test |
| `count()`, `timechart()`, aggregates | `Aggregate` | have the node; per-function mapping needed |
| `now() - 24h` | `TimeRef`/`Duration` | have the types |

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
